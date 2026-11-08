"""[Nivel 3 · infraestructura] Copia local e indexada de los logs, descargada a través de la API simulada.

La API recorre la fuente entera en cada búsqueda (0,1–1 s) y devuelve como mucho 2.000 eventos. Para el triaje basta,
pero para rastrear un incidente por saltos (decenas de entidades × 18 fuentes) no. Este módulo descarga cada fuente
**por la API** (nada se lee de 04_logs ni se modifica en DTT-UAB-The-Hack-main) y la guarda en
`salidas/indice_logs.sqlite`, con un índice invertido de identificadores.

- Descarga: `/logs/{fuente}?desde=<cursor>&limit=2000`, avanzando el cursor al último `timestamp` de cada página y
  descartando los eventos ya vistos con ese mismo instante. Requiere que la API devuelva cada fuente en orden
  cronológico (así es en el dataset); si una página llega desordenada o un mismo instante llena una página entera
  (2.000 eventos), se aborta con `IndiceNoFiable` en vez de guardar un índice incompleto.
- Índice: cada valor de texto se parte en identificadores con la misma regla que `herramientas._coincide` (letras,
  cifras, «_», «-» y «.» seguido de otro de ellos). Solo se indexan los que tienen forma de entidad (IP, equipo, UPN,
  hash, dominio, clave, ID…): con «.», «_» o «-», o con cifras y letras, o números de 5+ cifras. Las palabras sueltas
  («admin», «login») no se indexan; para ellas `eventos_de` devuelve None y el llamador usa la API.
- Consulta: `eventos_de(texto, desde, hasta, fuentes)` da el mismo resultado que `herramientas.buscar_eventos` (los
  candidatos del índice se verifican con `_coincide`), pero sobre todas las fuentes, sin límite de 2.000 y en ms.

Uso: `python agent.py --construir-indice` (unos minutos, una vez) y `python agent.py --estado-indice`.
Las herramientas del modelo siguen consultando la API en vivo (traza de la demo); el índice es para el código
determinista que necesita volumen (cronología y rastreo del nivel 3).
"""
import datetime as dt
import json
import os
import re
import sqlite3
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agente import herramientas
from agente.herramientas import FUENTES_LOG, _coincide

RUTA = Path(__file__).resolve().parent.parent / "salidas" / "indice_logs.sqlite"
PAGINA = 2000  # máximo que admite la API
CAMPOS_TIEMPO = ("timestamp", "eventTime")
_RUN = re.compile(r"[0-9A-Za-z_\-]+(?:\.[0-9A-Za-z_\-]+)*")  # identificador completo, como herramientas._coincide
_SUFIJO = re.compile(r"\.([0-9A-Za-z_\-]+(?:\.[0-9A-Za-z_\-]+)*)")  # '.dominio' = subdominios de dominio


class IndiceNoFiable(RuntimeError):
    """La API no permite descargar la fuente completa con garantías (orden o tamaño de página)."""


def _ts(evento: dict) -> str:
    return evento.get("timestamp") or evento.get("eventTime", "")


def _clave(evento: dict) -> str:
    return str(evento.get("event_id") or zlib.crc32(json.dumps(evento, sort_keys=True).encode()))


# --------------------------------------------------------------------------------------------- tokens

def indexable(token: str) -> bool:
    """Forma de entidad: con «.», «_» o «-», con cifras y letras, o número de 5+ cifras; mínimo 3 caracteres."""
    if len(token) < 3:
        return False
    if any(c in token for c in "._-"):
        return True
    if token.isdigit():
        return len(token) >= 5
    return any(c.isdigit() for c in token)


def _valores(obj, raiz=True):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not (raiz and k in CAMPOS_TIEMPO):
                yield from _valores(v, False)
    elif isinstance(obj, list):
        for v in obj:
            yield from _valores(v, False)
    elif isinstance(obj, str):
        yield obj
    elif obj is not None and not isinstance(obj, bool):
        yield str(obj)


def tokens_de_evento(evento: dict) -> set[str]:
    """Identificadores con forma de entidad que aparecen en los valores del evento (en minúsculas)."""
    return {t.lower() for v in _valores(evento) for t in _RUN.findall(v) if indexable(t)}


def tokens_exactos(texto: str) -> list[str]:
    """Identificadores de la consulta que deben aparecer tal cual como token en el evento.

    Un identificador pegado a un «.» en un extremo de la consulta no es exacto: '.evil.com' casa con 'a.evil.com',
    cuyo token es 'a.evil.com', no 'evil.com'. El resto sí, porque `_coincide` exige límites en los extremos que son
    de identificador y los caracteres intermedios de la consulta coinciden con los del evento."""
    exactos = []
    for m in _RUN.finditer(texto):
        if (m.start() == 1 and texto[0] == ".") or (m.end() == len(texto) - 1 and texto[-1] == "."):
            continue
        if indexable(m.group()):
            exactos.append(m.group().lower())
    return exactos


# --------------------------------------------------------------------------------------------- descarga por la API

def descargar(fuente: str, get=None):
    """Genera páginas con todos los eventos de `fuente` vía `/logs/{fuente}`, sin repetir ninguno."""
    get = get or herramientas._get
    cursor, vistos = "", set()  # vistos: eventos con timestamp == cursor ya entregados
    while True:
        d, error, _ = get(f"/logs/{fuente}", {"desde": cursor, "limit": PAGINA})
        if d is None:
            raise IndiceNoFiable(f"{fuente}: la API devolvió {error}")
        items = d["items"]
        tiempos = [_ts(e) for e in items]
        if any(a > b for a, b in zip(tiempos, tiempos[1:])):
            raise IndiceNoFiable(f"{fuente}: la API no devuelve los eventos en orden cronológico; "
                                 "no se puede paginar por tiempo sin perder eventos")
        nuevos = [e for e in items if _clave(e) not in vistos]
        if nuevos:
            yield nuevos
        if not d.get("truncated") or len(items) < PAGINA:
            return
        if tiempos[-1] == cursor:
            raise IndiceNoFiable(f"{fuente}: al menos {PAGINA} eventos con el instante {cursor}; "
                                 "no se puede paginar sin perder eventos")
        cursor = tiempos[-1]
        vistos = {_clave(e) for e, t in zip(items, tiempos) if t == cursor}


# --------------------------------------------------------------------------------------------- compresión
# Cada evento se comprime por separado (acceso aleatorio) con un diccionario de muestras de su fuente: los eventos de
# una fuente repiten claves y valores, y así ocupan ~4,5 veces menos que con zlib sin diccionario.

def _diccionario(textos: list[bytes], muestras: int = 400) -> bytes:
    paso = max(1, len(textos) // muestras)
    return b"".join(textos[::paso])[-32768:]


def _comprimir(texto: bytes, dicc: bytes) -> bytes:
    c = zlib.compressobj(6, zdict=dicc)
    return c.compress(texto) + c.flush()


def _descomprimir(datos: bytes, dicc: bytes) -> dict:
    d = zlib.decompressobj(zdict=dicc)
    return json.loads(d.decompress(datos) + d.flush())


# --------------------------------------------------------------------------------------------- construcción

_ESQUEMA = """
CREATE TABLE eventos (id INTEGER PRIMARY KEY, fuente TEXT NOT NULL, event_id TEXT NOT NULL, ts TEXT NOT NULL,
                      datos BLOB NOT NULL);
CREATE TABLE tokens (id INTEGER PRIMARY KEY, texto TEXT UNIQUE NOT NULL, n INTEGER NOT NULL DEFAULT 0);
CREATE TABLE apariciones (token INTEGER NOT NULL, evento INTEGER NOT NULL, PRIMARY KEY (token, evento)) WITHOUT ROWID;
CREATE TABLE fuentes (fuente TEXT PRIMARY KEY, eventos INTEGER, primero TEXT, ultimo TEXT, segundos REAL,
                      diccionario BLOB);
CREATE TABLE meta (clave TEXT PRIMARY KEY, valor TEXT);
"""


def construir(fuentes: list[str] | None = None, ruta: Path = RUTA, get=None, hilos: int = 4, aviso=print) -> dict:
    """Descarga las fuentes por la API y crea el índice en `ruta` (se escribe en un temporal y se sustituye al final,
    así que un índice anterior sigue utilizable hasta que el nuevo está completo). Devuelve `estado()` del nuevo."""
    fuentes = fuentes or FUENTES_LOG
    tmp = ruta.with_suffix(".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.unlink(missing_ok=True)
    con = sqlite3.connect(tmp)
    con.executescript("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;" + _ESQUEMA)
    ids_token: dict[str, int] = {}
    cuentas: dict[int, int] = {}
    t_total = time.time()

    def bajar(fuente):
        t0 = time.time()
        return fuente, [e for pagina in descargar(fuente, get) for e in pagina], time.time() - t0

    try:
        with ThreadPoolExecutor(max_workers=hilos) as pool:  # descarga en paralelo, escritura en este hilo
            for fuente, evs, segundos in pool.map(bajar, fuentes):
                filas, apariciones = [], []
                siguiente = (con.execute("SELECT COALESCE(MAX(id), 0) FROM eventos").fetchone()[0]) + 1
                textos = [json.dumps(e, ensure_ascii=False).encode() for e in evs]
                dicc = _diccionario(textos)
                for i, (e, texto) in enumerate(zip(evs, textos), siguiente):
                    filas.append((i, fuente, _clave(e), _ts(e), _comprimir(texto, dicc)))
                    for t in tokens_de_evento(e):
                        tid = ids_token.setdefault(t, len(ids_token) + 1)
                        cuentas[tid] = cuentas.get(tid, 0) + 1
                        apariciones.append((tid, i))
                con.executemany("INSERT INTO eventos VALUES (?,?,?,?,?)", filas)
                con.executemany("INSERT INTO apariciones VALUES (?,?)", apariciones)
                tiempos = [_ts(e) for e in evs]
                con.execute("INSERT INTO fuentes VALUES (?,?,?,?,?,?)",
                            (fuente, len(evs), min(tiempos, default=""), max(tiempos, default=""),
                             round(segundos, 1), dicc))
                aviso(f"  {fuente:13} {len(evs):>7} eventos  {segundos:5.1f} s")
        con.executemany("INSERT INTO tokens VALUES (?,?,?)", ((i, t, cuentas[i]) for t, i in ids_token.items()))
        con.executescript("CREATE INDEX eventos_fuente_ts ON eventos (fuente, ts); "
                          "CREATE INDEX eventos_ts ON eventos (ts); "
                          "CREATE INDEX eventos_event_id ON eventos (event_id);")
        con.executemany("INSERT INTO meta VALUES (?,?)", [
            ("construido", dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")),
            ("api_url", herramientas.API_URL), ("segundos", str(round(time.time() - t_total, 1)))])
        con.commit()
    except BaseException:
        con.close()
        tmp.unlink(missing_ok=True)
        raise
    con.close()
    _cerrar(ruta)
    os.replace(tmp, ruta)
    return estado(ruta)


# --------------------------------------------------------------------------------------------- consulta

_CONEXIONES: dict[Path, sqlite3.Connection] = {}
_DICCIONARIOS: dict[Path, dict[str, bytes]] = {}


def _conexion(ruta: Path = RUTA) -> sqlite3.Connection | None:
    if ruta not in _CONEXIONES:
        if not ruta.exists():
            return None
        con = sqlite3.connect(f"file:{ruta}?mode=ro", uri=True, check_same_thread=False)
        _DICCIONARIOS[ruta] = dict(con.execute("SELECT fuente, diccionario FROM fuentes"))
        _CONEXIONES[ruta] = con
    return _CONEXIONES[ruta]


def _cerrar(ruta: Path = RUTA) -> None:
    con = _CONEXIONES.pop(ruta, None)
    _DICCIONARIOS.pop(ruta, None)
    if con:
        con.close()


def disponible(ruta: Path = RUTA) -> bool:
    return _conexion(ruta) is not None


def estado(ruta: Path = RUTA) -> dict | None:
    """Resumen del índice: cuándo y desde qué API se construyó, y eventos por fuente. None si no existe."""
    con = _conexion(ruta)
    if con is None:
        return None
    meta = dict(con.execute("SELECT clave, valor FROM meta"))
    fuentes = {f: {"eventos": n, "primero": p, "ultimo": u, "segundos": s} for f, n, p, u, s in
               con.execute("SELECT fuente, eventos, primero, ultimo, segundos FROM fuentes ORDER BY fuente")}
    return {**meta, "ruta": str(ruta), "mb": round(ruta.stat().st_size / 1e6, 1),
            "eventos": sum(x["eventos"] for x in fuentes.values()), "fuentes": fuentes}


def _filas(ruta: Path, sql: str, params: list, texto: str | None, limite: int | None) -> list[dict]:
    salida, dicc = [], _DICCIONARIOS[ruta]
    for fuente, datos in _CONEXIONES[ruta].execute(sql, params):
        e = _descomprimir(datos, dicc[fuente])
        if texto is None or _coincide(texto, e):
            salida.append({**e, "_fuente": fuente})
            if limite and len(salida) >= limite:
                break
    return salida


def _filtros(desde: str, hasta: str, fuentes: list[str] | None) -> tuple[str, list]:
    sql, params = "", []
    if desde:  # mismas comparaciones que la API: cadenas ISO en UTC, límites incluidos
        sql, params = sql + " AND e.ts >= ?", params + [desde]
    if hasta:
        sql, params = sql + " AND e.ts <= ?", params + [hasta]
    if fuentes:
        sql += f" AND e.fuente IN ({','.join('?' * len(fuentes))})"
        params += list(fuentes)
    return sql, params


def eventos_de(texto: str, desde: str = "", hasta: str = "", fuentes: list[str] | None = None,
               limite: int | None = None, ruta: Path = RUTA) -> list[dict] | None:
    """Eventos de cualquier fuente que contienen `texto` como identificador completo, en orden cronológico; cada uno
    lleva `_fuente`. '.dominio' devuelve los eventos de sus subdominios (como en la API). Devuelve None si no hay
    índice o si `texto` no tiene ningún identificador indexable (p. ej. una palabra suelta): entonces hay que usar
    `herramientas.buscar_eventos`."""
    con = _conexion(ruta)
    if con is None:
        return None
    filtro, p = _filtros(desde, hasta, fuentes)
    sufijo = _SUFIJO.fullmatch(texto)
    if sufijo and indexable(sufijo.group(1)):  # '.dominio': el dominio y sus subdominios
        patron = "%." + re.sub(r"([\\%_])", r"\\\1", sufijo.group(1).lower())
        sql = ("SELECT e.fuente, e.datos FROM eventos e WHERE e.id IN (SELECT evento FROM apariciones WHERE token IN "
               "(SELECT id FROM tokens WHERE texto LIKE ? ESCAPE '\\'))")
        return _consultar(ruta, "indice:eventos_de", sql, [patron], filtro, p, texto, desde, hasta, fuentes, limite)
    exactos = tokens_exactos(texto)
    if not exactos:
        return None
    ids = []
    for t in set(exactos):
        fila = con.execute("SELECT id, n FROM tokens WHERE texto = ?", (t,)).fetchone()
        if fila is None:
            return []  # un token obligatorio no aparece en ningún evento
        ids.append(fila)
    ids.sort(key=lambda x: x[1])  # el más raro primero: lista de candidatos más corta
    sql = "SELECT e.fuente, e.datos FROM apariciones a JOIN eventos e ON e.id = a.evento WHERE a.token = ?"
    params = [ids[0][0]]
    for tid, _ in ids[1:]:
        sql += " AND EXISTS (SELECT 1 FROM apariciones b WHERE b.token = ? AND b.evento = a.evento)"
        params.append(tid)
    return _consultar(ruta, "indice:eventos_de", sql, params, filtro, p, texto, desde, hasta, fuentes, limite)


def _consultar(ruta, nombre, sql, params, filtro, p, texto, desde, hasta, fuentes, limite) -> list[dict]:
    """Ejecuta la consulta de candidatos, verifica cada uno con `_coincide` y deja la consulta en la traza."""
    t0 = time.time()
    salida = _filas(ruta, sql + filtro + " ORDER BY e.ts, e.id", params + p, texto, limite)
    herramientas._registrar(nombre, {"q": texto, "desde": desde, "hasta": hasta,
                                     **({"fuentes": fuentes} if fuentes else {})},
                            int((time.time() - t0) * 1000), len(salida), None)
    return salida


def eventos_entre(desde: str, hasta: str, fuentes: list[str] | None = None, limite: int | None = None,
                  ruta: Path = RUTA) -> list[dict] | None:
    """Todos los eventos de la ventana (y fuentes) en orden cronológico; None si no hay índice."""
    con = _conexion(ruta)
    if con is None:
        return None
    filtro, params = _filtros(desde, hasta, fuentes)
    return _filas(ruta, "SELECT e.fuente, e.datos FROM eventos e WHERE 1=1" + filtro + " ORDER BY e.ts, e.id",
                  params, None, limite)


def evento(event_id: str, ruta: Path = RUTA) -> dict | None:
    """Un evento por su ID (p. ej. los `related_events` de una alerta); None si no está o no hay índice."""
    con = _conexion(ruta)
    if con is None:
        return None
    fila = con.execute("SELECT fuente, datos FROM eventos WHERE event_id = ?", (event_id,)).fetchone()
    return {**_descomprimir(fila[1], _DICCIONARIOS[ruta][fila[0]]), "_fuente": fila[0]} if fila else None
