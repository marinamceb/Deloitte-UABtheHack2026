"""[Nivel 2 · correlación] Agrupación determinista de alertas en incidentes candidatos, antes de llamar al modelo.

1. Se aparta el ruido de fondo: alertas cuyo patrón (regla + campos estables de la evidencia, ver PATRONES_RUIDO) se
   repite >= UMBRAL_RUIDO veces en todo el SIEM. Ese ruido lo resuelven las plantillas; si se usara para enlazar,
   uniría cosas sin relación (p. ej. el inventario de SCCM y un correo reportado del mismo usuario).
2. Entre las alertas restantes se enlazan las que comparten una entidad exacta (equipo, usuario, IP, dominio, hash o
   identidad cloud) con menos de VENTANA_H horas entre una y la siguiente (enlace en cadena: un incidente puede durar
   días). Las entidades que aparecen en más de MAX_ALERTAS_ENTIDAD alertas (concentradores como wetransfer.com o
   la IP de salida corporativa) no enlazan.
   Las entidades «fuertes» (hash, IP o dominio maliciosos según el TIP, cuenta que incumple una regla interna)
   enlazan hasta VENTANA_FUERTE_H horas: identifican al atacante aunque el ataque dure días (ransomware del 9/10 y su
   persistencia del 18/10 con la misma cuenta y el mismo malware).
   Las alertas cubiertas por un cambio aprobado (por origen autorizado, ver cambios.py) nunca son ruido y solo se
   enlazan a través de su cambio: forman una única actividad autorizada (p. ej. las 20 alertas del pentest desde
   tres IPs) y no se mezclan con un ataque que comparta entidades (la sesión autorizada de ext.logisoft del 16/10).
3. Las componentes conexas son los incidentes candidatos. El modelo los revisa y confirma qué alertas pertenecen al
   mismo ataque; el código solo propone.
Además, `tickets_relacionados` avisa al crear un ticket si alguna de sus entidades fuertes ya está en otro ticket.
"""
import collections
import json
import re
from functools import lru_cache

from . import almacen, api
from . import herramientas as h
from .comun import de_alerta, es_interna, utc
from .plantillas import FIRMAS

PATRONES_RUIDO = {
    **FIRMAS,
    "UC-EDR-001": ["process_tree", "signer", "edr_action"],                       # Excel > saplogon firmado por SAP
    "UC-IDP-001": ["previous_login", "minutes_between", "device", "distance_km", "note", "post_login_actions"],
}
UMBRAL_RUIDO = 20
VENTANA_H = 72                  # equipos, usuarios y demás entidades
VENTANA_FUERTE_H = 14 * 24      # entidades fuertes
MAX_ALERTAS_ENTIDAD = 15        # más alertas = concentrador (no enlaza)
MAX_ALERTAS_FUERTE = 50

_ALERTAS: dict[str, dict] | None = None
_INCIDENTES: dict[str, list[str]] | None = None  # alert_id → alert_ids del incidente (ordenados por fecha)


def todas_las_alertas() -> dict[str, dict]:
    global _ALERTAS
    if _ALERTAS is None:
        datos, error, _ = h._get("/alerts", {"status": "new", "limit": 100000})
        if datos is None:
            raise RuntimeError(f"No se pudieron cargar las alertas: {error}")
        _ALERTAS = {a["alert_id"]: a for a in datos["items"]}
    return _ALERTAS


def _patron(a: dict) -> str | None:
    campos = PATRONES_RUIDO.get(a.get("rule_id", ""))
    if not campos:
        return None
    ev = a.get("evidence", {})
    return a["rule_id"] + "|" + json.dumps({c: ev.get(c) for c in campos}, ensure_ascii=False, sort_keys=True)


def entidades(a: dict) -> set[str]:
    """Entidades de enlace con prefijo de tipo (host:, user:, ip:, dom:, hash:, cloud:)."""
    e = de_alerta(a)
    return ({"host:" + x.lower() for x in e["hosts"]} | {"user:" + x.lower() for x in e["users"]}
            | {"ip:" + x for x in e["ips"]} | {"dom:" + x for x in e["domains"]} | {"hash:" + x for x in e["hashes"]}
            | {"cloud:" + e["cloud"][k] for k in ("identity", "bucket") if e["cloud"].get(k)})


def _fecha(a: dict):
    return utc(a["created_at"])


@lru_cache(maxsize=1)
def _cubiertas() -> dict[str, frozenset[str]]:
    """alert_id → cambios aprobados que la cubren por origen autorizado (solo las que tienen alguno)."""
    from . import cambios
    return {i: frozenset(c) for i, a in todas_las_alertas().items() if (c := cambios.ids_que_cubren(a))}


@lru_cache(maxsize=1)
def _ids_senal() -> frozenset[str]:
    return frozenset(a["alert_id"] for a in _senal())


def es_ruido(alert_id: str) -> bool:
    """Ruido de fondo: patrón repetido >= UMBRAL_RUIDO veces y no cubierto por un cambio aprobado."""
    return alert_id not in _ids_senal()


def cubierta_por_cambio(alert_id: str) -> frozenset[str]:
    """Cambios aprobados que cubren la alerta (vacío si ninguno)."""
    return _cubiertas().get(alert_id, frozenset())


def _senal() -> list[dict]:
    """Alertas que no son ruido de fondo (las cubiertas por un cambio aprobado nunca lo son)."""
    alertas = todas_las_alertas().values()
    frec = collections.Counter(p for a in alertas if (p := _patron(a)))
    return [a for a in alertas if a["alert_id"] in _cubiertas()
            or not ((p := _patron(a)) and frec[p] >= UMBRAL_RUIDO)]


@lru_cache(maxsize=1)
def cuentas_sospechosas() -> frozenset[str]:
    """Cuentas con un resultado `sospechosa`: reglas internas de cuentas (adm.*, ext.*, svc_*) o RRHH (cuenta usada
    tras el último día, fuga antes de la baja)."""
    from . import contexto
    from . import reglas_internas as R
    patron = re.compile(r"\b(?:adm\.[a-z0-9_.-]+|ext\.[a-z0-9_.-]+|svc_[a-z0-9_]+)")
    cuentas = set()
    with h.origen("incidentes"):
        for a in _senal():
            if patron.search(json.dumps(a)):
                for r in R.regla_cuentas_adm([a]) + R.regla_logisoft([a]) + R.regla_svc_backup([a]):
                    if r["estado"] == R.SOSPECHOSA:
                        cuentas |= set(patron.findall(r["sujeto"]))
            if de_alerta(a)["users"]:
                cuentas |= {r["sujeto"].split("@")[0] for r in contexto.rrhh([a]) if r["estado"] == R.SOSPECHOSA}
    return frozenset(cuentas)


@lru_cache(maxsize=4096)
def _es_fuerte(x: str) -> bool:
    tipo, valor = x.split(":", 1)
    if tipo == "hash":
        return True
    if tipo == "user":
        return valor.split("@")[0] in cuentas_sospechosas()
    if (tipo == "ip" and not es_interna(valor)) or tipo == "dom":
        with h.origen("incidentes"):
            return api.reputacion(valor) == "malicious"
    return False


def entidades_fuertes(a: dict) -> set[str]:
    """[Nivel 2] Hash, IP o dominio maliciosos según el TIP, o cuenta que incumple una regla interna."""
    return {x for x in entidades(a) if _es_fuerte(x)}


def construir() -> dict[str, list[str]]:
    global _INCIDENTES
    if _INCIDENTES is not None:
        return _INCIDENTES
    alertas = todas_las_alertas()
    senal = _senal()
    cubiertas = _cubiertas()
    ent_alerta = {a["alert_id"]: {"chg:" + c for c in cubiertas[a["alert_id"]]} if a["alert_id"] in cubiertas
                  else entidades(a) for a in senal}
    frec_ent = collections.Counter(x for a in senal for x in ent_alerta[a["alert_id"]])

    padre = {a["alert_id"]: a["alert_id"] for a in senal}

    def raiz(x):
        while padre[x] != x:
            padre[x] = padre[padre[x]]
            x = padre[x]
        return x

    def limites(x: str) -> tuple[float, int]:
        """(ventana en horas, máximo de alertas) con que enlaza una entidad."""
        if x.startswith("chg:"):
            return float("inf"), 10 ** 6
        return (VENTANA_FUERTE_H, MAX_ALERTAS_FUERTE) if _es_fuerte(x) else (VENTANA_H, MAX_ALERTAS_ENTIDAD)

    por_entidad = collections.defaultdict(list)
    for a in senal:
        for x in ent_alerta[a["alert_id"]]:
            por_entidad[x].append(a)
    for x, lista in por_entidad.items():
        ventana_h, maximo = limites(x)
        if frec_ent[x] > maximo:
            continue
        lista.sort(key=_fecha)
        for p, q in zip(lista, lista[1:]):
            if (_fecha(q) - _fecha(p)).total_seconds() <= ventana_h * 3600:
                padre[raiz(p["alert_id"])] = raiz(q["alert_id"])

    grupos = collections.defaultdict(list)
    for aid in padre:
        grupos[raiz(aid)].append(aid)
    _INCIDENTES = {}
    for ids in grupos.values():
        if len(ids) > 1:
            ids.sort(key=lambda i: alertas[i]["created_at"])
            for i in ids:
                _INCIDENTES[i] = ids
    return _INCIDENTES


def incidente_de(alert_id: str) -> list[str]:
    """Alertas del incidente candidato de esta alerta (incluida), o [] si está sola o es ruido."""
    return construir().get(alert_id, [])


def resumen(alert_ids: list[str], excluir: str = "", maximo: int = 12) -> str:
    """Las alertas del incidente en formato compacto para el modelo (las más graves primero si hay que recortar)."""
    alertas = todas_las_alertas()
    orden = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    otras = [alertas[i] for i in alert_ids if i != excluir]
    elegidas = sorted(sorted(otras, key=lambda a: orden.get(a["severity"], 5))[:maximo], key=lambda a: a["created_at"])
    campos = ("alert_id", "created_at", "rule_id", "rule_name", "severity", "entities", "evidence", "related_events")
    lineas = [json.dumps({k: a.get(k) for k in campos}, ensure_ascii=False, separators=(",", ":")) for a in elegidas]
    if len(otras) > maximo:
        lineas.append(f"(y {len(otras) - maximo} alertas más de menor severidad; consúltalas con consultar_alerta)")
    return "\n".join(lineas)


def tickets_relacionados(alert_ids: list[str], ticket_id: str) -> list[dict]:
    """[Nivel 2] Otros tickets que comparten alguna entidad fuerte con estas alertas (posible mismo ataque)."""
    todas = todas_las_alertas()

    def fuertes(ids) -> set[str]:
        return set().union(*(entidades_fuertes(todas[i]) for i in ids if i in todas))

    mias, out = fuertes(alert_ids), []
    for tid, res in almacen.tickets().items() if mias else []:
        if tid != ticket_id and (comunes := mias & fuertes(res["ticket"].get("alert_ids", []))):
            out.append({"ticket_id": tid, "entidades": sorted(comunes)})
    return out


def listar() -> list[list[str]]:
    vistos, out = set(), []
    for ids in construir().values():
        if ids[0] not in vistos:
            vistos.add(ids[0])
            out.append(ids)
    return sorted(out, key=lambda ids: todas_las_alertas()[ids[0]]["created_at"])
