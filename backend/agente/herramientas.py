"""[Nivel 1 · investigar] Acceso a la API simulada del SOC y herramientas de solo lectura del modelo.

- Infraestructura compartida: `_get` (HTTP), `consultar_api` (lectura con traza, para código determinista),
  `buscar_eventos` / `buscar_alertas` (búsqueda por identificador completo) y el registro TRAZA con su `origen`.
- Herramientas del modelo (@beta_tool): la salida va delimitada como datos no confiables.
Ninguna herramienta ejecuta contención: el agente solo propone; ejecutar es una decisión humana (ver contencion.py).
"""
import datetime as dt
import json
import re
import threading
import time
from contextlib import contextmanager

import requests
from anthropic import beta_tool

from .config import API_URL

MAX_CHARS = 15000  # tope por resultado para no inundar el contexto; se avisa al modelo si se recorta
FUENTES_LOG = [
    "ad_events", "ai_gateway", "cicd_builds", "cloudtrail", "dlp", "dns", "ecom_account", "ecom_auth", "edr_events",
    "email", "email_clicks", "firewall", "idp_audit", "idp_signins", "proxy", "sql_audit", "vpn", "waf",
]

# --------------------------------------------------------------------------------------------- traza

# La traza y el origen son por hilo: la web atiende peticiones mientras un hilo de fondo tría o investiga, y las
# consultas de unos no deben colarse en la traza de otros. Para cada hilo funcionan como una lista y un texto normales.
_LOCAL = threading.local()


class _TrazaPorHilo:
    """Lista de consultas del hilo actual (se reinicia por alerta desde triaje.py / informe.py)."""

    def _lista(self) -> list[dict]:
        if not hasattr(_LOCAL, "traza"):
            _LOCAL.traza = []
        return _LOCAL.traza

    def append(self, x: dict) -> None:
        self._lista().append(x)

    def clear(self) -> None:
        self._lista().clear()

    def __iter__(self):
        return iter(list(self._lista()))

    def __len__(self) -> int:
        return len(self._lista())

    def __getitem__(self, i):
        return self._lista()[i]


TRAZA = _TrazaPorHilo()


def _origen_actual() -> str:
    """Quién hace la consulta: agente (modelo), auto (investigación previa), reglas, politica..."""
    return getattr(_LOCAL, "origen", "agente")


def __getattr__(nombre: str):   # compatibilidad: herramientas.ORIGEN sigue funcionando (por hilo)
    if nombre == "ORIGEN":
        return _origen_actual()
    raise AttributeError(nombre)


@contextmanager
def origen(nombre: str):
    """Marca con `nombre` las consultas hechas dentro del bloque en este hilo (y restaura el origen anterior)."""
    previo = _origen_actual()
    _LOCAL.origen = nombre
    try:
        yield
    finally:
        _LOCAL.origen = previo


def _registrar(nombre: str, args: dict, ms: int, chars: int, error: str | None, preview: str = "") -> None:
    TRAZA.append({"tool": nombre, "args": args, "origen": _origen_actual(), "ms": ms, "chars": chars, "error": error,
                  "preview": preview})


# --------------------------------------------------------------------------------------------- API

def _get(ruta: str, params: dict | None = None):
    """GET a la API. Devuelve (datos, error, ms); un 404 es un resultado (p. ej. activo no gestionado), no una excepción."""
    t0 = time.time()
    try:
        r = requests.get(f"{API_URL}{ruta}", params={k: v for k, v in (params or {}).items() if v not in ("", None)},
                         timeout=120)
    except requests.ConnectionError:
        raise RuntimeError(f"La API simulada no responde en {API_URL}. ¿Está arrancada?")
    ms = int((time.time() - t0) * 1000)
    if r.status_code == 404:
        es_json = r.headers.get("content-type", "").startswith("application/json")
        return None, f"404: {r.json().get('detail', 'no encontrado') if es_json else 'no encontrado'}", ms
    r.raise_for_status()
    return r.json(), None, ms


def _post(ruta: str, cuerpo: dict):
    """POST a la API (solo lo usa el nivel 4: aprobaciones y contención). Devuelve (datos, error); un rechazo de la
    API (403 por OT, falta de aprobación...) es un resultado con su motivo, no una excepción."""
    try:
        r = requests.post(f"{API_URL}{ruta}", json=cuerpo, timeout=30)
    except requests.ConnectionError:
        return None, f"La API simulada no responde en {API_URL}"
    if r.ok:
        return r.json(), None
    try:
        detalle = r.json().get("detail", r.text)
    except ValueError:
        detalle = r.text
    return None, f"{r.status_code}: {detalle}"


def consultar_api(nombre: str, ruta: str, params: dict | None = None):
    """Lectura para código determinista (reglas, política...). Devuelve (datos, error) y queda en la traza."""
    try:
        d, e, ms = _get(ruta, params)
    except RuntimeError as exc:
        d, e, ms = None, str(exc), 0
    _registrar(nombre, {"ruta": ruta, **{k: v for k, v in (params or {}).items() if v}}, ms,
               len(json.dumps(d, ensure_ascii=False)) if d is not None else 0, e)
    return d, e


# --------------------------------------------------------------------------------------------- búsqueda exacta
# La API original busca subcadenas ('198.18.58.15' también devuelve '198.18.58.157'). Aquí se exige el identificador
# completo y, si la API devuelve coincidencias parciales, se piden más resultados y se filtran localmente.

_ID = r"0-9A-Za-z_\-"


def _coincide(texto: str, obj) -> bool:
    """True si `texto` aparece en `obj` como identificador completo: '198.18.58.15' no casa con '198.18.58.157' ni
    'WS-BCN-1174' con 'WS-BCN-11740' o 'WS-BCN-1174-B'. Son parte de un identificador las letras, cifras, «_», «-» y
    el «.» seguido de otro de esos caracteres; los límites solo se exigen en los extremos que son de identificador."""
    if not texto:
        return True
    cadena = json.dumps(obj, ensure_ascii=False)
    if texto.lower() not in cadena.lower():
        return False
    patron = re.escape(texto)
    if re.match(rf"[{_ID}]", texto):
        patron = rf"(?<![{_ID}])(?<![{_ID}]\.)" + patron
    if re.search(rf"[{_ID}]$", texto):
        patron += rf"(?![{_ID}])(?!\.[{_ID}])"
    return re.search(patron, cadena, re.IGNORECASE) is not None


def buscar_eventos(fuente: str, texto: str, desde: str = "", hasta: str = "", limit: int = 200):
    """Eventos de una fuente que contienen `texto` como identificador completo.
    Devuelve ({"count", "truncated", "items"} | None, error, ms)."""
    params = {"q": texto, "desde": desde, "hasta": hasta}
    d, e, ms = _get(f"/logs/{fuente}", {**params, "limit": limit})
    if d is not None and not all(_coincide(texto, x) for x in d["items"]):
        d, e, ms2 = _get(f"/logs/{fuente}", {**params, "limit": 2000})
        ms += ms2
        if d is not None:
            items = [x for x in d["items"] if _coincide(texto, x)]
            d = {"count": min(len(items), limit), "truncated": len(items) > limit or d["truncated"],
                 "items": items[:limit]}
    return d, e, ms


def eventos(fuente: str, texto: str, desde: str = "", hasta: str = "", limit: int = 500) -> list[dict]:
    """Eventos de una fuente con búsqueda exacta, para código determinista; la consulta queda en la traza."""
    d, e, ms = buscar_eventos(fuente, texto, desde, hasta, limit)
    _registrar(f"logs:{fuente}", {"q": texto, "desde": desde, "hasta": hasta}, ms, (d or {}).get("count", 0), e)
    return (d or {}).get("items", [])


def buscar_alertas(texto: str, desde: str = "", hasta: str = "", limit: int = 30):
    """Alertas que contienen `texto` como identificador completo. Devuelve ({"total", "items"} | None, error, ms)."""
    params = {"status": "new", "desde": desde, "hasta": hasta}
    d, e, ms = _get("/alerts", {**params, "q": texto, "limit": limit})
    if d is not None and not all(_coincide(texto, a) for a in d["items"]):
        d, e, ms2 = _get("/alerts", {**params, "limit": 100000})  # la API original ignora q
        ms += ms2
        if d is not None:
            items = [a for a in d["items"] if _coincide(texto, a)]
            d = {"total": len(items), "items": items[:limit]}
    # alertas recibidas por el backend (agente/ingesta.py): la API simulada no las conoce
    from .ingesta import leer
    extra = [a for a in leer() if _coincide(texto, a) and (not desde or a["created_at"] >= desde)
             and (not hasta or a["created_at"] <= hasta)]
    if extra and d is not None:
        items = d["items"] + extra
        d = {"total": d.get("total", len(d["items"])) + len(extra), "items": items[:limit]}
    return d, e, ms


def alerta_por_id(alert_id: str):
    """Una alerta de la API o, si no está ahí, de las recibidas por el backend. Devuelve (datos, error, ms)."""
    d, e, ms = _get(f"/alerts/{alert_id}")
    if d is None:
        from .ingesta import por_id
        if recibida := por_id(alert_id):
            return recibida, None, ms
    return d, e, ms


# --------------------------------------------------------------------------------------------- herramientas del modelo

def _salida(nombre: str, args: dict, datos, error: str | None, ms: int) -> str:
    texto = error or json.dumps(datos, ensure_ascii=False)
    total = len(texto)
    if total > MAX_CHARS:
        texto = texto[:MAX_CHARS] + (f"\n[RECORTADO: se muestran {MAX_CHARS} de {total} caracteres. "
                                     "Afina la búsqueda con un texto más concreto o una ventana de tiempo menor.]")
    _registrar(nombre, args, ms, total, error, texto[:300])
    # Delimitar los datos: su contenido puede haberlo escrito el atacante y nunca son instrucciones.
    return f"<datos_no_confiables herramienta=\"{nombre}\">\n{texto}\n</datos_no_confiables>"


@beta_tool
def consultar_alerta(alert_id: str) -> str:
    """Detalle de otra alerta del SIEM.

    Args:
        alert_id: p. ej. ALR-20261005-000301.
    """
    return _salida("consultar_alerta", {"alert_id": alert_id}, *alerta_por_id(alert_id))


@beta_tool
def buscar_alertas_relacionadas(texto: str, desde: str, hasta: str, limit: int = 30) -> str:
    """Alertas del SIEM que mencionan una entidad en una ventana de tiempo.

    Args:
        texto: Entidad exacta (usuario, host, IP, dominio, hash).
        desde: ISO 8601 UTC.
        hasta: ISO 8601 UTC.
        limit: Máximo de alertas.
    """
    d, e, ms = buscar_alertas(texto, desde, hasta, limit)
    if d is not None:
        campos = ("alert_id", "created_at", "rule_id", "rule_name", "severity", "entities", "related_events")
        d = {"total_coincidencias": d["total"], "items": [{k: a.get(k) for k in campos} for a in d["items"]]}
    return _salida("buscar_alertas_relacionadas", {"texto": texto, "desde": desde, "hasta": hasta}, d, e, ms)


@beta_tool
def consultar_activo(hostname_o_ip: str) -> str:
    """CMDB: criticidad, zona, servicio, propietario, EDR y vulnerabilidades. 404 = no gestionado.

    Args:
        hostname_o_ip: Hostname o IP interna.
    """
    return _salida("consultar_activo", {"hostname_o_ip": hostname_o_ip}, *_get(f"/assets/{hostname_o_ip}"))


@beta_tool
def consultar_usuario(upn_o_username: str) -> str:
    """Directorio: cargo, privilegios, VIP, MFA, estado, puesto y eventos de RRHH.

    Args:
        upn_o_username: UPN o nombre de usuario.
    """
    return _salida("consultar_usuario", {"upn_o_username": upn_o_username}, *_get(f"/users/{upn_o_username}"))


@beta_tool
def buscar_logs(fuente: str, texto: str, desde: str = "", hasta: str = "", limit: int = 50) -> str:
    """Eventos de una fuente de log que contienen la entidad o texto exacto.

    Args:
        fuente: ad_events, ai_gateway, cicd_builds, cloudtrail, dlp, dns, ecom_account, ecom_auth, edr_events, email,
            email_clicks, firewall, idp_audit, idp_signins, proxy, sql_audit, vpn o waf.
        texto: ID de evento, usuario, host, IP, dominio, message_id, hash...
        desde: ISO 8601 UTC (opcional).
        hasta: ISO 8601 UTC (opcional).
        limit: Máximo de eventos (1-200).
    """
    if fuente not in FUENTES_LOG:
        raise ValueError(f"Fuente desconocida '{fuente}'. Válidas: {', '.join(FUENTES_LOG)}")
    d, e, ms = buscar_eventos(fuente, texto, desde, hasta, max(1, min(int(limit), 200)))
    return _salida("buscar_logs", {"fuente": fuente, "texto": texto, "desde": desde, "hasta": hasta}, d, e, ms)


@beta_tool
def consultar_inteligencia(indicador: str) -> str:
    """TIP interno + GeoIP/ASN de una IP, dominio, URL o hash.

    Args:
        indicador: Valor exacto.
    """
    return _salida("consultar_inteligencia", {"indicador": indicador}, *_get(f"/intel/{indicador}"))


@beta_tool
def consultar_sandbox(sha256: str) -> str:
    """Informe de sandbox de un fichero. 404 = nunca analizado.

    Args:
        sha256: Hash SHA-256.
    """
    return _salida("consultar_sandbox", {"sha256": sha256}, *_get(f"/sandbox/{sha256}"))


@beta_tool
def buscar_cambios(texto: str) -> str:
    """Calendario de cambios y flujos aprobados.

    Args:
        texto: Host, IP, usuario, servicio o palabra clave.
    """
    return _salida("buscar_cambios", {"texto": texto}, *_get("/changes", {"q": texto}))


@beta_tool
def leer_runbook(runbook: str) -> str:
    """Runbook de otra regla (el de la alerta ya está en el mensaje).

    Args:
        runbook: RB-01 a RB-10.
    """
    from .prompts import texto_runbook
    texto = texto_runbook(runbook)
    return _salida("leer_runbook", {"runbook": runbook}, texto, None if texto else f"runbook desconocido: {runbook}", 0)


HERRAMIENTAS = [
    consultar_alerta, buscar_alertas_relacionadas, consultar_activo, consultar_usuario, buscar_logs,
    consultar_inteligencia, consultar_sandbox, buscar_cambios, leer_runbook,
]


def ahora_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()
