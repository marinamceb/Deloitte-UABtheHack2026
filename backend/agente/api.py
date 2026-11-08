"""[Común] Datos de referencia de la API simulada (CMDB, identidades, inteligencia, sandbox, cambios) con caché.

Punto único para estas consultas: antes había un envoltorio en cada módulo y el mismo activo o indicador se pedía
varias veces por triaje. Son datos estables durante la ejecución, así que se guardan en memoria; un 404 también se
guarda (es una respuesta: equipo no gestionado, indicador desconocido). Los errores de conexión no se guardan.

Traza: cada consulta queda en herramientas.TRAZA con su `origen`, también las servidas desde la caché (marcadas con
`cache: true`), para que la demo muestre todo lo que se tuvo en cuenta. El código que consulta en bloque (la cola
sobre 11.061 alertas, la normalización de IPs del rastreo) pasa `trazar=False`.
"""
import time

from . import herramientas as h
from .comun import es_interna

_CACHE: dict[str, object] = {}


def _consulta(nombre: str, ruta: str, params: dict | None = None, trazar: bool = True):
    clave = ruta + "?" + "&".join(f"{k}={v}" for k, v in sorted((params or {}).items()))
    if clave in _CACHE:
        if trazar:
            h._registrar(nombre, {"ruta": ruta, **(params or {}), "cache": True}, 0, 0, None)
        return _CACHE[clave]
    if trazar:
        datos, error = h.consultar_api(nombre, ruta, params)
    else:
        try:
            datos, error, _ = h._get(ruta, params)
        except RuntimeError as e:
            datos, error = None, str(e)
    if datos is not None or (error or "").startswith("404"):
        _CACHE[clave] = datos
    return datos


def limpiar() -> None:
    """Vacía la caché (tests, o si cambian los datos de la API)."""
    _CACHE.clear()


def activo(hostname_o_ip: str, trazar: bool = True) -> dict | None:
    """Ficha de la CMDB (con vulnerabilidades) por nombre o IP; None si no está (externo o no gestionado)."""
    return _consulta("activo", f"/assets/{hostname_o_ip}", trazar=trazar) if hostname_o_ip else None


def usuario(upn_o_username: str, trazar: bool = True) -> dict | None:
    """Ficha del directorio con sus eventos de RRHH; None si no existe."""
    return _consulta("usuario", f"/users/{upn_o_username}", trazar=trazar) if upn_o_username else None


def intel(indicador: str, trazar: bool = True) -> dict:
    """TIP + GeoIP de un indicador ({"tip": None, "geo": None} si es desconocido; {} si la API falla)."""
    return _consulta("intel", f"/intel/{indicador}", trazar=trazar) or {}


def reputacion(indicador: str) -> str:
    return ((intel(indicador).get("tip") or {}).get("reputation")) or ""


def sandbox(sha256: str, trazar: bool = True) -> dict | None:
    return _consulta("sandbox", f"/sandbox/{sha256}", trazar=trazar)


def cambios(trazar: bool = True) -> list[dict]:
    """Calendario completo de cambios y flujos aprobados."""
    return _consulta("cambios", "/changes", {"q": ""}, trazar=trazar) or []


# --------------------------------------------------------------------------------------------- inventario

def host_de_ip(ip: str) -> str | None:
    """Equipo de la CMDB con esa IP interna (en mayúsculas); None si es externa o no está inventariada."""
    if not es_interna(ip):
        return None
    a = activo(ip, trazar=False)
    return a["hostname"].upper() if a else None


def ip_de(host: str) -> str | None:
    a = activo(host, trazar=False)
    return a.get("ip") if a else None


def es_equipo(nombre: str) -> bool:
    """¿Está en la CMDB? (descarta tokens que parecen equipos y no lo son, p. ej. OT-MAINT-TEMP)."""
    return activo(nombre, trazar=False) is not None


# --------------------------------------------------------------------------------------------- escritura (nivel 4)
# Sin caché y siempre en la traza: solo las llama agente/acciones.py tras la aprobación humana.

def solicitar_aprobacion(accion: str, objetivo: str, aprobador: str, motivo: str) -> tuple[dict | None, str | None]:
    """POST /approvals → {"approval_token", ...}. El token vale solo para esa acción y ese objetivo."""
    t0 = time.time()
    datos, error = h._post("/approvals", {"action": accion, "target": objetivo, "approver": aprobador,
                                          "reason": motivo})
    h._registrar("aprobacion", {"action": accion, "target": objetivo}, int((time.time() - t0) * 1000),
                 0, error)
    return datos, error


def contener(accion: str, objetivo: str, justificacion: str, token: str = "", ticket_id: str = ""
             ) -> tuple[dict | None, str | None]:
    """POST /containment/{accion}. La API comprueba el token y rechaza cualquier acción sobre OT."""
    datos, error = h._post(f"/containment/{accion}", {"target": objetivo, "justification": justificacion,
                                                      "approval_token": token, "ticket_id": ticket_id})
    h._registrar("contencion", {"action": accion, "target": objetivo}, 0, 0, error)
    return datos, error


def registro_contencion() -> list[dict]:
    """Acciones ya ejecutadas según la API (GET /containment/log), para no repetirlas."""
    try:
        datos, _, _ = h._get("/containment/log")
    except RuntimeError:
        return []
    return datos or []
