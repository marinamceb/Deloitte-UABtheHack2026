"""[Nivel 4 · web] Estado del servicio (comprobación de salud de Docker)."""
from fastapi import APIRouter

from agente import usuarios_soc
from agente.herramientas import _get

router = APIRouter(prefix="/api", tags=["estado"])


@router.get("/salud")
def salud():
    """La web responde y dice si la API simulada y PostgreSQL responden ahora (sin caché)."""
    try:
        api_ok = _get("/alerts", {"limit": 1})[0] is not None
    except Exception:  # noqa: BLE001 - cualquier fallo de red cuenta como «no responde»
        api_ok = False
    try:
        db_ok = bool(usuarios_soc.listar())
    except usuarios_soc.BaseDeDatosNoDisponible:
        db_ok = False
    return {"web": True, "api_soc": api_ok, "db": db_ok}
