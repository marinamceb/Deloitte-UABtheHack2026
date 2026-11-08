"""[Nivel 4 · web] Solicitudes de contención: bandeja por rol, detalle y decisiones (aprobar, rechazar, marcar como
hecha, reintentar). Las reglas las aplica agente/acciones.py; aquí solo se traduce a HTTP:
PermisoDenegado → 403, EstadoNoValido → 409, no existe o no es visible → 404 (para no revelar que existe)."""
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from agente import acciones
from servidor.seguridad import exigir_soc, persona_actual, ve_todo

router = APIRouter(prefix="/api/acciones", tags=["acciones"])
SINCRONIZAR_CADA_S = 30
_ULTIMA_SINCRONIZACION = 0.0


def sincronizar(forzar: bool = False) -> None:
    """Incorpora las acciones de tickets e informes nuevos, como mucho cada SINCRONIZAR_CADA_S segundos."""
    global _ULTIMA_SINCRONIZACION
    if forzar or time.time() - _ULTIMA_SINCRONIZACION > SINCRONIZAR_CADA_S:
        acciones.sincronizar()
        _ULTIMA_SINCRONIZACION = time.time()


def visible(sol: dict, persona: dict) -> bool:
    """El SOC ve todo; el resto, lo que puede decidir y aquello en lo que ya intervino."""
    return ve_todo(persona) or bool(acciones.que_puede_hacer(sol, persona)) or any(
        h.get("email") == persona["email"] for h in sol["historial"])


def vista(sol: dict, persona: dict) -> dict:
    """La solicitud más lo que esta persona puede hacer (`puedo`), las aprobaciones que faltan (`faltan`) y, si falta
    la de un responsable de servicio de la empresa, a quién hay que pedírsela (`negocio`)."""
    i = acciones._requisito_negocio(sol)
    return {**sol, "puedo": sorted(acciones.que_puede_hacer(sol, persona)),
            "faltan": [sol["requisitos"][j]["etiqueta"] for j in acciones._faltan(sol)],
            "negocio": ({k: sol["requisitos"][i].get(k) for k in ("cargo", "servicio")} if i is not None else None)}


@router.get("/pendientes")
def pendientes(persona: dict = Depends(persona_actual)):
    """«Mis pendientes»: lo que esta persona puede decidir ahora."""
    sincronizar()
    return [vista(s, persona) for s in acciones.pendientes_de(persona)]


@router.get("")
def listar(estado: str = "", persona: dict = Depends(persona_actual)):
    sincronizar()
    estados = set(estado.split(",")) if estado else None
    return [vista(s, persona) for s in acciones.listar(estados) if visible(s, persona)]


@router.post("/sincronizar")
def forzar_sincronizacion(persona: dict = Depends(persona_actual)):
    exigir_soc(persona)
    antes = len(acciones.listar())
    sincronizar(forzar=True)
    return {"nuevas": len(acciones.listar()) - antes}


def _visible_o_404(id_solicitud: str, persona: dict) -> dict:
    sol = acciones.obtener(id_solicitud)
    if sol is None or not visible(sol, persona):
        raise HTTPException(404, "No existe esa solicitud")
    return sol


@router.get("/{id_solicitud}")
def detalle(id_solicitud: str, persona: dict = Depends(persona_actual)):
    return vista(_visible_o_404(id_solicitud, persona), persona)


class Decision(BaseModel):
    comentario: str = ""
    en_nombre_de: str = ""   # email de Tarvia: aprobación de un responsable de servicio registrada por un N2+


def _decidir(operacion, id_solicitud: str, persona: dict, *args) -> dict:
    _visible_o_404(id_solicitud, persona)
    try:
        sol = operacion(id_solicitud, persona["email"], *args)
    except acciones.PermisoDenegado as e:
        raise HTTPException(403, str(e))
    except acciones.EstadoNoValido as e:
        raise HTTPException(409, str(e))
    return vista(sol, persona)


@router.post("/{id_solicitud}/aprobar")
def aprobar(id_solicitud: str, datos: Decision, persona: dict = Depends(persona_actual)):
    return _decidir(acciones.aprobar, id_solicitud, persona, datos.comentario, datos.en_nombre_de.strip())


@router.post("/{id_solicitud}/rechazar")
def rechazar(id_solicitud: str, datos: Decision, persona: dict = Depends(persona_actual)):
    if not datos.comentario.strip():
        raise HTTPException(422, "Indica el motivo del rechazo")
    return _decidir(acciones.rechazar, id_solicitud, persona, datos.comentario)


@router.post("/{id_solicitud}/hecha")
def hecha(id_solicitud: str, datos: Decision, persona: dict = Depends(persona_actual)):
    return _decidir(acciones.marcar_hecha, id_solicitud, persona, datos.comentario)


@router.post("/{id_solicitud}/reintentar")
def reintentar(id_solicitud: str, datos: Decision, persona: dict = Depends(persona_actual)):
    return _decidir(acciones.reintentar, id_solicitud, persona)
