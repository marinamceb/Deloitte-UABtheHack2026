"""[Nivel 4 · web] Avisos por rol (agente/avisos.py): escalados y notificaciones del SLA para el SOC, y notificaciones
a terceros de Tarvia (DPO con plazo de 72 h, Tesorería, Operaciones...) que el SOC debe hacer y registrar."""
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from agente import avisos
from servidor.seguridad import persona_actual

router = APIRouter(prefix="/api/avisos", tags=["avisos"])
SINCRONIZAR_CADA_S = 30
_ULTIMA_SINCRONIZACION = 0.0


def sincronizar(forzar: bool = False) -> None:
    global _ULTIMA_SINCRONIZACION
    if forzar or time.time() - _ULTIMA_SINCRONIZACION > SINCRONIZAR_CADA_S:
        avisos.sincronizar()
        _ULTIMA_SINCRONIZACION = time.time()


def vista(a: dict, persona: dict) -> dict:
    return {**a, "puedo": (["atender"] if avisos.puede_atender(a, persona) else [])}


@router.get("")
def listar(persona: dict = Depends(persona_actual)):
    sincronizar()
    return [vista(a, persona) for a in avisos.para(persona)]


class Atencion(BaseModel):
    comentario: str = ""


@router.post("/{id_aviso}/atender")
def atender(id_aviso: str, datos: Atencion, persona: dict = Depends(persona_actual)):
    if not any(a["id"] == id_aviso for a in avisos.para(persona)):
        raise HTTPException(404, "No existe ese aviso")
    try:
        return vista(avisos.atender(id_aviso, persona, datos.comentario), persona)
    except avisos.NoPermitido as e:
        raise HTTPException(403, str(e))
