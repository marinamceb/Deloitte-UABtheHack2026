"""[Nivel 4 · web] Registro de contención de la API simulada (GET /containment/log): lo que de verdad se ha ejecutado,
para contrastarlo con el estado de las solicitudes. Solo lectura, solo SOC."""
from fastapi import APIRouter, Depends

from agente import api
from servidor.seguridad import persona_actual, ve_todo

router = APIRouter(prefix="/api/contencion", tags=["contención"])


@router.get("/registro")
def registro(persona: dict = Depends(persona_actual)):
    if not ve_todo(persona):
        return []
    return sorted(api.registro_contencion(), key=lambda r: r.get("timestamp", ""), reverse=True)
