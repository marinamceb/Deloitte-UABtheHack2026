"""[Nivel 4 · web] Login por email, logout y «quién soy»."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from agente import roles
from servidor.seguridad import persona_actual, registrar_acceso

router = APIRouter(prefix="/api", tags=["sesión"])


class Login(BaseModel):
    email: str


@router.post("/login")
def login(datos: Login, request: Request):
    persona = roles.identificar(datos.email)
    if persona is None:
        registrar_acceso("login_rechazado", datos.email, request, "no existe o no tiene rol")
        raise HTTPException(403, "Ese email no existe en el directorio o no tiene acceso a la consola")
    request.session.clear()
    request.session["email"] = persona["email"]
    registrar_acceso("login", persona["email"], request, ", ".join(persona["roles"]))
    return persona


@router.post("/logout")
def logout(request: Request):
    if email := request.session.get("email"):
        registrar_acceso("logout", email, request)
    request.session.clear()
    return {"ok": True}


@router.get("/yo")
def yo(persona: dict = Depends(persona_actual)):
    return persona
