"""[Nivel 4 · web] Login del equipo del SOC (usuario o email + contraseña, base de datos propia), logout y «quién
soy». El directorio de Tarvia (la empresa monitorizada) no da acceso a la consola."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from agente import roles
from servidor.seguridad import con_permisos, persona_actual, registrar_acceso

router = APIRouter(prefix="/api", tags=["sesión"])


class Login(BaseModel):
    usuario: str    # nombre de usuario o email del SOC
    password: str


@router.post("/login")
def login(datos: Login, request: Request):
    persona = roles.autenticar(datos.usuario, datos.password)
    if persona is None:   # mismo mensaje si el usuario no existe o la contraseña es incorrecta
        registrar_acceso("login_rechazado", datos.usuario, request, "credenciales incorrectas")
        raise HTTPException(401, "Usuario o contraseña incorrectos")
    request.session.clear()
    request.session["email"] = persona["email"]
    request.session["acceso_anterior"] = persona.get("ultimo_login")   # leído antes de actualizarlo
    registrar_acceso("login", persona["email"], request, ", ".join(persona["roles"]))
    return {**con_permisos(persona), "acceso_anterior": persona.get("ultimo_login")}


@router.post("/logout")
def logout(request: Request):
    if email := request.session.get("email"):
        registrar_acceso("logout", email, request)
    request.session.clear()
    return {"ok": True}


@router.get("/yo")
def yo(request: Request, persona: dict = Depends(persona_actual)):
    return {**con_permisos(persona), "acceso_anterior": request.session.get("acceso_anterior")}
