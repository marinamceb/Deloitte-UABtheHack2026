"""[Nivel 4 · web] Sesión, rol y defensas comunes a todas las rutas. Decide el servidor; el navegador solo muestra.

- Login solo con email: usuarios.csv no tiene contraseñas. El email se resuelve con /users (roles.identificar) y solo
  entran personas con un rol (SOC, responsables de servicio, DPO, Tesorería, Operaciones). Es suplantable a propósito
  de la demo: en producción iría detrás del SSO corporativo. Cada login, logout y rechazo queda en
  salidas/accesos.jsonl.
- La sesión es una cookie firmada (WEB_SECRETO) que guarda solo el email. El rol se vuelve a calcular en cada petición
  desde el directorio (`persona_actual`): nunca viaja desde el navegador.
- CSRF: cookie SameSite=Strict y los POST de /api solo admiten JSON (un formulario de otra web no puede enviarlo).
"""
import os
import secrets

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from agente import almacen, roles
from agente.herramientas import ahora_iso

SECRETO = os.environ.get("WEB_SECRETO") or secrets.token_hex(32)   # sin variable: las sesiones mueren al reiniciar
COOKIE = {"session_cookie": "tarvia_soc", "max_age": 8 * 3600, "same_site": "strict",
          "https_only": os.environ.get("WEB_HTTPS") == "1"}
SOC_LECTURA = {"N1", "N2", "responsable_soc", "ciso", "deteccion"}  # ven todas las solicitudes


async def solo_json_en_post(request: Request, siguiente):
    """Middleware: los POST de la API solo aceptan JSON."""
    if request.method == "POST" and request.url.path.startswith("/api/"):
        if not request.headers.get("content-type", "").startswith("application/json"):
            return JSONResponse({"detail": "Content-Type debe ser application/json"}, status_code=415)
    return await siguiente(request)


def persona_actual(request: Request) -> dict:
    """Dependencia de cada ruta protegida: persona de la sesión con los roles recalculados ahora. 401 si no hay."""
    email = request.session.get("email")
    persona = roles.identificar(email) if email else None
    if persona is None:
        request.session.clear()
        raise HTTPException(401, "Inicia sesión")
    return persona


def exigir_soc(persona: dict) -> None:
    if not roles.es_soc(persona):
        raise HTTPException(403, "Solo el personal del SOC")


def ve_todo(persona: dict) -> bool:
    return bool(set(persona["roles"]) & SOC_LECTURA)


def registrar_acceso(evento: str, email: str, request: Request, detalle: str = "") -> None:
    almacen.registrar_acceso({"ts": ahora_iso(), "evento": evento, "email": email, "detalle": detalle,
                              "ip": request.client.host if request.client else ""})
