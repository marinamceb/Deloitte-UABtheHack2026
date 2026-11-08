"""[Nivel 4 · web] Sesión, rol y defensas comunes a todas las rutas. Decide el servidor; el navegador solo muestra.

- Solo entra nuestro equipo del SOC: usuario o email + contraseña contra su propia base de datos
  (agente/usuarios_soc.py, db/usuarios_soc.sql). Las contraseñas de ejemplo están en claro: solo para la demo (en
  producción, hash con sal o SSO). El directorio de Tarvia, la empresa monitorizada, no da acceso. Cada login,
  logout y rechazo queda en salidas/accesos.jsonl.
- La sesión es una cookie firmada (WEB_SECRETO) que guarda solo el email. Rol y estado (activo) se vuelven a leer
  de la base de datos en cada petición (`persona_actual`): nunca viajan desde el navegador.
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


def permisos(persona: dict) -> dict:
    """Qué puede hacer cada rol, para que la web muestre solo lo que corresponde (el servidor lo vuelve a comprobar
    en cada ruta: esto no da permisos, solo los describe)."""
    r = set(persona["roles"])
    return {
        "ver": bool(r & SOC_LECTURA),                               # cola, tickets, incidentes, registro
        "decidir": roles.es_soc(persona),                           # ejecutar lo del N1, marcar tareas hechas
        "aprobar_n2": bool(r & roles.PUEDE["N2"]),                  # acciones disruptivas
        "registrar_negocio": roles.registra_en_nombre(persona),     # aprobación de un responsable de Tarvia
        "avisos": bool(r & {"N2", "responsable_soc", "ciso"}),     # escalados, SLA y notificaciones a terceros
        "supervisar": bool(r & {"responsable_soc", "ciso"}),       # visión de conjunto
        "solo_lectura": not roles.es_soc(persona),
    }


def con_permisos(persona: dict) -> dict:
    return {**persona, "permisos": permisos(persona)}


def registrar_acceso(evento: str, email: str, request: Request, detalle: str = "") -> None:
    almacen.registrar_acceso({"ts": ahora_iso(), "evento": evento, "email": email, "detalle": detalle,
                              "ip": request.client.host if request.client else ""})
