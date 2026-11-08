"""[Nivel 4 · personas] Roles de quien aprueba o recibe avisos, deducidos de su ficha del directorio (por la API).

usuarios.csv no tiene contraseñas: la identidad es el email y el rol sale del departamento y el cargo:
  Ciberseguridad   «Analista SOC N1» → N1, «Analista SOC N2» → N2, «Responsable SOC» → responsable_soc,
                   «CISO» → ciso, «Ingeniero de Detección» → deteccion (solo lectura)
  responsable_servicio:<servicio>   su cargo es el responsable de ese servicio en servicios_negocio.csv
                                    (p. ej. «Director de Tecnología» → Integración continua, Copias de seguridad...)
  dpo, tesoreria, operaciones       destinatarios de avisos (DPO, Responsable de Tesorería, Directora de Operaciones)
Una cuenta que no está activa o que no tiene ningún rol no tiene acceso.

Jerarquía para aprobar: lo que puede el N1 lo pueden el N2, el Responsable SOC y el CISO; lo del N2, el Responsable
SOC y el CISO. La aprobación del responsable de un servicio solo la da ese responsable (o el Responsable SOC cuando el
servicio no tiene responsable registrado, que es lo que fija politica.requisitos).
"""
from . import api
from .comun import SERVICIOS

CARGOS_SOC = {"Analista SOC N1": "N1", "Analista SOC N2": "N2", "Responsable SOC": "responsable_soc", "CISO": "ciso",
              "Ingeniero de Detección": "deteccion"}
CARGOS_AVISOS = {"DPO": "dpo", "Responsable de Tesorería": "tesoreria", "Directora de Operaciones": "operaciones",
                 "Director de Operaciones": "operaciones"}
SOC = {"N1", "N2", "responsable_soc", "ciso", "deteccion"}
PUEDE = {  # requisito → roles que lo cumplen
    "N1": {"N1", "N2", "responsable_soc", "ciso"},
    "N2": {"N2", "responsable_soc", "ciso"},
    "responsable_soc": {"responsable_soc", "ciso"},
}


def roles(ficha: dict | None) -> set[str]:
    """Roles de una ficha del directorio (vacío si no existe o no está activa)."""
    if not ficha or ficha.get("status", "active") != "active":
        return set()
    cargo, depto = ficha.get("title", ""), ficha.get("department", "")
    out = set()
    if depto == "Ciberseguridad" and cargo in CARGOS_SOC:
        out.add(CARGOS_SOC[cargo])
    if cargo in CARGOS_AVISOS:
        out.add(CARGOS_AVISOS[cargo])
    out |= {f"responsable_servicio:{s['servicio']}" for s in SERVICIOS if s["responsable"] == cargo}
    return out


def identificar(email: str) -> dict | None:
    """Persona que inicia sesión: {email, nombre, cargo, roles}, o None si no existe o no tiene rol."""
    email = (email or "").strip().lower()
    if "@" not in email:
        return None
    ficha = api.usuario(email)
    r = roles(ficha)
    if not r:
        return None
    return {"email": ficha["upn"].lower(), "nombre": ficha.get("display_name", email), "cargo": ficha.get("title", ""),
            "roles": sorted(r)}


def cumple(persona: dict, requisito: dict) -> bool:
    """¿Puede esta persona dar esta aprobación?"""
    rol, mios = requisito["rol"], set(persona["roles"])
    if rol == "responsable_servicio":
        return f"responsable_servicio:{requisito.get('servicio')}" in mios
    return bool(mios & PUEDE.get(rol, {rol}))


def es_soc(persona: dict) -> bool:
    return bool(set(persona["roles"]) & PUEDE["N1"])
