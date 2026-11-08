"""[Nivel 4 · personas] Quién puede hacer qué.

Dos poblaciones distintas:
- Nuestro equipo del SOC, que inicia sesión en la consola (usuarios_soc.py, base de datos propia): N1, N2,
  responsable_soc, ciso, deteccion (solo lectura). Jerarquía: lo del N1 lo pueden el N2, el Responsable SOC y el
  CISO; lo del N2, el Responsable SOC y el CISO.
- Las personas de Tarvia, la empresa que monitorizamos (su directorio, por la API /users), que NO entran en la
  consola. Algunas aprueban por su cargo: el responsable de un servicio de servicios_negocio.csv debe dar el visto
  bueno para aislar un servidor de su servicio (política, apartado 4). Esa aprobación la obtiene un N2 o superior
  (teléfono, correo) y la registra en su nombre; aquí se comprueba que esa persona es de verdad el responsable.
"""
from . import api, usuarios_soc
from .comun import SERVICIOS

CARGOS_AVISOS = {"DPO": "dpo", "Responsable de Tesorería": "tesoreria", "Directora de Operaciones": "operaciones",
                 "Director de Operaciones": "operaciones"}
PUEDE = {  # requisito → roles del SOC que lo cumplen
    "N1": {"N1", "N2", "responsable_soc", "ciso"},
    "N2": {"N2", "responsable_soc", "ciso"},
    "responsable_soc": {"responsable_soc", "ciso"},
}
REGISTRA_EN_NOMBRE = PUEDE["N2"]   # quién puede registrar la aprobación de un responsable de servicio de la empresa


# =============================================================================================== equipo del SOC

def identificar(usuario_o_email: str) -> dict | None:
    """Persona del SOC activa (sin comprobar contraseña: revalidar una sesión ya iniciada, CLI local)."""
    return usuarios_soc.por_email(usuario_o_email)


def autenticar(usuario_o_email: str, password: str) -> dict | None:
    return usuarios_soc.autenticar(usuario_o_email, password)


def cumple(persona: dict, requisito: dict) -> bool:
    """¿Puede esta persona del SOC dar esta aprobación por sí misma? (las de negocio se registran en nombre de otro)"""
    return requisito["rol"] != "responsable_servicio" and bool(set(persona["roles"]) & PUEDE.get(requisito["rol"],
                                                                                                 {requisito["rol"]}))


def es_soc(persona: dict) -> bool:
    """Puede operar (todo el SOC salvo ingeniería de detección, que es solo lectura)."""
    return bool(set(persona["roles"]) & PUEDE["N1"])


def registra_en_nombre(persona: dict) -> bool:
    return bool(set(persona["roles"]) & REGISTRA_EN_NOMBRE)


# =============================================================================================== empresa monitorizada

def roles_empresa(ficha: dict | None) -> set[str]:
    """Papeles de una persona de Tarvia según su ficha del directorio: responsable_servicio:<servicio>, dpo,
    tesoreria, operaciones (destinatarios de avisos y aprobaciones de negocio). Vacío si no existe o no está activa."""
    if not ficha or ficha.get("status", "active") != "active":
        return set()
    cargo = ficha.get("title", "")
    out = {CARGOS_AVISOS[cargo]} if cargo in CARGOS_AVISOS else set()
    return out | {f"responsable_servicio:{s['servicio']}" for s in SERVICIOS if s["responsable"] == cargo}


def responsable_de(email_empresa: str, servicio: str) -> dict | None:
    """Ficha de la persona de Tarvia si es responsable de ese servicio; None si no existe o no lo es."""
    ficha = api.usuario((email_empresa or "").strip().lower())
    if f"responsable_servicio:{servicio}" in roles_empresa(ficha):
        return ficha
    return None
