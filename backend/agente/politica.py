"""[Niveles 1, 2 y 4] Validación determinista del ticket contra politica_soc.md (apartados 3, 4 y 5).

El modelo propone; aquí se corrige lo que la política fija sin necesidad de juicio. `validar()` aplica, en orden:
  [N1] no dar por buena una actividad que incumple una regla interna; datos que faltan → open_questions
  [N2] descartar con argumentos: un benign_true_positive debe citar qué lo autoriza
  [N4] quién aprueba cada acción de contención; IOC maliciosos sin bloquear
  [N1] escalado obligatorio (apartado 5) y notificaciones según el SLA (apartado 3)
Cada corrección queda en `ajustes_politica` para que el analista vea qué cambió el código y por qué.
"""
import json

from . import api
from . import herramientas as h
from .comun import local, servicio

DISRUPTIVAS = {"isolate_host", "disable_user", "revoke_sessions", "reset_password", "disable_access_key"}
ETIQUETAS_USO_DUAL = {"dual-use", "legit-service", "vpn-commercial"}
NOTIFICAR = {"critical": ["Responsable SOC", "CISO"], "high": ["Responsable SOC"]}


def validar(ticket: dict, alerta: dict, comprobaciones: list[dict] = ()) -> dict:
    ajustes: list[str] = []
    ticket = _no_dar_por_buena_una_regla_incumplida(ticket, comprobaciones, ajustes)
    ticket = _exigir_argumento(ticket, alerta, comprobaciones, ajustes)
    ticket = _preguntar_datos_faltantes(ticket, comprobaciones)
    acciones = aprobar_acciones(ticket["recommended_actions"], ajustes)
    acciones += bloqueos_pendientes(ticket, acciones, ajustes)
    escalado, acciones = _escalado_y_sla(ticket, alerta, acciones, ajustes)
    return {**ticket, "recommended_actions": acciones, "escalation": escalado, "ajustes_politica": ajustes}


def _activo(host: str) -> dict | None:
    with h.origen("politica"):
        return api.activo(host)


def _tip(indicador: str) -> dict:
    with h.origen("politica"):
        return api.intel(indicador).get("tip") or {}


def _sandbox(sha256: str) -> dict | None:
    with h.origen("politica"):
        return api.sandbox(sha256)


def _con_pregunta(ticket: dict, pregunta: str) -> dict:
    return {**ticket, "open_questions": ticket["open_questions"] + [pregunta]}


# =============================================================================================== [N1] reglas internas

def _no_dar_por_buena_una_regla_incumplida(ticket: dict, comprobaciones, ajustes: list[str]) -> dict:
    """[Nivel 1] Un veredicto benigno o falso positivo que contradice una comprobación `sospechosa` → needs_more_info."""
    sospechosas = [c for c in comprobaciones if c["estado"] == "sospechosa"]
    if not sospechosas or ticket["verdict"] not in ("false_positive", "benign_true_positive"):
        return ticket
    s = sospechosas[0]
    ajustes.append(f"Veredicto {ticket['verdict']} → needs_more_info: contradice la comprobación interna "
                   f"«{s['regla']}» ({s['motivo'][:120]})")
    return {**_con_pregunta(ticket, f"Resolver la regla interna incumplida: {s['regla']} — {s['sujeto']}"),
            "verdict": "needs_more_info"}


def _preguntar_datos_faltantes(ticket: dict, comprobaciones) -> dict:
    """[Nivel 1] Cada comprobación `requiere_info` deja su dato faltante como pregunta abierta."""
    for c in comprobaciones:
        pregunta = f"{c['regla']} ({c['sujeto']}): falta {c['dato_faltante']}"
        if c["estado"] == "requiere_info" and c["dato_faltante"] and pregunta not in ticket["open_questions"]:
            ticket = _con_pregunta(ticket, pregunta)
    return ticket


# =============================================================================================== [N2] con argumentos

def _exigir_argumento(ticket: dict, alerta: dict, comprobaciones, ajustes: list[str]) -> dict:
    """[Nivel 2] Descartar con argumentos: un benign_true_positive debe citar un cambio o flujo que exista y esté
    vigente a la hora de la alerta, o tener una comprobación `permitida`. Si no, → needs_more_info."""
    if ticket["verdict"] != "benign_true_positive":
        return ticket
    from . import cambios
    texto = json.dumps({k: ticket.get(k) for k in ("summary", "severity_rationale", "evidence",
                                                    "recommended_actions", "title")}, ensure_ascii=False)
    validos, invalidos = [], []
    for id_cambio in sorted(cambios.citados(texto)):
        c = cambios.por_id(id_cambio)
        es_valido = c and (id_cambio.startswith("FLUJO-") or cambios.vigente(c, alerta["created_at"]))
        (validos if es_valido else invalidos).append(id_cambio)
    for x in invalidos:
        ajustes.append(f"El ticket cita {x}, que no existe o no está vigente en el momento de la alerta")
    if validos or any(c["estado"] == "permitida" for c in comprobaciones):
        return ticket
    ajustes.append("Veredicto benign_true_positive → needs_more_info: no cita ningún cambio, flujo o "
                   "comprobación que autorice la actividad")
    return {**_con_pregunta(ticket, "Indicar el cambio, flujo aprobado o regla que autoriza esta actividad"),
            "verdict": "needs_more_info"}


# =============================================================================================== [N4] contención

def requisitos(accion: str, objetivo: str) -> dict:
    """[Nivel 4] Apartado 4 de la política en forma estructurada, para la web y el CLI de aprobaciones:
    {"permitida", "motivo", "aprobaciones": [{"rol": "N2"} | {"rol": "responsable_servicio", "servicio", "cargo"} |
    {"rol": "responsable_soc"}], "texto"}. Sin aprobaciones = la puede ejecutar el N1 directamente."""
    n2 = {"rol": "N2"}
    if accion == "isolate_host":
        activo = _activo(objetivo)
        if not activo:
            return {"permitida": True, "motivo": "activo no está en la CMDB", "aprobaciones": [n2],
                    "texto": "N2 (activo no está en la CMDB)"}
        if activo.get("zone") == "LOGISTICS-OT":
            return {"permitida": False, "motivo": "el SOC nunca actúa sobre OT: solo escalar a Operaciones",
                    "aprobaciones": [], "texto": "prohibida (OT)"}
        if activo.get("type") == "Portátil":
            return {"permitida": True, "motivo": "puesto de trabajo", "aprobaciones": [n2], "texto": "N2"}
        s = servicio(activo.get("business_service", ""))
        negocio = activo.get("type") in ("TPV", "Frontal web", "Pasarela de pagos")
        etiqueta = "negocio" if negocio else "responsable del servicio"
        if not s:  # la política exige al responsable; sin datos decide el Responsable SOC y queda anotado
            return {"permitida": True, "motivo": "servicio sin responsable en servicios_negocio.csv",
                    "aprobaciones": [n2, {"rol": "responsable_soc"}],
                    "texto": f"N2 + {etiqueta}: SIN RESPONSABLE en servicios_negocio.csv (decide el Responsable SOC)"}
        return {"permitida": True, "motivo": f"{activo.get('type', 'servidor')} del servicio {s['servicio']}",
                "aprobaciones": [n2, {"rol": "responsable_servicio", "servicio": s["servicio"],
                                      "cargo": s["responsable"]}],
                "texto": f"N2 + {etiqueta}: {s['responsable']} ({s['servicio']})"}
    if accion in DISRUPTIVAS:
        return {"permitida": True, "motivo": "acción disruptiva", "aprobaciones": [n2], "texto": "N2"}
    if accion == "block_ioc":
        tip = _tip(objetivo)
        etiquetas = set(str(tip.get("tags", "")).split(","))
        if etiquetas & ETIQUETAS_USO_DUAL or tip.get("reputation") == "benign":
            motivo = f"servicio de uso dual o legítimo según el TIP ({tip.get('tags', '')})"
            return {"permitida": True, "motivo": motivo,
                    "aprobaciones": [n2], "texto": "N2"}
        return {"permitida": True, "motivo": "indicador", "aprobaciones": [], "texto": ""}
    if accion == "purge_email":
        return {"permitida": True, "motivo": "", "aprobaciones": [], "texto": ""}
    # fuera de la API (borrar una regla de buzón, quitar un MFA, eliminar un usuario IAM...): la política no las
    # lista; se tratan como disruptivas (N2), que es lo conservador
    return {"permitida": True, "motivo": "tarea manual fuera de la API", "aprobaciones": [n2], "texto": "N2"}


def aprobar_acciones(propuestas: list[dict], ajustes: list[str]) -> list[dict]:
    """[Nivel 4] Apartado 4: acciones disruptivas con aprobación, nada sobre OT, uso dual con N2."""
    acciones = []
    for a in propuestas:
        accion = a["action"]
        if accion not in DISRUPTIVAS and accion not in ("block_ioc", "isolate_host"):
            acciones.append(a)  # notificar, escalar, cerrar, purgar... se quedan como las propuso el modelo
            continue
        r = requisitos(accion, a["target"])
        if not r["permitida"]:
            ajustes.append(f"Eliminado {accion} sobre {a['target']}: {r['motivo']} (apartado 4)")
            acciones.append({"action": "escalate_operations", "target": "Responsable de Operaciones",
                             "requires_approval": False, "approvers": "",
                             "justification": "Activo OT: solo escalar (apartado 4)"})
            continue
        if r["aprobaciones"]:
            if accion == "isolate_host" and a.get("approvers") != r["texto"]:
                ajustes.append(f"isolate_host {a['target']}: requiere aprobación de {r['texto']}")
            elif accion == "block_ioc" and not a["requires_approval"]:
                ajustes.append(f"block_ioc {a['target']}: {r['motivo']}; bloquearlo requiere N2 (apartado 4)")
            elif accion in DISRUPTIVAS and not a["requires_approval"]:
                ajustes.append(f"{accion} {a['target']}: marcada como pendiente de aprobación de N2 (apartado 4)")
            a = {**a, "requires_approval": True,
                 "approvers": r["texto"] if accion == "isolate_host" else (a.get("approvers") or r["texto"])}
        acciones.append(a)
    return acciones


def bloqueos_pendientes(ticket: dict, acciones: list[dict], ajustes: list[str]) -> list[dict]:
    """[Nivel 4] IOC maliciosos según el TIP o la sandbox que el modelo no propuso bloquear (los puede ejecutar el N1)."""
    if ticket["verdict"] != "true_positive":
        return []
    bloqueados = {a["target"] for a in acciones if a["action"] == "block_ioc"}
    nuevos = []
    for e in ticket.get("enrichment", []):
        ind, tipo = e["indicator"], e["type"]
        if ind in bloqueados or tipo not in ("ip", "domain", "sha256", "url"):
            continue
        tip = _tip(ind)
        sbx = _sandbox(ind) if tipo == "sha256" else None
        if tip.get("reputation") == "malicious" or (sbx or {}).get("verdict") == "malicious":
            fuente = "sandbox" if sbx else "TIP"
            nuevos.append({"action": "block_ioc", "target": ind, "requires_approval": False, "approvers": "",
                           "justification": f"Indicador malicioso según {fuente}"})
            bloqueados.add(ind)
            ajustes.append(f"Añadido block_ioc {ind}: malicioso según {fuente}")
    return nuevos


# =============================================================================================== [N1] escalado y SLA

def _fuera_de_horario(iso: str) -> bool:
    """SOC: 8-20 h de lunes a viernes, hora de España (Europe/Madrid)."""
    t = local(iso)
    return t.weekday() >= 5 or not 8 <= t.hour < 20


def _escalado_y_sla(ticket: dict, alerta: dict, acciones: list[dict], ajustes: list[str]) -> tuple[dict, list[dict]]:
    """[Nivel 1] Escalado obligatorio de true_positive high/critical (apartado 5), teléfono si es crítico y
    notificaciones del SLA (apartado 3). Devuelve (escalado, acciones con las notificaciones añadidas)."""
    esc = dict(ticket["escalation"])
    if ticket["verdict"] == "true_positive" and ticket["severity"] in ("high", "critical") and not esc["escalate"]:
        esc = {"escalate": True, "to": "N2", "reason": "true_positive de severidad alta o crítica (apartado 5)"}
        ajustes.append("Escalado a N2 obligatorio: true_positive high/critical (apartado 5)")
    if esc["escalate"] and ticket["severity"] == "critical":
        destino = "N2 guardia (teléfono)" if _fuera_de_horario(alerta["created_at"]) else "N2 inmediato (teléfono)"
        if "teléfono" not in esc.get("to", ""):
            ajustes.append(f"Escalado crítico: {destino} (apartado 3)")
            esc["to"] = destino + (f", {esc['to']}" if esc.get("to") else "")
    if esc["escalate"]:
        notificados = {a["target"] for a in acciones if a["action"].startswith("notify")}
        for quien in NOTIFICAR.get(ticket["severity"], []):
            if quien not in notificados and quien not in esc.get("to", ""):
                acciones = acciones + [{"action": "notify", "target": quien, "requires_approval": False,
                                        "approvers": "", "justification": f"SLA de severidad {ticket['severity']} "
                                                                          "(apartado 3)"}]
                ajustes.append(f"Añadida notificación a {quien} (SLA {ticket['severity']}, apartado 3)")
    return esc, acciones
