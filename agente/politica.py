"""Validación determinista del ticket contra politica_soc.md (apartados 3, 4 y 5).

El modelo propone; este módulo corrige lo que la política fija sin necesidad de juicio:
- Escalado obligatorio (apartado 5) y notificaciones según el SLA (apartado 3).
- Quién aprueba cada acción (apartado 4): aprobación obligatoria para acciones disruptivas, aprobadores concretos al
  aislar servidores, TPV o frontales (responsable del servicio según servicios_negocio.csv), nada sobre OT.
- Bloqueos: los IOC que el TIP o la sandbox marcan como maliciosos se bloquean; los de uso dual requieren N2.
Cada corrección queda listada en `ajustes_politica` para que el analista vea qué cambió el código y por qué.
"""
import csv
import datetime as dt

import requests

from .herramientas import API_URL
from .prompts import DATASET

DISRUPTIVAS = {"isolate_host", "disable_user", "revoke_sessions", "reset_password", "disable_access_key"}
ETIQUETAS_USO_DUAL = {"dual-use", "legit-service", "vpn-commercial"}
NOTIFICAR = {"critical": ["Responsable SOC", "CISO"], "high": ["Responsable SOC"]}

with open(DATASET / "02_inventario" / "servicios_negocio.csv", encoding="utf-8") as _f:
    SERVICIOS = list(csv.DictReader(_f))


def _api(ruta: str) -> dict | None:
    try:
        r = requests.get(f"{API_URL}{ruta}", timeout=30)
        return r.json() if r.ok else None
    except requests.RequestException:
        return None


def _responsable(activo: dict) -> str:
    servicio = activo.get("business_service", "")
    for s in SERVICIOS:
        if servicio.startswith(s["servicio"]):
            return f"{s['responsable']} ({s['servicio']})"
    return ""


def _fuera_de_horario(iso: str) -> bool:
    """SOC: 8-20 h de lunes a viernes, hora de España (UTC+2 en el periodo del dataset)."""
    t = dt.datetime.fromisoformat(iso.replace("Z", "+00:00")) + dt.timedelta(hours=2)
    return t.weekday() >= 5 or not 8 <= t.hour < 20


def _aprobacion_aislamiento(accion: dict, ajustes: list[str]) -> dict | None:
    """Devuelve la acción con los aprobadores de la política, o None si no se permite (OT)."""
    activo = _api(f"/assets/{accion['target']}")
    if not activo:
        aprobadores = "N2 (activo no está en la CMDB)"
    elif activo.get("zone") == "LOGISTICS-OT":
        ajustes.append(f"Eliminado isolate_host sobre {accion['target']}: el SOC nunca actúa sobre OT (apartado 4)")
        return None
    elif activo.get("type") in ("TPV", "Frontal web", "Pasarela de pagos"):
        aprobadores = f"N2 + negocio: {_responsable(activo) or 'responsable del servicio (sin datos)'}"
    elif activo.get("type") == "Portátil":
        aprobadores = "N2"
    else:
        resp = _responsable(activo)
        aprobadores = f"N2 + responsable del servicio: {resp or 'SIN RESPONSABLE en servicios_negocio.csv'}"
    if accion.get("approvers") != aprobadores:
        ajustes.append(f"isolate_host {accion['target']}: requiere aprobación de {aprobadores}")
    return {**accion, "requires_approval": True, "approvers": aprobadores}


def validar(ticket: dict, alerta: dict) -> dict:
    ajustes: list[str] = []
    acciones = []

    for a in ticket["recommended_actions"]:
        accion = a["action"]
        if accion == "isolate_host":
            a = _aprobacion_aislamiento(a, ajustes)
            if a is None:
                acciones.append({"action": "escalate_operations", "target": "Responsable de Operaciones",
                                 "requires_approval": False, "approvers": "",
                                 "justification": "Activo OT: solo escalar (apartado 4)"})
                continue
        elif accion in DISRUPTIVAS and not a["requires_approval"]:
            ajustes.append(f"{accion} {a['target']}: marcada como pendiente de aprobación de N2 (apartado 4)")
            a = {**a, "requires_approval": True, "approvers": "N2"}
        elif accion in DISRUPTIVAS:
            a = {**a, "approvers": a.get("approvers") or "N2"}
        elif accion == "block_ioc":
            tip = (_api(f"/intel/{a['target']}") or {}).get("tip") or {}
            etiquetas = set(str(tip.get("tags", "")).split(","))
            if etiquetas & ETIQUETAS_USO_DUAL or tip.get("reputation") == "benign":
                if not a["requires_approval"]:
                    ajustes.append(f"block_ioc {a['target']}: servicio de uso dual o legítimo según el TIP "
                                   f"({tip.get('tags', '')}); bloquearlo requiere N2 (apartado 4)")
                a = {**a, "requires_approval": True, "approvers": "N2"}
        acciones.append(a)

    # IOC maliciosos según el TIP o la sandbox que el modelo no propuso bloquear (el N1 puede ejecutarlo)
    if ticket["verdict"] == "true_positive":
        bloqueados = {a["target"] for a in acciones if a["action"] == "block_ioc"}
        for e in ticket.get("enrichment", []):
            ind, tipo = e["indicator"], e["type"]
            if ind in bloqueados or tipo not in ("ip", "domain", "sha256", "url"):
                continue
            tip = (_api(f"/intel/{ind}") or {}).get("tip") or {}
            sbx = _api(f"/sandbox/{ind}") if tipo == "sha256" else None
            if tip.get("reputation") == "malicious" or (sbx or {}).get("verdict") == "malicious":
                acciones.append({"action": "block_ioc", "target": ind, "requires_approval": False, "approvers": "",
                                 "justification": f"Indicador malicioso según {'sandbox' if sbx else 'TIP'}"})
                bloqueados.add(ind)
                ajustes.append(f"Añadido block_ioc {ind}: malicioso según {'sandbox' if sbx else 'TIP'}")

    # Escalado obligatorio y notificaciones (apartados 3 y 5)
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
                acciones.append({"action": "notify", "target": quien, "requires_approval": False, "approvers": "",
                                 "justification": f"SLA de severidad {ticket['severity']} (apartado 3)"})
                ajustes.append(f"Añadida notificación a {quien} (SLA {ticket['severity']}, apartado 3)")

    return {**ticket, "recommended_actions": acciones, "escalation": esc, "ajustes_politica": ajustes}
