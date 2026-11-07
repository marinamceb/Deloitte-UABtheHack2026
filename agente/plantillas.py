"""Reutilización de veredictos para alertas con un patrón idéntico (ruido repetitivo) sin volver a llamar al modelo.

Una alerta hereda el veredicto de un ticket anterior solo si:
- su regla está en FIRMAS (reglas de ruido repetitivo donde el veredicto depende del patrón, no de la entidad) y la
  firma (regla + campos estables de la evidencia) es idéntica;
- el ticket de referencia lo trió el modelo (no es heredado), con confianza >= 0.7, sin escalado, el modelo marcó
  `patron_generalizable` (su veredicto no depende de un cambio, una fecha, una IP o una entidad), y su veredicto es
  false_positive / benign_true_positive, o true_positive bloqueado por un control (action en la firma) de severidad
  informational o low;
- la regla de la nueva alerta no es high ni critical.
Lo demás se tría siempre individualmente. El ticket heredado lo dice explícitamente y deja una pregunta abierta para que
el humano pueda revisarlo; la severidad se recalcula con la criticidad del activo de la nueva alerta.
"""
import json
from pathlib import Path

from . import herramientas as h
from .modelos import calcular_severidad

# Regla → campos de la evidencia que definen el patrón (excluye IDs, contadores y otros valores volátiles).
# No se incluyen reglas cuyo veredicto depende de la entidad (p. ej. UC-IDP-001 viaje imposible: depende del usuario).
FIRMAS = {
    "UC-EDR-002": ["parent", "user", "decoded_preview"],          # mismo comando de un agente de gestión
    "UC-WEB-001": ["rule_id", "action"],                          # misma firma WAF y mismo resultado (bloqueado)
    "UC-EML-001": ["sender", "subject"],                          # mismo correo reportado por varios usuarios
    "UC-NET-005": ["parent_domain"],                              # subdominios aleatorios de una misma CDN
    "UC-NET-001": ["domain", "user_agent"],                       # mismo destino periódico y mismo cliente
    "UC-EDR-003": ["detection_name", "action", "executed"],       # misma detección y misma acción del antivirus
    "UC-AI-001": ["guardrail_category", "action", "prompt_excerpt"],
}
ACCIONES_BLOQUEO = {"blocked", "quarantined"}
_INDICE: dict[str, dict] | None = None  # firma → resultado de referencia


def firma(alerta: dict) -> str | None:
    campos = FIRMAS.get(alerta.get("rule_id", ""))
    if not campos:
        return None
    ev = alerta.get("evidence", {})
    return alerta["rule_id"] + "|" + json.dumps({c: ev.get(c) for c in campos}, ensure_ascii=False, sort_keys=True)


def _es_referencia(res: dict) -> bool:
    t = res["ticket"]
    if res.get("heredado_de") or t["confidence"] < 0.7 or t["escalation"]["escalate"]:
        return False
    # El modelo debe declarar que su veredicto no depende de la IP, entidad, fecha o un cambio concreto
    if not res.get("entrada_severidad", {}).get("patron_generalizable"):
        return False
    if t["verdict"] in ("false_positive", "benign_true_positive"):
        return True
    accion = str(res["alerta"].get("evidence", {}).get("action", "")).lower()
    return (t["verdict"] == "true_positive" and t["severity"] in ("informational", "low")
            and accion in ACCIONES_BLOQUEO and "action" in FIRMAS.get(res["alerta"]["rule_id"], []))


def _indice(dir_tickets: Path) -> dict[str, dict]:
    global _INDICE
    if _INDICE is None:
        _INDICE = {}
        for p in sorted(dir_tickets.glob("TKT-*.json")):
            try:
                registrar(json.loads(p.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, KeyError):
                continue
    return _INDICE


def registrar(res: dict) -> None:
    """Añade un resultado triado por el modelo como posible referencia para su firma."""
    f = res.get("firma")
    if _INDICE is not None and f and _es_referencia(res):
        _INDICE.setdefault(f, res)


def buscar(alerta: dict, dir_tickets: Path) -> dict | None:
    if alerta.get("severity") in ("high", "critical"):
        return None
    f = firma(alerta)
    return _indice(dir_tickets).get(f) if f else None


def heredar(alerta: dict, ref: dict) -> tuple[dict, dict]:
    """Construye el ticket de una alerta con el mismo patrón que `ref`. Devuelve (ticket sin ids/tiempos, entrada)."""
    e = alerta.get("entities", {})
    hosts = [x["hostname"] for x in e.get("hosts", []) if x.get("hostname")]
    users = [x["upn"] for x in e.get("users", []) if x.get("upn")]
    entrada = dict(ref["entrada_severidad"])
    # La severidad depende del activo: se consulta la criticidad del de esta alerta (queda en la traza como "auto")
    if hosts:
        h.ORIGEN = "auto"
        try:
            datos = h.consultar_activo.call({"hostname_o_ip": hosts[0]})
        finally:
            h.ORIGEN = "agente"
        for nivel in ("Crítica", "Alta", "Media", "Baja"):
            if f'"criticality": "{nivel}"' in datos:
                entrada.update(activo_mas_critico=hosts[0], criticidad=nivel)
                break
    rt = ref["ticket"]
    severidad, explicacion = calcular_severidad(alerta.get("severity", "medium"), {**entrada, "verdict": rt["verdict"]})
    ticket = {
        "alert_ids": [alerta["alert_id"]],
        "title": rt["title"],
        "verdict": rt["verdict"],
        "confidence": round(rt["confidence"] * 0.9, 2),
        "severity": severidad,
        "severity_rationale": explicacion,
        "affected": {"users": users, "hosts": hosts, "business_services": rt["affected"]["business_services"],
                     "customers": []},
        "summary": f"Patrón idéntico a {rt['ticket_id']} (misma regla y evidencia). Veredicto heredado sin "
                   f"investigación individual. Resumen de la referencia: {rt['summary']}",
        "evidence": [{"source": "plantilla", "event_id": rt["ticket_id"],
                      "finding": "Ticket de referencia triado por el agente con el mismo patrón"}],
        "enrichment": [],
        "mitre": rt["mitre"],
        "recommended_actions": [{"action": "close", "target": alerta["alert_id"], "requires_approval": False,
                                 "justification": f"Mismo patrón que {rt['ticket_id']}"}],
        "escalation": {"escalate": False, "to": "", "reason": ""},
        "open_questions": [f"Veredicto heredado de {rt['ticket_id']}: revisar si el contexto de "
                           f"{', '.join(hosts + users) or 'esta alerta'} difiere del de la referencia."],
    }
    return ticket, entrada
