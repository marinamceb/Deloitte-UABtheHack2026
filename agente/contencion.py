"""[Nivel 4 · respuesta] Punto de decisión humana: el agente propone, la persona aprueba y solo entonces se llama a
la API de contención."""
import requests

from .herramientas import API_URL, ahora_iso
from .triaje import guardar

ACCIONES_API = {"isolate_host", "disable_user", "revoke_sessions", "reset_password", "block_ioc", "purge_email",
                "disable_access_key"}
SIN_APROBACION_N2 = {"block_ioc", "purge_email"}  # el N1 puede ejecutarlas (política, apartado 4)


def revisar_acciones(resultado: dict, aprobador: str) -> None:
    """Pregunta al analista por cada acción ejecutable que propuso el agente y registra lo que se hace."""
    ticket = resultado["ticket"]
    propuestas = [a for a in ticket["recommended_actions"] if a["action"] in ACCIONES_API]
    if not propuestas:
        return
    print(f"\n  Acciones de contención propuestas para {ticket['ticket_id']}:")
    for a in propuestas:
        nivel = ("N1 (tú)" if a["action"] in SIN_APROBACION_N2 and not a["requires_approval"]
                 else "aprobación: " + (a.get("approvers") or "N2"))
        print(f"   - {a['action']} → {a['target']}  [{nivel}]\n     {a['justification']}")
        if input("     ¿Ejecutar? [s/N] ").strip().lower() != "s":
            ticket["executed_actions"].append({"action": a["action"], "target": a["target"], "result": "rechazada",
                                               "decided_by": aprobador, "timestamp": ahora_iso()})
            continue
        token = ""
        if a["action"] not in SIN_APROBACION_N2 or a["requires_approval"]:
            r = requests.post(f"{API_URL}/approvals", json={"action": a["action"], "target": a["target"],
                              "approver": aprobador, "reason": a["justification"]}, timeout=30)
            r.raise_for_status()
            token = r.json()["approval_token"]
        r = requests.post(f"{API_URL}/containment/{a['action']}", json={
            "target": a["target"], "justification": a["justification"], "approval_token": token,
            "ticket_id": ticket["ticket_id"]}, timeout=30)
        rec = r.json() if r.ok else {"action": a["action"], "target": a["target"],
                                     "result": f"error {r.status_code}: {r.json().get('detail', r.text)}"}
        rec.update(decided_by=aprobador)
        ticket["executed_actions"].append(rec)
        print(f"     → {rec['result']}")
    guardar(resultado)
