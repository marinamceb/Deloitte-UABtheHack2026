"""Utilidades comunes de los tests: disponibilidad de la API simulada, constantes y constructores de alertas."""
import json
import os

import pytest
import requests

API_URL = os.environ.get("SOC_API_URL", "http://localhost:8000")


def _api_disponible() -> bool:
    try:
        return requests.get(f"{API_URL}/alerts", params={"limit": 1}, timeout=5).ok
    except requests.RequestException:
        return False


requiere_api = pytest.mark.skipif(not _api_disponible(), reason=f"API simulada no disponible en {API_URL}")

# Pentest autorizado del calendario (CHG-2026-1042), para pruebas sintéticas de cambios y argumentos
PENTEST = {"id": "CHG-2026-1042", "titulo": "Pentest", "inicio": "2026-10-08 08:00", "fin": "2026-10-10 18:00",
           "detalle": "IPs origen 192.0.2.10-12; alcance www.tarvia.example", "alcance": "WEB-ECOM01..04"}


def alerta(rule_id="UC-X", created_at="2026-10-14T10:00:00Z", entities=None, evidence=None, related=(), aid="ALR-T"):
    """Alerta sintética mínima."""
    return {"alert_id": aid, "created_at": created_at, "rule_id": rule_id, "entities": entities or {},
            "evidence": evidence or {}, "related_events": list(related)}


# =============================================================================================== nivel 4: SOC simulado
# Directorio, CMDB, TIP y API de contención falsos (nada se ejecuta en la API real, que escribiría en
# containment_log.jsonl) y un ticket + un informe con acciones propuestas. Lo usan tests/nivel4.

PERSONAS = {
    "neus.benitez@tarvia.example": ("Neus Benítez", "Ciberseguridad", "Analista SOC N1"),
    "pablo.coll@tarvia.example": ("Pablo Coll", "Ciberseguridad", "Analista SOC N2"),
    "berta.gimenez@tarvia.example": ("Berta Giménez", "Ciberseguridad", "Analista SOC N2"),
    "celia.llorens@tarvia.example": ("Celia Llorens", "Ciberseguridad", "Responsable SOC"),
    "alejandro.benitez@tarvia.example": ("Alejandro Benítez", "Dirección", "Director de Tecnología"),
    "elena.mora@tarvia.example": ("Elena Mora", "Legal y Cumplimiento", "DPO"),
    "marta.puig@tarvia.example": ("Marta Puig", "Finanzas", "Técnico de Cuentas a Pagar"),
}
N1, N2, N2B, RSOC = "neus.benitez@tarvia.example", "pablo.coll@tarvia.example", "berta.gimenez@tarvia.example", \
    "celia.llorens@tarvia.example"
DIRTEC = "alejandro.benitez@tarvia.example"
ACTIVOS = {
    "FS01": {"hostname": "FS01", "type": "Servidor de ficheros", "criticality": "Alta", "zone": "SERVERS",
             "business_service": "Copias de seguridad"},           # responsable: Director de Tecnología
    "WS-BCN-1770": {"hostname": "WS-BCN-1770", "type": "Portátil", "criticality": "Media", "zone": "HQ-USERS",
                    "business_service": "Puesto de trabajo"},
    "PLC-SORT01": {"hostname": "PLC-SORT01", "type": "PLC", "criticality": "Alta", "zone": "LOGISTICS-OT",
                   "business_service": "Clasificación automática de pedidos"},
    "SRV-HUERFANO": {"hostname": "SRV-HUERFANO", "type": "Servidor", "criticality": "Media", "zone": "SERVERS",
                     "business_service": "Servicio inexistente"},
}
TIP = {"mega.nz": {"reputation": "benign", "tags": "dual-use,legit-service"}}


@pytest.fixture
def soc(monkeypatch, tmp_path):
    from agente import acciones, almacen, api
    """Directorio, CMDB, TIP y API de contención falsos; tickets e informes en tmp_path."""
    fichas = {e: {"upn": e, "display_name": n, "department": d, "title": t, "status": "active",
                  "account_type": "user", "vip": "False"} for e, (n, d, t) in PERSONAS.items()}
    fichas["svc_backup"] = {"upn": "svc_backup@tarvia.example", "display_name": "Copias", "account_type": "service"}
    monkeypatch.setattr(api, "usuario", lambda k, trazar=True: fichas.get(k))
    monkeypatch.setattr(api, "activo", lambda k, trazar=True: ACTIVOS.get(k.upper()))
    monkeypatch.setattr(api, "intel", lambda k, trazar=True: {"tip": TIP.get(k)})
    monkeypatch.setattr(api, "sandbox", lambda k, trazar=True: None)
    estado = {"aprobaciones": [], "contenciones": [], "registro": [], "error": None}

    def solicitar(accion, objetivo, aprobador, motivo):
        estado["aprobaciones"].append({"action": accion, "target": objetivo, "approver": aprobador})
        return {"approval_token": f"APR-{len(estado['aprobaciones'])}"}, None

    def contener(accion, objetivo, justificacion, token="", ticket_id=""):
        if estado["error"]:
            return None, estado["error"]
        estado["contenciones"].append({"action": accion, "target": objetivo, "token": token, "ticket": ticket_id})
        return {"action": accion, "target": objetivo, "result": "ok (simulado)"}, None

    monkeypatch.setattr(api, "solicitar_aprobacion", solicitar)
    monkeypatch.setattr(api, "contener", contener)
    monkeypatch.setattr(api, "registro_contencion", lambda: estado["registro"])
    monkeypatch.setattr(almacen, "SALIDAS", tmp_path)

    def accion(a, t, j="motivo"):
        return {"action": a, "target": t, "requires_approval": False, "justification": j}
    (tmp_path / "tickets").mkdir()
    ticket = {"ticket": {"ticket_id": "TKT-1", "alert_ids": ["ALR-1"], "executed_actions": [],
                         "recommended_actions": [
                             accion("isolate_host", "fs01"), accion("isolate_host", "WS-BCN-1770"),
                             accion("isolate_host", "PLC-SORT01"), accion("block_ioc", "evil.example"),
                             accion("block_ioc", "mega.nz"), accion("disable_user", "svc_backup"),
                             accion("delete_inbox_rule", "laura.ferrer2@tarvia.example"),
                             accion("close", "ALR-1"), accion("notify", "CISO"), accion("escalate_n2", "N2")]}}
    (tmp_path / "tickets" / "TKT-1.json").write_text(json.dumps(ticket))
    (tmp_path / "informes").mkdir()
    informe = {"informe": {"incident_id": "INC-1", "containment_plan": [
        {"action": "block_ioc", "target": "evil.example", "approver": "—", "business_impact": "ninguno",
         "justification": "C2"}]}}
    (tmp_path / "informes" / "INC-1.json").write_text(json.dumps(informe))
    acciones.sincronizar()
    return estado
