"""[Nivel 3] Composición del informe (agente/informe.py): lo que el código fija y verifica sobre la salida del LLM.
Sin LLM: el motor se sustituye por uno falso."""
import pytest

from apoyo import requiere_api
from agente import almacen, indice, informe, politica

HECHOS = {
    "alert_ids": ["ALR-20261015-011819", "ALR-20261016-011821"],
    "cronologia": [
        {"timestamp": "2026-10-13T12:22:00.000Z", "event_id": "CI-0000602", "source": "cicd_builds", "nivel": "pivote",
         "description": "build", "mitre": "T1195.002", "senales": [], "entidades": []},
        {"timestamp": "2026-10-16T00:40:00.000Z", "event_id": "CT-0005457", "source": "cloudtrail", "nivel": "núcleo",
         "description": "GetObject", "mitre": "T1530", "senales": [], "entidades": [],
         "event_ids": ["CT-0005457", "CT-0005458"]},
    ],
    "acceso_inicial_candidatos": [], "paciente_cero_candidato": [],
    "alcance": {"hosts": ["CI-RUNNER01"], "users": ["svc_ecom_deploy"], "bytes_salida_eventos_notables": 0,
                "filas_sql": 0, "objetos_cloud_leidos": {"tarvia-backups-prod": 1400},
                "servicios": ["Copias de seguridad", "Integración continua"], "criticidad": {}},
    "relacionados": [{"incidente": "ALR-20261012-003200", "alertas": ["ALR-20261013-011901"], "eventos": []}],
    "huecos": [], "iocs": [], "entidades": {}, "concentradores": [], "contexto_descartado": {},
}


def _llm(**cambios):
    base = {
        "title": "Fuga del CRM", "alert_ids": ["ALR-20261015-011819", "ALR-20261016-011821"],
        "patient_zero": "CI-RUNNER01", "initial_access": "Confusión de dependencias (CI-0000602)",
        "initial_access_event_id": "CI-0000602",
        "timeline": [{"event_id": "CT-0005458", "description": "descarga"},
                     {"event_id": "CI-0000602", "description": "paquete falso"}],
        "scope": {"users": [], "hosts": [], "data": "112 GB", "business_impact": "CRM"},
        "root_cause": "x", "containment_plan": [], "eradication_and_recovery": [], "notifications": [],
        "detection_gaps": [], "related_incidents": ["ALR-20261012-003200"], "descartados": [], "confidence": 0.9,
        "open_questions": [],
    }
    return {**base, **cambios}


@pytest.fixture(autouse=True)
def sin_api(monkeypatch):
    """La política consulta la API (CMDB, TIP): aquí se simula."""
    activos = {"PLC-SORT01": {"zone": "LOGISTICS-OT"}, "CI-RUNNER01": {"type": "Servidor",
                                                                       "business_service": "Integración continua"}}
    monkeypatch.setattr(politica, "_activo", activos.get)
    monkeypatch.setattr(politica, "_tip", lambda i: {})
    monkeypatch.setattr(politica, "_sandbox", lambda s: None)


def test_fechas_y_mitre_de_los_hechos_y_orden():
    inf, _ = informe.componer(_llm(), HECHOS)
    assert [x["event_id"] for x in inf["timeline"]] == ["CI-0000602", "CT-0005458"]   # ordenado por fecha
    assert inf["timeline"][1]["mitre"] == "T1530"                                       # de su grupo de repeticiones
    assert inf["incident_id"] == "INC-20261015-011819"


def test_event_id_inventado_se_elimina(monkeypatch):
    monkeypatch.setattr(indice, "evento", lambda i: None)
    inf, ajustes = informe.componer(_llm(timeline=[{"event_id": "EVT-FALSO", "description": "x"}],
                                         initial_access_event_id="EVT-FALSO"), HECHOS)
    assert inf["timeline"] == []
    assert any("inexistente" in a for a in ajustes) and "no verificado" in inf["initial_access"]


def test_politica_en_la_contencion():
    plan = [{"action": "isolate_host", "target": "PLC-SORT01", "business_impact": "", "justification": ""},
            {"action": "isolate_host", "target": "CI-RUNNER01", "business_impact": "", "justification": ""},
            {"action": "disable_access_key", "target": "AKIA1", "business_impact": "", "justification": ""}]
    inf, _ = informe.componer(_llm(containment_plan=plan), HECHOS)
    acciones = {(a["action"], a["target"]): a["approver"] for a in inf["containment_plan"]}
    assert ("isolate_host", "PLC-SORT01") not in acciones                      # nunca sobre OT
    assert ("escalate_operations", "Responsable de Operaciones") in acciones
    assert "responsable del servicio" in acciones[("isolate_host", "CI-RUNNER01")]
    assert acciones[("disable_access_key", "AKIA1")] == "N2"


def test_notificaciones_obligatorias_sin_duplicar():
    inf, _ = informe.componer(_llm(), HECHOS)
    assert any("DPO" in n and "72 h" in n for n in inf["notifications"])         # copias del CRM leídas
    inf, ajustes = informe.componer(_llm(notifications=["Avisar al Delegado de Protección de Datos"]), HECHOS)
    assert not any("DPO" in a for a in ajustes)


def test_relacionados_solo_de_los_hechos():
    inf, _ = informe.componer(_llm(related_incidents=["ALR-20261012-003200", "ALR-INVENTADA"]), HECHOS)
    assert inf["related_incidents"] == ["ALR-20261012-003200"]


@requiere_api
@pytest.mark.skipif(not indice.disponible(), reason="sin índice")
def test_generar_con_motor_falso(tmp_path, monkeypatch):
    """Extremo a extremo sin gastar cuota: si el modelo no entrega informe, queda un borrador con los hechos."""
    class MotorFalso:
        @staticmethod
        def ejecutar(*a, **k):
            return {"salida": None, "motivo": "fallo simulado", "uso": {"input_tokens": 0, "output_tokens": 0},
                    "razonamiento": [], "modelo": "falso"}
    monkeypatch.setattr(informe, "motor", lambda: MotorFalso)
    monkeypatch.setattr(almacen, "SALIDAS", tmp_path)
    r = informe.generar(["ALR-20261016-011821"])
    assert not r["con_llm"] and (tmp_path / "informes" / "INC-20261015-011819.json").exists()
    assert "CI-0000602" in {x["event_id"] for x in r["informe"]["timeline"]}
    assert any("fallo simulado" in q for q in r["informe"]["open_questions"])


# --------------------------------------------------------------------------------------------- optimizaciones 1, 4 y 5

HECHOS_COMPLETOS = {**HECHOS, "huecos": [], "acceso_inicial_candidatos": [
    {"event_id": "CI-0000602", "timestamp": "2026-10-13T12:22:00.000Z", "description": "build", "nivel": "pivote"}]}


def test_huella_estable_y_sensible():
    a = informe.huella(HECHOS_COMPLETOS)
    assert a == informe.huella(dict(HECHOS_COMPLETOS))
    otro = {**HECHOS_COMPLETOS, "cronologia": HECHOS_COMPLETOS["cronologia"][:1]}
    assert informe.huella(otro) != a


def test_cronologia_para_llm_prioriza_y_respeta_el_orden():
    crono = [{"event_id": f"E{i}", "timestamp": f"{i:02d}", "nivel": "pivote" if i % 2 else "núcleo",
              "senales": ["raro: x"] if i % 2 else ["alerta: y"], "description": "d"} for i in range(10)]
    elegidas = informe.cronologia_para_llm({"cronologia": crono, "acceso_inicial_candidatos": [{"event_id": "E9"}]}, 6)
    ids = [x["event_id"] for x in elegidas]
    assert ids == sorted(ids) and "E9" in ids and {"E0", "E2", "E4", "E6", "E8"} <= set(ids)


def test_cache_y_sin_herramientas(tmp_path, monkeypatch):
    llamadas = []

    class Motor:
        @staticmethod
        def ejecutar(*a, **k):
            llamadas.append(k)
            return {"salida": None, "motivo": "simulado", "uso": {"input_tokens": 0, "output_tokens": 0},
                    "razonamiento": [], "modelo": "falso"}
    monkeypatch.setattr(informe, "motor", lambda: Motor)
    monkeypatch.setattr(almacen, "SALIDAS", tmp_path)
    monkeypatch.setattr(informe.investigacion, "investigar", lambda ids: HECHOS_COMPLETOS)
    monkeypatch.setattr(informe, "resolver", lambda ids: ids)
    monkeypatch.setattr(informe, "mensaje", lambda h: "hechos")
    monkeypatch.setattr(informe, "componer", lambda llm, h: ({"incident_id": "INC-20261015-011819"}, []))
    informe.generar(["A"])
    assert llamadas[0]["con_herramientas"] is False                        # optimización 1: sin herramientas
    previo = almacen.informe("INC-20261015-011819")
    almacen.guardar_informe({**previo, "con_llm": True})                  # como si el LLM lo hubiera redactado
    r = informe.generar(["A"])
    assert r["reutilizado"] and len(llamadas) == 1                         # optimización 5: misma huella, sin LLM
    assert informe.generar(["A"], forzar=True) and len(llamadas) == 2
    assert informe.generar(["A"], usar_llm=False)["no_guardado"]           # un borrador no pisa el informe del LLM


def test_preparar_solo_si_procede(monkeypatch):
    llamadas = []
    monkeypatch.setattr(informe.indice, "disponible", lambda: True)
    monkeypatch.setattr(informe, "generar", lambda ids, usar_llm: llamadas.append((ids, usar_llm)) or
                        {"informe": {"incident_id": "INC-X"}})
    t = {"ticket_id": "TKT-1", "verdict": "true_positive", "severity": "critical", "escalation": {"escalate": True}}
    assert informe.preparar({"ticket": t}) == "INC-X" and llamadas == [(["TKT-1"], False)]
    assert informe.preparar({"ticket": {**t, "severity": "medium"}}) is None
    assert informe.preparar({"ticket": {**t, "verdict": "false_positive"}}) is None
