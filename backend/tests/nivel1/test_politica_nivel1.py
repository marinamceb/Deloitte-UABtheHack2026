"""[Nivel 1] Política aplicada por código con las reglas internas (agente/politica.py) y su efecto en el triaje:
no dar por buena una actividad que incumple una regla, preguntar por los datos que faltan, no heredar plantilla."""
import pytest

from agente import politica
from agente import reglas_internas as R
from apoyo import alerta

P, S, I = R.PERMITIDA, R.SOSPECHOSA, R.REQUIERE_INFO


def _ticket(verdict):
    return {"verdict": verdict, "severity": "low", "enrichment": [], "recommended_actions": [], "open_questions": [],
            "escalation": {"escalate": False, "to": "", "reason": ""}}


def test_politica_no_da_por_buena_una_regla_incumplida():
    c = [R.hallazgo("Cuentas adm.* solo desde JUMP01", "adm.x", S, "uso desde WS-1", ["S1"])]
    t = politica.validar(_ticket("benign_true_positive"), {"created_at": "2026-10-14T10:00:00Z"}, c)
    assert t["verdict"] == "needs_more_info" and any("needs_more_info" in a for a in t["ajustes_politica"])


def test_politica_respeta_veredicto_si_la_regla_se_cumple():
    c = [R.hallazgo("Acceso a OT", "ENG-WS01", P, "origen autorizado", ["F1"])]
    t = politica.validar(_ticket("benign_true_positive"), {"created_at": "2026-10-14T10:00:00Z"}, c)
    assert t["verdict"] == "benign_true_positive"


def test_politica_anota_datos_faltantes_en_open_questions():
    c = [R.hallazgo("svc_backup", "svc_backup", I, "origen desconocido", ["V2"], "IPs del proveedor")]
    t = politica.validar(_ticket("true_positive"), {"created_at": "2026-10-14T10:00:00Z"}, c)
    assert any("IPs del proveedor" in q for q in t["open_questions"])


def test_triaje_no_hereda_plantilla_si_una_regla_no_se_cumple(monkeypatch, tmp_path):
    from agente import almacen, incidentes, plantillas, triaje
    monkeypatch.setattr(almacen, "SALIDAS", tmp_path)
    monkeypatch.setattr(incidentes, "incidente_de", lambda _id: [])
    monkeypatch.setattr(incidentes, "todas_las_alertas", lambda: {})
    monkeypatch.setattr(triaje.reglas_internas, "evaluar",
                        lambda a, o: [R.hallazgo("Acceso a OT", "WS-1", S, "sin cambio", ["F1"])])
    monkeypatch.setattr(plantillas, "buscar", lambda *a: pytest.fail("no debe buscar plantilla"))
    monkeypatch.setattr(triaje, "preinvestigar", lambda a, o: "")
    monkeypatch.setattr(triaje, "motor", lambda: type("M", (), {"ejecutar": staticmethod(
        lambda *a: {"salida": None, "motivo": "modelo simulado", "uso": {}, "razonamiento": [], "modelo": "test"})}))
    res = triaje.triar(alerta("UC-OT-001", entities={"hosts": [{"hostname": "WS-1"}]}, aid="ALR-20261014-999999"))
    assert res["heredado_de"] is None
    assert res["ticket"]["comprobaciones_internas"][0]["estado"] == S
