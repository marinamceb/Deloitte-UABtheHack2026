"""[Nivel 2] Descartar con argumentos (politica._exigir_argumento): un benign_true_positive debe citar un cambio o
flujo vigente, o tener una comprobación permitida."""
from agente import politica
from agente import reglas_internas as R


# ============================================================================================ B: con argumentos

def ticket(verdict="benign_true_positive", summary="Actividad legítima."):
    return {"verdict": verdict, "severity": "informational", "summary": summary, "severity_rationale": "",
            "title": "t", "evidence": [], "enrichment": [], "recommended_actions": [], "open_questions": [],
            "escalation": {"escalate": False, "to": "", "reason": ""}}


def test_benigno_sin_argumento_pasa_a_needs_more_info(calendario):
    t = politica.validar(ticket(), {"created_at": "2026-10-09T10:00:00Z"}, [])
    assert t["verdict"] == "needs_more_info" and any("no cita" in a for a in t["ajustes_politica"])


def test_benigno_con_cambio_vigente_citado_se_acepta(calendario):
    t = politica.validar(ticket(summary="Pentest autorizado CHG-2026-1042."), {"created_at": "2026-10-09T10:00:00Z"}, [])
    assert t["verdict"] == "benign_true_positive"


def test_benigno_con_cambio_fuera_de_ventana_no_se_acepta(calendario):
    t = politica.validar(ticket(summary="Pentest autorizado CHG-2026-1042."), {"created_at": "2026-10-20T10:00:00Z"}, [])
    assert t["verdict"] == "needs_more_info" and any("no está vigente" in a for a in t["ajustes_politica"])


def test_benigno_con_comprobacion_permitida_se_acepta(calendario):
    c = [R.hallazgo("Acceso a OT", "ENG-WS01", R.PERMITIDA, "origen autorizado", ["F1"])]
    assert politica.validar(ticket(), {"created_at": "2026-10-09T10:00:00Z"}, c)["verdict"] == "benign_true_positive"


def test_informativa_no_es_argumento(calendario):
    c = [R.hallazgo("Cambio aprobado vigente", "CHG-2026-1042", R.INFORMATIVA, "no la cubre", ["X"], tipo="cambio")]
    assert politica.validar(ticket(), {"created_at": "2026-10-09T10:00:00Z"}, c)["verdict"] == "needs_more_info"


def test_true_positive_no_necesita_autorizacion(calendario):
    assert politica.validar(ticket("true_positive"), {"created_at": "2026-10-09T10:00:00Z"}, [])["verdict"] == "true_positive"
