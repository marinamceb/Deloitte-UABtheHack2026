"""[Nivel 2 + optimización del nivel 1] Plantilla del viaje imposible por el relé Private Relay
(agente/plantillas.py con la línea base de agente/contexto.py)."""
import pytest

from agente import reglas_internas as R
from apoyo import requiere_api


# ============================================================================================ F: plantilla Private Relay

def test_viaje_imposible_solo_hereda_con_explicacion(monkeypatch, tmp_path):
    from agente import plantillas
    monkeypatch.setattr(plantillas, "_indice", lambda: pytest.fail("no debe buscar referencia"))
    alerta = {"rule_id": "UC-IDP-001", "severity": "medium", "evidence": {}}
    assert plantillas.buscar(alerta, []) is None
    assert plantillas.buscar(alerta, [R.hallazgo("x", "y", R.INFORMATIVA, "z")]) is None


@requiere_api
def test_firma_private_relay_agrupa_las_899():
    import collections
    from agente import incidentes, plantillas
    idp = [a for a in incidentes.todas_las_alertas().values() if a["rule_id"] == "UC-IDP-001"]
    firmas = collections.Counter(plantillas.firma(a) for a in idp)
    assert sorted(firmas.values()) == [1, 1, 899]
    assert "Private Relay" in firmas.most_common(1)[0][0]


@requiere_api
def test_plantilla_private_relay_de_principio_a_fin(monkeypatch, tmp_path, alerta_real):
    """1ª alerta: el modelo (simulado) la tría y la línea base la justifica. 2ª alerta con el mismo patrón: la hereda
    sin llamar al modelo. La alerta de Sergio (VPN comercial) tiene otra firma y no hereda."""
    from agente import almacen, plantillas, triaje
    monkeypatch.setattr(almacen, "SALIDAS", tmp_path)
    monkeypatch.setattr(plantillas, "_INDICE", None)
    llamadas = []
    salida = {"alert_ids": [], "title": "Relé Private Relay", "verdict": "benign_true_positive", "confidence": 0.9,
              "activo_mas_critico": "u", "criticidad": "Media", "ajuste": "0", "motivo_ajuste": "",
              "affected": {"users": [], "hosts": [], "business_services": [], "customers": []},
              "summary": "Salida del relé del móvil corporativo.", "evidence": [], "enrichment": [], "mitre": [],
              "recommended_actions": [], "escalation": {"escalate": False, "to": "", "reason": ""},
              "open_questions": [], "patron_generalizable": True}

    def ejecutar(*a):
        llamadas.append(1)
        return {"salida": salida, "motivo": "", "uso": {}, "razonamiento": [], "modelo": "stub"}
    monkeypatch.setattr(triaje, "motor", lambda: type("M", (), {"ejecutar": staticmethod(ejecutar)}))

    primera = triaje.triar(alerta_real("ALR-20261009-001917"))
    assert primera["ticket"]["verdict"] == "benign_true_positive" and len(llamadas) == 1   # argumento: línea base
    segunda = triaje.triar(alerta_real("ALR-20261012-002799"))
    assert segunda["heredado_de"] == "TKT-20261009-001917" and len(llamadas) == 1          # sin llamar al modelo
    sergio = triaje.triar(alerta_real("ALR-20261010-011828"))
    assert sergio["heredado_de"] is None and len(llamadas) == 2
