"""[Nivel 2] Correlación por entidades fuertes (agente/incidentes.py): ventana larga y tickets relacionados."""
import pytest

from apoyo import requiere_api


# ============================================================================================ D: entidades fuertes

@requiere_api
def test_cuentas_sospechosas():
    from agente import incidentes
    assert incidentes.cuentas_sospechosas() == {"adm.aortega", "ext.logisoft", "svc_backup", "nuria.vidal"}


@requiere_api
@pytest.mark.parametrize("una, otra", [
    ("ALR-20261009-011790", "ALR-20261018-011895"),   # ransomware 9/10 y su persistencia del 18/10
    ("ALR-20261009-002236", "ALR-20261028-011882"),   # ext.logisoft del 9/10 al 28/10
    ("ALR-20261014-011817", "ALR-20261022-007094"),   # nuria.vidal antes y después de su salida
])
def test_entidad_fuerte_enlaza_mas_de_72h(monkeypatch, una, otra):
    from agente import incidentes
    monkeypatch.setattr(incidentes, "_INCIDENTES", None)
    assert otra in incidentes.incidente_de(una)


@requiere_api
def test_tickets_relacionados(monkeypatch, tmp_path):
    import json as _json
    from agente import incidentes
    (tmp_path / "TKT-OTRO.json").write_text(_json.dumps({"ticket": {"alert_ids": ["ALR-20261018-011895"]}}))
    (tmp_path / "TKT-AJENO.json").write_text(_json.dumps({"ticket": {"alert_ids": ["ALR-20261005-000301"]}}))
    r = incidentes.tickets_relacionados(["ALR-20261010-011797"], tmp_path, "TKT-YO")
    assert [x["ticket_id"] for x in r] == ["TKT-OTRO"]
    assert "user:adm.aortega@tarvia.example" in r[0]["entidades"]
