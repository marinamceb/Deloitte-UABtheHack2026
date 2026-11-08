"""[Nivel 1] Cola de triaje ordenada por prioridad (agente/cola.py): severidad estimada con la matriz y el inventario,
SLA de la política, señal antes que ruido, incidentes antes que alertas sueltas, sin LLM."""
import datetime as dt

import pytest

from agente import cola, incidentes
from apoyo import alerta, requiere_api

pytestmark = requiere_api  # la criticidad y los privilegios se consultan a la CMDB y al directorio por la API


@pytest.fixture
def sin_incidentes(monkeypatch):
    """Cada alerta va sola, nada es ruido ni está cubierto por un cambio (salvo que el test lo cambie)."""
    estado = {"grupos": {}, "ruido": set(), "cambios": {}, "todas": {}}
    monkeypatch.setattr(incidentes, "incidente_de", lambda i: estado["grupos"].get(i, []))
    monkeypatch.setattr(incidentes, "es_ruido", lambda i: i in estado["ruido"])
    monkeypatch.setattr(incidentes, "cubierta_por_cambio", lambda i: frozenset(estado["cambios"].get(i, ())))
    monkeypatch.setattr(incidentes, "todas_las_alertas", lambda: estado["todas"])
    return estado


def _a(aid, severidad="high", host=None, user=None, fecha="2026-10-14T10:00:00Z", fuente="EDR", **evidencia):
    ent = {}
    if host:
        ent["hosts"] = [{"hostname": host}]
    if user:
        ent["users"] = [{"upn": user}]
    return {**alerta("UC-X", fecha, ent, evidencia, aid=aid), "severity": severidad, "source_product": fuente}


def test_matriz_con_inventario(sin_incidentes):
    e = cola.estimar([_a("A", "high", host="WS-BCN-1001")])       # portátil de criticidad Alta en la CMDB
    assert (e["severidad"], e["criticidad"]) == ("high", "Alta")
    e = cola.estimar([_a("A", "high", host="DC01")])              # controlador de dominio, Crítica
    assert e["severidad"] == "critical"


def test_sla_de_la_politica(sin_incidentes):
    e = cola.estimar([_a("A", "high", host="DC01", fecha="2026-10-14T10:00:00Z")])
    assert e["vence"] - e["inicio"] == dt.timedelta(minutes=15)   # critical: 15 min


def test_identidad_privilegiada_suma_y_bloqueo_resta(sin_incidentes):
    adm = "adm.aortega@tarvia.example"
    assert cola.estimar([_a("A", "medium", user=adm)])["severidad"] == "high"           # Media + 1
    assert cola.estimar([_a("A", "high", user="ana.x@tarvia.example", action="blocked")])["severidad"] == "medium"
    assert cola.estimar([_a("A", "high", user=adm, action="blocked")])["severidad"] == "high"   # se compensan


def test_la_tienda_es_critica_aunque_no_haya_equipo(sin_incidentes):
    e = cola.estimar([_a("A", "high", fuente="WAF")])
    assert e["criticidad"] == "Crítica" and e["severidad"] == "critical"


def test_actividad_autorizada_baja_de_prioridad(sin_incidentes):
    sin_incidentes["cambios"]["A"] = {"CHG-2026-1057"}
    e = cola.estimar([_a("A", "critical", host="DC01")])
    assert e["autorizada"] and e["severidad"] in ("informational", "low") and "CHG-2026-1057" in e["motivo"]


def test_orden_de_la_cola(sin_incidentes):
    alertas = [
        _a("BAJA", "low", host="WS-BCN-1001"),
        _a("RUIDO", "high", host="DC01", fecha="2026-10-05T10:00:00Z"),     # más antigua, pero es ruido
        _a("SUELTA", "high", host="DC01", fecha="2026-10-06T10:00:00Z"),
        _a("INC1", "high", host="DC01", fecha="2026-10-07T10:00:00Z"),
        _a("INC2", "medium", host="DC01", fecha="2026-10-07T11:00:00Z"),
    ]
    sin_incidentes["todas"] = {a["alert_id"]: a for a in alertas}
    sin_incidentes["grupos"] = {"INC1": ["INC1", "INC2"], "INC2": ["INC1", "INC2"]}
    sin_incidentes["ruido"] = {"RUIDO"}
    orden = [(x["alerta"]["alert_id"], len(x["alert_ids"])) for x in cola.priorizar(alertas)]
    # critical: incidente > alerta suelta > ruido; después lo de menor severidad
    assert orden == [("INC1", 2), ("SUELTA", 1), ("RUIDO", 1), ("BAJA", 1)]


def test_omite_alertas_que_ya_tienen_ticket(sin_incidentes):
    alertas = [_a("A"), _a("B")]
    sin_incidentes["todas"] = {a["alert_id"]: a for a in alertas}
    assert [x["alerta"]["alert_id"] for x in cola.priorizar(alertas, omitir={"A"})] == ["B"]


def test_cola_real():
    entradas = cola.priorizar(list(incidentes.todas_las_alertas().values()))
    primeros = {x["alerta"]["alert_id"] for x in entradas[:6]}
    todos = {i for x in entradas[:6] for i in x["alert_ids"]}
    assert "ALR-20261009-011790" in todos            # ransomware en cabeza
    assert "ALR-20261016-011821" in todos            # fuga del CRM
    assert entradas[0]["severidad"] == "critical"
    psexec = next(x for x in entradas if "ALR-20261013-011869" in x["alert_ids"])
    assert psexec["autorizada"] and psexec["severidad"] in ("informational", "low")   # CHG-2026-1057
    assert not primeros & {"ALR-20261013-011869"}
