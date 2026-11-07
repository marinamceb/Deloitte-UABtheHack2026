"""[Nivel 2] Contexto de RRHH y líneas base (agente/contexto.py)."""
import pytest

import datetime as _dt

from agente import contexto as X
from agente import reglas_internas as R
from apoyo import requiere_api


# ============================================================================================ E: RRHH y líneas base

D = _dt.date


@pytest.mark.parametrize("evento, esperado", [
    ({"tipo": "viaje", "fecha": "2026-10-02", "fecha_efectiva": "2026-10-11",
      "detalle": "Nueva York (reuniones) del 11/10 al 14/10."}, (D(2026, 10, 11), D(2026, 10, 14))),
    ({"tipo": "vacaciones", "fecha": "2026-10-01", "fecha_efectiva": "2026-10-26",
      "detalle": "Vacaciones 26/10 a 30/10 (sustituye Tesorería)."}, (D(2026, 10, 26), D(2026, 10, 30))),
    ({"tipo": "vacaciones", "fecha": "2026-10-03", "fecha_efectiva": "2026-10-10", "detalle": "Una semana"},
     (D(2026, 10, 10), D(2026, 10, 16))),
    ({"tipo": "teletrabajo_temporal", "fecha": "2026-10-07", "fecha_efectiva": "2026-10-11",
      "detalle": "Teletrabajo desde Valencia dos semanas"}, (D(2026, 10, 11), D(2026, 10, 24))),
    ({"tipo": "baja_voluntaria_comunicada", "fecha": "2026-09-30", "fecha_efectiva": "2026-10-16",
      "detalle": "Baja voluntaria; último día 16/10/2026."}, (D(2026, 9, 30), D(2026, 10, 16))),
    ({"tipo": "baja_voluntaria_comunicada", "fecha": "2026-10-05", "fecha_efectiva": "2026-10-24",
      "detalle": "Último día a final de mes"}, (D(2026, 10, 5), D(2026, 10, 24))),
    ({"tipo": "viaje", "fecha": "2026-10-06", "fecha_efectiva": "2026-10-27", "detalle": "Milán (feria textil)"},
     (D(2026, 10, 27), None)),   # sin fecha de fin: no se supone
])
def test_periodos_de_rrhh(evento, esperado):
    assert X.periodo(evento) == esperado


@requiere_api
@pytest.mark.parametrize("alert_id, tipo, estado", [
    ("ALR-20261011-011873", "rrhh", R.PERMITIDA),         # viaje a Nueva York registrado en RRHH
    ("ALR-20261022-007094", "rrhh", R.SOSPECHOSA),        # nuria.vidal: cuenta usada tras su último día
    ("ALR-20261014-011817", "rrhh", R.SOSPECHOSA),        # nuria.vidal: fuga entre la comunicación y su salida
    ("ALR-20261016-004600", "rrhh", R.REQUIERE_INFO),     # andrea.font: actividad durante sus vacaciones
    ("ALR-20261015-004414", "rrhh", R.INFORMATIVA),       # marina.munoz: alta reciente
    ("ALR-20261009-001917", "linea_base", R.PERMITIDA),   # viaje imposible por el relé Private Relay
    ("ALR-20261010-011828", "linea_base", R.SOSPECHOSA),  # sergio.navarro desde VPN comercial nueva
    ("ALR-20261007-011786", "linea_base", R.SOSPECHOSA),  # BEC: inicio de sesión desde hosting
    ("ALR-20261006-000501", "linea_base", R.PERMITIDA),   # teams.microsoft.com: uso generalizado
    ("ALR-20261011-002565", "linea_base", R.PERMITIDA),   # subdominio aleatorio de cloudfront.net
    ("ALR-20261019-011888", "linea_base", R.INFORMATIVA),  # túnel DNS: dominio que casi nadie visita
])
def test_contexto_casos_reales(alerta_real, alert_id, tipo, estado):
    r = [x for x in X.evaluar(alerta_real(alert_id)) if x["tipo"] == tipo]
    assert len(r) == 1 and r[0]["estado"] == estado, r


@requiere_api
def test_dominio_malicioso_nunca_se_da_por_bueno(alerta_real):
    assert X.evaluar(alerta_real("ALR-20261009-011792")) == []   # aplihartom.com, C2 del ransomware


@pytest.fixture
def usuario_sintetico(monkeypatch):
    datos = {"hr": [], "signins": [], "geo": {}}
    monkeypatch.setattr(X, "_usuario", lambda upn: {"hr_events": datos["hr"]})
    monkeypatch.setattr(X, "_inicios_de_sesion", lambda upn: tuple(datos["signins"]))
    monkeypatch.setattr(X, "_intel", lambda ip: {"geo": datos["geo"].get(ip, {})})
    return datos


def _login(ip, ciudad="", fecha="2026-10-14T10:00:00Z", dispositivo="portátil"):
    return {"alert_id": "ALR-T", "created_at": fecha, "rule_id": "UC-IDP-001",
            "entities": {"users": [{"upn": "u@tarvia.example"}], "ips": [ip]},
            "evidence": {"current_login": {"city": ciudad, "ip": ip}, "device": dispositivo}}


def test_origen_habitual_permitida(usuario_sintetico):
    usuario_sintetico["geo"]["203.0.113.9"] = {"country": "ES", "asn": "AS1", "as_org": "ISP"}
    usuario_sintetico["signins"] = [{"result": "success", "country": "ES", "asn": "AS1",
                                     "timestamp": f"2026-10-0{d}T09:00:00Z"} for d in range(1, 5)]
    assert [x["estado"] for x in X.evaluar(_login("203.0.113.9"))] == [R.PERMITIDA]


def test_origen_nuevo_residencial_requiere_info(usuario_sintetico):
    usuario_sintetico["geo"]["203.0.113.9"] = {"country": "PT", "asn": "AS9", "as_org": "ISP Lisboa"}
    assert [x["estado"] for x in X.evaluar(_login("203.0.113.9", "Lisboa"))] == [R.REQUIERE_INFO]


def test_teletrabajo_explica_el_origen_nuevo(usuario_sintetico):
    usuario_sintetico["hr"] = [{"tipo": "teletrabajo_temporal", "fecha": "2026-10-07", "fecha_efectiva": "2026-10-11",
                                "detalle": "Teletrabajo desde Valencia dos semanas"}]
    usuario_sintetico["geo"]["203.0.113.9"] = {"country": "ES", "asn": "AS9", "city": "Valencia"}
    r = X.evaluar(_login("203.0.113.9", "Valencia"))
    assert [(x["tipo"], x["estado"]) for x in r] == [("rrhh", R.PERMITIDA)]   # sin «origen nuevo» redundante


def test_viaje_sin_fecha_de_fin_requiere_info(usuario_sintetico):
    usuario_sintetico["hr"] = [{"tipo": "viaje", "fecha": "2026-10-06", "fecha_efectiva": "2026-10-13",
                                "detalle": "Milán (feria textil)"}]
    usuario_sintetico["geo"]["203.0.113.9"] = {"country": "IT", "asn": "AS9", "city": "Milán"}
    r = [x for x in X.evaluar(_login("203.0.113.9", "Milán")) if x["tipo"] == "rrhh"]
    assert r[0]["estado"] == R.REQUIERE_INFO and "fin" in r[0]["dato_faltante"]


def test_origen_nuevo_desde_tor_es_sospechosa(usuario_sintetico):
    usuario_sintetico["geo"]["203.0.113.9"] = {"country": "NL", "asn": "AS9", "is_tor": "True"}
    assert R.SOSPECHOSA in [x["estado"] for x in X.evaluar(_login("203.0.113.9"))]
