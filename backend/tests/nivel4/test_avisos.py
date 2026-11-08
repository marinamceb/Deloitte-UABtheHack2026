"""[Nivel 4 · avisos] Avisos por rol (agente/avisos.py) y vistas de consulta de la web (servidor/rutas/consulta.py).
Con el SOC simulado de tests/apoyo.py."""
import datetime as dt

import pytest
from fastapi.testclient import TestClient

from agente import almacen, avisos, roles
from apoyo import CLAVES, CISO, DET, N1, N2, RSOC, soc  # noqa: F401  (soc es el fixture del entorno simulado)


@pytest.fixture
def datos(soc):
    """Un ticket crítico escalado (fuera de horario) y un informe con notificaciones a terceros."""
    res = almacen.ticket("TKT-1")
    res["triado_en"] = "2026-11-07T18:16:00+00:00"            # sábado 19:16 en España
    res["ticket"].update(severity="critical", title="Minero en JENKINS",
                         escalation={"escalate": True, "to": "N2 de guardia (teléfono)", "reason": "RCE confirmado"})
    res["ticket"]["recommended_actions"] += [
        {"action": "notify", "target": "Responsable SOC", "requires_approval": False, "justification": "SLA"},
        {"action": "notify", "target": "CISO", "requires_approval": False, "justification": "SLA"}]
    almacen.guardar_ticket(res)
    inf = almacen.informe("INC-1")
    inf.update(generado_en="2026-11-08T00:49:00+00:00")
    inf["informe"].update(title="Fuga del CRM", alert_ids=[], notifications=[
        "Notificar a la AEPD y CNPD en 72 horas por la exfiltración de copias del CRM",
        "Responsable del SOC y CISO (severidad crítica, apartado 3)",
        "Notificar al equipo de DevOps para revisar el registro de paquetes"])
    almacen.guardar_informe(inf)
    avisos.sincronizar()
    return soc


def _por(categoria, origen):
    return next(a for a in almacen.leer_json("avisos.json", {}).values()
                if a["categoria"] == categoria and a["origen"]["id"] == origen)


# --------------------------------------------------------------------------------------------- generación

@pytest.mark.parametrize("texto,esperado", [
    ("Notificar a la AEPD en 72 h", ["dpo"]),
    ("Responsable del SOC y CISO (Alba Rovira)", ["ciso", "responsable_soc"]),
    ("Avisar a Tesorería del cambio de IBAN", ["tesoreria"]),
    ("Notificar al proveedor legítimo Hilaturas Alcoi", ["proveedor"]),
    ("Notificar al equipo de DevOps", []),
])
def test_clasificacion(texto, esperado):
    assert sorted(avisos.clasificar(texto)) == sorted(esperado)


def test_avisos_del_ticket_y_del_informe(datos):
    esc = _por("escalado", "TKT-1")
    assert esc["interno"] and esc["destinatarios"] == ["N2", "responsable_soc"]
    assert dt.datetime.fromisoformat(esc["plazo"]) - dt.datetime.fromisoformat("2026-11-07T18:16:00+00:00") \
        == dt.timedelta(minutes=15)                                        # crítico: 15 min (apartado 3)
    dpo = _por("dpo", "INC-1")
    assert not dpo["interno"] and dpo["contacto"] == "DPO"
    assert dt.datetime.fromisoformat(dpo["plazo"]) - dt.datetime.fromisoformat("2026-11-08T00:49:00+00:00") \
        == dt.timedelta(hours=72)                                          # RGPD: 72 h desde la constancia
    assert {a["categoria"] for a in almacen.leer_json("avisos.json", {}).values()} == {
        "escalado", "responsable_soc", "ciso", "dpo"}                      # DevOps no genera aviso
    assert avisos.sincronizar() == 0                                       # no se duplican


def test_plazo_alto_en_la_jornada():
    fin = avisos._plazo_escalado("high", "2026-11-03T10:00:00+00:00")       # martes 11:00 en España (UTC+1)
    assert fin.startswith("2026-11-03T19:00")                              # hasta las 20:00 locales


def test_cada_rol_ve_lo_suyo(datos):
    def cats(email):
        return {a["categoria"] for a in avisos.para(roles.identificar(email))}
    assert cats(N1) == set()
    assert cats(N2) == {"escalado", "dpo"}
    assert cats(RSOC) == cats(CISO) == {"escalado", "responsable_soc", "ciso", "dpo"}


def test_atender(datos):
    n2, rsoc = roles.identificar(N2), roles.identificar(RSOC)
    with pytest.raises(avisos.NoPermitido):
        avisos.atender(_por("ciso", "INC-1")["id"], n2, "")               # no le corresponde
    with pytest.raises(avisos.NoPermitido):
        avisos.atender(_por("dpo", "INC-1")["id"], n2, " ")               # a terceros: hay que decir cómo
    a = avisos.atender(_por("dpo", "INC-1")["id"], n2, "Llamada a la DPO Elena Mora, 10:15; acuse por correo")
    assert a["estado"] == "notificado" and a["atendido"]["email"] == N2
    assert avisos.atender(_por("responsable_soc", "INC-1")["id"], rsoc, "")["estado"] == "enterado"
    with pytest.raises(avisos.NoPermitido):
        avisos.atender(a["id"], rsoc, "otra vez")                          # ya atendido


# --------------------------------------------------------------------------------------------- web

@pytest.fixture
def web(datos):
    from servidor import app as modulo
    from servidor.rutas import acciones as ra, avisos as rv
    ra._ULTIMA_SINCRONIZACION = rv._ULTIMA_SINCRONIZACION = 0.0

    def cliente(email):
        c = TestClient(modulo.app)
        u = email.split("@")[0]
        assert c.post("/api/login", json={"usuario": u, "password": CLAVES[u]}).status_code == 200
        return c
    return cliente


def test_web_avisos(web):
    c = web(N2)
    lista = c.get("/api/avisos").json()
    dpo = next(a for a in lista if a["categoria"] == "dpo")
    assert dpo["puedo"] == ["atender"]
    assert c.post(f"/api/avisos/{dpo['id']}/atender", json={"comentario": ""}).status_code == 403
    r = c.post(f"/api/avisos/{dpo['id']}/atender", json={"comentario": "DPO avisada por teléfono"})
    assert r.json()["estado"] == "notificado"
    otro = _por("ciso", "INC-1")["id"]
    assert c.post(f"/api/avisos/{otro}/atender", json={}).status_code == 404   # no lo ve: ni sabe que existe


def test_web_tickets_e_informes(web):
    c = web(N1)
    assert [t["ticket_id"] for t in c.get("/api/tickets").json()] == ["TKT-1"]
    t = c.get("/api/tickets/TKT-1").json()
    aislar = next(a for a in t["ticket"]["recommended_actions"] if a["action"] == "isolate_host")
    assert aislar["solicitud"]["estado"] == "pendiente"                    # enlazada con su solicitud
    assert next(a for a in t["ticket"]["recommended_actions"] if a["action"] == "close")["solicitud"] is None
    i = c.get("/api/informes/INC-1").json()
    assert i["informe"]["containment_plan"][0]["solicitud"]["id"].startswith("ACC-")
    assert c.get("/api/tickets/TKT-NO").status_code == 404


def test_web_cola(web, monkeypatch):
    from agente import cola
    entrada = {"alerta": {"alert_id": "ALR-1", "rule_id": "UC-X", "rule_name": "Regla", "created_at": "2026-10-10",
                          "severity": "high"}, "alert_ids": ["ALR-1", "ALR-2"], "severidad": "critical",
               "criticidad": "Alta", "activo": "FS01", "motivo": "m", "ruido": False, "autorizada": False,
               "vence": dt.datetime(2026, 10, 10, tzinfo=dt.timezone.utc)}
    monkeypatch.setattr(cola, "actual", lambda: [entrada])
    from servidor.rutas import consulta
    monkeypatch.setitem(consulta._COLA, "ts", 0.0)
    r = web(DET).get("/api/cola?limite=5").json()                            # detección: lectura
    assert r["total"] == 1 and r["entradas"][0]["n"] == 2 and r["entradas"][0]["vence"].startswith("2026-10-10")
