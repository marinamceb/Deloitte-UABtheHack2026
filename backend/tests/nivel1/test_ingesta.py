"""[Nivel 1 · entrada] Alertas nuevas recibidas por el backend (agente/ingesta.py y servidor/rutas/entrada.py): se
completan con el catálogo, se suman a las de la API, entran en la cola priorizada y se correlacionan."""
import json
import re

import pytest
from fastapi.testclient import TestClient

from agente import almacen, incidentes, ingesta
from apoyo import CLAVES, DET, N1, requiere_api, soc  # noqa: F401  (soc: SOC simulado para las rutas web)

YO = {"email": "n1@soc.example"}


@pytest.fixture
def buzon(tmp_path, monkeypatch):
    monkeypatch.setattr(almacen, "SALIDAS", tmp_path)
    incidentes.reiniciar()
    yield tmp_path
    incidentes.reiniciar()


def test_se_completa_con_el_catalogo(buzon):
    [a] = ingesta.recibir([{"rule_id": "UC-EDR-004", "alert_id": "SIEM-77",
                            "entities": {"hosts": [{"hostname": "FS01"}]}}], YO)
    assert re.fullmatch(r"ALR-\d{8}-900001", a["alert_id"])
    assert (a["rule_name"], a["severity"], a["runbook"]) == ("Acceso a la memoria de LSASS", "critical", "RB-02")
    assert a["mitre"]["technique_id"] == "T1003.001" and a["status"] == "new"
    assert a["recibida"]["external_id"] == "SIEM-77" and a["recibida"]["por"] == YO["email"]
    assert ingesta.por_id(a["alert_id"])["rule_id"] == "UC-EDR-004"
    [b] = ingesta.recibir([{"rule_id": "UC-EDR-004", "created_at": "2026-10-10T02:00:00+02:00"}], YO)
    assert b["alert_id"] == "ALR-20261010-900002" and b["created_at"] == "2026-10-10T00:00:00.000Z"   # UTC


def test_regla_fuera_del_catalogo(buzon):
    with pytest.raises(ingesta.AlertaNoValida, match="catálogo"):
        ingesta.recibir([{"rule_id": "UC-NO-EXISTE"}], YO)
    [a] = ingesta.recibir([{"rule_id": "UC-NO-EXISTE", "rule_name": "Regla propia", "severity": "high"}], YO)
    assert a["recibida"]["fuera_de_catalogo"] and a["severity"] == "high"


def test_todo_o_nada(buzon):
    with pytest.raises(ingesta.AlertaNoValida, match="Alerta 2"):
        ingesta.recibir([{"rule_id": "UC-EDR-004"}, {"rule_id": "UC-EDR-004", "created_at": "ayer"}], YO)
    assert ingesta.leer() == []
    with pytest.raises(ingesta.AlertaNoValida):
        ingesta.recibir([], YO)


@requiere_api
def test_entra_en_la_cola_y_se_correlaciona(buzon):
    """Una alerta nueva con la cuenta comprometida del ransomware se une a ese incidente y aparece en la cola."""
    from agente import cola
    [a] = ingesta.recibir([{"rule_id": "UC-NET-004", "created_at": "2026-10-12T03:00:00Z",
                            "entities": {"hosts": [{"hostname": "FS01"}],
                                         "users": [{"upn": "adm.aortega@tarvia.example"}]},
                            "evidence": {"method": "PsExec", "account": "adm.aortega"}}], YO)
    assert a["alert_id"] in incidentes.todas_las_alertas()
    assert "ALR-20261009-011790" in incidentes.incidente_de(a["alert_id"])
    entrada = next(x for x in cola.actual() if a["alert_id"] in x["alert_ids"])
    assert entrada["severidad"] == "critical" and len(entrada["alert_ids"]) > 1


# --------------------------------------------------------------------------------------------- web

@pytest.fixture
def web(soc, monkeypatch):
    from servidor import app as modulo
    from servidor.rutas import consulta, entrada
    monkeypatch.setattr(consulta, "cola_cacheada", lambda: [
        {"alert_id": "X", "alert_ids": ["X"], "severidad": "low", "n": 1, "ruido": False, "vence": "2026-11-08"}])
    monkeypatch.setattr(entrada, "alerta_por_id",
                        lambda i: (ingesta.por_id(i), None if ingesta.por_id(i) else "404", 0))
    incidentes.reiniciar()

    def cliente(email):
        c = TestClient(modulo.app)
        u = email.split("@")[0]
        assert c.post("/api/login", json={"usuario": u, "password": CLAVES[u]}).status_code == 200
        return c
    yield cliente
    incidentes.reiniciar()


def test_web_recibir_y_triar(web, monkeypatch):
    from agente import triaje
    from servidor.rutas import entrada
    c = web(N1)
    r = c.post("/api/alertas", json={"alertas": [{"rule_id": "UC-EDR-004"}]})
    assert r.status_code == 200 and r.json()[0]["rule_name"] == "Acceso a la memoria de LSASS"
    aid = r.json()[0]["alert_id"]
    assert c.post("/api/alertas", json={"alertas": [{"rule_id": "UC-NO"}]}).status_code == 422
    assert c.get("/api/alertas/recibidas").json()[0]["alert_id"] == aid
    assert any(x["rule_id"] == "UC-EDR-004" for x in c.get("/api/catalogo").json()["reglas"])

    monkeypatch.setattr(triaje, "triar", lambda alerta: {"ticket": {"ticket_id": "TKT-X", "verdict": "true_positive",
                                                                    "severity": "critical"}, "heredado_de": None})
    t = c.post(f"/api/alertas/{aid}/triar", json={}).json()
    assert t["estado"] in ("en_cola", "triando", "hecho")
    entrada.esperar_trabajos()
    hecho = next(x for x in c.get("/api/trabajos").json() if x["id"] == t["id"])
    assert (hecho["estado"], hecho["ticket_id"]) == ("hecho", "TKT-X")
    assert c.post("/api/alertas/ALR-NO/triar", json={}).status_code == 404


def test_web_deteccion_no_envia(web):
    assert web(DET).post("/api/alertas", json={"alertas": [{"rule_id": "UC-EDR-004"}]}).status_code == 403


# ------------------------------------------------------------------------------------ ruta pública (otros sistemas)

@pytest.fixture
def externa(buzon, monkeypatch):
    from servidor import app as modulo
    from servidor.rutas import consulta, integracion
    monkeypatch.setenv("INGESTA_TOKEN", "secreto-de-prueba")
    monkeypatch.setenv("INGESTA_POR_MINUTO", "5")
    integracion._ENVIOS.clear()
    monkeypatch.setattr(consulta, "invalidar_cola", lambda: None)
    return TestClient(modulo.app)


URL = "/api/ingesta/alertas"
CLAVE = {"X-API-Key": "secreto-de-prueba", "X-Origen": "siem-pruebas"}


def test_externa_desactivada_sin_token(externa, monkeypatch):
    monkeypatch.delenv("INGESTA_TOKEN")
    assert externa.post(URL, json={"rule_id": "UC-EDR-004"}, headers=CLAVE).status_code == 503


def test_externa_exige_token(externa):
    assert externa.post(URL, json={"rule_id": "UC-EDR-004"}).status_code == 401
    assert externa.post(URL, json={"rule_id": "UC-EDR-004"}, headers={"X-API-Key": "otro"}).status_code == 401
    assert ingesta.leer() == []


def test_externa_tres_formatos_sin_sesion(externa):
    r = externa.post(URL, json={"rule_id": "UC-EDR-004"}, headers=CLAVE)               # una alerta
    assert r.status_code == 202 and r.json()["recibidas"] == 1
    lista = [{"rule_id": "UC-EML-001"}, {"rule_id": "UC-NET-004"}]                       # una lista
    assert externa.post(URL, json=lista, headers=CLAVE).json()["recibidas"] == 2
    assert externa.post(URL, json={"alertas": [{"rule_id": "UC-IDP-002"}]}, headers=CLAVE).json()["recibidas"] == 1
    recibidas = ingesta.leer()
    assert len(recibidas) == 4 and recibidas[0]["recibida"]["por"] == "integracion:siem-pruebas"
    eventos = [json.loads(x)["evento"] for x in (almacen.SALIDAS / "accesos.jsonl").read_text().splitlines()]
    assert eventos.count("ingesta") == 3


def test_externa_errores_y_limite(externa):
    r = externa.post(URL, content=b"{no es json", headers={**CLAVE, "Content-Type": "application/json"})
    assert r.status_code == 400
    assert externa.post(URL, json={"rule_id": "UC-NO"}, headers=CLAVE).status_code == 422
    assert externa.post(URL, data={"rule_id": "x"}, headers=CLAVE).status_code == 415    # solo JSON
    codigos = [externa.post(URL, json={"rule_id": "UC-EDR-004"}, headers=CLAVE).status_code for _ in range(5)]
    assert 429 in codigos                                                                  # 5 por minuto
