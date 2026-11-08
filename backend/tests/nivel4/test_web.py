"""[Nivel 4 · web] Backend de la consola (servidor/): login del SOC con contraseña, sesión firmada y comprobación de
rol en cada endpoint. Con el SOC simulado de tests/apoyo.py: nada llega a la API real."""
import json

import pytest
from fastapi.testclient import TestClient

from agente import acciones, almacen, api
from apoyo import DET, DIRTEC, N1, N2, N2B, CLAVES, soc  # noqa: F401  (soc es el fixture del entorno simulado)


@pytest.fixture
def web(soc):
    from servidor import app as modulo
    from servidor.rutas import acciones as rutas_acciones
    rutas_acciones._ULTIMA_SINCRONIZACION = 0.0

    def cliente(email: str | None = None) -> TestClient:
        c = TestClient(modulo.app)
        if email:
            usuario = email.split("@")[0]
            r = c.post("/api/login", json={"usuario": usuario, "password": CLAVES[usuario]})
            assert r.status_code == 200, r.text
        return c
    return cliente


def _id(accion, objetivo):
    return acciones.id_de(accion, objetivo)


# --------------------------------------------------------------------------------------------- login y sesión

def test_login_del_soc_con_contrasena(web):
    c = web()
    assert c.post("/api/login", json={"usuario": "n1", "password": "mal"}).status_code == 401
    assert c.post("/api/login", json={"usuario": DIRTEC, "password": "x"}).status_code == 401   # la empresa no entra
    r = c.post("/api/login", json={"usuario": " N1@soc.example ", "password": "n1demo"})
    assert r.status_code == 200 and r.json()["roles"] == ["N1"] and "password" not in r.json()
    assert c.get("/api/yo").json()["email"] == N1
    eventos = [json.loads(x)["evento"] for x in (almacen.SALIDAS / "accesos.jsonl").read_text().splitlines()]
    assert eventos == ["login_rechazado", "login_rechazado", "login"]


def test_sin_sesion_no_hay_datos(web):
    c = web()
    detalle = f"/api/acciones/{_id('block_ioc', 'evil.example')}"
    for ruta in ("/api/yo", "/api/acciones/pendientes", "/api/acciones", detalle):
        assert c.get(ruta).status_code == 401, ruta
    assert c.post(f"/api/acciones/{_id('block_ioc', 'evil.example')}/aprobar", json={}).status_code == 401


def test_cookie_manipulada_no_vale(web):
    c = web()
    c.cookies.set("tarvia_soc", "eyJlbWFpbCI6ICJwYWJsby5jb2xsQHRhcnZpYS5leGFtcGxlIn0=.falsa.firma")
    assert c.get("/api/yo").status_code == 401


def test_el_rol_se_recalcula_en_cada_peticion(web, soc):
    c = web(N2)
    next(f for f in soc["usuarios"] if f["email"] == N2)["activo"] = False   # baja con la sesión abierta
    assert c.get("/api/acciones/pendientes").status_code == 401


def test_logout(web):
    c = web(N1)
    assert c.post("/api/logout", json={}).status_code == 200
    assert c.get("/api/yo").status_code == 401


def test_post_solo_json(web):
    """Un formulario de otra web no puede forjar una aprobación."""
    c = web(N1)
    r = c.post(f"/api/acciones/{_id('block_ioc', 'evil.example')}/aprobar", data={"comentario": "x"})
    assert r.status_code == 415


# --------------------------------------------------------------------------------------------- decisiones por rol

def test_bandeja_y_permisos_del_n1(web, soc):
    c = web(N1)
    mias = {(s["action"], s["target"]) for s in c.get("/api/acciones/pendientes").json()}
    assert ("block_ioc", "evil.example") in mias and ("isolate_host", "FS01") not in mias
    r = c.post(f"/api/acciones/{_id('isolate_host', 'WS-BCN-1770')}/aprobar", json={"comentario": "x"})
    assert r.status_code == 403 and "N2" in r.json()["detail"]
    r = c.post(f"/api/acciones/{_id('block_ioc', 'evil.example')}/aprobar", json={"comentario": "C2"})
    assert r.status_code == 200 and r.json()["estado"] == "ejecutada"
    assert soc["contenciones"][0]["target"] == "evil.example"
    assert c.post(f"/api/acciones/{_id('block_ioc', 'evil.example')}/aprobar", json={}).status_code == 409


def test_cuatro_ojos_entre_dos_sesiones(web, soc):
    sid = _id("isolate_host", "FS01")
    r = web(N2).post(f"/api/acciones/{sid}/aprobar", json={"comentario": "ransomware"})
    assert r.json()["estado"] == "pendiente" and r.json()["faltan"] == [
        "Director de Tecnología (responsable de Copias de seguridad)"]
    otro = web(N2B)
    vista = otro.get(f"/api/acciones/{sid}").json()
    assert "registrar_responsable" in vista["puedo"]
    assert vista["negocio"] == {"cargo": "Director de Tecnología", "servicio": "Copias de seguridad"}
    r = otro.post(f"/api/acciones/{sid}/aprobar", json={"comentario": "x", "en_nombre_de": "x@tarvia.example"})
    assert r.status_code == 403                                                    # no es el responsable
    r = otro.post(f"/api/acciones/{sid}/aprobar", json={"comentario": "por teléfono 10:42", "en_nombre_de": DIRTEC})
    assert r.json()["estado"] == "ejecutada" and soc["contenciones"][0]["token"] == "APR-1"
    assert r.json()["aprobaciones"][1]["registrado_por"] == N2B


def test_deteccion_solo_lectura(web):
    c = web(DET)
    assert len(c.get("/api/acciones").json()) == 7 and c.get("/api/acciones/pendientes").json() == []
    r = c.post(f"/api/acciones/{_id('block_ioc', 'evil.example')}/aprobar", json={})
    assert r.status_code == 403
    assert c.post("/api/acciones/sincronizar", json={}).status_code == 403


def test_soc_ve_todo_y_filtra_por_estado(web):
    c = web(N1)
    assert len(c.get("/api/acciones").json()) == 7
    assert [s["action"] for s in c.get("/api/acciones?estado=prohibida").json()] == ["isolate_host"]


def test_rechazo_exige_motivo(web):
    c = web(N2)
    sid = _id("isolate_host", "WS-BCN-1770")
    assert c.post(f"/api/acciones/{sid}/rechazar", json={"comentario": "  "}).status_code == 422
    r = c.post(f"/api/acciones/{sid}/rechazar", json={"comentario": "falso positivo"})
    assert r.json()["estado"] == "rechazada"


def test_estaticos_y_salud(web):
    from agente import config
    c = web()
    if config.FRONTEND.is_dir():   # en desarrollo el backend sirve el frontend; en Docker lo sirve nginx
        assert c.get("/").status_code == 200 and "Tarvia SOC" in c.get("/").text
    else:
        assert c.get("/").status_code == 404
    assert set(c.get("/api/salud").json()) == {"web", "api_soc", "db"}


def test_registro_de_la_api(web, soc):
    soc["registro"].append({"timestamp": "2026-11-08T10:00:00Z", "action": "block_ioc", "target": "evil.example",
                            "result": "ok (simulado)"})
    assert web(N1).get("/api/contencion/registro").json()[0]["target"] == "evil.example"
    assert web().get("/api/contencion/registro").status_code == 401


def test_permisos_por_rol(web):
    p = web(N1).get("/api/yo").json()["permisos"]
    assert p["decidir"] and not p["aprobar_n2"] and not p["avisos"]
    p = web(N2).get("/api/yo").json()["permisos"]
    assert p["aprobar_n2"] and p["registrar_negocio"] and p["avisos"] and not p["supervisar"]
    p = web(DET).get("/api/yo").json()["permisos"]
    assert p["ver"] and p["solo_lectura"] and not p["decidir"]


def test_resumen_segun_permisos(web, monkeypatch):
    from servidor.rutas import panel
    monkeypatch.setattr(panel, "cola_cacheada", lambda: [
        {"alert_id": "A1", "severidad": "critical", "ruido": False},
        {"alert_id": "A2", "severidad": "low", "ruido": True}])
    monkeypatch.setattr(panel.incidentes, "listar", lambda: [["A1"]])
    monkeypatch.setattr(panel.incidentes, "todas_las_alertas", lambda: {"A1": {}, "A2": {}})
    n1 = web(N1).get("/api/resumen").json()
    assert "avisos" not in n1 and n1["cola"]["por_severidad"] == {"critical": 1} and n1["cola"]["ruido"] == 1
    assert n1["acciones"]["pendientes_mias"] > 0 and n1["tickets"]["total"] == 1
    assert "avisos" in web(N2).get("/api/resumen").json()


def test_investigar_desde_la_web(web, monkeypatch):
    from agente import indice, informe
    from servidor.rutas import entrada
    monkeypatch.setattr(indice, "disponible", lambda: True)
    monkeypatch.setattr(informe, "generar", lambda ids, usar_llm, forzar=False: {
        "informe": {"incident_id": "INC-1"}, "con_llm": usar_llm,
        "uso": {"input_tokens": 10, "llamadas_modelo": 1}})
    t = web(N2).post("/api/investigar", json={"ids": ["TKT-1"], "llm": True}).json()
    entrada.esperar_trabajos()
    hecho = next(x for x in web(N2).get("/api/trabajos").json() if x["id"] == t["id"])
    assert (hecho["estado"], hecho["incident_id"], hecho["con_llm"]) == ("hecho", "INC-1", True)
    assert web(DET).post("/api/investigar", json={"ids": ["TKT-1"]}).status_code == 403
