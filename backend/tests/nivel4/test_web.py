"""[Nivel 4 · web] Backend de la consola (servidor/): login por email, sesión firmada y comprobación de rol en cada
endpoint. Con el SOC simulado de tests/apoyo.py: nada llega a la API real."""
import json

import pytest
from fastapi.testclient import TestClient

from agente import acciones, almacen, api
from apoyo import DIRTEC, N1, N2, soc  # noqa: F401  (soc es el fixture del entorno simulado)


@pytest.fixture
def web(soc):
    from servidor import app as modulo
    from servidor.rutas import acciones as rutas_acciones
    rutas_acciones._ULTIMA_SINCRONIZACION = 0.0

    def cliente(email: str | None = None) -> TestClient:
        c = TestClient(modulo.app)
        if email:
            r = c.post("/api/login", json={"email": email})
            assert r.status_code == 200, r.text
        return c
    return cliente


def _id(accion, objetivo):
    return acciones.id_de(accion, objetivo)


# --------------------------------------------------------------------------------------------- login y sesión

def test_login_solo_para_personas_con_rol(web):
    c = web()
    assert c.post("/api/login", json={"email": "nadie@tarvia.example"}).status_code == 403
    assert c.post("/api/login", json={"email": "marta.puig@tarvia.example"}).status_code == 403  # sin rol
    r = c.post("/api/login", json={"email": " Neus.Benitez@tarvia.example "})
    assert r.status_code == 200 and r.json()["roles"] == ["N1"]
    assert c.get("/api/yo").json()["email"] == N1
    eventos = [json.loads(x)["evento"] for x in (almacen.SALIDAS / "accesos.jsonl").read_text().splitlines()]
    assert eventos == ["login_rechazado", "login_rechazado", "login"]


def test_sin_sesion_no_hay_datos(web):
    c = web()
    for ruta in ("/api/yo", "/api/acciones/pendientes", "/api/acciones", f"/api/acciones/{_id('block_ioc', 'evil.example')}"):
        assert c.get(ruta).status_code == 401, ruta
    assert c.post(f"/api/acciones/{_id('block_ioc', 'evil.example')}/aprobar", json={}).status_code == 401


def test_cookie_manipulada_no_vale(web):
    c = web()
    c.cookies.set("tarvia_soc", "eyJlbWFpbCI6ICJwYWJsby5jb2xsQHRhcnZpYS5leGFtcGxlIn0=.falsa.firma")
    assert c.get("/api/yo").status_code == 401


def test_el_rol_se_recalcula_en_cada_peticion(web, monkeypatch):
    c = web(N2)
    original = api.usuario
    # la persona causa baja en el directorio con la sesión abierta
    monkeypatch.setattr(api, "usuario", lambda k, trazar=True: None if k == N2 else original(k))
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
    director = web(DIRTEC)
    assert director.get(f"/api/acciones/{sid}").json()["puedo"] == ["aprobar", "rechazar"]
    r = director.post(f"/api/acciones/{sid}/aprobar", json={"comentario": "asumo la parada"})
    assert r.json()["estado"] == "ejecutada" and soc["contenciones"][0]["token"] == "APR-1"


def test_responsable_de_servicio_solo_ve_lo_suyo(web):
    c = web(DIRTEC)
    assert {s["target"] for s in c.get("/api/acciones").json()} == {"FS01"}
    assert c.get(f"/api/acciones/{_id('block_ioc', 'evil.example')}").status_code == 404   # ni sabe que existe
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
    assert set(c.get("/api/salud").json()) == {"web", "api_soc"}
