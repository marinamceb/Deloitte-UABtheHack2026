"""[Nivel 2] Matriz de severidad con la criticidad real (agente/severidad.py): CMDB, servicios de negocio,
identidades como Media y ajustes -1/+1 verificados."""
import pytest

from agente import herramientas as h
from agente import severidad


# ============================================================================================ C: criticidad y ajuste

INVENTARIO = {
    "/assets/DC01": {"hostname": "DC01", "criticality": "Crítica", "business_service": "Identidad y directorio activo"},
    "/assets/LT-T07-02": {"hostname": "LT-T07-02", "criticality": "Media", "business_service": "Puesto de trabajo"},
    "/assets/WEB-ECOM01": {"hostname": "WEB-ECOM01", "criticality": "Crítica",
                           "business_service": "Tienda online y app (≈38% de la facturación)"},
    "/users/adm.x@tarvia.example": {"username": "adm.x", "privileged": "True", "vip": "False"},
    "/users/ana@tarvia.example": {"username": "ana", "privileged": "False", "vip": "False"},
    "/users/ceo@tarvia.example": {"username": "ceo", "privileged": "False", "vip": "True"},
}


@pytest.fixture
def inventario(monkeypatch):
    monkeypatch.setattr(h, "consultar_api", lambda nombre, ruta, params=None: (INVENTARIO.get(ruta), None))


def salida_modelo(**kw):
    base = {"verdict": "true_positive", "activo_mas_critico": "?", "criticidad": "Media", "ajuste": "0",
            "motivo_ajuste": "", "affected": {"users": [], "hosts": [], "business_services": [], "customers": []}}
    return {**base, **kw}


def test_criticidad_se_corrige_con_la_cmdb(inventario):
    t, notas = severidad.revisar(salida_modelo(criticidad="Baja", activo_mas_critico="DC01",
                                               affected={"users": [], "hosts": ["DC01"], "business_services": [],
                                                         "customers": []}), [])
    assert t["criticidad"] == "Crítica" and any("Baja" in n and "Crítica" in n for n in notas)


def test_criticidad_toma_el_activo_mas_critico_de_las_alertas(inventario):
    alertas = [{"entities": {"hosts": [{"hostname": "LT-T07-02"}, {"hostname": "DC01"}]}, "evidence": {}}]
    t, _ = severidad.revisar(salida_modelo(), alertas)
    assert (t["criticidad"], t["activo_mas_critico"]) in {("Crítica", "DC01"), ("Crítica", "Identidad y directorio activo")}


def test_bucket_usa_servicios_negocio(inventario):
    alertas = [{"entities": {"cloud": {"bucket": "tarvia-backups-prod"}}, "evidence": {}}]
    t, _ = severidad.revisar(salida_modelo(criticidad="Baja"), alertas)
    assert t["criticidad"] == "Alta" and "Copias de seguridad" in t["activo_mas_critico"]


def test_identidad_privilegiada_no_se_cuenta_dos_veces(inventario):
    """Antes: identidad privilegiada = Alta y además +1 por privilegiada. Ahora: Media y +1."""
    t, notas = severidad.revisar(salida_modelo(criticidad="Alta", activo_mas_critico="adm.x@tarvia.example",
                                               affected={"users": ["adm.x@tarvia.example"], "hosts": [],
                                                         "business_services": [], "customers": []}), [])
    assert t["criticidad"] == "Media" and t["ajuste"] == "+1"


def test_vip_suma_un_nivel(inventario):
    t, _ = severidad.revisar(salida_modelo(affected={"users": ["ceo@tarvia.example"], "hosts": [],
                                                     "business_services": [], "customers": []}), [])
    assert t["ajuste"] == "+1" and "VIP" in t["motivo_ajuste"]


def test_menos_uno_requiere_bloqueo_real(inventario):
    no_bloqueada = [{"entities": {}, "evidence": {"action": "allow"}}]
    t, notas = severidad.revisar(salida_modelo(ajuste="-1", motivo_ajuste="bloqueado"), no_bloqueada)
    assert t["ajuste"] == "0" and any("-1 descartado" in n for n in notas)
    bloqueada = [{"entities": {}, "evidence": {"action": "blocked"}}]
    t, _ = severidad.revisar(salida_modelo(ajuste="-1", motivo_ajuste="bloqueado"), bloqueada)
    assert t["ajuste"] == "-1"


def test_ajustes_se_compensan(inventario):
    bloqueada = [{"entities": {}, "evidence": {"edr_action": "quarantined"}}]
    t, notas = severidad.revisar(salida_modelo(ajuste="-1", motivo_ajuste="cuarentena",
                                               affected={"users": ["adm.x@tarvia.example"], "hosts": [],
                                                         "business_services": [], "customers": []}), bloqueada)
    assert t["ajuste"] == "0" and any("compensan" in n for n in notas)


def test_sin_inventario_se_conserva_la_propuesta(inventario):
    t, notas = severidad.revisar(salida_modelo(criticidad="Alta", activo_mas_critico="algo-externo"), [])
    assert t["criticidad"] == "Alta" and any("Sin datos de inventario" in n for n in notas)
