"""Pruebas del nivel 2: criticidad real (C), descarte con argumentos (B) y cruce con el calendario de cambios (A).
Sin LLM: el modelo se sustituye por un stub cuando hace falta."""
import pytest

from agente import cambios as C
from agente import herramientas as h
from agente import politica, severidad
from agente import reglas_internas as R
from conftest import requiere_api

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


# ============================================================================================ B: con argumentos

def ticket(verdict="benign_true_positive", summary="Actividad legítima."):
    return {"verdict": verdict, "severity": "informational", "summary": summary, "severity_rationale": "",
            "title": "t", "evidence": [], "enrichment": [], "recommended_actions": [], "open_questions": [],
            "escalation": {"escalate": False, "to": "", "reason": ""}}


PENTEST = {"id": "CHG-2026-1042", "titulo": "Pentest", "inicio": "2026-10-08 08:00", "fin": "2026-10-10 18:00",
           "detalle": "IPs origen 192.0.2.10-12; alcance www.tarvia.example", "alcance": "WEB-ECOM01..04"}


@pytest.fixture
def calendario(monkeypatch):
    monkeypatch.setattr(C, "_CACHE", [C.interpretar(PENTEST)])


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


# ============================================================================================ A: calendario de cambios

def test_interpretacion_de_rangos_y_franjas():
    c = C.interpretar(PENTEST)
    assert c["origen_ips"] == {"192.0.2.10", "192.0.2.11", "192.0.2.12"}
    assert c["alcance_hosts"] == {"WEB-ECOM01", "WEB-ECOM02", "WEB-ECOM03", "WEB-ECOM04"}
    assert "www.tarvia.example" in c["alcance_dominios"]
    sccm = C.interpretar({"id": "CHG-X", "titulo": "Inventario SCCM", "inicio": "2026-09-28 00:00",
                          "fin": "2026-12-31 23:59", "detalle": "svc_sccm ejecuta diariamente 08:00-10:00",
                          "alcance": "Todos los puestos"})
    assert sccm["franja"] == (8, 0, 10, 0) and sccm["origen_cuentas"] == {"svc_sccm"}
    assert sccm["alcance_categoria"] == "todos los puestos"
    otra = C.interpretar({"id": "CHG-Y", "titulo": "t", "inicio": "2026-10-17 08:00", "fin": "2026-10-17 14:00",
                          "detalle": "Acceso vía JUMP01; regla temporal OT-MAINT-TEMP", "alcance": "PLC-SORT01..06"})
    assert otra["origen_hosts"] == {"JUMP01"} and len(otra["alcance_hosts"]) == 6  # OT-MAINT-TEMP no es un equipo


def test_franja_diaria():
    c = C.interpretar({"id": "CHG-X", "titulo": "t", "inicio": "2026-09-28 00:00", "fin": "2026-12-31 23:59",
                       "detalle": "diariamente 08:00-10:00", "alcance": ""})
    assert C.vigente(c, "2026-10-05T07:30:00Z")        # 09:30 en Madrid
    assert not C.vigente(c, "2026-10-05T10:30:00Z")    # 12:30 en Madrid


def _waf(ip, fecha="2026-10-09T10:00:00Z"):
    return {"alert_id": "ALR-T", "created_at": fecha, "rule_id": "UC-WEB-001", "source_product": "WAF",
            "entities": {"ips": [ip], "urls": ["https://www.tarvia.example/api?id=1"]}, "evidence": {"action": "blocked"}}


def test_pentest_desde_ip_autorizada_permitida(calendario):
    r = C.evaluar(_waf("192.0.2.11"))
    assert [(x["sujeto"], x["estado"]) for x in r] == [("CHG-2026-1042", R.PERMITIDA)]


def test_ataque_real_durante_el_pentest_informativa(calendario):
    r = C.evaluar(_waf("198.18.58.15"))
    assert [(x["sujeto"], x["estado"]) for x in r] == [("CHG-2026-1042", R.INFORMATIVA)]
    assert "no la cubre" in r[0]["motivo"]


def test_pentest_fuera_de_ventana_no_aplica(calendario):
    assert C.evaluar(_waf("192.0.2.11", "2026-10-12T10:00:00Z")) == []


def test_cita_cambio_inexistente_sospechosa(calendario):
    a = {**_waf("10.0.0.1"), "evidence": {"maintenance_window": "CHG-2026-9999"}}
    r = {x["sujeto"]: x["estado"] for x in C.evaluar(a)}
    assert r["CHG-2026-9999"] == R.SOSPECHOSA
    assert r["CHG-2026-1042"] == R.INFORMATIVA  # además, el pentest está en curso pero no la cubre


@requiere_api
@pytest.mark.parametrize("alert_id, cambio, estado", [
    ("ALR-20261008-011833", "CHG-2026-1042", R.PERMITIDA),      # pentest desde 192.0.2.11
    ("ALR-20261009-001854", "CHG-2026-1042", R.INFORMATIVA),    # escáner real durante el pentest
    ("ALR-20261024-011918", "CHG-2026-1080", R.PERMITIDA),      # parada del EDR en FS01 (Windows Server)
    ("ALR-20261024-011920", "CHG-2026-1080", R.REQUIERE_INFO),  # ERP-APP01 es SUSE Linux: fuera de alcance
    ("ALR-20261017-011876", "CHG-2026-1063", R.PERMITIDA),      # OT desde JUMP01 (PLC nombrados por IP)
    ("ALR-20261023-011915", "CHG-2026-1078", R.PERMITIDA),      # JUMP01 es origen, el alcance es el directorio
    ("ALR-20261005-000301", "CHG-2026-1031", R.INFORMATIVA),    # SCCM: relacionado, pero origen SYSTEM ≠ svc_sccm
])
def test_cambios_casos_reales(monkeypatch, alerta_real, alert_id, cambio, estado):
    monkeypatch.setattr(C, "_CACHE", None)
    r = [x for x in C.evaluar(alerta_real(alert_id)) if x["sujeto"] == cambio]
    assert r and r[0]["estado"] == estado, r


@requiere_api
def test_alerta_sin_cambio_no_tiene_hallazgos(monkeypatch, alerta_real):
    monkeypatch.setattr(C, "_CACHE", None)
    assert C.evaluar(alerta_real("ALR-20261018-011896")) == []   # parada del EDR en PRINT01 sin ventana


@requiere_api
def test_pentest_es_un_unico_incidente(monkeypatch):
    from agente import incidentes
    monkeypatch.setattr(incidentes, "_INCIDENTES", None)
    monkeypatch.setattr(C, "_CACHE", None)
    grupo = incidentes.incidente_de("ALR-20261008-011831")
    todas = incidentes.todas_las_alertas()
    ips = {ip for i in grupo for ip in todas[i]["entities"].get("ips", [])}
    assert len(grupo) == 15 and ips == {"192.0.2.10", "192.0.2.11", "192.0.2.12"}


# ============================================================================================ integración (sin LLM)

@requiere_api
def test_triaje_completo_del_pentest_sin_llm(monkeypatch, tmp_path, alerta_real):
    """El modelo (simulado) da benigno sin citar el cambio: lo acepta la comprobación permitida del calendario;
    la criticidad sale de la CMDB (tienda online, Crítica) y la alerta no hereda plantilla."""
    from agente import triaje
    monkeypatch.setattr(triaje, "SALIDAS", tmp_path)
    monkeypatch.setattr(C, "_CACHE", None)
    salida = {"alert_ids": ["ALR-20261008-011833"], "title": "Pentest", "verdict": "benign_true_positive",
              "confidence": 0.9, "activo_mas_critico": "www.tarvia.example", "criticidad": "Baja", "ajuste": "-1",
              "motivo_ajuste": "bloqueado por el WAF",
              "affected": {"users": [], "hosts": ["WEB-ECOM01"], "business_services": [], "customers": []},
              "summary": "Pruebas de la auditora.", "evidence": [], "enrichment": [], "mitre": ["T1190"],
              "recommended_actions": [{"action": "close", "target": "ALR-20261008-011833", "requires_approval": False,
                                       "justification": "autorizado"}],
              "escalation": {"escalate": False, "to": "", "reason": ""}, "open_questions": [],
              "patron_generalizable": False}
    monkeypatch.setattr(triaje, "motor", lambda: type("M", (), {"ejecutar": staticmethod(
        lambda *a: {"ticket": salida, "motivo": "", "uso": {}, "razonamiento": [], "modelo": "stub"})}))
    res = triaje.triar(alerta_real("ALR-20261008-011833"))
    t = res["ticket"]
    assert t["verdict"] == "benign_true_positive" and res["heredado_de"] is None
    assert any(c["tipo"] == "cambio" and c["estado"] == R.PERMITIDA for c in t["comprobaciones_internas"])
    assert res["entrada_severidad"]["criticidad"] == "Crítica"
    assert any("Crítica" in a for a in t["ajustes_politica"])
