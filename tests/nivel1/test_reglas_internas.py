"""[Nivel 1] Reglas internas de Tarvia (agente/reglas_internas.py).

- Casos reales: alertas del dataset contra la API simulada (se saltan si la API no está levantada).
- Casos sintéticos: datos falsos inyectados en la capa de acceso a datos, para situaciones que no aparecen en el
  dataset (dominio parecido al de la gestoría, Logisoft hacia otro destino, NESSUS hacia OT, TeamViewer...).
"""
import pytest

from agente import cambios
from agente import herramientas as h
from agente import reglas_internas as R
from apoyo import alerta, requiere_api

P, S, I = R.PERMITIDA, R.SOSPECHOSA, R.REQUIERE_INFO


# ------------------------------------------------------------------------------------------- casos reales del dataset

@requiere_api
@pytest.mark.parametrize("alert_id, regla, estado", [
    # 1. adm.* solo desde JUMP01
    ("ALR-20261010-011797", "Cuentas adm.*", S),   # PsExec con adm.aortega desde WS-BCN-1770 (ransomware)
    ("ALR-20261018-011895", "Cuentas adm.*", S),   # adm.aortega crea cuenta y la mete en Domain Admins desde PRINT01
    ("ALR-20261013-011869", "Cuentas adm.*", P),   # adm.dnavarro desde JUMP01 dentro de CHG-2026-1057
    ("ALR-20261023-011915", "Cuentas adm.*", P),   # adm.aferrer desde JUMP01
    # 2. AnyDesk
    ("ALR-20261012-011829", "Herramienta de acceso remoto", S),
    # 3. OT
    ("ALR-20261009-002231", "Acceso a OT", P),     # ENG-WS01 (regla del SIEM mal afinada)
    ("ALR-20261017-011876", "Acceso a OT", P),     # JUMP01 dentro de CHG-2026-1063
    # 4. NESSUS01
    ("ALR-20261007-011850", "Escaneo de NESSUS01", P),
    ("ALR-20261028-011864", "Escaneo de NESSUS01", P),   # después del cambio de hora (UTC+1)
    # 5. Nóminas a la gestoría
    ("ALR-20261007-011874", "Envío de nóminas", P),      # marc.reyes, Personas
    # 6. ext.logisoft
    ("ALR-20261011-011877", "Acceso de ext.logisoft", S),  # domingo 03:38 desde 77.90.185.20
    ("ALR-20261016-011922", "Acceso de ext.logisoft", P),  # viernes 22:10 cubierto por CHG-2026-1071
    ("ALR-20261009-002236", "Acceso de ext.logisoft", S),  # viernes 18:06, fuera de la ventana contractual
    # 7. svc_backup
    ("ALR-20261013-011816", "svc_backup", S),             # VPN desde Tor + reconocimiento en BACKUP01
])
def test_casos_reales(alerta_real, alert_id, regla, estado):
    resultados = R.evaluar(alerta_real(alert_id))
    de_la_regla = [r for r in resultados if r["regla"].startswith(regla)]
    assert de_la_regla, f"la regla {regla} debería aplicar a {alert_id}"
    assert de_la_regla[0]["estado"] == estado, de_la_regla[0]
    assert de_la_regla[0]["evidencias"], "cada hallazgo debe citar evidencias"


@requiere_api
@pytest.mark.parametrize("alert_id", ["ALR-20261005-000301", "ALR-20261009-001854", "ALR-20261015-011818"])
def test_reglas_que_no_aplican(alerta_real, alert_id):
    """SCCM, WAF y una fuga a correo personal no tocan ninguna regla interna (la fuga no es el flujo de nóminas)."""
    assert R.evaluar(alerta_real(alert_id)) == []


@requiere_api
def test_consultas_quedan_en_la_traza(alerta_real):
    h.TRAZA.clear()
    R.evaluar(alerta_real("ALR-20261013-011816"))
    assert h.TRAZA and all(t["origen"] == "reglas" for t in h.TRAZA)
    assert h.ORIGEN == "agente"


# ------------------------------------------------------------------------------------------- datos sintéticos

@pytest.fixture
def datos(monkeypatch):
    """Sustituye la capa de acceso a datos de reglas_internas por un pequeño dataset en memoria."""
    d = {"logs": {}, "activos": {}, "usuarios": {}, "intel": {}, "cambios": []}

    def logs(fuente, q, desde="", hasta="", limit=500):
        out = []
        for e in d["logs"].get(fuente, []):
            t = e.get("timestamp", "")
            if (desde and t < desde) or (hasta and t > hasta) or not h._coincide(q, e):
                continue
            out.append(e)
        return out[:limit]

    monkeypatch.setattr(R, "_logs", logs)
    monkeypatch.setattr(R, "_activo", lambda k: d["activos"].get(k.upper()))
    monkeypatch.setattr(R, "_usuario", lambda k: d["usuarios"].get(k))
    monkeypatch.setattr(R, "_intel", lambda k: d["intel"].get(k, {}))
    monkeypatch.setattr(cambios, "calendario", lambda: [cambios.interpretar(c) for c in d["cambios"]])
    return d


def estado(resultados, prefijo):
    r = [x for x in resultados if x["regla"].startswith(prefijo)]
    assert len(r) == 1, resultados
    return r[0]


# 1. adm.* ----------------------------------------------------------------------------------------------------------

def test_adm_desde_jump01_permitida(datos):
    datos["logs"]["idp_signins"] = [{"event_id": "S1", "timestamp": "2026-10-14T09:00:00Z",
                                     "user_upn": "adm.prueba@tarvia.example", "device_id": "JUMP01", "src_ip": "10.20.6.61"}]
    r = estado(R.regla_cuentas_adm([alerta(entities={"users": [{"upn": "adm.prueba@tarvia.example"}]})]), "Cuentas")
    assert r["estado"] == P and "S1" in r["evidencias"]


def test_adm_desde_puesto_sospechosa(datos):
    datos["logs"]["idp_signins"] = [{"event_id": "S2", "timestamp": "2026-10-14T09:00:00Z",
                                     "user_upn": "adm.prueba@tarvia.example", "device_id": "WS-BCN-1001", "src_ip": "10.10.1.12"}]
    r = estado(R.regla_cuentas_adm([alerta(entities={"users": [{"upn": "adm.prueba@tarvia.example"}]})]), "Cuentas")
    assert r["estado"] == S and "WS-BCN-1001" in r["motivo"]


def test_adm_en_servidor_sin_origen_requiere_info(datos):
    """Un evento del EDR en un servidor no dice desde dónde se abrió la sesión: sin firewall ni cambio, falta info."""
    datos["logs"]["edr_events"] = [{"event_id": "E1", "timestamp": "2026-10-14T09:00:00Z", "hostname": "FS01",
                                    "user": "TARVIA\\adm.prueba"}]
    datos["activos"]["FS01"] = {"hostname": "FS01", "ip": "10.20.2.20"}
    r = estado(R.regla_cuentas_adm([alerta(entities={"users": [{"upn": "adm.prueba@tarvia.example"}]})]), "Cuentas")
    assert r["estado"] == I and r["dato_faltante"]


def test_adm_en_servidor_con_conexion_desde_jump01_permitida(datos):
    datos["logs"]["edr_events"] = [{"event_id": "E1", "timestamp": "2026-10-14T09:00:00Z", "hostname": "FS01",
                                    "user": "TARVIA\\adm.prueba"}]
    datos["logs"]["firewall"] = [{"event_id": "F1", "timestamp": "2026-10-14T08:58:00Z", "src_ip": "10.20.6.61",
                                  "dst_ip": "10.20.2.20", "dst_port": "445"}]
    datos["activos"]["FS01"] = {"hostname": "FS01", "ip": "10.20.2.20"}
    r = estado(R.regla_cuentas_adm([alerta(entities={"users": [{"upn": "adm.prueba@tarvia.example"}]})]), "Cuentas")
    assert r["estado"] == P


# 2. Herramienta de acceso remoto -------------------------------------------------------------------------------------

def test_anydesk_sospechosa(datos):
    datos["logs"]["edr_events"] = [{"event_id": "E1", "timestamp": "2026-10-14T09:00:00Z", "hostname": "WS-T1",
                                    "process_name": "AnyDesk.exe", "process_path": "C:\\Users\\x\\AnyDesk.exe"}]
    r = estado(R.regla_acceso_remoto([alerta("UC-EDR-005", entities={"hosts": [{"hostname": "WS-T1"}]})]), "Herramienta")
    assert r["estado"] == S and "E1" in r["evidencias"]


def test_teamviewer_requiere_info(datos):
    datos["logs"]["edr_events"] = [{"event_id": "E2", "timestamp": "2026-10-14T09:00:00Z", "hostname": "WS-T1",
                                    "process_name": "TeamViewer.exe", "process_path": "C:\\Program Files\\TeamViewer"}]
    r = estado(R.regla_acceso_remoto([alerta("UC-EDR-005", entities={"hosts": [{"hostname": "WS-T1"}]})]), "Herramienta")
    assert r["estado"] == I and "TeamViewer" in r["dato_faltante"]


def test_alerta_rmm_sin_herramienta_identificada_requiere_info(datos):
    r = estado(R.regla_acceso_remoto([alerta("UC-EDR-005", entities={"hosts": [{"hostname": "WS-T1"}]})]), "Herramienta")
    assert r["estado"] == I


# 3. OT ---------------------------------------------------------------------------------------------------------------

def test_ot_desde_eng_ws01_permitida(datos):
    a = alerta("UC-OT-001", entities={"hosts": [{"hostname": "ENG-WS01", "ip": "10.40.2.20"}]},
               evidence={"src": "ENG-WS01", "dst_zone": "LOGISTICS-OT"})
    assert estado(R.regla_acceso_ot([a]), "Acceso a OT")["estado"] == P


def test_ot_desde_otro_equipo_sin_cambio_sospechosa(datos):
    a = alerta("UC-OT-001", entities={"hosts": [{"hostname": "WS-BCN-1001", "ip": "10.10.1.12"}]},
               evidence={"src": "WS-BCN-1001", "dst_zone": "LOGISTICS-OT"})
    assert estado(R.regla_acceso_ot([a]), "Acceso a OT")["estado"] == S


def test_ot_desde_jump01_con_cambio_permitida(datos):
    datos["cambios"] = [{"id": "CHG-T", "titulo": "Mantenimiento PLC", "inicio": "2026-10-14 08:00",
                         "fin": "2026-10-14 14:00", "detalle": "Acceso vía JUMP01", "alcance": "PLC-SORT01..06"}]
    a = alerta("UC-OT-001", created_at="2026-10-14T08:00:00Z",  # 10:00 hora local
               entities={"hosts": [{"hostname": "JUMP01", "ip": "10.20.6.61"}]}, evidence={"src": "JUMP01"})
    r = estado(R.regla_acceso_ot([a]), "Acceso a OT")
    assert r["estado"] == P and "CHG-T" in r["evidencias"]


def test_ot_cambio_fuera_de_ventana_no_cubre(datos):
    datos["cambios"] = [{"id": "CHG-T", "titulo": "Mantenimiento PLC", "inicio": "2026-10-14 08:00",
                         "fin": "2026-10-14 14:00", "detalle": "Acceso vía JUMP01", "alcance": "PLC-SORT01..06"}]
    a = alerta("UC-OT-001", created_at="2026-10-14T18:00:00Z",
               entities={"hosts": [{"hostname": "JUMP01", "ip": "10.20.6.61"}]}, evidence={"src": "JUMP01"})
    assert estado(R.regla_acceso_ot([a]), "Acceso a OT")["estado"] == S


# 4. NESSUS01 ---------------------------------------------------------------------------------------------------------

def _nessus(created_at):
    return alerta("UC-NET-003", created_at=created_at, entities={"hosts": [{"hostname": "NESSUS01", "ip": "10.20.6.62"}]})


def test_nessus_en_ventana_permitida(datos):
    # martes 23:30 UTC = miércoles 01:30 en Madrid (UTC+2)
    assert estado(R.regla_escaner_nessus([_nessus("2026-10-13T23:30:00Z")]), "Escaneo")["estado"] == P


def test_nessus_fuera_de_ventana_sospechosa(datos):
    assert estado(R.regla_escaner_nessus([_nessus("2026-10-13T13:00:00Z")]), "Escaneo")["estado"] == S


def test_nessus_respeta_cambio_de_hora(datos):
    """28/10 03:30 UTC = 04:30 en Madrid (UTC+1, ya en horario de invierno): dentro de la ventana.
    Con un desfase fijo de +2 h serían las 05:30 y se marcaría por error como fuera de ventana."""
    assert estado(R.regla_escaner_nessus([_nessus("2026-10-28T03:30:00Z")]), "Escaneo")["estado"] == P


def test_nessus_hacia_ot_sospechosa(datos):
    datos["logs"]["firewall"] = [{"event_id": "F9", "timestamp": "2026-10-13T23:31:00Z", "src_ip": "10.20.6.62",
                                  "dst_ip": "10.40.16.21", "dst_port": "502"}]
    r = estado(R.regla_escaner_nessus([_nessus("2026-10-13T23:30:00Z")]), "Escaneo")
    assert r["estado"] == S and "F9" in r["evidencias"]


# 5. Nóminas ----------------------------------------------------------------------------------------------------------

FLUJO = {"id": "FLUJO-0007", "titulo": "Envío mensual de variables de nómina a gestoría", "inicio": "2026-01-01 00:00",
         "fin": "2026-12-31 23:59", "solicitante": "Personas", "detalle": "Destino asesoria@gestoria-pons.example",
         "alcance": "Correo"}


def _envio(remitente, destino="asesoria@gestoria-pons.example", fecha="2026-10-14T09:00:00Z"):
    return alerta("UC-DLP-002", created_at=fecha, entities={"users": [{"upn": remitente}]},
                  evidence={"recipient": destino, "matches": {"iban": 10}})


def test_nominas_desde_personas_permitida(datos):
    datos["cambios"] = [FLUJO]
    datos["usuarios"]["p@tarvia.example"] = {"department": "Personas", "title": "Técnica de Nóminas"}
    r = estado(R.regla_nominas_gestoria([_envio("p@tarvia.example")]), "Envío de nóminas")
    assert r["estado"] == P and "FLUJO-0007" in r["evidencias"]


def test_nominas_desde_otro_departamento_requiere_info(datos):
    datos["cambios"] = [FLUJO]
    datos["usuarios"]["m@tarvia.example"] = {"department": "Marketing", "title": "Analista"}
    assert estado(R.regla_nominas_gestoria([_envio("m@tarvia.example")]), "Envío de nóminas")["estado"] == I


def test_nominas_a_dominio_parecido_sospechosa(datos):
    datos["cambios"] = [FLUJO]
    datos["usuarios"]["p@tarvia.example"] = {"department": "Personas"}
    r = estado(R.regla_nominas_gestoria([_envio("p@tarvia.example", "asesoria@gestoria-ponss.example")]), "Envío")
    assert r["estado"] == S and "suplantación" in r["motivo"]


def test_nominas_sin_flujo_vigente_requiere_info(datos):
    datos["cambios"] = [FLUJO]
    datos["usuarios"]["p@tarvia.example"] = {"department": "Personas"}
    r = estado(R.regla_nominas_gestoria([_envio("p@tarvia.example", fecha="2027-02-01T09:00:00Z")]), "Envío")
    assert r["estado"] == I


def test_nominas_otro_destino_no_aplica(datos):
    assert R.regla_nominas_gestoria([_envio("p@tarvia.example", "proveedor@textiles-montroig.example")]) == []


# 6. ext.logisoft -----------------------------------------------------------------------------------------------------

HABITUAL = "198.18.240.10"


def _vpn(eid, ts, ip, asignada="10.99.60.50", pais="ES"):
    return {"event_id": eid, "timestamp": ts, "user": "ext.logisoft", "src_ip": ip, "assigned_ip": asignada,
            "country": pais}


@pytest.fixture
def historico_logisoft(datos):
    # tres conexiones en horario desde la IP habitual (martes 14/10, 10:00-12:00 locales)
    datos["logs"]["vpn"] = [_vpn(f"H{i}", f"2026-10-14T{8 + i:02d}:00:00Z", HABITUAL) for i in range(3)]
    datos["logs"]["firewall"] = []
    return datos


def _alerta_logisoft(fecha):
    return alerta("UC-VPN-001", created_at=fecha, entities={"users": [{"upn": "ext.logisoft@tarvia.example"}]})


def test_logisoft_en_horario_desde_origen_habitual_permitida(historico_logisoft):
    assert estado(R.regla_logisoft([_alerta_logisoft("2026-10-14T09:00:00Z")]), "Acceso de ext.logisoft")["estado"] == P


def test_logisoft_fuera_de_horario_y_origen_nuevo_sospechosa(historico_logisoft):
    historico_logisoft["logs"]["vpn"].append(_vpn("N1", "2026-10-18T01:00:00Z", "77.90.185.20", pais="LT"))
    r = estado(R.regla_logisoft([_alerta_logisoft("2026-10-18T01:05:00Z")]), "Acceso de ext.logisoft")
    assert r["estado"] == S and "N1" in r["evidencias"]


def test_logisoft_destino_distinto_de_wms01_sospechosa(historico_logisoft):
    historico_logisoft["logs"]["firewall"] = [{"event_id": "F1", "timestamp": "2026-10-14T09:10:00Z",
                                               "src_ip": "10.99.60.50", "dst_ip": "10.20.3.30", "dst_port": "1433"}]
    r = estado(R.regla_logisoft([_alerta_logisoft("2026-10-14T09:00:00Z")]), "Acceso de ext.logisoft")
    assert r["estado"] == S and "WMS01" in r["motivo"]


def test_logisoft_en_horario_desde_origen_nuevo_requiere_info(historico_logisoft):
    historico_logisoft["logs"]["vpn"].append(_vpn("N2", "2026-10-15T09:00:00Z", "203.0.113.50"))
    r = estado(R.regla_logisoft([_alerta_logisoft("2026-10-15T09:00:00Z")]), "Acceso de ext.logisoft")
    assert r["estado"] == I and r["dato_faltante"]


def test_logisoft_fuera_de_horario_con_cambio_permitida(historico_logisoft):
    historico_logisoft["cambios"] = [{"id": "CHG-L", "titulo": "Actualización del WMS", "inicio": "2026-10-16 21:00",
                                      "fin": "2026-10-16 23:59", "detalle": "Acceso VPN de ext.logisoft",
                                      "alcance": "WMS01"}]
    historico_logisoft["logs"]["vpn"].append(_vpn("C1", "2026-10-16T20:10:00Z", HABITUAL))  # 22:10 local
    r = estado(R.regla_logisoft([_alerta_logisoft("2026-10-16T20:15:00Z")]), "Acceso de ext.logisoft")
    assert r["estado"] == P and "CHG-L" in r["evidencias"]


# 7. svc_backup -------------------------------------------------------------------------------------------------------

def _alerta_backup():
    return alerta("UC-IDP-004", created_at="2026-10-14T01:00:00Z", entities={"users": [{"upn": "svc_backup@tarvia.example"}]})


def test_svc_backup_desde_tor_sospechosa(datos):
    datos["logs"]["vpn"] = [{"event_id": "V1", "timestamp": "2026-10-14T00:55:00Z", "user": "svc_backup",
                             "src_ip": "87.118.116.103", "mfa_result": "not_required (excluida)"}]
    datos["intel"]["87.118.116.103"] = {"tip": {"reputation": "suspicious", "tags": "tor"}, "geo": {"is_tor": "True"}}
    r = estado(R.regla_svc_backup([_alerta_backup()]), "svc_backup")
    assert r["estado"] == S and "V1" in r["evidencias"]


def test_svc_backup_sin_mfa_desde_origen_desconocido_requiere_info(datos):
    """La falta de MFA es un riesgo aceptado: no basta para marcarla sospechosa, pero el origen no está documentado."""
    datos["logs"]["vpn"] = [{"event_id": "V2", "timestamp": "2026-10-14T00:55:00Z", "user": "svc_backup",
                             "src_ip": "203.0.113.80", "mfa_result": "not_required (excluida)"}]
    datos["intel"]["203.0.113.80"] = {"tip": None, "geo": {"as_org": "Proveedor X", "is_tor": "False"}}
    r = estado(R.regla_svc_backup([_alerta_backup()]), "svc_backup")
    assert r["estado"] == I and "proveedor" in r["dato_faltante"] and "riesgo aceptado" in r["motivo"]


def test_svc_backup_reconocimiento_sospechosa(datos):
    datos["logs"]["edr_events"] = [{"event_id": "E5", "timestamp": "2026-10-14T01:00:00Z", "hostname": "BACKUP01",
                                    "user": "TARVIA\\svc_backup", "process_name": "nltest.exe",
                                    "command_line": "nltest /domain_trusts"}]
    assert estado(R.regla_svc_backup([_alerta_backup()]), "svc_backup")["estado"] == S


def test_svc_backup_uso_normal_permitida(datos):
    assert estado(R.regla_svc_backup([_alerta_backup()]), "svc_backup")["estado"] == P
