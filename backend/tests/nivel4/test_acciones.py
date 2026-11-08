"""[Nivel 4] Solicitudes de contención con aprobación humana por rol (agente/acciones.py, roles.py y
politica.requisitos).

Todo sintético: el directorio, la CMDB, el TIP y la API de contención se sustituyen por datos en memoria, así que
nada se ejecuta de verdad (la API real escribiría en containment_log.jsonl)."""
import pytest

from agente import acciones, almacen, politica, roles

from apoyo import DIRTEC, N1, N2, N2B, RSOC, soc  # noqa: F401  (soc es el fixture del entorno simulado)


def _sol(accion, objetivo):
    return acciones.obtener(acciones.id_de(accion, objetivo))


# --------------------------------------------------------------------------------------------- roles y política

def test_roles_del_directorio(soc):
    assert roles.identificar(N1)["roles"] == ["N1"]
    assert roles.identificar(RSOC)["roles"] == ["responsable_soc"]
    assert "responsable_servicio:Copias de seguridad" in roles.identificar(DIRTEC)["roles"]
    assert "dpo" in roles.identificar("elena.mora@tarvia.example")["roles"]
    assert roles.identificar("marta.puig@tarvia.example") is None      # empleada sin rol: sin acceso
    assert roles.identificar("nadie@tarvia.example") is None


@pytest.mark.parametrize("accion,objetivo,esperado", [
    ("isolate_host", "FS01", ["N2", "responsable_servicio"]),     # servidor: N2 + responsable del servicio
    ("isolate_host", "WS-BCN-1770", ["N2"]),                      # portátil: N2
    ("isolate_host", "SRV-HUERFANO", ["N2", "responsable_soc"]),  # servicio sin responsable: decide el Resp. SOC
    ("block_ioc", "evil.example", []),                            # IOC malicioso: lo ejecuta el N1
    ("block_ioc", "mega.nz", ["N2"]),                             # uso dual: N2
    ("disable_user", "svc_backup", ["N2"]),
    ("delete_inbox_rule", "x", ["N2"]),                           # fuera de la API: conservador
])
def test_requisitos_de_la_politica(soc, accion, objetivo, esperado):
    assert [r["rol"] for r in politica.requisitos(accion, objetivo)["aprobaciones"]] == esperado


# --------------------------------------------------------------------------------------------- sincronización

def test_sincronizar_solo_contencion_y_sin_duplicados(soc):
    todas = acciones.listar()
    assert {s["action"] for s in todas} == {"isolate_host", "block_ioc", "disable_user", "delete_inbox_rule"}
    assert len(todas) == 7
    assert {o["id"] for o in _sol("block_ioc", "evil.example")["origenes"]} == {"TKT-1", "INC-1"}
    assert _sol("isolate_host", "FS01")["target"] == "FS01"           # nombre exacto de la CMDB
    assert acciones.sincronizar() == 0                                 # idempotente


def test_ot_prohibida(soc):
    s = _sol("isolate_host", "PLC-SORT01")
    assert s["estado"] == acciones.PROHIBIDA and "OT" in s["resultado"]["motivo"]
    with pytest.raises(acciones.EstadoNoValido):
        acciones.aprobar(s["id"], N2)


def test_impacto_para_quien_aprueba(soc):
    assert "Copias de seguridad" in _sol("isolate_host", "FS01")["impacto"]
    assert "Cuenta de servicio" in _sol("disable_user", "svc_backup")["impacto"]
    assert "uso dual" in _sol("block_ioc", "mega.nz")["impacto"]


# --------------------------------------------------------------------------------------------- aprobar y ejecutar

def test_n1_ejecuta_un_bloqueo_sin_aprobacion(soc):
    s = acciones.aprobar(_sol("block_ioc", "evil.example")["id"], N1, "C2 del ransomware")
    assert s["estado"] == acciones.EJECUTADA
    assert soc["aprobaciones"] == [] and soc["contenciones"][0]["token"] == ""   # la API no pide token
    ticket = almacen.ticket("TKT-1")["ticket"]
    assert ticket["executed_actions"][0]["target"] == "evil.example"
    assert almacen.informe("INC-1")["acciones_ejecutadas"][0]["solicitud"] == s["id"]


def test_n1_no_puede_lo_que_pide_n2(soc):
    with pytest.raises(acciones.PermisoDenegado):
        acciones.aprobar(_sol("isolate_host", "WS-BCN-1770")["id"], N1)
    with pytest.raises(acciones.PermisoDenegado):
        acciones.aprobar(_sol("block_ioc", "mega.nz")["id"], N1)
    with pytest.raises(acciones.PermisoDenegado):
        acciones.aprobar(_sol("isolate_host", "WS-BCN-1770")["id"], "marta.puig@tarvia.example")


def test_aislar_un_servidor_cuatro_ojos(soc):
    sid = _sol("isolate_host", "FS01")["id"]
    s = acciones.aprobar(sid, N2, "ransomware en curso")
    assert s["estado"] == acciones.PENDIENTE and soc["contenciones"] == []        # falta el responsable
    with pytest.raises(acciones.PermisoDenegado):
        acciones.aprobar(sid, N2)                                                  # la misma persona no repite
    with pytest.raises(acciones.PermisoDenegado):
        acciones.aprobar(sid, N2B)                                                 # otro N2 no es el responsable
    s = acciones.aprobar(sid, DIRTEC, "asumo la parada de copias")
    assert s["estado"] == acciones.EJECUTADA
    firmantes = soc["aprobaciones"][0]["approver"]
    assert "Pablo Coll" in firmantes and "Alejandro Benítez" in firmantes
    assert soc["contenciones"][0] == {"action": "isolate_host", "target": "FS01", "token": "APR-1", "ticket": "TKT-1"}
    assert [h["evento"] for h in s["historial"]] == ["propuesta", "aprobación", "aprobación", "ejecutada"]


def test_no_repite_lo_ya_ejecutado(soc):
    soc["registro"].append({"action": "disable_user", "target": "svc_backup", "result": "ok (simulado)"})
    s = acciones.aprobar(_sol("disable_user", "svc_backup")["id"], N2)
    assert s["estado"] == acciones.EJECUTADA and s["resultado"]["ya_constaba"] and soc["contenciones"] == []


def test_fallo_de_la_api_y_reintento(soc):
    soc["error"] = "403: falta aprobación humana válida"
    sid = _sol("disable_user", "svc_backup")["id"]
    s = acciones.aprobar(sid, N2)
    assert s["estado"] == acciones.FALLIDA and "403" in s["resultado"]["error"]
    soc["error"] = None
    assert acciones.reintentar(sid, N1)["estado"] == acciones.EJECUTADA


def test_tarea_manual(soc):
    sid = _sol("delete_inbox_rule", "laura.ferrer2@tarvia.example")["id"]
    assert acciones.aprobar(sid, N2)["estado"] == acciones.APROBADA            # aprobada, falta hacerla
    assert soc["contenciones"] == []                                            # nunca va a la API
    s = acciones.marcar_hecha(sid, N1, "regla «.» borrada en Exchange")
    assert s["estado"] == acciones.HECHA


def test_rechazo(soc):
    sid = _sol("isolate_host", "WS-BCN-1770")["id"]
    with pytest.raises(acciones.PermisoDenegado):
        acciones.rechazar(sid, N1, "no")                                        # solo quien podría aprobarla
    assert acciones.rechazar(sid, N2, "falso positivo confirmado")["estado"] == acciones.RECHAZADA
    with pytest.raises(acciones.EstadoNoValido):
        acciones.aprobar(sid, N2B)


def test_bandeja_por_rol(soc):
    def ids(email):
        return {(s["action"], s["target"]) for s in acciones.pendientes_de(roles.identificar(email))}
    assert ("isolate_host", "FS01") in ids(N2) and ("block_ioc", "evil.example") in ids(N1)
    assert ("isolate_host", "FS01") not in ids(N1)
    assert ids(DIRTEC) == {("isolate_host", "FS01")}                             # solo lo de sus servicios
    assert ids("elena.mora@tarvia.example") == set()                            # la DPO no aprueba contención
