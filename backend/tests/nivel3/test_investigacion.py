"""[Nivel 3] Reconstrucción de la cadena de ataque (agente/investigacion.py).

Sintéticos: normalización de entidades, niveles de relevancia y candidatos a acceso inicial.
Reales (índice + API): las cadenas verificadas a mano en los logs."""
import pytest

from apoyo import requiere_api
from agente import indice, investigacion as I

requiere_indice = pytest.mark.skipif(not indice.disponible(), reason="sin índice: python agent.py --construir-indice")


# --------------------------------------------------------------------------------------------- entidades

@pytest.mark.parametrize("tipo,valor,esperado", [
    ("user", "TARVIA\\adm.aortega", "user:adm.aortega"),
    ("user", "Marta.Puig@tarvia.example", "user:marta.puig"),
    ("user", "pedidos@pedidos-hilaturas-alcoi.example", "dom:pedidos-hilaturas-alcoi.example"),  # remitente externo
    ("ip", "2.57.121.25", "ip:2.57.121.25"),
    ("ip", "10.250.250.250", None),                      # interna y fuera de la CMDB: no aporta
    ("url", "POST https://npm-telemetry-stats.example/collect (2,1 KB)", "dom:npm-telemetry-stats.example"),
    ("hash", "abc", None),
    ("host", "ws-bcn-1770", "host:WS-BCN-1770"),
])
def test_normalizar(tipo, valor, esperado):
    assert I.normalizar(tipo, valor) == esperado


@requiere_api
def test_ip_interna_pasa_a_su_equipo():
    assert I.normalizar("ip", "172.16.10.21") == "host:CI-RUNNER01"    # IP → equipo, preguntando a la CMDB (API)


def test_entidades_de_evento_anidadas_y_paquetes():
    e = {"_fuente": "cicd_builds", "runner": "CI-RUNNER01",
         "details": {"new_packages": [{"name": "Tarvia-Checkout-Utils", "sha256": "f" * 64}],
                     "network": "POST https://npm-telemetry-stats.example/collect"}}
    assert I.entidades_de_evento(e) == {"host:CI-RUNNER01", "pkg:tarvia-checkout-utils", f"hash:{'f' * 64}",
                                        "dom:npm-telemetry-stats.example"}


# --------------------------------------------------------------------------------------------- relevancia

@pytest.mark.parametrize("senales,nivel", [
    ([("alerta", "citado por ALR-1")], I.NUCLEO),
    ([("ioc", "indicador del ataque: x")], I.NUCLEO),
    ([("alerta", "citado por ALR-9 (alerta de fuera del incidente)")], I.CONTEXTO),
    ([("alerta", "citado por ALR-9 (alerta de fuera del incidente)"), ("operacion", "x")], I.PIVOTE),
    ([("origen_nuevo", "x")], I.PIVOTE),        # teletrabajo y viajes: por sí solo no prueba nada
    ([("raro", "x")], I.PIVOTE),
    ([("operacion", "x")], I.CONTEXTO),
])
def test_relevancia(senales, nivel):
    assert I.relevancia(senales) == nivel


def test_acceso_inicial_incluye_artefacto_raro_previo():
    """El build que robó la clave es candidato aunque sea «pivote»: está antes del primer evento del núcleo."""
    crono = [
        {"event_id": "SIGN-1", "timestamp": "1", "nivel": "pivote", "description": "", "entidades": ["ip:1.1.1.1"],
         "senales": ["origen_nuevo: x"]},
        {"event_id": "CI-602", "timestamp": "2", "nivel": "pivote", "description": "",
         "entidades": ["host:CI-RUNNER01", "pkg:tarvia-checkout-utils"],
         "senales": ["raro: poco común en la empresa: tarvia-checkout-utils"]},
        {"event_id": "CT-1", "timestamp": "3", "nivel": "núcleo", "description": "",
         "entidades": ["ip:2.57.121.25", "user:svc_ecom_deploy"], "senales": ["ioc: x"]},
    ]
    r = I.acceso_inicial(crono)
    assert [c["event_id"] for c in r["acceso_inicial_candidatos"]] == ["CI-602", "CT-1"]
    assert r["paciente_cero_candidato"] == ["CI-RUNNER01"]


# --------------------------------------------------------------------------------------------- cadenas reales

def _ids(hechos):
    return {i for x in hechos["cronologia"] for i in [x["event_id"], *x.get("event_ids", [])]}


@pytest.fixture(scope="module")
def crm():
    return I.investigar(["ALR-20261015-011819", "ALR-20261015-011820", "ALR-20261016-011821"])


@requiere_api
@requiere_indice
def test_crm_llega_a_la_cadena_de_suministro(crm):
    """La clave robada lleva a su origen habitual (CI-RUNNER01) y de ahí al build #1842 que la robó."""
    assert "origen habitual" in crm["entidades"]["host:CI-RUNNER01"]["via"]
    assert {"CI-0000602", "CI-0000603"} <= _ids(crm)
    assert "CI-0000602" in [c["event_id"] for c in crm["acceso_inicial_candidatos"]]
    assert any("ALR-20261013-011901" in r["alertas"] for r in crm["relacionados"])
    assert crm["alcance"]["objetos_cloud_leidos"].get("tarvia-backups-prod", 0) >= 1400


@requiere_api
@requiere_indice
def test_crm_sin_ruido_diario(crm):
    """Las PutBucketPolicy diarias del runner (alertas de fondo) no entran en la cronología."""
    assert not any("PutBucketPolicy" in x["description"] for x in crm["cronologia"])


@pytest.fixture(scope="module")
def ransomware():
    from agente import incidentes
    return I.investigar(incidentes.incidente_de("ALR-20261009-011790"))


@requiere_api
@requiere_indice
def test_ransomware_encuentra_lo_que_no_alerto(ransomware):
    """El mismo binario en PRINT01 (10/10) y el C2 desde un servidor no tienen alerta: deben salir como huecos."""
    assert "EDR-0123435" in _ids(ransomware)
    assert any(h["fuente"] == "edr_events" for h in ransomware["huecos"])
    assert any(h["fuente"] == "firewall" for h in ransomware["huecos"])
    assert "EML-0062206" in [c["event_id"] for c in ransomware["acceso_inicial_candidatos"]]


@requiere_api
@requiere_indice
def test_ransomware_teletrabajo_no_es_nucleo(ransomware):
    """La VPN desde casa de la usuaria no es del ataque: como mucho «pivote»."""
    assert all(x["nivel"] != "núcleo" for x in ransomware["cronologia"] if x["source"] == "vpn")


@requiere_api
@requiere_indice
def test_servicio_publico_de_la_alerta_no_es_ioc():
    from agente import incidentes
    h = I.investigar(incidentes.incidente_de("ALR-20261014-011817"))
    assert "dom:mega.nz" not in h["iocs"] and "dom:wetransfer.com" not in h["iocs"]
    assert h["alcance"]["filas_sql"] > 1_000_000


@requiere_api
@requiere_indice
def test_fatiga_mfa_compacta():
    h = I.investigar(["ALR-20261010-011827", "ALR-20261010-011828"])
    assert len(h["cronologia"]) <= 8                      # 26 pushes agrupados por resultado
    assert {"SIGN-0084055", "AUD-0000828", "AUD-0000829"} <= _ids(h)
