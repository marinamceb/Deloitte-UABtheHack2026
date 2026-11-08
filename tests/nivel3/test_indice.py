"""[Nivel 3 · infraestructura] Índice local de logs descargado por la API (agente/indice.py).

Los casos sintéticos usan una API falsa con la misma semántica que /logs/{fuente} (desde inclusivo, comparación de
cadenas, corte en `limit`); los reales comparan el índice construido con la búsqueda por la API."""
import pytest

from apoyo import requiere_api
from agente import herramientas, indice


def _api_falsa(datos: dict[str, list[dict]]):
    """Imita search_logs de mock_soc_api.py: recorre la fuente en orden y corta al llegar a `limit`."""
    def get(ruta, params):
        fuente = ruta.rsplit("/", 1)[1]
        desde, limit = params.get("desde", ""), params["limit"]
        out = [e for e in datos[fuente] if not desde or (e.get("timestamp") or "") >= desde][:limit]
        return {"count": len(out), "truncated": len(out) >= limit, "items": out}, None, 0
    return get


def _ev(i, ts, **campos):
    return {"event_id": f"EV-{i}", "timestamp": ts, **campos}


# --------------------------------------------------------------------------------------------- descarga

def test_paginacion_con_instantes_repetidos_en_el_corte(monkeypatch):
    monkeypatch.setattr(indice, "PAGINA", 3)
    evs = [_ev(i, ts) for i, ts in enumerate(["T1", "T2", "T3", "T3", "T4", "T5", "T5", "T6"])]
    bajados = [e for p in indice.descargar("f", _api_falsa({"f": evs})) for e in p]
    assert [e["event_id"] for e in bajados] == [e["event_id"] for e in evs]


def test_pagina_exacta_no_duplica(monkeypatch):
    monkeypatch.setattr(indice, "PAGINA", 2)
    evs = [_ev(i, f"T{i}") for i in range(4)]
    bajados = [e for p in indice.descargar("f", _api_falsa({"f": evs})) for e in p]
    assert len(bajados) == 4 and len({e["event_id"] for e in bajados}) == 4


def test_fuente_desordenada_no_es_fiable(monkeypatch):
    monkeypatch.setattr(indice, "PAGINA", 3)
    evs = [_ev(0, "T2"), _ev(1, "T1"), _ev(2, "T3"), _ev(3, "T4")]
    with pytest.raises(indice.IndiceNoFiable, match="orden"):
        list(indice.descargar("f", _api_falsa({"f": evs})))


def test_demasiados_eventos_en_un_instante_no_es_fiable(monkeypatch):
    monkeypatch.setattr(indice, "PAGINA", 2)
    evs = [_ev(i, "T1") for i in range(3)]
    with pytest.raises(indice.IndiceNoFiable, match="instante"):
        list(indice.descargar("f", _api_falsa({"f": evs})))


# --------------------------------------------------------------------------------------------- consulta

@pytest.fixture
def indice_sintetico(tmp_path, monkeypatch):
    monkeypatch.setattr(indice, "PAGINA", 2)
    datos = {
        "firewall": [_ev(1, "2026-10-10T10:00:00Z", src_ip="198.18.58.15", dst="WS-BCN-1174"),
                     _ev(2, "2026-10-10T11:00:00Z", src_ip="198.18.58.157", dst="WS-BCN-11740"),
                     _ev(3, "2026-10-12T09:00:00Z", src_ip="10.0.0.5", dst="WS-BCN-1174-B")],
        "proxy": [_ev(4, "2026-10-11T08:00:00Z", user="Nuria.Vidal@tarvia.example", host="a.evil.com"),
                  _ev(5, "2026-10-11T09:00:00Z", user="admin", host="evil.com"),
                  _ev(6, "2026-10-13T09:00:00Z", detalle={"lista": ["x", "ws-bcn-1174"]}, host="notevil.com")],
    }
    ruta = tmp_path / "indice.sqlite"
    indice.construir(list(datos), ruta=ruta, get=_api_falsa(datos), aviso=lambda *_: None)
    yield ruta
    indice._cerrar(ruta)


def _ids(evs):
    return [e["event_id"] for e in evs]


def test_identificador_completo(indice_sintetico):
    assert _ids(indice.eventos_de("198.18.58.15", ruta=indice_sintetico)) == ["EV-1"]
    assert _ids(indice.eventos_de("WS-BCN-1174", ruta=indice_sintetico)) == ["EV-1", "EV-6"]  # anidado y en minúsculas


def test_varios_identificadores_y_mayusculas(indice_sintetico):
    assert _ids(indice.eventos_de("nuria.vidal@tarvia.example", ruta=indice_sintetico)) == ["EV-4"]
    assert _ids(indice.eventos_de("nuria.vidal", ruta=indice_sintetico)) == ["EV-4"]


def test_subdominios(indice_sintetico):
    assert _ids(indice.eventos_de(".evil.com", ruta=indice_sintetico)) == ["EV-4"]
    assert _ids(indice.eventos_de("evil.com", ruta=indice_sintetico)) == ["EV-5"]


def test_filtros_de_tiempo_y_fuente(indice_sintetico):
    assert _ids(indice.eventos_de("WS-BCN-1174", desde="2026-10-11", ruta=indice_sintetico)) == ["EV-6"]
    assert indice.eventos_de("WS-BCN-1174", fuentes=["proxy"], ruta=indice_sintetico)[0]["_fuente"] == "proxy"
    assert _ids(indice.eventos_entre("2026-10-10T10:30:00Z", "2026-10-11T08:00:00Z",
                                     ruta=indice_sintetico)) == ["EV-2", "EV-4"]


def test_no_indexable_o_sin_indice(indice_sintetico, tmp_path):
    assert indice.eventos_de("admin", ruta=indice_sintetico) is None   # palabra suelta → usar la API
    assert indice.eventos_de("198.18.58.15", ruta=tmp_path / "no.sqlite") is None
    assert indice.eventos_de("10.9.9.9", ruta=indice_sintetico) == []


def test_evento_por_id_y_estado(indice_sintetico):
    assert indice.evento("EV-3", ruta=indice_sintetico)["dst"] == "WS-BCN-1174-B"
    e = indice.estado(indice_sintetico)
    assert e["eventos"] == 6 and e["fuentes"]["firewall"]["eventos"] == 3


# --------------------------------------------------------------------------------------------- datos reales

@requiere_api
@pytest.mark.skipif(not indice.disponible(), reason="sin índice: python agent.py --construir-indice")
@pytest.mark.parametrize("texto", ["WS-BCN-1174", "svc_ecom_deploy", "nuria.vidal@tarvia.example", "198.18.58.15"])
def test_mismo_resultado_que_la_api(texto):
    api = set()
    for fuente in herramientas.FUENTES_LOG:
        d, _, _ = herramientas.buscar_eventos(fuente, texto, limit=2000)
        assert not d["truncated"]
        api |= {e["event_id"] for e in d["items"]}
    assert {e["event_id"] for e in indice.eventos_de(texto)} == api
