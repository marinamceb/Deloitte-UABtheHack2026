"""[Nivel 3] Las cadenas verificadas de tests/evaluacion/casos_nivel3.json: sensibilidad 100 %, sin el ruido legítimo
comprobado, acceso inicial entre los candidatos, huecos, pivotes y tamaño (rastreo por código, sin LLM)."""
import sys
from pathlib import Path

import pytest

from agente import indice
from apoyo import requiere_api

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluacion"))
import evaluar_nivel3 as E  # noqa: E402


@requiere_api
@pytest.mark.skipif(not indice.disponible(), reason="sin índice: python agent.py --construir-indice")
@pytest.mark.parametrize("caso", E.CASOS, ids=[c["semilla"] for c in E.CASOS])
def test_caso_verificado(caso):
    r = E.evaluar(caso)
    assert not r["faltan"] and not r["ruido"], r
    assert r["acceso_inicial"] and r["tamano_ok"] and r["huecos_ok"] and r["entidades_ok"], r
    assert r["relacionado_ok"] and r["iocs_ok"], r
