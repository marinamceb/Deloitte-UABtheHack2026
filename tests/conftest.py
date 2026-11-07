"""Configuración común de pytest para tests/nivel1, tests/nivel2 (y la ruta del proyecto)."""
import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # paquete `agente`
sys.path.insert(0, str(Path(__file__).resolve().parent))         # `apoyo`

from apoyo import API_URL, PENTEST  # noqa: E402


@pytest.fixture
def alerta_real():
    """Devuelve una alerta del dataset por su ID (requiere la API simulada)."""
    def _alerta(alert_id: str) -> dict:
        r = requests.get(f"{API_URL}/alerts/{alert_id}", timeout=30)
        r.raise_for_status()
        return r.json()
    return _alerta


@pytest.fixture
def calendario(monkeypatch):
    """Calendario de cambios reducido al pentest CHG-2026-1042."""
    from agente import cambios
    monkeypatch.setattr(cambios, "_CACHE", [cambios.interpretar(PENTEST)])
