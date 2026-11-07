import os
import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

API_URL = os.environ.get("SOC_API_URL", "http://localhost:8000")


def _api_disponible() -> bool:
    try:
        return requests.get(f"{API_URL}/alerts", params={"limit": 1}, timeout=5).ok
    except requests.RequestException:
        return False


requiere_api = pytest.mark.skipif(not _api_disponible(), reason=f"API simulada no disponible en {API_URL}")


@pytest.fixture
def alerta_real():
    def _alerta(alert_id: str) -> dict:
        r = requests.get(f"{API_URL}/alerts/{alert_id}", timeout=30)
        r.raise_for_status()
        return r.json()
    return _alerta
