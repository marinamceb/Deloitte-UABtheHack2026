"""Utilidades comunes de los tests: disponibilidad de la API simulada, constantes y constructores de alertas."""
import os

import pytest
import requests

API_URL = os.environ.get("SOC_API_URL", "http://localhost:8000")


def _api_disponible() -> bool:
    try:
        return requests.get(f"{API_URL}/alerts", params={"limit": 1}, timeout=5).ok
    except requests.RequestException:
        return False


requiere_api = pytest.mark.skipif(not _api_disponible(), reason=f"API simulada no disponible en {API_URL}")

# Pentest autorizado del calendario (CHG-2026-1042), para pruebas sintéticas de cambios y argumentos
PENTEST = {"id": "CHG-2026-1042", "titulo": "Pentest", "inicio": "2026-10-08 08:00", "fin": "2026-10-10 18:00",
           "detalle": "IPs origen 192.0.2.10-12; alcance www.tarvia.example", "alcance": "WEB-ECOM01..04"}


def alerta(rule_id="UC-X", created_at="2026-10-14T10:00:00Z", entities=None, evidence=None, related=(), aid="ALR-T"):
    """Alerta sintética mínima."""
    return {"alert_id": aid, "created_at": created_at, "rule_id": rule_id, "entities": entities or {},
            "evidence": evidence or {}, "related_events": list(related)}
