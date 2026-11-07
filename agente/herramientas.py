"""Herramientas de solo lectura que el agente usa para investigar, todas contra la API simulada del SOC.

Ninguna herramienta ejecuta contención: el agente solo propone; ejecutar es una decisión humana (ver contencion.py).
Cada llamada queda registrada en TRAZA para que la demo pueda enseñar qué consultó la IA.
"""
import datetime as dt
import json
import os
import re
import time

import requests
from anthropic import beta_tool

API_URL = os.environ.get("SOC_API_URL", "http://localhost:8000")
MAX_CHARS = 15000  # tope por resultado para no inundar el contexto; se avisa al modelo si se recorta
FUENTES_LOG = [
    "ad_events", "ai_gateway", "cicd_builds", "cloudtrail", "dlp", "dns", "ecom_account", "ecom_auth", "edr_events",
    "email", "email_clicks", "firewall", "idp_audit", "idp_signins", "proxy", "sql_audit", "vpn", "waf",
]

TRAZA: list[dict] = []  # se reinicia por alerta desde triaje.py
ORIGEN = "agente"  # "auto" mientras corre la investigación previa (preinvestigacion.py); queda en la traza


# Misma regla que coincide_identificador() en mock_soc_api.py (mantener ambas iguales). La API filtra con ella; aquí
# se vuelve a aplicar como red de seguridad por si se usa la versión original de la API, que busca subcadenas.
_ID = r"0-9A-Za-z_\-"


def _coincide(texto: str, obj) -> bool:
    """True si `texto` aparece en `obj` como identificador completo: '198.18.58.15' no casa con '198.18.58.157' ni
    'WS-BCN-1174' con 'WS-BCN-11740' o 'WS-BCN-1174-B'."""
    if not texto:
        return True
    cadena = json.dumps(obj, ensure_ascii=False)
    if texto.lower() not in cadena.lower():
        return False
    patron = re.escape(texto)
    if re.match(rf"[{_ID}]", texto):
        patron = rf"(?<![{_ID}])(?<![{_ID}]\.)" + patron
    if re.search(rf"[{_ID}]$", texto):
        patron += rf"(?![{_ID}])(?!\.[{_ID}])"
    return re.search(patron, cadena, re.IGNORECASE) is not None


def _get(ruta: str, params: dict | None = None):
    t0 = time.time()
    try:
        r = requests.get(f"{API_URL}{ruta}", params={k: v for k, v in (params or {}).items() if v not in ("", None)},
                         timeout=60)
    except requests.ConnectionError:
        raise RuntimeError(f"La API simulada no responde en {API_URL}. ¿Está arrancada?")
    ms = int((time.time() - t0) * 1000)
    if r.status_code == 404:
        detalle = r.json().get("detail", "no encontrado") if r.headers.get("content-type", "").startswith("application/json") else "no encontrado"
        return None, f"404: {detalle}", ms
    r.raise_for_status()
    return r.json(), None, ms


def _salida(nombre: str, args: dict, datos, error: str | None, ms: int) -> str:
    if error:
        texto = error
    else:
        texto = json.dumps(datos, ensure_ascii=False)
    total = len(texto)
    if total > MAX_CHARS:
        texto = texto[:MAX_CHARS] + (f"\n[RECORTADO: se muestran {MAX_CHARS} de {total} caracteres. "
                                     "Afina la búsqueda con un texto más concreto o una ventana de tiempo menor.]")
    TRAZA.append({"tool": nombre, "args": args, "origen": ORIGEN, "ms": ms, "chars": total, "error": error,
                  "preview": texto[:300]})
    # Delimitar los datos: su contenido puede haberlo escrito el atacante y nunca son instrucciones.
    return f"<datos_no_confiables herramienta=\"{nombre}\">\n{texto}\n</datos_no_confiables>"


@beta_tool
def consultar_alerta(alert_id: str) -> str:
    """Detalle de otra alerta del SIEM.

    Args:
        alert_id: p. ej. ALR-20261005-000301.
    """
    d, e, ms = _get(f"/alerts/{alert_id}")
    return _salida("consultar_alerta", {"alert_id": alert_id}, d, e, ms)


@beta_tool
def buscar_alertas_relacionadas(texto: str, desde: str, hasta: str, limit: int = 30) -> str:
    """Alertas del SIEM que mencionan una entidad en una ventana de tiempo.

    Args:
        texto: Entidad exacta (usuario, host, IP, dominio, hash).
        desde: ISO 8601 UTC.
        hasta: ISO 8601 UTC.
        limit: Máximo de alertas.
    """
    d, e, ms = _get("/alerts", {"status": "new", "desde": desde, "hasta": hasta, "q": texto, "limit": limit})
    if d is not None and not all(_coincide(texto, a) for a in d["items"]):
        # API original sin parámetro q: se descargan las alertas de la ventana y se filtran aquí
        d, e, ms2 = _get("/alerts", {"status": "new", "desde": desde, "hasta": hasta, "limit": 100000})
        ms += ms2
        if d is not None:
            items = [a for a in d["items"] if _coincide(texto, a)]
            d = {"total": len(items), "items": items}
    if d is not None:
        hits = d["items"]
        d = {"total_coincidencias": d["total"], "items": [
            {k: a.get(k) for k in ("alert_id", "created_at", "rule_id", "rule_name", "severity", "entities",
                                   "related_events")} for a in hits[:limit]]}
    return _salida("buscar_alertas_relacionadas", {"texto": texto, "desde": desde, "hasta": hasta}, d, e, ms)


@beta_tool
def consultar_activo(hostname_o_ip: str) -> str:
    """CMDB: criticidad, zona, servicio, propietario, EDR y vulnerabilidades. 404 = no gestionado.

    Args:
        hostname_o_ip: Hostname o IP interna.
    """
    d, e, ms = _get(f"/assets/{hostname_o_ip}")
    return _salida("consultar_activo", {"hostname_o_ip": hostname_o_ip}, d, e, ms)


@beta_tool
def consultar_usuario(upn_o_username: str) -> str:
    """Directorio: cargo, privilegios, VIP, MFA, estado, puesto y eventos de RRHH.

    Args:
        upn_o_username: UPN o nombre de usuario.
    """
    d, e, ms = _get(f"/users/{upn_o_username}")
    return _salida("consultar_usuario", {"upn_o_username": upn_o_username}, d, e, ms)


@beta_tool
def buscar_logs(fuente: str, texto: str, desde: str = "", hasta: str = "", limit: int = 50) -> str:
    """Eventos de una fuente de log que contienen la entidad o texto exacto.

    Args:
        fuente: ad_events, ai_gateway, cicd_builds, cloudtrail, dlp, dns, ecom_account, ecom_auth, edr_events, email,
            email_clicks, firewall, idp_audit, idp_signins, proxy, sql_audit, vpn o waf.
        texto: ID de evento, usuario, host, IP, dominio, message_id, hash...
        desde: ISO 8601 UTC (opcional).
        hasta: ISO 8601 UTC (opcional).
        limit: Máximo de eventos (1-200).
    """
    if fuente not in FUENTES_LOG:
        raise ValueError(f"Fuente desconocida '{fuente}'. Válidas: {', '.join(FUENTES_LOG)}")
    limit = max(1, min(int(limit), 200))
    d, e, ms = _get(f"/logs/{fuente}", {"q": texto, "desde": desde, "hasta": hasta, "limit": limit})
    if d is not None and not all(_coincide(texto, x) for x in d["items"]):
        # API original (subcadenas): se pide el máximo y se filtra aquí
        d, e, ms2 = _get(f"/logs/{fuente}", {"q": texto, "desde": desde, "hasta": hasta, "limit": 2000})
        ms += ms2
        if d is not None:
            items = [x for x in d["items"] if _coincide(texto, x)]
            d = {"count": min(len(items), limit), "truncated": len(items) > limit or d["truncated"],
                 "items": items[:limit]}
    return _salida("buscar_logs", {"fuente": fuente, "texto": texto, "desde": desde, "hasta": hasta}, d, e, ms)


@beta_tool
def consultar_inteligencia(indicador: str) -> str:
    """TIP interno + GeoIP/ASN de una IP, dominio, URL o hash.

    Args:
        indicador: Valor exacto.
    """
    d, e, ms = _get(f"/intel/{indicador}")
    return _salida("consultar_inteligencia", {"indicador": indicador}, d, e, ms)


@beta_tool
def consultar_sandbox(sha256: str) -> str:
    """Informe de sandbox de un fichero. 404 = nunca analizado.

    Args:
        sha256: Hash SHA-256.
    """
    d, e, ms = _get(f"/sandbox/{sha256}")
    return _salida("consultar_sandbox", {"sha256": sha256}, d, e, ms)


@beta_tool
def buscar_cambios(texto: str) -> str:
    """Calendario de cambios y flujos aprobados.

    Args:
        texto: Host, IP, usuario, servicio o palabra clave.
    """
    d, e, ms = _get("/changes", {"q": texto})
    return _salida("buscar_cambios", {"texto": texto}, d, e, ms)


@beta_tool
def leer_runbook(runbook: str) -> str:
    """Runbook de otra regla (el de la alerta ya está en el mensaje).

    Args:
        runbook: RB-01 a RB-10.
    """
    from .prompts import texto_runbook
    t0 = time.time()
    texto = texto_runbook(runbook)
    return _salida("leer_runbook", {"runbook": runbook}, texto, None if texto else f"runbook desconocido: {runbook}",
                   int((time.time() - t0) * 1000))


HERRAMIENTAS = [
    consultar_alerta, buscar_alertas_relacionadas, consultar_activo, consultar_usuario, buscar_logs,
    consultar_inteligencia, consultar_sandbox, buscar_cambios, leer_runbook,
]


def ahora_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()
