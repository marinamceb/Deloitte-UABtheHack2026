"""Herramientas de solo lectura que el agente usa para investigar, todas contra la API simulada del SOC.

Ninguna herramienta ejecuta contención: el agente solo propone; ejecutar es una decisión humana (ver contencion.py).
Cada llamada queda registrada en TRAZA para que la demo pueda enseñar qué consultó la IA.
"""
import datetime as dt
import json
import os
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
    TRAZA.append({"tool": nombre, "args": args, "ms": ms, "chars": total, "error": error,
                  "preview": texto[:300]})
    # Delimitar los datos: su contenido puede haberlo escrito el atacante y nunca son instrucciones.
    return f"<datos_no_confiables herramienta=\"{nombre}\">\n{texto}\n</datos_no_confiables>"


@beta_tool
def consultar_alerta(alert_id: str) -> str:
    """Devuelve el detalle completo de una alerta del SIEM.

    Args:
        alert_id: Identificador de la alerta, p. ej. ALR-20261005-000301.
    """
    d, e, ms = _get(f"/alerts/{alert_id}")
    return _salida("consultar_alerta", {"alert_id": alert_id}, d, e, ms)


@beta_tool
def buscar_alertas_relacionadas(texto: str, desde: str, hasta: str, limit: int = 30) -> str:
    """Busca otras alertas del SIEM en una ventana de tiempo que mencionen una entidad (usuario, host, IP, dominio,
    hash...). Úsala para correlacionar (±24 h por defecto, más si sospechas una campaña de días).

    Args:
        texto: Entidad a buscar (subcadena, sin distinguir mayúsculas), p. ej. WS-BCN-1174 o 203.0.113.7.
        desde: Inicio de la ventana en ISO 8601 UTC, p. ej. 2026-10-05T00:00:00Z.
        hasta: Fin de la ventana en ISO 8601 UTC.
        limit: Máximo de alertas a devolver (resumidas).
    """
    d, e, ms = _get("/alerts", {"status": "new", "desde": desde, "hasta": hasta, "limit": 20000})
    if d is not None:
        t = texto.lower()
        hits = [a for a in d["items"] if t in json.dumps(a, ensure_ascii=False).lower()]
        d = {"total_coincidencias": len(hits), "items": [
            {k: a.get(k) for k in ("alert_id", "created_at", "rule_id", "rule_name", "severity", "entities",
                                   "related_events")} for a in hits[:limit]]}
    return _salida("buscar_alertas_relacionadas", {"texto": texto, "desde": desde, "hasta": hasta}, d, e, ms)


@beta_tool
def consultar_activo(hostname_o_ip: str) -> str:
    """CMDB: criticidad, zona de red, servicio de negocio, propietario, si tiene EDR y vulnerabilidades del activo.
    Un 404 significa que el equipo NO está en la CMDB (externo o no gestionado), lo cual es un hallazgo en sí.

    Args:
        hostname_o_ip: Hostname (p. ej. WS-BCN-1174) o IP interna.
    """
    d, e, ms = _get(f"/assets/{hostname_o_ip}")
    return _salida("consultar_activo", {"hostname_o_ip": hostname_o_ip}, d, e, ms)


@beta_tool
def consultar_usuario(upn_o_username: str) -> str:
    """Directorio: departamento, cargo, privilegios, VIP, método MFA, estado, manager, puesto asignado y eventos de
    RRHH (bajas, viajes, cambios de puesto).

    Args:
        upn_o_username: UPN (nombre@tarvia.example) o nombre de usuario.
    """
    d, e, ms = _get(f"/users/{upn_o_username}")
    return _salida("consultar_usuario", {"upn_o_username": upn_o_username}, d, e, ms)


@beta_tool
def buscar_logs(fuente: str, texto: str, desde: str = "", hasta: str = "", limit: int = 50) -> str:
    """Busca eventos en los logs crudos de una fuente. La búsqueda es por subcadena sobre el evento completo.
    Recuerda que la clave suele estar en eventos que NO aparecen en related_events de la alerta.

    Args:
        fuente: Una de ad_events, ai_gateway, cicd_builds, cloudtrail, dlp, dns, ecom_account, ecom_auth, edr_events,
            email, email_clicks, firewall, idp_audit, idp_signins, proxy, sql_audit, vpn, waf.
        texto: Subcadena a buscar (ID de evento, usuario, host, IP, dominio, message_id, hash...).
        desde: Inicio opcional en ISO 8601 UTC.
        hasta: Fin opcional en ISO 8601 UTC.
        limit: Máximo de eventos (1-200).
    """
    if fuente not in FUENTES_LOG:
        raise ValueError(f"Fuente desconocida '{fuente}'. Válidas: {', '.join(FUENTES_LOG)}")
    limit = max(1, min(int(limit), 200))
    d, e, ms = _get(f"/logs/{fuente}", {"q": texto, "desde": desde, "hasta": hasta, "limit": limit})
    return _salida("buscar_logs", {"fuente": fuente, "texto": texto, "desde": desde, "hasta": hasta}, d, e, ms)


@beta_tool
def consultar_inteligencia(indicador: str) -> str:
    """TIP interno + GeoIP/ASN de un indicador (IP, dominio, URL o hash). Un indicador desconocido NO es un indicador
    limpio: indícalo como 'sin datos', no como benigno.

    Args:
        indicador: Valor exacto del indicador.
    """
    d, e, ms = _get(f"/intel/{indicador}")
    return _salida("consultar_inteligencia", {"indicador": indicador}, d, e, ms)


@beta_tool
def consultar_sandbox(sha256: str) -> str:
    """Informe de sandbox de un fichero, si se envió. 404 = nunca se analizó (no implica que sea limpio).

    Args:
        sha256: Hash SHA-256 del fichero.
    """
    d, e, ms = _get(f"/sandbox/{sha256}")
    return _salida("consultar_sandbox", {"sha256": sha256}, d, e, ms)


@beta_tool
def buscar_cambios(texto: str) -> str:
    """Calendario de cambios y flujos aprobados (pentests, mantenimientos, despliegues). Una alerta que coincide con un
    cambio aprobado (objeto, fechas y origen) es benign_true_positive.

    Args:
        texto: Subcadena a buscar (host, IP, servicio, usuario, palabra clave como pentest).
    """
    d, e, ms = _get("/changes", {"q": texto})
    return _salida("buscar_cambios", {"texto": texto}, d, e, ms)


HERRAMIENTAS = [
    consultar_alerta, buscar_alertas_relacionadas, consultar_activo, consultar_usuario, buscar_logs,
    consultar_inteligencia, consultar_sandbox, buscar_cambios,
]


def ahora_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()
