"""Investigación inicial determinista, antes de llamar al modelo.

Las primeras consultas de cualquier triaje son siempre las mismas (activo, identidad, inteligencia de los indicadores,
eventos citados por la alerta, alertas de las mismas entidades en ±24 h y cambios aprobados). Hacerlas en código
contra la API local es gratis y ahorra al modelo una o dos rondas de peticiones, que es lo que limita el plan gratuito.
Cada consulta pasa por las mismas herramientas, así que queda en la traza (con origen "auto") para la demo.
"""
import datetime as dt
import ipaddress

from . import herramientas as h

# Prefijo del ID de evento → fuente de log
PREFIJOS = {
    "ADE": "ad_events", "AIG": "ai_gateway", "CI": "cicd_builds", "CT": "cloudtrail", "DLP": "dlp", "DNS": "dns",
    "ECO": "ecom_account", "ECA": "ecom_auth", "EDR": "edr_events", "CLK": "email_clicks", "EML": "email",
    "FW": "firewall", "AUD": "idp_audit", "SIGN": "idp_signins", "PRX": "proxy", "SQL": "sql_audit", "VPN": "vpn",
    "WAF": "waf",
}
MAX_EVENTOS = 8     # eventos de related_events que se recuperan
MAX_ENTIDADES = 4   # entidades por tipo, para no inflar el contexto en alertas con muchas IPs o dominios


# Solo RFC 1918. No vale ip.is_private: marca como privados los rangos de documentación (198.51.100.0/24,
# 198.18.0.0/15...), que en este dataset son IPs externas de atacantes.
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _es_interna(ip: str) -> bool:
    try:
        return any(ipaddress.ip_address(ip) in n for n in RFC1918)
    except ValueError:
        return False


def _ventana(alerta: dict, horas: int = 24) -> tuple[str, str]:
    t = dt.datetime.fromisoformat(alerta["created_at"].replace("Z", "+00:00"))
    fmt = lambda x: x.strftime("%Y-%m-%dT%H:%M:%SZ")
    return fmt(t - dt.timedelta(hours=horas)), fmt(t + dt.timedelta(hours=horas))


def _unicos(valores, n=MAX_ENTIDADES) -> list[str]:
    out = []
    for v in valores:
        if v and v not in out:
            out.append(v)
    return out[:n]


def _fusionar(alerta: dict, otras: list[dict]) -> tuple[dict, list[str]]:
    """Entidades y eventos de la alerta principal seguidos de los del resto del incidente (la principal primero)."""
    e = {k: list(v) if isinstance(v, list) else v for k, v in alerta.get("entities", {}).items()}
    eventos = list(alerta.get("related_events", []))
    for o in otras:
        for k, v in o.get("entities", {}).items():
            if isinstance(v, list):
                e[k] = e.get(k, []) + [x for x in v if x not in e.get(k, [])]
            elif isinstance(v, dict) and not e.get(k):
                e[k] = v
        eventos += [x for x in o.get("related_events", []) if x not in eventos]
    return e, eventos


def preinvestigar(alerta: dict, otras: list[dict] = ()) -> str:
    """Hace las consultas básicas sobre la alerta y las demás alertas de su incidente candidato, y devuelve los
    resultados como texto para el primer mensaje al modelo."""
    e, eventos = _fusionar(alerta, list(otras))
    max_eventos = MAX_EVENTOS + 4 * bool(otras)
    hosts = _unicos(x.get("hostname") for x in e.get("hosts", []))
    users = _unicos(x.get("upn") for x in e.get("users", []))
    ips = _unicos(e.get("ips", []), n=MAX_ENTIDADES * 2)
    ips_internas = [i for i in ips if _es_interna(i)]
    ips_externas = _unicos(i for i in ips if not _es_interna(i))
    dominios = _unicos(e.get("domains", []))
    hashes = _unicos(x.get("sha256") for x in e.get("files", []))
    cloud = e.get("cloud", {}) if isinstance(e.get("cloud"), dict) else {}

    bloques = []
    h.ORIGEN = "auto"
    try:
        for host in hosts:
            bloques.append(h.consultar_activo.call({"hostname_o_ip": host}))
        for ip in ips_internas:
            if not any(ip == x.get("ip") for x in e.get("hosts", [])):
                bloques.append(h.consultar_activo.call({"hostname_o_ip": ip}))
        for upn in users:
            bloques.append(h.consultar_usuario.call({"upn_o_username": upn}))
        for ind in ips_externas + dominios + hashes:
            bloques.append(h.consultar_inteligencia.call({"indicador": ind}))
        for sha in hashes:
            bloques.append(h.consultar_sandbox.call({"sha256": sha}))

        for ev in eventos[:max_eventos]:
            fuente = PREFIJOS.get(ev.split("-")[0])
            if fuente:
                bloques.append(h.buscar_logs.call({"fuente": fuente, "texto": ev, "limit": 1}))

        desde, hasta = _ventana(alerta)
        for ent in _unicos(hosts + users + ips_externas + [cloud.get("identity")]):
            bloques.append(h.buscar_alertas_relacionadas.call({"texto": ent, "desde": desde, "hasta": hasta,
                                                               "limit": 15}))
        for ent in _unicos(hosts + [u.split("@")[0] for u in users] + [cloud.get("identity")]):
            bloques.append(h.buscar_cambios.call({"texto": ent}))
    finally:
        h.ORIGEN = "agente"

    return "\n".join(bloques)
