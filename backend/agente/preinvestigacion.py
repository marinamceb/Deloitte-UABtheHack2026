"""[Nivel 1 · optimización] Investigación inicial determinista, antes de llamar al modelo.

Las primeras consultas de cualquier triaje son siempre las mismas (activo, identidad, inteligencia de los indicadores,
eventos citados por la alerta, alertas de las mismas entidades en ±24 h y cambios aprobados). Hacerlas en código
contra la API local es gratis y ahorra al modelo una o dos rondas de peticiones, que es lo que limita el plan gratuito.
Cada consulta pasa por las mismas herramientas, así que queda en la traza (con origen "auto") para la demo.
"""
from . import herramientas as h
from .comun import es_interna, fusionar, ventana

# Prefijo del ID de evento → fuente de log
PREFIJOS = {
    "ADE": "ad_events", "AIG": "ai_gateway", "CI": "cicd_builds", "CT": "cloudtrail", "DLP": "dlp", "DNS": "dns",
    "ECO": "ecom_account", "ECA": "ecom_auth", "EDR": "edr_events", "CLK": "email_clicks", "EML": "email",
    "FW": "firewall", "AUD": "idp_audit", "SIGN": "idp_signins", "PRX": "proxy", "SQL": "sql_audit", "VPN": "vpn",
    "WAF": "waf",
}
MAX_EVENTOS = 8     # eventos de related_events que se recuperan (+4 si es un incidente)
MAX_ENTIDADES = 4   # entidades por tipo, para no inflar el contexto en alertas con muchas IPs o dominios


def _primeros(valores, n: int = MAX_ENTIDADES) -> list[str]:
    return list(dict.fromkeys(v for v in valores if v))[:n]


def preinvestigar(alerta: dict, otras: list[dict] = ()) -> str:
    """Consultas básicas sobre la alerta y las demás de su incidente candidato; devuelve el texto para el modelo."""
    alertas = [alerta, *otras]
    e = fusionar(alertas)
    eventos = list(dict.fromkeys(x for a in alertas for x in a.get("related_events", [])))
    max_eventos = MAX_EVENTOS + 4 * bool(otras)

    hosts = _primeros(e["hosts"])
    users = _primeros(e["users"])
    ips = _primeros(e["ips"], MAX_ENTIDADES * 2)
    ips_internas = [i for i in ips if es_interna(i) and i not in e["host_ips"].values()]
    ips_externas = _primeros(i for i in ips if not es_interna(i))
    dominios, hashes = _primeros(e["domains"]), _primeros(e["hashes"])
    identidad_cloud = e["cloud"].get("identity")

    bloques = []
    with h.origen("auto"):
        for x in hosts + ips_internas:
            bloques.append(h.consultar_activo.call({"hostname_o_ip": x}))
        for upn in users:
            bloques.append(h.consultar_usuario.call({"upn_o_username": upn}))
        for indicador in ips_externas + dominios + hashes:
            bloques.append(h.consultar_inteligencia.call({"indicador": indicador}))
        for sha in hashes:
            bloques.append(h.consultar_sandbox.call({"sha256": sha}))

        for ev in eventos[:max_eventos]:
            if fuente := PREFIJOS.get(ev.split("-")[0]):
                bloques.append(h.buscar_logs.call({"fuente": fuente, "texto": ev, "limit": 1}))

        desde, hasta = ventana(alerta["created_at"], 24)
        for ent in _primeros(hosts + users + ips_externas + [identidad_cloud]):
            bloques.append(h.buscar_alertas_relacionadas.call({"texto": ent, "desde": desde, "hasta": hasta,
                                                               "limit": 15}))
        for ent in _primeros(hosts + [u.split("@")[0] for u in users] + [identidad_cloud]):
            bloques.append(h.buscar_cambios.call({"texto": ent}))
    return "\n".join(bloques)
