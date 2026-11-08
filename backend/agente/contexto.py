"""[Nivel 2 · actividad autorizada y líneas base] Contexto que explica (o no) la actividad de una alerta.

RRHH (eventos_rrhh.csv vía /users): viajes y teletrabajo pueden autorizar un acceso desde otra ciudad; vacaciones,
bajas y altas son contexto o señales de alerta (cuenta usada tras el último día, fuga antes de irse).
Líneas base: origen habitual del usuario (país/ASN de sus inicios de sesión), relé Private Relay del móvil corporativo,
prevalencia de un dominio en el proxy/DNS y CDN conocidas.

Mismo formato de hallazgo que las reglas internas (tipo "rrhh" o "linea_base"); las consultas quedan en la traza con
origen "contexto". Las fechas de RRHH están en texto libre: si no se puede deducir el fin de un periodo, el resultado es
requiere_info, nunca se supone.
"""
import datetime as dt
import re
from functools import lru_cache

from . import api
from . import herramientas as h
from .comun import (INFORMATIVA, PERMITIDA, REQUIERE_INFO, SOSPECHOSA, de_alerta, es_interna, hallazgo, local,
                    utc)

ANIO = 2026  # las fechas de RRHH van sin año (dd/mm)
CIUDAD_PAIS = {"nueva york": "US", "milán": "IT", "parís": "FR", "valencia": "ES", "madrid": "ES", "barcelona": "ES",
               "londres": "GB", "lisboa": "PT", "dublín": "IE", "ámsterdam": "NL"}
ACTIVIDAD_EN_VACACIONES = REQUIERE_INFO  # la política no lo fija: se pide confirmación, sin afirmar que sea malicioso
CDN = ("cloudfront.net", "akamaized.net", "azureedge.net", "blob.core.windows.net", "amazonaws.com", "cdn77.example",
       "fastly.net", "googleusercontent.com")
PREVALENCIA_ALTA = 50                           # equipos distintos que visitan el dominio: uso generalizado
MIN_HISTORIAL = 3                               # inicios de sesión para considerar un origen habitual
REGLAS_DE_ACCESO = ("UC-IDP-001", "UC-IDP-004", "UC-IDP-006", "UC-VPN-001")


# =============================================================================================== datos (con caché)

def _usuario(upn: str) -> dict:
    return api.usuario(upn) or {}


def _intel(indicador: str) -> dict:
    return api.intel(indicador)


@lru_cache(maxsize=512)
def _inicios_de_sesion(upn: str) -> tuple:
    return tuple(h.eventos("idp_signins", upn, limit=2000))


@lru_cache(maxsize=512)
def _equipos_que_visitan(dominio: str) -> int:
    """Equipos distintos que consultan el dominio o cualquier subdominio (proxy: campo domain; DNS: query). Aquí no
    sirve la búsqueda por identificador exacto, que a propósito no casa «e5.sk» dentro de «abc.e5.sk»."""
    equipos = set()
    for fuente, campo in (("proxy", "domain"), ("dns", "query")):
        # «.dominio» casa con cualquier subdominio tanto si la API busca subcadenas como identificadores completos
        for q in (dominio, "." + dominio):
            d, e, ms = h._get(f"/logs/{fuente}", {"q": q, "limit": 2000})
            items = [x for x in (d or {}).get("items", []) if str(x.get(campo, "")).lower() == dominio
                     or str(x.get(campo, "")).lower().endswith("." + dominio)]
            h._registrar(f"prevalencia:{fuente}", {"q": q}, ms, len(items), e)
            equipos |= {x.get("src_ip") for x in items}
    return len(equipos - {None, ""})


# =============================================================================================== RRHH

def _fecha(dia: str, mes: str, anio: str | None = None) -> dt.date:
    return dt.date(int(anio or ANIO), int(mes), int(dia))


def periodo(evento: dict) -> tuple[dt.date, dt.date | None]:
    """(inicio, fin) de un evento de RRHH a partir del texto; fin None si no se puede deducir."""
    texto, efectiva = evento.get("detalle", ""), dt.date.fromisoformat(evento["fecha_efectiva"])
    if m := re.search(r"(\d{1,2})/(\d{1,2})\s+(?:al|a)\s+(\d{1,2})/(\d{1,2})", texto):
        return _fecha(m[1], m[2]), _fecha(m[3], m[4])
    if evento["tipo"] == "baja_voluntaria_comunicada":
        m = re.search(r"último día (\d{1,2})/(\d{1,2})(?:/(\d{4}))?", texto, re.IGNORECASE)
        return dt.date.fromisoformat(evento["fecha"]), _fecha(m[1], m[2], m[3]) if m else efectiva
    semanas = {"una semana": 7, "dos semanas": 14, "tres semanas": 21}
    for patron, dias in semanas.items():
        if patron in texto.lower():
            return efectiva, efectiva + dt.timedelta(days=dias - 1)
    return efectiva, None


def _destino(evento: dict) -> str:
    """Ciudad de un viaje o teletrabajo («Nueva York (reuniones…)», «Teletrabajo desde Valencia…»)."""
    texto = re.sub(r"^teletrabajo desde ", "", evento.get("detalle", ""), flags=re.IGNORECASE)
    return re.split(r"[(,.]| dos | una | del ", texto)[0].strip()


def _acceso(alerta: dict) -> dict:
    """Ciudad, país, IP y dispositivo del acceso que motiva una alerta de identidad (si los hay)."""
    ev = alerta.get("evidence", {})
    actual = ev.get("current_login") if isinstance(ev.get("current_login"), dict) else {}
    ip = actual.get("ip") or ev.get("src_ip") or next(
        (x for x in de_alerta(alerta)["ips"] if not es_interna(x)), "")
    geo = (_intel(ip).get("geo") or {}) if ip else {}
    ciudad = actual.get("city") or geo.get("city") or ""
    return {"ip": ip, "ciudad": ciudad, "pais": geo.get("country") or CIUDAD_PAIS.get(ciudad.lower(), ""),
            "geo": geo, "dispositivo": str(ev.get("device", ""))}


def rrhh(alertas: list[dict]) -> list[dict]:
    out = []
    for a in alertas:
        t = local(a["created_at"]).date()
        for upn in de_alerta(a)["users"]:
            for ev in _usuario(upn).get("hr_events", []):
                out += _evento_rrhh(a, upn, ev, t)
    return out


def _evento_rrhh(a: dict, upn: str, ev: dict, t: dt.date) -> list[dict]:
    regla, tipo = "Contexto de RRHH", ev["tipo"]
    inicio, fin = periodo(ev)
    acceso = _acceso(a) if a["rule_id"] in REGLAS_DE_ACCESO else {}
    if tipo in ("viaje", "teletrabajo_temporal") and acceso.get("ip") and t >= inicio:
        destino = _destino(ev)
        coincide = destino.lower() in acceso["ciudad"].lower() or CIUDAD_PAIS.get(destino.lower()) == acceso["pais"]
        motivo = f"{tipo.replace('_', ' ')} registrado en RRHH a {destino} desde el {inicio:%d/%m}"
        if fin and t <= fin and coincide:
            return [hallazgo(regla, upn, PERMITIDA, f"{motivo} al {fin:%d/%m}; el acceso es desde "
                             f"{acceso['ciudad'] or acceso['pais']}", [a["alert_id"]], tipo="rrhh")]
        if not fin and coincide:
            return [hallazgo(regla, upn, REQUIERE_INFO, f"{motivo}, sin fecha de fin; el acceso es desde "
                             f"{acceso['ciudad'] or acceso['pais']}", [a["alert_id"]], "fecha de fin del "
                             f"{tipo.replace('_', ' ')}", tipo="rrhh")]
        if fin and t <= fin:
            return [hallazgo(regla, upn, INFORMATIVA, f"{motivo} al {fin:%d/%m}, pero el acceso es desde "
                             f"{acceso['ciudad'] or acceso['pais']}: no lo explica", [a["alert_id"]], tipo="rrhh")]
    if tipo == "vacaciones" and fin and inicio <= t <= fin:
        return [hallazgo(regla, upn, ACTIVIDAD_EN_VACACIONES, f"actividad durante sus vacaciones ({inicio:%d/%m} a "
                         f"{fin:%d/%m})", [a["alert_id"]], "confirmar la actividad con el usuario o su responsable",
                         tipo="rrhh")]
    if tipo == "baja_voluntaria_comunicada":
        if t > fin:
            despues = [e for e in _inicios_de_sesion(upn) if e.get("result") == "success"
                       and local(e["timestamp"]).date() > fin]
            return [hallazgo(regla, upn, SOSPECHOSA, f"cuenta usada después de su último día ({fin:%d/%m}); "
                             f"{len(despues)} inicios de sesión correctos posteriores", [a["alert_id"]] +
                             [e["event_id"] for e in despues[:5]], tipo="rrhh")]
        if a["rule_id"].startswith("UC-DLP") and inicio <= t <= fin:
            return [hallazgo(regla, upn, SOSPECHOSA, f"salida de datos entre la comunicación de su baja "
                             f"({inicio:%d/%m}) y su último día ({fin:%d/%m}): «{ev.get('detalle', '')}»",
                             [a["alert_id"]], tipo="rrhh")]
    if tipo in ("alta", "cambio_puesto") and 0 <= (t - inicio).days <= 30:
        texto = "cuenta nueva" if tipo == "alta" else "cambio de puesto"
        return [hallazgo(regla, upn, INFORMATIVA, f"{texto} desde el {inicio:%d/%m}: su actividad aún no tiene "
                         "historial comparable", [a["alert_id"]], tipo="rrhh")]
    return []


# =============================================================================================== líneas base

def origen_habitual(alertas: list[dict], explicados: set[str]) -> list[dict]:
    """Origen del acceso frente al historial del usuario. `explicados`: alertas cuyo origen ya justifica RRHH."""
    regla, out = "Origen del acceso frente a su historial", []
    for a in alertas:
        if a["rule_id"] not in REGLAS_DE_ACCESO:
            continue
        acceso = _acceso(a)
        if not acceso["ip"] or es_interna(acceso["ip"]):
            continue
        geo, t = acceso["geo"], utc(a["created_at"])
        for upn in de_alerta(a)["users"]:
            previos = [e for e in _inicios_de_sesion(upn) if e.get("result") == "success" and utc(e["timestamp"]) < t]
            vistos = sum(1 for e in previos if e.get("country") == geo.get("country") and e.get("asn") == geo.get("asn"))
            sitio = f"{acceso['ip']} ({geo.get('as_org', '?')}, {geo.get('country', '?')})"
            if "private relay" in geo.get("as_org", "").lower() and "conocido" in acceso["dispositivo"].lower():
                out.append(hallazgo(regla, upn, PERMITIDA, f"{sitio}: salida del relé Private Relay del móvil, con "
                                    f"dispositivo «{acceso['dispositivo']}»; no es un desplazamiento real",
                                    [a["alert_id"]], tipo="linea_base"))
            elif vistos >= MIN_HISTORIAL:
                out.append(hallazgo(regla, upn, PERMITIDA, f"{sitio}: origen habitual ({vistos} inicios de sesión "
                                    "previos desde el mismo país y ASN)", [a["alert_id"]], tipo="linea_base"))
            elif any(geo.get(k) == "True" for k in ("is_tor", "is_vpn_provider", "is_hosting")):
                tipo_red = "Tor" if geo.get("is_tor") == "True" else "VPN comercial" if geo.get(
                    "is_vpn_provider") == "True" else "hosting"
                out.append(hallazgo(regla, upn, SOSPECHOSA, f"{sitio}: origen nuevo para el usuario y de {tipo_red}",
                                    [a["alert_id"]], tipo="linea_base"))
            elif a["alert_id"] not in explicados:
                out.append(hallazgo(regla, upn, REQUIERE_INFO, f"{sitio}: origen nuevo para el usuario "
                                    f"({vistos} accesos previos desde ahí)", [a["alert_id"]],
                                    "confirmar el acceso con el usuario", tipo="linea_base"))
    return out


def _dominios(alerta: dict) -> list[str]:
    ev = alerta.get("evidence", {})
    candidatos = de_alerta(alerta)["domains"] + [str(ev.get(k, "")).lower() for k in ("domain", "parent_domain")]
    return list(dict.fromkeys(d for d in candidatos if d and "." in d))[:3]


def prevalencia_dominios(alertas: list[dict]) -> list[dict]:
    """Dominios de alertas de red: CDN conocida, uso generalizado en Tarvia o dominio poco frecuente."""
    regla, out = "Prevalencia del dominio en Tarvia", []
    for a in alertas:
        if not a["rule_id"].startswith("UC-NET"):
            continue
        ev = a.get("evidence", {})
        for dominio in _dominios(a):
            tip = _intel(dominio).get("tip") or {}
            if tip.get("reputation") == "malicious":
                continue  # ya lo aporta la inteligencia de la investigación previa; nunca se da por bueno
            cdn = next((c for c in CDN if dominio == c or dominio.endswith("." + c)), None)
            if cdn:
                if not any(r["regla"] == regla and cdn in r["sujeto"] and a["alert_id"] in r["evidencias"] for r in out):
                    out.append(hallazgo(regla, dominio, PERMITIDA, f"{dominio} pertenece a {cdn}, una CDN o nube "
                                        "pública conocida; los subdominios aleatorios son normales en ella",
                                        [a["alert_id"]], tipo="linea_base"))
                continue
            n = _equipos_que_visitan(dominio)
            edad = ev.get("domain_age_days")
            if n >= PREVALENCIA_ALTA:
                out.append(hallazgo(regla, dominio, PERMITIDA, f"{dominio} lo visitan {n} equipos de Tarvia (uso "
                                    "generalizado)", [a["alert_id"]], tipo="linea_base"))
            else:
                out.append(hallazgo(regla, dominio, INFORMATIVA, f"{dominio} solo lo visitan {n} equipos"
                                    + (f"; antigüedad declarada {edad} días" if edad is not None else "")
                                    + (f"; en el TIP desde {tip['first_seen']}" if tip.get("first_seen") else ""),
                                    [a["alert_id"]], tipo="linea_base"))
    return out


# =============================================================================================== punto de entrada

def evaluar(alerta: dict, otras: list[dict] = ()) -> list[dict]:
    alertas = [alerta, *otras]
    with h.origen("contexto"):
        de_rrhh = rrhh(alertas)
        explicados = {e for c in de_rrhh if c["estado"] in (PERMITIDA, REQUIERE_INFO) for e in c["evidencias"]}
        return de_rrhh + origen_habitual(alertas, explicados) + prevalencia_dominios(alertas)
