"""[Nivel 3 · investigar] Reconstrucción de la cadena de ataque por código, sobre el índice de logs (indice.py).

Mismo principio que en los niveles 1 y 2: el código reúne, filtra y ordena los hechos; el LLM (informe.py) los
interpreta y redacta. `investigar(alert_ids)` devuelve los hechos que alimentan informe_incidente.schema.json:

1. Semillas: entidades de las alertas del incidente (equipos, cuentas, IPs, dominios, hashes, claves cloud).
2. Rastreo por saltos (hasta MAX_SALTOS): para cada entidad se leen sus eventos de las 18 fuentes en la ventana
   [primera alerta − 7 días, última + 3 días] y se quedan solo los **notables** (ver `senales`). Las entidades de los
   eventos notables son el siguiente salto; los concentradores (miles de eventos: DC, IP de salida, dominio propio)
   no se expanden.
   Pivote especial: si una credencial se usa desde un origen nuevo, se añade su **origen habitual** (p. ej. la clave
   de svc_ecom_deploy, siempre desde CI-RUNNER01): es donde pudo robarse.
3. Señales de un evento notable (todas deterministas y explicables):
   alerta       el evento está en los related_events de una alerta (del incidente o de otra: relación)
   ioc          contiene un indicador del ataque (IP/dominio/hash externos de las alertas o descubiertos)
   raro         contiene un indicador externo, hash o paquete visto en ≤ RARO equipos/cuentas de toda la empresa
   operacion    su tipo es poco frecuente en 4 semanas (≤ OPERACION_RARA: alta de cuenta, cambio de grupo, regla de
                buzón, nuevo MFA, CreateUser, servicio instalado...) o es una detección del EDR
   origen_nuevo una cuenta o clave se usa por primera vez desde una IP (externa) o un país
4. Cronología: eventos notables ordenados, sin duplicados, con las repeticiones agrupadas (beaconing ×118) y la
   técnica MITRE de la alerta o del tipo de evento.
5. Candidatos a paciente cero y acceso inicial (el LLM los confirma o discute), alcance calculado (equipos, cuentas,
   servicios, volumen), incidentes relacionados y huecos de detección (eventos notables que ninguna alerta cubre).

Límites honestos: los logs empiezan el 4/10; las señales son heurísticas (puede entrar ruido de la misma cuenta o
equipo, y el LLM debe descartarlo); sin índice (`agent.py --construir-indice`) no se puede investigar.
"""
import collections
import datetime as dt
import json
import re
import time
from functools import lru_cache
from urllib.parse import urlparse

from . import api, herramientas, incidentes, indice
from .comun import a_iso, de_alerta, es_interna, servicio, utc
from .contexto import CDN

VENTANA_ANTES_D = 7
VENTANA_DESPUES_D = 3
MAX_SALTOS = 2
MAX_ENTIDADES_SALTO = 25
CONCENTRADOR = 3000      # eventos en todo el dataset a partir de los que una entidad no se expande
RARO = 2                 # equipos/cuentas distintos que usan un indicador para considerarlo raro
OPERACION_RARA = 40      # apariciones en 4 semanas de un tipo de evento para considerarlo poco frecuente (< 1,5/día)
MAX_CRONOLOGIA = 80
DIAS_RUTINA = 3          # días distintos en la ventana a partir de los que algo es rutina de un equipo o cuenta
LEJOS_H = 48             # un pivote débil a más de estas horas de cualquier alerta del incidente pasa a contexto
DOMINIO_PROPIO = "tarvia.example"

# Campo que identifica el tipo de evento en cada fuente (para la frecuencia de tipos)
TIPO_EVENTO = {
    "ad_events": lambda e: str(e.get("event_code")),
    "idp_audit": lambda e: e.get("operation", ""),
    "edr_events": lambda e: e.get("event_type", ""),
    "cloudtrail": lambda e: e.get("eventName", ""),
    "cicd_builds": lambda e: (e.get("step", "").split(":")[0]
                              + ("+paquetes" if (e.get("details") or {}).get("new_packages") else "")),
    "ecom_account": lambda e: e.get("event", ""),
    "vpn": lambda e: e.get("action", ""),
    "email": lambda e: f"{e.get('direction')}/{e.get('verdict')}",
    "idp_signins": lambda e: f"{e.get('result')}/{e.get('mfa_result')}",
}

# Técnica MITRE por tipo de evento (cuando el evento no pertenece a una alerta, que ya trae la suya)
MITRE_TIPO = {
    ("ad_events", "4720"): "T1136.002", ("ad_events", "4728"): "T1098", ("ad_events", "4732"): "T1098",
    ("ad_events", "4724"): "T1098", ("ad_events", "4740"): "T1110",
    ("idp_audit", "New-InboxRule"): "T1564.008", ("idp_audit", "Add-MfaMethod"): "T1098.005",
    ("idp_audit", "Consent to application"): "T1528", ("idp_audit", "FileDownloaded"): "T1530",
    ("idp_audit", "MailItemsAccessed"): "T1114.002", ("idp_audit", "Set-MailboxAutoReply"): "T1114",
    ("cloudtrail", "CreateUser"): "T1136.003", ("cloudtrail", "AttachUserPolicy"): "T1098.003",
    ("cloudtrail", "CreateAccessKey"): "T1098.001", ("cloudtrail", "GetCallerIdentity"): "T1087.004",
    ("cloudtrail", "ListBuckets"): "T1619", ("cloudtrail", "GetObject"): "T1530",
    ("cloudtrail", "PutBucketPolicy"): "T1098.003",
    ("edr_events", "service_install"): "T1569.002", ("edr_events", "agent_status"): "T1562.001",
    ("edr_events", "process_access"): "T1003.001", ("edr_events", "registry_set"): "T1547.001",
    ("cicd_builds", "npm ci+paquetes"): "T1195.001", ("cicd_builds", "postinstall"): "T1552.001",
    ("ecom_account", "email_change"): "T1098", ("ecom_account", "giftcard_purchase"): "T1657",
    ("email", "inbound/suspicious"): "T1566.001", ("vpn", "auth_fail"): "T1110",
}
MITRE_SENAL = {"origen_nuevo": "T1078"}
FUENTES_RED = ("proxy", "dns", "firewall")  # un indicador del ataque en tráfico de red = comunicación con C2 (T1071)

# Campos con entidades, a cualquier profundidad del evento → tipo
CAMPOS = {
    "hostname": "host", "src_host": "host", "client_host": "host", "runner": "host", "remote_host": "host",
    "user": "user", "user_upn": "user", "actor_upn": "user", "subject": "user", "target": "user",
    "userName": "user", "recipients": "user", "sender": "user",
    "src_ip": "ip", "dst_ip": "ip", "sourceIPAddress": "ip", "response": "ip",
    "domain": "dom", "query": "dom", "url": "url", "network": "url", "host": "dom",
    "sha256": "hash", "accessKeyId": "key", "access_key": "key", "message_id": "msg", "session_id": "session",
}
_URL = re.compile(r"https?://[^\s/\"']+")
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# =============================================================================================== entidades

def normalizar(tipo: str, valor) -> str | None:
    """'tipo:valor' canónico, o None si no es una entidad útil. Las cuentas internas pierden dominio y prefijo
    (TARVIA\\adm.aortega, adm.aortega@tarvia.example → user:adm.aortega); las IPs internas pasan a su equipo."""
    if not isinstance(valor, str) or not valor.strip():
        return None
    v = valor.strip()
    if tipo == "host":
        return f"host:{v.upper()}"
    if tipo == "user":
        v = v.split("\\")[-1].lower()
        if "@" in v:
            local, dominio = v.rsplit("@", 1)
            if dominio != DOMINIO_PROPIO:
                return f"dom:{dominio}"  # remitente/destinatario externo: interesa su dominio
            v = local
        return f"user:{v}" if re.fullmatch(r"[a-z0-9._\-]{3,}", v) else None
    if tipo == "ip":
        if not _IP.match(v):
            return None
        if es_interna(v):
            return f"host:{h}" if (h := api.host_de_ip(v)) else None
        return f"ip:{v}"
    if tipo in ("dom", "url"):
        m = _URL.search(v)
        dominio = (urlparse(m.group()).hostname if m else v).lower().strip(".")
        if _IP.match(dominio):
            return normalizar("ip", dominio)
        return f"dom:{dominio}" if "." in dominio and " " not in dominio else None
    if tipo == "hash":
        return f"hash:{v.lower()}" if re.fullmatch(r"[0-9a-fA-F]{64}", v) else None
    if tipo in ("key", "msg", "session"):
        return f"{tipo}:{v}"
    return None


def entidades_de_evento(e: dict) -> set[str]:
    salida = set()

    def recorrer(o, campo=None):
        if isinstance(o, dict):
            for k, v in o.items():
                recorrer(v, k)
        elif isinstance(o, list):
            for v in o:
                recorrer(v, campo)
        elif campo in CAMPOS and (x := normalizar(CAMPOS[campo], o)):
            salida.add(x)

    recorrer({k: v for k, v in e.items() if k != "_fuente"})
    # paquetes instalados en CI: nombre del paquete como entidad
    for p in (e.get("details") or {}).get("new_packages", []) if isinstance(e.get("details"), dict) else []:
        if p.get("name"):
            salida.add(f"pkg:{p['name'].lower()}")
    return salida


def de_alertas(alertas: list[dict]) -> set[str]:
    out = set()
    for a in alertas:
        e = de_alerta(a)
        out |= {f"host:{h.upper()}" for h in e["hosts"]}
        out |= {x for u in e["users"] if (x := normalizar("user", u))}
        out |= {x for ip in e["ips"] if (x := normalizar("ip", ip))}
        out |= {x for d in e["domains"] if (x := normalizar("dom", d))}
        out |= {f"hash:{h.lower()}" for h in e["hashes"]}
        nube = e["cloud"] or {}
        if nube.get("access_key"):
            out.add(f"key:{nube['access_key']}")
        for k in ("identity", "new_user"):
            if nube.get(k):
                out.add(f"user:{nube[k].lower()}")
    return out


def _consulta(entidad: str) -> str:
    return entidad.split(":", 1)[1]


def externa(entidad: str) -> bool:
    tipo, valor = entidad.split(":", 1)
    return tipo == "ip" or (tipo == "dom" and not (valor == DOMINIO_PROPIO or valor.endswith("." + DOMINIO_PROPIO)))


# =============================================================================================== estadísticas

@lru_cache(maxsize=None)
def frecuencia_tipos(fuente: str) -> collections.Counter:
    """Apariciones de cada tipo de evento de la fuente en todo el periodo (del índice, una vez por fuente)."""
    clave = TIPO_EVENTO[fuente]
    return collections.Counter(clave(e) for e in indice.eventos_entre("", "", fuentes=[fuente]) or [])


def tipo_de(e: dict) -> str:
    f = TIPO_EVENTO.get(e["_fuente"])
    return f(e) if f else ""


@lru_cache(maxsize=None)
def eventos_globales(entidad: str) -> int:
    """Eventos de todo el dataset con el token de la entidad (del índice, sin descomprimir)."""
    con = indice._conexion()
    fila = con.execute("SELECT n FROM tokens WHERE texto = ?", (_consulta(entidad).lower(),)).fetchone()
    return fila[0] if fila else 0


@lru_cache(maxsize=None)
def dispersion(entidad: str) -> int:
    """Equipos y cuentas internos distintos que aparecen junto a la entidad en todo el periodo (tope 300 eventos)."""
    if eventos_globales(entidad) > CONCENTRADOR:
        return 10 ** 6
    actores = set()
    for e in indice.eventos_de(_consulta(entidad), limite=300) or []:
        actores |= {x for x in entidades_de_evento(e) if x.split(":")[0] in ("host", "user") and x != entidad}
    return len(actores)


# =============================================================================================== señales

class Contexto:
    """Estado del rastreo: alertas del incidente, indicadores del ataque y alertas que cita cada evento."""

    def __init__(self, alertas: list[dict]):
        self.alertas = alertas
        self.ids_alertas = {a["alert_id"] for a in alertas}
        self.iocs = iocs_iniciales(alertas)
        self.alerta_de_evento = _alerta_de_evento()


def iocs_iniciales(alertas: list[dict]) -> set[str]:
    """Indicadores externos y hashes de las alertas que son del atacante: maliciosos según el TIP, o usados por muy
    pocos equipos/cuentas. No lo son los servicios públicos que la alerta menciona (mega.nz en una alerta DLP) ni
    la IP desde la que una cuenta del incidente se conecta habitualmente (su casa, en un viaje imposible)."""
    habituales = set()
    for x in de_alertas(alertas):
        if x.startswith("user:"):
            habituales |= {ip for ip, h in historial_origenes(x).items() if len(h["dias"]) >= DIAS_HABITUAL}
    out = set()
    for x in de_alertas(alertas):
        if not (externa(x) or x.startswith("hash:")) or _consulta(x) in habituales:
            continue
        with herramientas.origen("investigacion"):
            maliciosa = api.reputacion(_consulta(x)) in ("malicious", "suspicious")
        if x.startswith("hash:") or maliciosa or dispersion(x) <= 3:
            out.add(x)
    return out


@lru_cache(maxsize=1)
def _alerta_de_evento() -> dict[str, list[str]]:
    """event_id → alertas (de las 11.061) que lo citan en related_events."""
    out = collections.defaultdict(list)
    for a in incidentes.todas_las_alertas().values():
        for ev in a.get("related_events", []):
            out[ev].append(a["alert_id"])
    return dict(out)


def _origen(e: dict) -> tuple[str, str] | None:
    """(credencial, IP de origen) de un inicio de sesión correcto, una conexión VPN o una llamada a la nube."""
    f = e["_fuente"]
    if f == "idp_signins" and e.get("result") == "success":
        return normalizar("user", e.get("user_upn", "")), e.get("src_ip", "")
    if f == "vpn" and e.get("action") == "connect":
        return normalizar("user", e.get("user", "")), e.get("src_ip", "")
    if f == "cloudtrail":
        ui = e.get("userIdentity") or {}
        return normalizar("user", ui.get("userName", "")), e.get("sourceIPAddress", "")
    return None


DIAS_HABITUAL = 3  # un origen usado en 3 días distintos o más es habitual para esa credencial


@lru_cache(maxsize=None)
def historial_origenes(cred: str) -> dict[str, dict]:
    """IP de origen → {n, dias, primero} de una credencial en todo el periodo. Se mira el periodo completo (no solo
    lo anterior a la ventana) porque los logs empiezan el 4/10: al principio todo origen parecería nuevo."""
    h: dict[str, dict] = {}
    for e in indice.eventos_de(_consulta(cred), fuentes=["idp_signins", "vpn", "cloudtrail"]) or []:
        if (o := _origen(e)) and o[0] == cred and o[1]:
            x = h.setdefault(o[1], {"n": 0, "dias": set(), "primero": e["timestamp"]})
            x["n"] += 1
            x["dias"].add(e["timestamp"][:10])
    return h


def habitos(evs: list[dict]) -> dict[str, set]:
    """Rutina de una entidad en la ventana: para cada indicador externo/hash/paquete y cada tipo de operación, en
    qué días aparece entre sus eventos. Lo que se repite en DIAS_RUTINA días o más es habitual para ella (el runner
    de CI descarga de storage.googleapis.com cada pocos días; el paquete falso, una sola vez)."""
    dias: dict[str, set] = collections.defaultdict(set)
    for e in evs:
        dia = (e.get("timestamp") or "")[:10]
        for x in entidades_de_evento(e):
            if externa(x) or x.startswith(("hash:", "pkg:")):
                dias[x].add(dia)
        if t := tipo_de(e):
            dias[f"op:{e['_fuente']}/{t}"].add(dia)
    return dias


def _rutina(clave: str, rutina: dict | None) -> bool:
    return bool(rutina) and len(rutina.get(clave, ())) >= DIAS_RUTINA


def senales(e: dict, ctx: Contexto, entidades: set[str], rutina: dict | None = None) -> list[tuple[str, str]]:
    """Motivos por los que un evento es notable para la cadena ([] si no lo es). `rutina`: hábitos de la entidad
    desde la que se ha llegado al evento (lo que hace a menudo no es raro para ella aunque lo sea en la empresa)."""
    s = []
    # las alertas de ruido de fondo (patrones repetidos) no hacen notable un evento
    alertas = [a for a in ctx.alerta_de_evento.get(e["event_id"], [])
               if a in ctx.ids_alertas or not incidentes.es_ruido(a)]
    if alertas:
        propias = [a for a in alertas if a in ctx.ids_alertas]
        s.append(("alerta", f"citado por {', '.join((propias or alertas)[:3])}"
                            + ("" if propias else " (alerta de fuera del incidente)")))
    if comunes := entidades & ctx.iocs:
        s.append(("ioc", "indicador del ataque: " + ", ".join(sorted(_consulta(x) for x in comunes)[:3])))
    # en accesos (IdP, VPN) la IP de origen la juzga «origen_nuevo»: la IP de casa de alguien siempre es «rara»
    acceso = e["_fuente"] in ("idp_signins", "vpn")
    # en DNS y proxy decide el dominio, no la IP que resuelve (las CDN reparten IPs distintas a cada cliente)
    con_dominio = any(x.startswith("dom:") for x in entidades)
    raros = [x for x in entidades - ctx.iocs
             if (externa(x) or x.split(":")[0] in ("hash", "pkg"))
             and not (x.startswith("ip:") and (acceso or con_dominio))
             and not (x.startswith("dom:") and _consulta(x).endswith(CDN))
             and not _rutina(x, rutina)
             and dispersion(x) <= RARO]
    if raros:
        s.append(("raro", "poco común en la empresa: " + ", ".join(sorted(_consulta(x) for x in raros)[:3])))
    tipo = tipo_de(e)
    if tipo and (e["_fuente"], tipo) != ("edr_events", "process_start"):
        n = frecuencia_tipos(e["_fuente"])[tipo]
        if tipo == "detection" or (n <= OPERACION_RARA and not _rutina(f"op:{e['_fuente']}/{tipo}", rutina)):
            s.append(("operacion", f"{e['_fuente']}/{tipo} ({n} en 4 semanas)"))
    if (o := _origen(e)) and o[0] and o[1] and not es_interna(o[1]):
        cred, ip = o
        hist = historial_origenes(cred)
        x = hist.get(ip)
        if x and len(hist) > 1 and len(x["dias"]) < DIAS_HABITUAL and x["primero"] == e["timestamp"]:
            habitual = max(hist, key=lambda k: hist[k]["n"])
            s.append(("origen_nuevo", f"{_consulta(cred)} usada por primera vez desde {ip} "
                                      f"{e.get('country') or ''} (habitual: {habitual}, {hist[habitual]['n']} usos)"))
    return s


NUCLEO, PIVOTE, CONTEXTO = 1, 2, 3


def lejos(e: dict, tiempos_alertas: list) -> bool:
    try:
        t = utc(e["timestamp"])
    except (KeyError, ValueError):
        return False
    return min(abs((t - x).total_seconds()) for x in tiempos_alertas) > LEJOS_H * 3600


def pivotes_especiales(e: dict, ents: set[str]) -> dict[str, str]:
    """Entidades que un evento del núcleo señala como parte del ataque aunque sean comunes, con el porqué:
    - el mismo correo (message_id): los demás destinatarios del phishing (alcance de la campaña);
    - una cuenta creada por el atacante (alta en AD 4720, CreateUser en la nube): qué hizo después;
    - la sesión del atacante (session_id de un inicio de sesión con un indicador del ataque)."""
    out = {}
    f = e["_fuente"]
    if f == "email" and e.get("message_id"):
        out[f"msg:{e['message_id']}"] = f"evento {e['event_id']} (mismo correo: otros destinatarios)"
    creada = None
    if f == "ad_events" and str(e.get("event_code")) == "4720":
        creada = normalizar("user", e.get("target", ""))
    elif f == "cloudtrail" and e.get("eventName") == "CreateUser":
        creada = normalizar("user", (e.get("requestParameters") or {}).get("userName", ""))
    if creada:
        out[creada] = f"evento {e['event_id']} (cuenta creada por el atacante)"
    for x in ents:
        if x.startswith("session:"):
            out[x] = f"evento {e['event_id']} (sesión del atacante)"
    return out


def relevancia(s: list[tuple[str, str]]) -> int:
    """1 núcleo (alerta del incidente o indicador del ataque); 2 pivote (indicador poco común, origen nuevo de una
    credencial —la gente teletrabaja y viaja: por sí solo no prueba nada— u operación rara citada por otra alerta);
    3 contexto (una sola señal débil: no entra en la cronología ni abre nuevos saltos, solo se cuenta)."""
    codigos = {c for c, _ in s}
    if "ioc" in codigos or any(c == "alerta" and "fuera del incidente" not in t for c, t in s):
        return NUCLEO
    if codigos & {"raro", "origen_nuevo"} or {"operacion", "alerta"} <= codigos:
        return PIVOTE
    return CONTEXTO


# =============================================================================================== rastreo

def investigar(alert_ids: list[str]) -> dict:
    """Hechos de la cadena de ataque de un incidente (lista de alertas). Requiere el índice de logs."""
    if not indice.disponible():
        raise RuntimeError("No hay índice de logs: créalo con `python agent.py --construir-indice`.")
    t0, n_traza = time.time(), len(herramientas.TRAZA)
    todas = incidentes.todas_las_alertas()
    alertas = sorted((todas[i] for i in alert_ids if i in todas), key=lambda a: a["created_at"])
    ctx = Contexto(alertas)
    desde = a_iso(utc(alertas[0]["created_at"]) - dt.timedelta(days=VENTANA_ANTES_D))
    hasta = a_iso(utc(alertas[-1]["created_at"]) + dt.timedelta(days=VENTANA_DESPUES_D))

    semillas = de_alertas(alertas)
    entidades = {x: {"salto": 0, "via": "alerta", "eventos": 0, "notables": 0} for x in semillas}
    concentradores: set[str] = set()
    notables: dict[str, dict] = {}

    # los eventos que citan las propias alertas entran siempre (aunque sus entidades sean concentradores)
    especiales: dict[str, str] = {}
    for a in alertas:
        for ev_id in a.get("related_events", []):
            if ev_id not in notables and (e := indice.evento(ev_id)):
                ents_e = entidades_de_evento(e)
                notables[ev_id] = {"evento": e, "senales": senales(e, ctx, ents_e), "entidades": ents_e,
                                   "por": {"alerta"}, "nivel": NUCLEO}
                especiales.update({k: v for k, v in pivotes_especiales(e, ents_e).items() if k not in entidades})

    tiempos_alertas = [utc(a["created_at"]) for a in alertas]
    frontera = sorted(semillas)
    for salto in range(MAX_SALTOS + 1):
        nuevas: dict[str, str] = {}
        for ent in frontera:
            if eventos_globales(ent) > CONCENTRADOR:
                concentradores.add(ent)
                continue
            evs = indice.eventos_de(_consulta(ent), desde, hasta) or []
            entidades[ent]["eventos"] = len(evs)
            rutina = habitos(evs) if ent.split(":")[0] in ("host", "user", "key") else None
            for e in evs:
                ents_e = entidades_de_evento(e)
                if ent.split(":")[0] in ("user", "host") and ent not in ents_e:
                    continue  # coincidencia textual fuera de un campo de entidad (p. ej. en una descripción)
                if e["event_id"] in notables:
                    notables[e["event_id"]]["por"].add(ent)
                    continue
                s = senales(e, ctx, ents_e, rutina)
                if not s:
                    continue
                nivel = relevancia(s)
                if nivel == PIVOTE and not any(c == "raro" for c, _ in s) and lejos(e, tiempos_alertas):
                    nivel = CONTEXTO   # pivote débil (origen nuevo, operación) lejos de las alertas: contexto
                notables[e["event_id"]] = {"evento": e, "senales": s, "entidades": ents_e, "por": {ent},
                                           "nivel": nivel}
                if nivel == CONTEXTO:
                    continue
                entidades[ent]["notables"] += 1
                # los indicadores externos poco comunes de un evento ligado al ataque (alerta del propio incidente,
                # indicador ya conocido u origen nuevo) pasan a ser indicadores del ataque
                if nivel == NUCLEO:
                    ctx.iocs |= {x for x in ents_e if (externa(x) or x.startswith("hash:")) and dispersion(x) <= RARO}
                for x in ents_e:
                    if x not in entidades and x not in nuevas and x.split(":")[0] not in ("msg",):
                        nuevas[x] = ent
                if nivel == NUCLEO:
                    especiales.update({k: v for k, v in pivotes_especiales(e, ents_e).items() if k not in entidades})
            # pivote: origen habitual de una credencial usada desde un origen nuevo
            if ent.startswith("user:") and any(c == "origen_nuevo" for n in notables.values() if ent in n["por"]
                                               for c, _ in n["senales"]):
                hist = historial_origenes(ent)
                for ip in sorted(hist, key=lambda k: -hist[k]["n"])[:2]:
                    h = api.host_de_ip(ip)
                    if h and len(hist[ip]["dias"]) >= DIAS_HABITUAL and f"host:{h}" not in entidades:
                        nuevas[f"host:{h}"] = f"{ent} (origen habitual: {hist[ip]['n']} usos desde {ip})"
        if salto == MAX_SALTOS:
            break
        # siguiente salto: primero los pivotes especiales (mismo correo, cuenta creada, sesión del atacante) y luego
        # lo más raro (menos eventos), sin concentradores
        nuevas.update(especiales)
        especiales.clear()
        candidatas = sorted((x for x in nuevas if eventos_globales(x) <= CONCENTRADOR),
                            key=lambda x: (" (" not in nuevas[x], eventos_globales(x)))
        concentradores |= {x for x in nuevas if eventos_globales(x) > CONCENTRADOR}
        frontera = candidatas[:MAX_ENTIDADES_SALTO]
        for x in frontera:
            entidades[x] = {"salto": salto + 1, "via": nuevas[x], "eventos": 0, "notables": 0}

    contexto = [n for n in notables.values() if n["nivel"] == CONTEXTO]
    notables = {k: n for k, n in notables.items() if n["nivel"] != CONTEXTO}
    hechos = {
        "alert_ids": [a["alert_id"] for a in alertas],
        "ventana": {"desde": desde, "hasta": hasta},
        "entidades": entidades,
        "concentradores": sorted(concentradores),
        "iocs": sorted(ctx.iocs),
        "cronologia": cronologia(notables, alertas),
        "eventos_notables": len(notables),
        "contexto_descartado": {"eventos": len(contexto),
                                "tipos": collections.Counter(f"{n['evento']['_fuente']}/{tipo_de(n['evento'])}"
                                                             for n in contexto).most_common(8)},
    }
    hechos.update(acceso_inicial(hechos["cronologia"]))
    hechos["alcance"] = alcance(notables, entidades)
    hechos["relacionados"] = relacionados(notables, ctx)
    hechos["huecos"] = huecos(notables)
    hechos["estadisticas"] = {"segundos": round(time.time() - t0, 1),
                              "consultas_indice": len(herramientas.TRAZA) - n_traza,
                              "entidades": len(entidades), "eventos_notables": len(notables)}
    return hechos


# =============================================================================================== cronología

def describir(e: dict) -> str:
    """Una línea legible del evento (campos clave por fuente; el resto del evento queda en el informe)."""
    f, g = e["_fuente"], e.get
    d = g("details") if isinstance(g("details"), dict) else {}
    extra = f" {json.dumps(d, ensure_ascii=False)[:120]}" if d else ""
    if f == "email":
        adj = ", ".join(a.get("name", "") for a in g("attachments") or [])
        return (f"Correo de {g('sender')} a {', '.join(g('recipients') or [])}: «{g('subject')}»"
                + (f" [{adj}]" if adj else ""))
    if f == "edr_events":
        return (f"{g('hostname')} · {g('event_type')} · {g('user')} · {g('process_name')} "
                f"{(g('command_line') or '')[:120]}".strip() + extra)
    if f == "proxy":
        return f"{g('hostname')} ({g('user')}) → {g('method')} {g('url')} [{g('action')}, {g('bytes_out')} B salida]"
    if f == "dns":
        return f"{g('hostname')} resuelve {g('query')} → {g('response')}"
    if f == "firewall":
        return f"{g('src_ip')} → {g('dst_ip')}:{g('dst_port')} {g('action')} ({g('bytes')} B, {g('rule')})"
    if f == "cloudtrail":
        ui = g("userIdentity") or {}
        return (f"{ui.get('userName')} · {g('eventName')} desde {g('sourceIPAddress')} "
                f"{json.dumps(g('requestParameters') or {}, ensure_ascii=False)[:100]}")
    if f == "idp_signins":
        return (f"Inicio de sesión de {g('user_upn')} en {g('app')}: {g('result')} (MFA {g('mfa_method')}/"
                f"{g('mfa_result')}) desde {g('src_ip')} {g('country')} {g('asn')}")
    if f == "idp_audit":
        return f"{g('actor_upn')} · {g('operation')} sobre {g('target')} desde {g('src_ip')}{extra}"
    if f == "ad_events":
        return f"{g('event')} ({g('event_code')}): {g('subject')} → {g('target')} en {g('src_host')}{extra[:81]}"
    if f == "cicd_builds":
        return (f"{g('build_id')} en {g('runner')} · {g('step')} · {g('status')} "
                f"{json.dumps(d, ensure_ascii=False)[:220]}")
    if f == "vpn":
        return f"VPN {g('action')} de {g('user')} desde {g('src_ip')} ({g('country')}) → {g('assigned_ip')}"
    if f == "dlp":
        return (f"DLP {g('action')}: {g('user')} en {g('hostname')} · {g('channel')} → {g('destination')} · "
                f"{g('file_name')} ({g('file_size')} B)")
    if f == "sql_audit":
        return (f"{g('user')} desde {g('client_host')} · {g('statement_type')} {g('database')}.{g('object')} "
                f"({g('rows_returned')} filas)")
    if f == "email_clicks":
        return f"{g('user')} hace clic en {g('url')} ({g('action')}, veredicto {g('verdict_at_click')})"
    resto = {k: v for k, v in e.items() if k not in ("event_id", "timestamp", "_fuente")}
    return json.dumps(resto, ensure_ascii=False)[:200]


def _firma_repeticion(n: dict) -> tuple:
    """Eventos «iguales» salvo el instante (beaconing, descargas repetidas): se agrupan en una entrada."""
    e = n["evento"]
    if any(c == "origen_nuevo" for c, _ in n["senales"]):
        return (e["event_id"],)  # el primer uso desde un origen nuevo se muestra aparte
    clave = {"proxy": ("hostname", "domain"), "dns": ("hostname", "query"), "firewall": ("src_ip", "dst_ip"),
             "cloudtrail": ("eventName", "sourceIPAddress"), "email_clicks": ("user", "url"),
             "idp_signins": ("user_upn", "src_ip", "result", "mfa_result"),
             "idp_audit": ("actor_upn", "operation", "src_ip"),
             "edr_events": ("hostname", "event_type", "process_name", "sha256", "command_line")}
    campos = clave.get(e["_fuente"])
    return (e["_fuente"],) + tuple(str(e.get(c)) for c in campos) if campos else (e["event_id"],)


def _alertas_que_citan(n: dict) -> set[str]:
    return {a for c, t in n["senales"] if c == "alerta" for a in re.findall(r"ALR-\d{8}-\d{6}", t)}


def _mitre(n: dict, alertas_por_id: dict) -> str:
    for c, texto in n["senales"]:
        if c == "alerta":
            for aid in re.findall(r"ALR-\d{8}-\d{6}", texto):
                if t := (alertas_por_id.get(aid, {}).get("mitre") or {}).get("technique_id"):
                    return t
    e = n["evento"]
    if t := MITRE_TIPO.get((e["_fuente"], tipo_de(e))):
        return t
    if e["_fuente"] == "edr_events" and e.get("event_type") == "detection":
        return (e.get("details") or {}).get("technique", "") if isinstance(e.get("details"), dict) else ""
    if e["_fuente"] in FUENTES_RED and any(c == "ioc" for c, _ in n["senales"]):
        return "T1071"
    return next((MITRE_SENAL[c] for c, _ in n["senales"] if c in MITRE_SENAL), "")


def cronologia(notables: dict[str, dict], alertas: list[dict]) -> list[dict]:
    """Eventos notables en orden, con repeticiones agrupadas; si hay más de MAX_CRONOLOGIA entradas se priorizan las
    citadas por alertas, las operaciones raras y los orígenes nuevos, y se indica cuántas se omiten."""
    todas = incidentes.todas_las_alertas()
    grupos: dict[tuple, list[dict]] = {}
    citados = {_firma_repeticion(n) for n in notables.values() if _alertas_que_citan(n)}
    for n in sorted(notables.values(), key=lambda n: (n["evento"]["timestamp"], n["evento"]["event_id"])):
        firma = _firma_repeticion(n)
        # los repetidos de un comportamiento ya citado por una alerta se agrupan con los citados
        grupos.setdefault(firma if firma in citados or not _alertas_que_citan(n) else firma + ("citado",), []).append(n)
    entradas = []
    for ns in grupos.values():
        e = ns[0]["evento"]
        n = next((x for x in ns if _alertas_que_citan(x)), ns[0])  # el citado por una alerta aporta MITRE y señales
        entrada = {"timestamp": e["timestamp"], "event_id": e["event_id"], "source": e["_fuente"],
                   "nivel": "núcleo" if min(x["nivel"] for x in ns) == NUCLEO else "pivote",
                   "description": describir(e), "mitre": _mitre(n, todas),
                   "senales": [f"{c}: {t}" for c, t in n["senales"]],
                   "entidades": sorted(n["entidades"])[:8]}
        if len(ns) > 1:
            entrada.update(repeticiones=len(ns), hasta=ns[-1]["evento"]["timestamp"],
                           event_ids=[x["evento"]["event_id"] for x in ns[:5]])
            entrada["description"] += f"  (×{len(ns)} hasta {ns[-1]['evento']['timestamp'][:16]})"
        entradas.append(entrada)
    if len(entradas) > MAX_CRONOLOGIA:
        peso = {"alerta": 0, "operacion": 1, "origen_nuevo": 1, "ioc": 2, "raro": 3}
        orden = sorted(entradas, key=lambda x: (x["nivel"] != "núcleo",
                                                min(peso[s.split(":")[0]] for s in x["senales"])))
        elegidas = {id(x) for x in orden[:MAX_CRONOLOGIA]}
        omitidas = len(entradas) - MAX_CRONOLOGIA
        entradas = [x for x in entradas if id(x) in elegidas]
        entradas.append({"timestamp": entradas[-1]["timestamp"], "event_id": "", "source": "", "nivel": "",
                         "description": f"({omitidas} entradas menos relevantes omitidas: solo «ioc»/«raro»)",
                         "mitre": "", "senales": [], "entidades": []})
    return entradas


# =============================================================================================== conclusiones

def acceso_inicial(crono: list[dict]) -> dict:
    """Candidatos al acceso inicial (el LLM elige y argumenta): el primer evento del núcleo con un indicador externo
    y, antes de él, los eventos pivote con un artefacto poco común (hash, paquete o dominio): p. ej. el build que
    robó la clave que el atacante usa después. Además, el primer evento del núcleo aunque no tenga nada externo: en
    una amenaza interna (una empleada que se lleva el CRM) el ataque empieza con un acceso legítimo de su cuenta.
    Paciente cero: equipos y cuentas internos del primer candidato."""
    candidatos, primero = [], None
    primero_nucleo = next((x for x in crono if x["event_id"] and x["nivel"] == "núcleo"), None)
    for x in crono:
        if not x["event_id"]:
            continue
        externos = [e for e in x["entidades"] if externa(e) or e.startswith(("hash:", "pkg:"))]
        if x["nivel"] == "núcleo" and externos:
            primero = x
            break
        raros = [s for s in x["senales"] if s.startswith("raro")]
        if raros and any(e.startswith(("hash:", "pkg:", "dom:")) and _consulta(e) in raros[0] for e in externos):
            candidatos.append(x)
    candidatos = candidatos[-3:] + ([primero] if primero else [])
    if primero_nucleo and primero_nucleo not in candidatos and (
            not primero or primero_nucleo["timestamp"] < primero["timestamp"]):
        candidatos.insert(0, primero_nucleo)   # interno: el primer paso del núcleo, antes que cualquier indicador

    def resumen(x):
        return {"event_id": x["event_id"], "timestamp": x["timestamp"], "description": x["description"],
                "nivel": x["nivel"]}
    internos = [e for e in (candidatos[0]["entidades"] if candidatos else []) if e.startswith(("host:", "user:"))]
    return {"acceso_inicial_candidatos": [resumen(x) for x in candidatos],
            "paciente_cero_candidato": [_consulta(e) for e in internos[:3]]}


def _bytes(e: dict) -> int:
    for k in ("bytes_out", "file_size"):
        try:
            return int(e.get(k) or 0)
        except (TypeError, ValueError):
            pass
    return 0


def alcance(notables: dict[str, dict], entidades: dict[str, dict]) -> dict:
    """Equipos, cuentas, servicios de negocio y volumen tocados por los eventos notables."""
    hosts, users = collections.Counter(), collections.Counter()
    servicios, salida, filas, objetos = set(), 0, 0, collections.Counter()
    for n in notables.values():
        e = n["evento"]
        for x in n["entidades"]:
            if x.startswith("host:"):
                hosts[_consulta(x)] += 1
            elif x.startswith("user:"):
                users[_consulta(x)] += 1
        salida += _bytes(e)
        filas += int(e.get("rows_returned") or 0) if e["_fuente"] == "sql_audit" else 0
        if e["_fuente"] == "cloudtrail" and e.get("eventName") == "GetObject":
            objetos[(e.get("requestParameters") or {}).get("bucketName", "?")] += 1
    fichas = {h: f for h in hosts if (f := api.activo(h, trazar=False))}
    for f in fichas.values():
        if s := servicio(f.get("business_service", "")):
            servicios.add(s["servicio"])
    for b in objetos:
        if s := servicio(b):
            servicios.add(s["servicio"])
    return {"hosts": [h for h, _ in hosts.most_common()], "users": [u for u, _ in users.most_common()],
            "servicios": sorted(servicios), "bytes_salida_eventos_notables": salida, "filas_sql": filas,
            "objetos_cloud_leidos": dict(objetos),
            "criticidad": {h: f["criticality"] for h, f in fichas.items()}}


def relacionados(notables: dict[str, dict], ctx: Contexto) -> list[dict]:
    """Otros incidentes candidatos cuyas alertas citan eventos de esta cadena (misma historia)."""
    out: dict[str, dict] = {}
    for n in notables.values():
        for aid in ctx.alerta_de_evento.get(n["evento"]["event_id"], []):
            if aid in ctx.ids_alertas or incidentes.es_ruido(aid):
                continue
            lider = (incidentes.incidente_de(aid) or [aid])[0]
            r = out.setdefault(lider, {"incidente": lider, "alertas": set(), "eventos": set()})
            r["alertas"].add(aid)
            r["eventos"].add(n["evento"]["event_id"])
    return [{"incidente": r["incidente"], "alertas": sorted(r["alertas"]), "eventos": sorted(r["eventos"])[:5]}
            for r in out.values()]


def huecos(notables: dict[str, dict]) -> list[dict]:
    """Eventos del núcleo (con un indicador del ataque) u operaciones raras de la cadena que ninguna alerta cita:
    candidatos a regla nueva o a afinar (detection_gaps)."""
    grupos = collections.defaultdict(list)
    cubiertos = {_firma_repeticion(n) for n in notables.values() if _alertas_que_citan(n)}
    for n in notables.values():
        codigos = {c for c, _ in n["senales"]}
        if "alerta" in codigos or not (n["nivel"] == NUCLEO or "operacion" in codigos):
            continue
        if _firma_repeticion(n) in cubiertos:
            continue  # repetición de un comportamiento que una alerta ya cubre (beaconing, descarga masiva)
        e = n["evento"]
        motivo = next((t for c, t in n["senales"] if c in ("ioc", "operacion")), "")
        grupos[(e["_fuente"], tipo_de(e) or "?")].append((e["event_id"], motivo))
    return [{"fuente": f, "tipo": t, "total": len(xs), "eventos": [i for i, _ in xs[:5]], "ejemplo": xs[0][1]}
            for (f, t), xs in sorted(grupos.items(), key=lambda kv: -len(kv[1]))]
