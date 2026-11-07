"""[Común a todos los niveles] Utilidades compartidas: fechas, inventario, entidades de una alerta y formato de los
hallazgos de las comprobaciones deterministas. Lo usan los módulos de los niveles 1, 2 y 4."""
import csv
import datetime as dt
import ipaddress
from zoneinfo import ZoneInfo

from .prompts import DATASET

# =============================================================================================== fechas
# Los logs y alertas están en UTC; las reglas de negocio (horarios, ventanas de cambios) en hora de España,
# Europe/Madrid (UTC+2 hasta el 25/10/2026 y UTC+1 después).

MADRID = ZoneInfo("Europe/Madrid")


def utc(iso: str) -> dt.datetime:
    return dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(dt.timezone.utc)


def local(iso: str) -> dt.datetime:
    return utc(iso).astimezone(MADRID)


def a_iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ventana(iso: str, antes_h: float, despues_h: float | None = None) -> tuple[str, str]:
    """(desde, hasta) en ISO UTC alrededor de un instante."""
    t = utc(iso)
    despues_h = antes_h if despues_h is None else despues_h
    return a_iso(t - dt.timedelta(hours=antes_h)), a_iso(t + dt.timedelta(hours=despues_h))


def en_horario(t: dt.datetime, desde_h: int, hasta_h: int) -> bool:
    """Lunes a viernes, de desde_h a hasta_h (hora local de `t`)."""
    return t.weekday() < 5 and desde_h <= t.hour < hasta_h


def local_desde_texto(texto: str) -> dt.datetime:
    """Fecha del calendario de cambios («2026-10-08 08:00», hora local)."""
    return dt.datetime.strptime(texto, "%Y-%m-%d %H:%M").replace(tzinfo=MADRID)


# =============================================================================================== inventario
# 02_inventario se carga una sola vez.

def _csv(nombre: str) -> list[dict]:
    with open(DATASET / "02_inventario" / nombre, encoding="utf-8") as f:
        return list(csv.DictReader(f))


ACTIVOS = {r["hostname"].upper(): r for r in _csv("activos.csv")}          # hostname (mayúsculas) → fila
IP_A_HOST = {a["ip"]: h for h, a in ACTIVOS.items()}
USUARIOS = {r["username"].lower() for r in _csv("usuarios.csv")}
ZONAS = {r["zona"]: ipaddress.ip_network(r["cidr"]) for r in _csv("zonas_red.csv")}
SERVICIOS = _csv("servicios_negocio.csv")
_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def ip_de(host: str) -> str | None:
    return ACTIVOS.get(host.upper(), {}).get("ip")


def zona_de_ip(ip: str) -> str | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return next((z for z, red in ZONAS.items() if a in red), None)


def es_interna(ip: str) -> bool:
    """Solo RFC 1918. No vale ip.is_private: marca como privados los rangos de documentación (198.51.100.0/24,
    198.18.0.0/15...), que en este dataset son IPs externas de atacantes."""
    try:
        return any(ipaddress.ip_address(ip) in red for red in _RFC1918)
    except ValueError:
        return False


def servicio(nombre_o_recurso: str) -> dict | None:
    """Servicio de negocio por nombre (la CMDB añade texto tras el nombre) o por un recurso de su columna `activos`."""
    x = nombre_o_recurso.lower().strip()
    if not x:
        return None
    for s in SERVICIOS:
        if x.startswith(s["servicio"].lower()) or s["servicio"].lower().startswith(x):
            return s
    return next((s for s in SERVICIOS if x in s["activos"].lower()), None)


def responsable(activo: dict) -> str:
    s = servicio(activo.get("business_service", ""))
    return f"{s['responsable']} ({s['servicio']})" if s else ""


# =============================================================================================== entidades
# Campo `entities` de una alerta del SIEM, normalizado una sola vez.

def _unicos(valores) -> list:
    return list(dict.fromkeys(v for v in valores if v))


def de_alerta(alerta: dict) -> dict:
    """hosts / host_ips / users (UPN reales) / ips / domains / urls / hashes / cloud, sin duplicados y en orden."""
    e = alerta.get("entities", {})
    hosts = [x for x in e.get("hosts", []) if x.get("hostname")]
    nube = e.get("cloud") if isinstance(e.get("cloud"), dict) else {}
    return {
        "hosts": _unicos(x["hostname"] for x in hosts),
        "host_ips": {x["hostname"]: x.get("ip", "") for x in hosts},
        "users": _unicos(x.get("upn", "") for x in e.get("users", []) if "@" in x.get("upn", "")),  # sin «(12 cuentas)»
        "ips": _unicos(e.get("ips", [])),
        "domains": _unicos(d.lower() for d in e.get("domains", [])),
        "urls": _unicos(e.get("urls", [])),
        "hashes": _unicos(f.get("sha256") for f in e.get("files", [])),
        "cloud": nube,
    }


def fusionar(alertas: list[dict]) -> dict:
    """Entidades de varias alertas (la primera manda en el orden)."""
    out = de_alerta(alertas[0])
    for a in alertas[1:]:
        otra = de_alerta(a)
        for k in ("hosts", "users", "ips", "domains", "urls", "hashes"):
            out[k] = _unicos(out[k] + otra[k])
        out["host_ips"] = {**otra["host_ips"], **out["host_ips"]}
        out["cloud"] = out["cloud"] or otra["cloud"]
    return out


# =============================================================================================== hallazgos
# Formato común de las comprobaciones deterministas: reglas internas (nivel 1) y cruce con cambios (nivel 2).

PERMITIDA, SOSPECHOSA, REQUIERE_INFO = "permitida", "sospechosa", "requiere_info"
INFORMATIVA = "informativa"  # hecho útil que no autoriza ni incumple nada (no bloquea plantillas ni veredictos)
SIMBOLO = {PERMITIDA: "✓", SOSPECHOSA: "⚠", REQUIERE_INFO: "?", INFORMATIVA: "ℹ"}


def hallazgo(regla: str, sujeto: str, estado: str, motivo: str, evidencias=(), dato_faltante: str = "",
             tipo: str = "regla_interna") -> dict:
    return {"tipo": tipo, "regla": regla, "sujeto": sujeto, "estado": estado, "motivo": motivo,
            "evidencias": sorted(set(evidencias)), "dato_faltante": dato_faltante}


def peor(estados: list[str]) -> str:
    return SOSPECHOSA if SOSPECHOSA in estados else REQUIERE_INFO if REQUIERE_INFO in estados else PERMITIDA


def resumen_estado(resultados: list[dict]) -> str:
    """Peor estado entre sospechosa, requiere_info y permitida (las informativas no cuentan); "" si no hay."""
    estados = [r["estado"] for r in resultados if r["estado"] != INFORMATIVA]
    return peor(estados) if estados else ""


def formatear(resultados: list[dict]) -> str:
    lineas = []
    for r in resultados:
        linea = f"{SIMBOLO[r['estado']]} [{r['estado']}] {r['regla']} — {r['sujeto']}: {r['motivo']}"
        if r["evidencias"]:
            linea += f" (evidencias: {', '.join(r['evidencias'][:6])})"
        if r["dato_faltante"]:
            linea += f" [falta: {r['dato_faltante']}]"
        lineas.append(linea)
    return "\n".join(lineas)
