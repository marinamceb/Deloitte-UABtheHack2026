"""[Nivel 2 · actividad autorizada] Cruce determinista de alertas con el calendario de cambios aprobados
(02_inventario/calendario_cambios.csv).

Cada cambio se interpreta en:
- ventana: inicio-fin en hora local (Europe/Madrid) y, si el detalle dice «diariamente HH:MM-HH:MM», esa franja diaria;
- orígenes autorizados: IPs y rangos («192.0.2.10-12»), equipos y cuentas (svc_*, ext.*, adm.*; «cuenta adm» = adm.*)
  nombrados en el detalle;
- alcance: equipos del campo alcance (con rangos «WEB-ECOM01..04»), dominios, o una categoría genérica
  («Servidores Windows», «Todos los puestos», «Todas las redes salvo OT», «Directorio activo»), resuelta con activos.csv.

Resultado por alerta (mismo formato de hallazgo que reglas_internas, tipo "cambio"):
- permitida:     cambio vigente con origen autorizado (y alcance, si lo define), o citado por la alerta con ventana y
                 alcance verificados.
- informativa:   hay un cambio vigente sobre el mismo objetivo pero el origen no es el autorizado (no lo cubre).
- requiere_info: la alerta cita un cambio vigente pero el activo queda fuera de su alcance.
- sospechosa:    la alerta cita un cambio que no existe o que no está vigente en ese momento.
Los FLUJO-* (flujos de datos) los evalúa la regla de nóminas de reglas_internas, no este módulo.
"""
import json
import re

from . import herramientas as h
from .comun import (ACTIVOS, INFORMATIVA, IP_A_HOST, PERMITIDA, REQUIERE_INFO, SOSPECHOSA, de_alerta, hallazgo,
                    local, local_desde_texto)

RE_ID = re.compile(r"\b(?:CHG-\d{4}-\d+|FLUJO-\d+)\b")
RE_IP = re.compile(r"\b((?:\d{1,3}\.){3})(\d{1,3})(?:-(\d{1,3}))?\b")
RE_HOST = re.compile(r"\b([A-Z][A-Z0-9]*(?:-[A-Z0-9]*[A-Z][A-Z0-9]*)*-?[A-Z]*)(\d{2,})(?:\.\.(\d{2,}))?\b")
RE_CUENTA = re.compile(r"\b((?:svc|ext|adm)[._][a-z0-9_.]*[a-z0-9])\b", re.IGNORECASE)
RE_DOMINIO = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:example|com|net|org|es))\b")
RE_FRANJA = re.compile(r"(?:diariamente|cada d[ií]a)\D*(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})", re.IGNORECASE)
CATEGORIAS = {
    "servidores windows": lambda a: "windows server" in a.get("os", "").lower(),
    "todos los puestos": lambda a: a.get("type") == "Portátil",
    "todas las redes salvo ot": lambda a: a.get("zone") != "LOGISTICS-OT",
    "directorio activo": lambda a: a.get("type") == "Controlador de dominio",
}
# Categorías que también se cumplen por el tipo de alerta, aunque no nombre ningún equipo destino
CATEGORIA_POR_FUENTE = {"directorio activo": {"AD"}}
# Palabras clave de cambios que relacionan una alerta con un cambio cuyo alcance es genérico (p. ej. SCCM)
RE_CLAVE = re.compile(r"\b(?:[A-Z]{3,}[0-9]*|PsExec|EncodedCommand)\b")
CLAVES_GENERICAS = {"VPN", "IPS", "DOS", "API", "WMS", "EDR", "CHG"}


def _expandir_ips(texto: str) -> set[str]:
    out = set()
    for base, ini, fin in RE_IP.findall(texto):
        for n in range(int(ini), int(fin or ini) + 1):
            out.add(f"{base}{n}")
    return out


def _expandir_hosts(texto: str) -> set[str]:
    out = set()
    for prefijo, ini, fin in RE_HOST.findall(texto):
        for n in range(int(ini), int(fin or ini) + 1):
            nombre = f"{prefijo}{n:0{len(ini)}d}".upper()
            if nombre in ACTIVOS:  # descarta tokens que no son equipos (p. ej. OT-MAINT-TEMP)
                out.add(nombre)
    return out


def interpretar(c: dict) -> dict:
    detalle, alcance = c.get("detalle", ""), c.get("alcance", "")
    cuentas = {x.lower() for x in RE_CUENTA.findall(detalle)}
    if re.search(r"cuenta\s+adm\b", detalle, re.IGNORECASE):
        cuentas.add("adm.*")
    franja = RE_FRANJA.search(detalle)
    return {
        "id": c["id"], "titulo": c.get("titulo", ""), "detalle": detalle, "alcance": alcance,
        "solicitante": c.get("solicitante", ""),
        "inicio": local_desde_texto(c["inicio"]), "fin": local_desde_texto(c["fin"]),
        "franja": tuple(int(x) for x in franja.groups()) if franja else None,
        "origen_ips": _expandir_ips(detalle),
        "origen_hosts": _expandir_hosts(detalle),
        "origen_cuentas": cuentas,
        "alcance_hosts": _expandir_hosts(alcance),
        "alcance_dominios": set(RE_DOMINIO.findall(detalle.lower())) | set(RE_DOMINIO.findall(alcance.lower())),
        "alcance_categoria": next((k for k in CATEGORIAS if k in alcance.lower()), None),
    }


_CACHE: list[dict] | None = None


def calendario() -> list[dict]:
    global _CACHE
    if _CACHE is None:
        datos, _ = h.consultar_api("cambios", "/changes", {"q": ""})
        _CACHE = []
        for c in datos or []:
            try:
                _CACHE.append(interpretar(c))
            except (KeyError, ValueError):
                continue
    return _CACHE


def vigente(c: dict, iso: str) -> bool:
    t = local(iso)
    if not c["inicio"] <= t <= c["fin"]:
        return False
    if c["franja"]:
        h1, m1, h2, m2 = c["franja"]
        return (h1, m1) <= (t.hour, t.minute) <= (h2, m2)
    return True


def vigentes(iso: str, *terminos: str) -> list[dict]:
    """Cambios y flujos vigentes en ese instante cuyo título, detalle o alcance menciona alguno de los términos."""
    def texto(c):
        return f"{c['titulo']} {c['detalle']} {c['alcance']}".lower()
    return [c for c in calendario() if vigente(c, iso) and any(t and t.lower() in texto(c) for t in terminos)]


def por_id(id_cambio: str) -> dict | None:
    return next((c for c in calendario() if c["id"] == id_cambio), None)


def citados(texto: str) -> set[str]:
    return set(RE_ID.findall(texto))


def entidades(alerta: dict) -> dict:
    """IPs, equipos, cuentas y dominios de la alerta (entidades y campos de evidencia)."""
    base, ev = de_alerta(alerta), alerta.get("evidence", {})
    ips = set()
    for ip in base["ips"]:
        ips |= _expandir_ips(ip) or {ip}   # «10.40.16.21-26» → seis IPs
    hosts = {x.upper() for x in base["hosts"]}
    hosts |= {IP_A_HOST[ip] for ip in ips if ip in IP_A_HOST}  # IPs internas → equipo del inventario
    hosts |= {str(ev[k]).upper() for k in ("src", "dst", "from_host") if ev.get(k) and str(ev[k]).upper() in ACTIVOS}
    cuentas = {u.split("@")[0].lower() for u in base["users"]}
    cuentas |= {str(ev[k]).lower() for k in ("by", "account", "user") if ev.get(k)}
    if base["cloud"].get("identity"):
        cuentas.add(base["cloud"]["identity"].lower())
    dominios = set(base["domains"]) | {re.sub(r"^https?://", "", u).split("/")[0].lower() for u in base["urls"]}
    origenes = {str(ev[k]).upper() for k in ("src", "from_host") if ev.get(k)}
    return {"ips": ips, "hosts": hosts, "cuentas": cuentas, "dominios": dominios, "origenes": origenes,
            "fuente": alerta.get("source_product", ""), "texto": json.dumps(ev, ensure_ascii=False)}


def _origen(c: dict, ent: dict) -> tuple[bool, bool]:
    """(el cambio define orígenes, la alerta tiene alguno de ellos)."""
    define = bool(c["origen_ips"] or c["origen_hosts"] or c["origen_cuentas"])
    ips_hosts = {ACTIVOS[h]["ip"] for h in c["origen_hosts"] if h in ACTIVOS}
    coincide = bool(ent["ips"] & (c["origen_ips"] | ips_hosts) or ent["hosts"] & c["origen_hosts"]
                    or ent["cuentas"] & c["origen_cuentas"]
                    or ("adm.*" in c["origen_cuentas"] and any(x.startswith("adm.") for x in ent["cuentas"])))
    return define, coincide


def _alcance(c: dict, ent: dict) -> tuple[bool, bool, list[str]]:
    """(el cambio define alcance, la alerta lo toca, equipos de la alerta fuera de la categoría)."""
    define = bool(c["alcance_hosts"] or c["alcance_dominios"] or c["alcance_categoria"])
    coincide = bool(ent["hosts"] & c["alcance_hosts"] or ent["dominios"] & c["alcance_dominios"])
    fuera = []
    if c["alcance_categoria"]:
        regla = CATEGORIAS[c["alcance_categoria"]]
        destinos = [x for x in ent["hosts"] - ent["origenes"] if x in ACTIVOS]  # los equipos de origen no son alcance
        dentro = [x for x in destinos if regla(ACTIVOS[x])]
        fuera = [x for x in destinos if not regla(ACTIVOS[x])]
        por_fuente = ent["fuente"] in CATEGORIA_POR_FUENTE.get(c["alcance_categoria"], set())
        coincide = coincide or bool(dentro) or por_fuente
        if por_fuente:
            fuera = []
    return define, coincide, fuera


def _claves(c: dict) -> set[str]:
    return {x for x in RE_CLAVE.findall(f"{c['titulo']} {c['detalle']}") if x.upper() not in CLAVES_GENERICAS}


def evaluar(alerta: dict, ya_evaluados: set[str] = frozenset()) -> list[dict]:
    """Hallazgos de cambios para una alerta. `ya_evaluados`: ids que ya cita otra comprobación (no se repiten)."""
    ent = entidades(alerta)
    cita = {x for x in citados(json.dumps(alerta.get("evidence", {}))) if not x.startswith("FLUJO-")}
    out = []

    for id_cambio in sorted(cita):
        c = por_id(id_cambio)
        if not c:
            out.append(hallazgo("Cambio citado en la alerta", id_cambio, SOSPECHOSA, f"la alerta cita {id_cambio}, que no "
                                "existe en el calendario de cambios", [alerta["alert_id"]], tipo="cambio"))
        elif not vigente(c, alerta["created_at"]):
            out.append(hallazgo("Cambio citado en la alerta", id_cambio, SOSPECHOSA, f"la alerta cita {id_cambio} "
                                f"({c['titulo']}), pero ocurre fuera de su ventana ({c['inicio']:%d/%m %H:%M}-"
                                f"{c['fin']:%d/%m %H:%M} local)", [alerta["alert_id"], id_cambio], tipo="cambio"))
        elif id_cambio not in ya_evaluados:
            _, toca, fuera = _alcance(c, ent)
            if fuera:
                out.append(hallazgo("Cambio citado en la alerta", id_cambio, REQUIERE_INFO, f"{id_cambio} ({c['titulo']}) "
                                    f"está vigente, pero {', '.join(fuera)} queda fuera de su alcance "
                                    f"(«{c['alcance_categoria']}» según activos.csv)", [alerta["alert_id"], id_cambio],
                                    "confirmación de que el cambio incluía ese activo", tipo="cambio"))
            else:
                out.append(hallazgo("Cambio citado en la alerta", id_cambio, PERMITIDA, f"{id_cambio} ({c['titulo']}) "
                                    f"vigente y con el activo dentro de su alcance; detalle del cambio: «{c['detalle']}»",
                                    [alerta["alert_id"], id_cambio], tipo="cambio"))

    for c in calendario():
        ya_visto = c["id"] in cita or c["id"] in ya_evaluados or c["id"].startswith("FLUJO-")
        if ya_visto or not vigente(c, alerta["created_at"]):
            continue
        def_origen, origen_ok = _origen(c, ent)
        def_alcance, alcance_ok, fuera = _alcance(c, ent)
        if def_origen and origen_ok and (not def_alcance or alcance_ok or not (ent["hosts"] or ent["dominios"])):
            out.append(hallazgo("Cambio aprobado vigente", c["id"], PERMITIDA, f"{c['id']} ({c['titulo']}): origen "
                                f"autorizado y dentro de su ventana; detalle: «{c['detalle']}»",
                                [alerta["alert_id"], c["id"]], tipo="cambio"))
        elif def_origen and not origen_ok and alcance_ok and (
                c["alcance_hosts"] or c["alcance_dominios"]
                or any(re.search(rf"\b{re.escape(k)}\b", ent["texto"], re.IGNORECASE) for k in _claves(c))):
            autorizados = sorted(c["origen_ips"] | c["origen_hosts"] | c["origen_cuentas"])
            out.append(hallazgo("Cambio aprobado vigente", c["id"], INFORMATIVA, f"{c['id']} ({c['titulo']}) está en curso "
                                f"sobre el mismo objetivo, pero el origen de la alerta no es el autorizado "
                                f"({', '.join(autorizados[:4])}): no la cubre", [alerta["alert_id"], c["id"]], tipo="cambio"))
    return out


def ids_que_cubren(alerta: dict) -> set[str]:
    """Cambios que cubren la alerta (origen autorizado, o citado por la alerta con ventana y alcance verificados), para
    agruparla en un único incidente autorizado."""
    return {r["sujeto"] for r in evaluar(alerta) if r["estado"] == PERMITIDA}
