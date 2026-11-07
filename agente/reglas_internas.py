"""[Nivel 1 · contexto de empresa] Reglas internas de Tarvia (empresa_tarvia.md, «Reglas internas que importan para
el triaje») comprobadas por código.

Cada comprobación devuelve un hallazgo con uno de tres estados:
- permitida:     cumple la regla o la cubre un cambio/flujo aprobado vigente.
- sospechosa:    incumple la regla y nada la cubre.
- requiere_info: faltan datos para decidir (se indica cuál). Nunca se da por buena.

Los datos salen de la API simulada (logs, CMDB, directorio, TIP, calendario de cambios) y de 02_inventario. Las horas se
evalúan en Europe/Madrid (el 25/10/2026 España pasa de UTC+2 a UTC+1). Las consultas quedan en la traza con
origen "reglas". El resultado se entrega al modelo como hechos verificados y se guarda en el ticket.
"""
import json
import re

from . import cambios
from . import herramientas as h
from .comun import (INFORMATIVA, PERMITIDA, REQUIERE_INFO, SOSPECHOSA, en_horario, hallazgo, ip_de, local, utc,
                    ventana, zona_de_ip)

__all__ = ["evaluar", "REGLAS", "hallazgo", "PERMITIDA", "SOSPECHOSA", "REQUIERE_INFO", "INFORMATIVA"]

# Valores fijados por empresa_tarvia.md
JUMP01 = "JUMP01"
ORIGENES_OT = {"ENG-WS01", "WMS01"}
NESSUS01 = "NESSUS01"
GESTORIA = "asesoria@gestoria-pons.example"
LOGISOFT = "ext.logisoft"
SVC_BACKUP = "svc_backup"
COMANDOS_RECONOCIMIENTO = re.compile(r"\b(whoami|net(\.exe)?\s+(user|group|localgroup|view)|nltest|dir\s+\\\\|"
                                     r"systeminfo|quser|ipconfig\s+/all|adfind|Get-ChildItem)", re.IGNORECASE)


# --------------------------------------------------------------------------------------------- acceso a datos
# Funciones pequeñas para que los tests puedan sustituirlas por datos sintéticos.

def _logs(fuente: str, q: str, desde: str = "", hasta: str = "", limit: int = 500) -> list[dict]:
    return h.eventos(fuente, q, desde, hasta, limit)


def _activo(clave: str) -> dict | None:
    return h.consultar_api("activo", f"/assets/{clave}")[0]


def _usuario(clave: str) -> dict | None:
    return h.consultar_api("usuario", f"/users/{clave}")[0]


def _intel(indicador: str) -> dict:
    return h.consultar_api("intel", f"/intel/{indicador}")[0] or {}


def cambios_vigentes(iso: str, *terminos: str) -> list[dict]:
    """Cambios o flujos aprobados vigentes en ese instante cuyo texto menciona alguno de los términos."""
    return cambios.vigentes(iso, *terminos)


def _ips_de(texto: str) -> list[str]:
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", texto)


# --------------------------------------------------------------------------------------------- regla 1: adm.*

def regla_cuentas_adm(alertas: list[dict]) -> list[dict]:
    """Las cuentas adm.* solo pueden usarse desde JUMP01."""
    regla = "Cuentas adm.* solo desde JUMP01"
    jump = {"ip": ip_de(JUMP01)}
    out = []
    cuentas = sorted({m.lower() for a in alertas for m in re.findall(r"\badm\.[a-z0-9_-]+", json.dumps(a))})
    for cuenta in cuentas:
        alerta = next(a for a in alertas if cuenta in json.dumps(a).lower())
        desde, hasta = ventana(alerta["created_at"], 24, 24)
        malos, dudosos, buenos = [], [], []

        # Origen declarado en la propia alerta (src/from_host junto a account/by)
        ev = alerta.get("evidence", {})
        if str(ev.get("account", ev.get("by", ""))).lower() == cuenta and (ev.get("src") or ev.get("from_host")):
            origen = (ev.get("src") or ev.get("from_host")).upper()
            (buenos if origen == JUMP01 else malos).append((alerta["alert_id"], f"origen {origen} según la alerta"))

        for e in _logs("idp_signins", cuenta, desde, hasta):
            origen = (e.get("device_id") or "").upper() or e.get("src_ip", "")
            if origen in (JUMP01, jump.get("ip")):
                buenos.append((e["event_id"], "inicio de sesión desde JUMP01"))
            else:
                malos.append((e["event_id"], f"inicio de sesión desde {origen or 'origen desconocido'}"))
        for e in _logs("ad_events", cuenta, desde, hasta):
            if e.get("subject", "").lower() != cuenta:
                continue
            (buenos if e.get("src_host", "").upper() == JUMP01 else malos).append(
                (e["event_id"], f"{e.get('event', 'evento AD')} desde {e.get('src_host')}"))
        for e in _logs("edr_events", cuenta, desde, hasta):
            host = e.get("hostname", "").upper()
            if host == JUMP01:
                buenos.append((e["event_id"], "ejecución en JUMP01"))
                continue
            # Se ejecuta en otro equipo: hay que saber desde dónde se abrió la sesión
            cambio = [c for c in cambios_vigentes(e["timestamp"], JUMP01) if "adm" in c["detalle"].lower()
                      and host.lower() in c["alcance"].lower()]
            activo = _activo(host) or {}
            d1, d2 = ventana(e["timestamp"], 10 / 60, 10 / 60)
            desde_jump = [f for f in _logs("firewall", jump.get("ip", "10.20.6.61"), d1, d2)
                          if f.get("dst_ip") == activo.get("ip")] if activo.get("ip") else []
            if cambio:
                buenos.append((e["event_id"], f"en {host}, cubierto por {cambio[0]['id']} (desde JUMP01)"))
            elif desde_jump:
                buenos.append((e["event_id"], f"en {host}, conexión previa desde JUMP01 ({desde_jump[0]['event_id']})"))
            else:
                dudosos.append((e["event_id"], f"en {host}, sin constancia de que la sesión viniera de JUMP01"))

        if malos:
            estado, motivo, evid = SOSPECHOSA, "; ".join(m for _, m in malos[:4]), [i for i, _ in malos]
        elif dudosos:
            estado, motivo, evid = REQUIERE_INFO, "; ".join(m for _, m in dudosos[:4]), [i for i, _ in dudosos]
        elif buenos:
            estado, motivo, evid = PERMITIDA, "; ".join(m for _, m in buenos[:4]), [i for i, _ in buenos]
        else:
            estado, motivo, evid = REQUIERE_INFO, "la alerta menciona la cuenta pero no hay eventos de uso en ±24 h", []
        out.append(hallazgo(regla, cuenta, estado, motivo, evid,
                            "origen de la sesión en el equipo destino" if estado == REQUIERE_INFO else ""))
    return out


# --------------------------------------------------------------------------------------------- regla 2: acceso remoto

def regla_acceso_remoto(alertas: list[dict]) -> list[dict]:
    """Solo TeamViewer Corporate gestionado por IT está aprobado; AnyDesk no."""
    regla = "Herramienta de acceso remoto aprobada"
    texto = json.dumps(alertas).lower()
    if not any(a["rule_id"] == "UC-EDR-005" for a in alertas) and not re.search(r"anydesk|teamviewer", texto):
        return []
    out = []
    for a in alertas:
        hosts = [x["hostname"] for x in a.get("entities", {}).get("hosts", []) if x.get("hostname")]
        users = [x["upn"].split("@")[0] for x in a.get("entities", {}).get("users", []) if x.get("upn")]
        desde, hasta = ventana(a["created_at"], 24, 24)
        anydesk, teamviewer = [], []
        for host in hosts:
            for e in _logs("edr_events", host, desde, hasta):
                p = f"{e.get('process_name', '')} {e.get('process_path', '')}".lower()
                if "anydesk" in p:
                    anydesk.append(e["event_id"])
                elif "teamviewer" in p:
                    teamviewer.append(e["event_id"])
        for clave in hosts + users:
            for fuente in ("proxy", "dns"):
                anydesk += [e["event_id"] for e in _logs(fuente, clave, desde, hasta)
                            if "anydesk" in json.dumps(e).lower()]
        sujeto = ", ".join(hosts + users) or a["alert_id"]
        if anydesk or "anydesk" in json.dumps(a).lower():
            out.append(hallazgo(regla, sujeto, SOSPECHOSA, "uso de AnyDesk, que no está aprobado (solo TeamViewer "
                                "Corporate gestionado por IT)", anydesk or [a["alert_id"]]))
        elif teamviewer or "teamviewer" in json.dumps(a).lower():
            out.append(hallazgo(regla, sujeto, REQUIERE_INFO, "TeamViewer detectado; no se puede verificar que sea la "
                                "instalación Corporate gestionada por IT", teamviewer or [a["alert_id"]],
                                "licencia o ID gestionado de TeamViewer"))
        elif a["rule_id"] == "UC-EDR-005":
            out.append(hallazgo(regla, sujeto, REQUIERE_INFO, "alerta de herramienta de acceso remoto sin identificar "
                                "la herramienta en los logs", [a["alert_id"]], "nombre de la herramienta"))
    return out


# --------------------------------------------------------------------------------------------- regla 3: OT

def regla_acceso_ot(alertas: list[dict]) -> list[dict]:
    """Solo ENG-WS01 y WMS01 pueden hablar con la red OT; cualquier otro acceso necesita un cambio aprobado."""
    regla = "Acceso a OT solo desde ENG-WS01/WMS01"
    out = []
    for a in alertas:
        ev, txt = a.get("evidence", {}), json.dumps(a)
        hacia_ot = (ev.get("dst_zone") == "LOGISTICS-OT" or a["rule_id"] == "UC-OT-001"
                    or any(zona_de_ip(ip) == "LOGISTICS-OT" for ip in _ips_de(txt)))
        if not hacia_ot:
            continue
        hosts = [x for x in a.get("entities", {}).get("hosts", []) if x.get("hostname")]
        origen = str(ev.get("src") or (hosts[0]["hostname"] if hosts else "")).upper()
        ip_origen = next((x.get("ip") for x in hosts if x["hostname"].upper() == origen), "")
        if not origen:
            out.append(hallazgo(regla, a["alert_id"], REQUIERE_INFO, "tráfico hacia OT sin origen identificable",
                                [a["alert_id"]], "equipo de origen"))
            continue
        if zona_de_ip(ip_origen) == "LOGISTICS-OT" and origen not in ORIGENES_OT:
            continue  # el propio activo es OT (no es acceso hacia OT desde fuera)
        desde, hasta = ventana(a["created_at"], 1, 1)
        eventos = [f["event_id"] for f in _logs("firewall", ip_origen, desde, hasta)
                   if zona_de_ip(f.get("dst_ip", "")) == "LOGISTICS-OT"] if ip_origen else []
        if origen in ORIGENES_OT:
            out.append(hallazgo(regla, origen, PERMITIDA, f"{origen} es un origen autorizado para OT",
                                eventos or [a["alert_id"]]))
            continue
        de_ot = [c for c in cambios_vigentes(a["created_at"], origen)
                 if re.search(r"\bOT\b|PLC|HMI|SORT", f"{c['titulo']} {c['detalle']} {c['alcance']}", re.I)]
        if de_ot:
            out.append(hallazgo(regla, origen, PERMITIDA, f"acceso a OT desde {origen} cubierto por el cambio "
                                f"aprobado {de_ot[0]['id']} ({de_ot[0]['titulo']})",
                                (eventos or [a["alert_id"]]) + [de_ot[0]["id"]]))
        else:
            out.append(hallazgo(regla, origen, SOSPECHOSA, f"{origen} accede a OT sin ser ENG-WS01/WMS01 y sin cambio "
                                "aprobado vigente", eventos or [a["alert_id"]]))
    return out


# --------------------------------------------------------------------------------------------- regla 4: NESSUS01

def regla_escaner_nessus(alertas: list[dict]) -> list[dict]:
    """NESSUS01 escanea todas las redes salvo OT cada miércoles de 01:00 a 05:00 (hora local)."""
    regla = "Escaneo de NESSUS01 en su ventana y sin OT"
    nessus = {"ip": ip_de(NESSUS01)}
    out = []
    for a in alertas:
        if NESSUS01.lower() not in json.dumps(a).lower() and nessus.get("ip", "~") not in json.dumps(a):
            continue
        t = local(a["created_at"])
        en_ventana = t.weekday() == 2 and 1 <= t.hour < 5
        desde, hasta = ventana(a["created_at"], 1, 1)
        a_ot = [f["event_id"] for f in _logs("firewall", nessus.get("ip", "10.20.6.62"), desde, hasta)
                if zona_de_ip(f.get("dst_ip", "")) == "LOGISTICS-OT"]
        a_ot += [a["alert_id"]] if any(zona_de_ip(ip) == "LOGISTICS-OT" for ip in _ips_de(json.dumps(a))) else []
        hora = t.strftime("%A %H:%M").replace("Wednesday", "miércoles")
        if a_ot:
            out.append(hallazgo(regla, NESSUS01, SOSPECHOSA, "NESSUS01 ha contactado con la red OT, que está excluida "
                                "del escaneo", a_ot))
        elif en_ventana:
            cambio = cambios_vigentes(a["created_at"], NESSUS01)
            out.append(hallazgo(regla, NESSUS01, PERMITIDA, f"escaneo en la ventana autorizada ({hora} local)"
                                + (f"; {cambio[0]['id']}" if cambio else ""),
                                [a["alert_id"]] + ([cambio[0]["id"]] if cambio else [])))
        else:
            cambio = cambios_vigentes(a["created_at"], NESSUS01)
            if cambio:
                out.append(hallazgo(regla, NESSUS01, PERMITIDA, f"fuera de la ventana semanal pero cubierto por "
                                    f"{cambio[0]['id']}", [a["alert_id"], cambio[0]["id"]]))
            else:
                out.append(hallazgo(regla, NESSUS01, SOSPECHOSA, f"actividad de NESSUS01 fuera de su ventana "
                                    f"(miércoles 01:00-05:00); hora local {t.strftime('%a %d %H:%M')}", [a["alert_id"]]))
    return out


# --------------------------------------------------------------------------------------------- regla 5: nóminas

def _distancia(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def regla_nominas_gestoria(alertas: list[dict]) -> list[dict]:
    """Los envíos de nóminas a asesoria@gestoria-pons.example son un flujo aprobado (FLUJO-0007, de Personas)."""
    regla = "Envío de nóminas a la gestoría autorizada"
    dominio_ok = GESTORIA.split("@")[1]
    out = []
    for a in alertas:
        ev = a.get("evidence", {})
        destinos = {str(v).lower() for k, v in ev.items() if k in ("recipient", "destination") and "@" in str(v)}
        for e in a.get("related_events", []):
            if e.startswith("DLP-"):
                destinos |= {x.get("destination", "").lower() for x in _logs("dlp", e) if "@" in x.get("destination", "")}
        for destino in sorted(destinos):
            dominio = destino.split("@")[1]
            if destino != GESTORIA and dominio != dominio_ok and (_distancia(dominio, dominio_ok) <= 2
                                                                 or "gestoria" in dominio or "pons" in dominio):
                out.append(hallazgo(regla, destino, SOSPECHOSA, f"destino parecido al de la gestoría autorizada "
                                    f"({GESTORIA}) pero distinto: posible suplantación", [a["alert_id"]]))
                continue
            if destino != GESTORIA:
                continue  # la regla no aplica a otros destinos
            flujo = cambios_vigentes(a["created_at"], GESTORIA)
            remitentes = [x["upn"] for x in a.get("entities", {}).get("users", []) if x.get("upn")]
            if not flujo:
                out.append(hallazgo(regla, destino, REQUIERE_INFO, "no hay flujo aprobado vigente para la gestoría en "
                                    "esa fecha", [a["alert_id"]], "flujo aprobado vigente"))
                continue
            solicitante = flujo[0].get("solicitante", "")
            for upn in remitentes or [""]:
                u = _usuario(upn) if upn else None
                if not u:
                    out.append(hallazgo(regla, upn or destino, REQUIERE_INFO, "no se puede identificar al remitente",
                                        [a["alert_id"], flujo[0]["id"]], "departamento del remitente"))
                elif u.get("department") == solicitante:
                    out.append(hallazgo(regla, upn, PERMITIDA, f"flujo aprobado {flujo[0]['id']}: remitente de "
                                        f"{solicitante} ({u.get('title')}) a la gestoría autorizada",
                                        [a["alert_id"], flujo[0]["id"]]))
                else:
                    out.append(hallazgo(regla, upn, REQUIERE_INFO, f"destino autorizado, pero el flujo {flujo[0]['id']} "
                                        f"es de {solicitante} y el remitente es de {u.get('department')}",
                                        [a["alert_id"], flujo[0]["id"]], f"autorización de {u.get('department')} "
                                        "para usar el flujo de nóminas"))
    return out


# --------------------------------------------------------------------------------------------- regla 6: ext.logisoft

def regla_logisoft(alertas: list[dict]) -> list[dict]:
    """ext.logisoft: VPN de lunes a viernes de 8 a 18 h (hora local), solo a WMS01."""
    regla = "Acceso de ext.logisoft en horario y solo a WMS01"
    if not any(LOGISOFT in json.dumps(a).lower() for a in alertas):
        return []
    wms = {"ip": ip_de("WMS01")}
    historico = _logs("vpn", LOGISOFT, limit=2000)
    # Origen habitual: IPs con al menos 3 conexiones dentro del horario contractual (la IP oficial no está documentada)
    conteo: dict[str, int] = {}
    for e in historico:
        if en_horario(local(e["timestamp"]), 8, 18):
            conteo[e["src_ip"]] = conteo.get(e["src_ip"], 0) + 1
    habituales = {ip for ip, n in conteo.items() if n >= 3}
    out = []
    for a in alertas:
        if LOGISOFT not in json.dumps(a).lower():
            continue
        t_alerta = utc(a["created_at"])
        cercanas = sorted((e for e in historico if abs((utc(e["timestamp"]) - t_alerta).total_seconds()) <= 6 * 3600),
                          key=lambda e: abs((utc(e["timestamp"]) - t_alerta).total_seconds()))
        if not cercanas:
            out.append(hallazgo(regla, LOGISOFT, REQUIERE_INFO, "no hay conexiones VPN de ext.logisoft cerca de la "
                                "alerta", [a["alert_id"]], "registro VPN de la conexión"))
            continue
        e = cercanas[0]
        t = local(e["timestamp"])
        dentro_horario = en_horario(t, 8, 18)
        habitual = e["src_ip"] in habituales
        d1, d2 = ventana(e["timestamp"], 0, 4)
        destinos = [f for f in _logs("firewall", e.get("assigned_ip", "~"), d1, d2)] if e.get("assigned_ip") else []
        otros = [f for f in destinos if f.get("dst_ip") != wms.get("ip")]
        cambio = cambios_vigentes(e["timestamp"], LOGISOFT, "Logisoft")
        cuando = t.strftime("%a %d/%m %H:%M")
        evid = [e["event_id"]] + [f["event_id"] for f in otros or destinos][:3]
        if otros:
            estado, motivo = SOSPECHOSA, f"accede a destinos distintos de WMS01: {sorted({f['dst_ip'] for f in otros})}"
        elif cambio and habitual:
            estado, motivo = PERMITIDA, f"{cuando} fuera de horario pero cubierto por {cambio[0]['id']} desde su IP habitual"
            evid.append(cambio[0]["id"])
        elif not dentro_horario and not habitual:
            estado = SOSPECHOSA
            motivo = (f"{cuando} fuera de la ventana L-V 8-18 h y desde un origen no habitual "
                      f"({e['src_ip']}, {e.get('country')})")
        elif not dentro_horario:
            estado = SOSPECHOSA
            motivo = (f"{cuando} fuera de la ventana contractual L-V 8-18 h (origen habitual {e['src_ip']}) "
                      "sin cambio aprobado")
        elif not habitual:
            estado = REQUIERE_INFO
            motivo = f"en horario pero desde un origen no habitual ({e['src_ip']}, {e.get('country')})"
        else:
            estado = PERMITIDA
            motivo = f"{cuando} en horario, desde su origen habitual" + (" y solo a WMS01" if destinos else "")
        out.append(hallazgo(regla, f"{LOGISOFT} {cuando}", estado, motivo, evid,
                            "IP o ASN oficiales de Logisoft (no documentados)" if estado == REQUIERE_INFO else ""))
    return out


# --------------------------------------------------------------------------------------------- regla 7: svc_backup

def regla_svc_backup(alertas: list[dict]) -> list[dict]:
    """svc_backup está excluida de MFA (riesgo aceptado en 2024) y tiene permitida la VPN para mantenimiento del
    proveedor. La falta de MFA no es una infracción; se comprueba que la cuenta no se use desde orígenes anónimos o
    maliciosos ni de forma interactiva para reconocimiento."""
    regla = "svc_backup (sin MFA por riesgo aceptado): origen y uso"
    if not any(SVC_BACKUP in json.dumps(a).lower() for a in alertas):
        return []
    a = next(x for x in alertas if SVC_BACKUP in json.dumps(x).lower())
    desde, hasta = ventana(a["created_at"], 24, 24)
    accesos = [e for e in _logs("idp_signins", SVC_BACKUP, desde, hasta) if e.get("result") == "success"]
    accesos += [e for e in _logs("vpn", SVC_BACKUP, desde, hasta)]
    externos = {e["src_ip"] for e in accesos if e.get("src_ip") and not zona_de_ip(e["src_ip"])}
    malos, dudosos = [], []
    for ip in sorted(externos):
        i = _intel(ip)
        tip, geo = i.get("tip") or {}, i.get("geo") or {}
        evid = [e["event_id"] for e in accesos if e.get("src_ip") == ip]
        etiquetas = str(tip.get("tags", ""))
        if (geo.get("is_tor") == "True" or "tor" in etiquetas or "anonymizer" in etiquetas
                or tip.get("reputation") in ("malicious", "suspicious")):
            motivo_ip = "Tor" if geo.get("is_tor") == "True" else etiquetas or tip.get("reputation")
            malos.append((evid, f"acceso desde {ip} ({motivo_ip}, {geo.get('as_org', '')})"))
        else:
            dudosos.append((evid, f"acceso VPN desde {ip} ({geo.get('as_org', 'ASN desconocido')})"))
    recon = [e for e in _logs("edr_events", SVC_BACKUP, desde, hasta) if COMANDOS_RECONOCIMIENTO.search(
        f"{e.get('process_name', '')} {e.get('command_line', '')}")]
    if recon:
        malos.append(([e["event_id"] for e in recon], f"comandos de reconocimiento con la cuenta en "
                      f"{', '.join(sorted({e['hostname'] for e in recon}))}: "
                      + "; ".join(e.get("command_line", "")[:40] for e in recon[:3])))
    nota = " (la ausencia de MFA es un riesgo aceptado, no una infracción)"
    if malos:
        return [hallazgo(regla, SVC_BACKUP, SOSPECHOSA, "; ".join(m for _, m in malos) + nota,
                         [x for ev, _ in malos for x in ev])]
    if dudosos:
        return [hallazgo(regla, SVC_BACKUP, REQUIERE_INFO, "; ".join(m for _, m in dudosos) + nota,
                         [x for ev, _ in dudosos for x in ev], "IPs del proveedor de mantenimiento de copias")]
    return [hallazgo(regla, SVC_BACKUP, PERMITIDA, "sin accesos externos anómalos ni uso interactivo" + nota,
                     [a["alert_id"]])]


# --------------------------------------------------------------------------------------------- punto de entrada

REGLAS = [regla_cuentas_adm, regla_acceso_remoto, regla_acceso_ot, regla_escaner_nessus, regla_nominas_gestoria,
          regla_logisoft, regla_svc_backup]


def evaluar(alerta: dict, otras: list[dict] = ()) -> list[dict]:
    """Aplica las reglas internas a la alerta (y a las demás de su incidente). Devuelve solo las reglas que aplican."""
    alertas = [alerta] + list(otras)
    resultados = []
    with h.origen("reglas"):
        for regla in REGLAS:
            try:
                resultados += regla(alertas)
            except Exception as e:  # una regla que falla no debe parar el triaje: queda como requiere_info
                resultados.append(hallazgo(regla.__name__, alerta["alert_id"], REQUIERE_INFO,
                                           f"la comprobación falló: {e}", [], "repetir la comprobación"))
    return resultados
