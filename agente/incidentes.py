"""Agrupación determinista de alertas en incidentes candidatos, antes de llamar al modelo.

1. Se aparta el ruido de fondo: alertas cuyo patrón (regla + campos estables de la evidencia, ver PATRONES_RUIDO) se
   repite >= UMBRAL_RUIDO veces en todo el SIEM. Ese ruido lo resuelven las plantillas; si se usara para enlazar,
   uniría cosas sin relación (p. ej. el inventario de SCCM y un correo reportado del mismo usuario).
2. Entre las alertas restantes se enlazan las que comparten una entidad exacta (equipo, usuario, IP, dominio, hash o
   identidad cloud) con menos de VENTANA_H horas entre una y la siguiente (enlace en cadena: un incidente puede durar
   días). Las entidades que aparecen en más de MAX_ALERTAS_ENTIDAD alertas (concentradores como wetransfer.com o
   la IP de salida corporativa) no enlazan.
   Las alertas cubiertas por el mismo cambio aprobado (por origen autorizado, ver cambios.py) se enlazan siempre:
   son una única actividad autorizada (p. ej. las alertas del pentest desde tres IPs).
3. Las componentes conexas son los incidentes candidatos. El modelo los revisa y confirma qué alertas pertenecen al
   mismo ataque; el código solo propone.

Calibrado sobre el dataset: 10.585 alertas de ruido; de las 476 restantes, 116 se agrupan en 28 incidentes.
"""
import collections
import datetime as dt
import json

import requests

from .herramientas import API_URL
from .plantillas import FIRMAS

PATRONES_RUIDO = {
    **FIRMAS,
    "UC-EDR-001": ["process_tree", "signer", "edr_action"],                       # Excel > saplogon firmado por SAP
    "UC-IDP-001": ["previous_login", "minutes_between", "device", "distance_km", "note", "post_login_actions"],
}
UMBRAL_RUIDO = 20
VENTANA_H = 72
MAX_ALERTAS_ENTIDAD = 15

_ALERTAS: dict[str, dict] | None = None
_INCIDENTES: dict[str, list[str]] | None = None  # alert_id → alert_ids del incidente (ordenados por fecha)


def todas_las_alertas() -> dict[str, dict]:
    global _ALERTAS
    if _ALERTAS is None:
        r = requests.get(f"{API_URL}/alerts", params={"status": "new", "limit": 100000}, timeout=120)
        r.raise_for_status()
        _ALERTAS = {a["alert_id"]: a for a in r.json()["items"]}
    return _ALERTAS


def _patron(a: dict) -> str | None:
    campos = PATRONES_RUIDO.get(a.get("rule_id", ""))
    if not campos:
        return None
    ev = a.get("evidence", {})
    return a["rule_id"] + "|" + json.dumps({c: ev.get(c) for c in campos}, ensure_ascii=False, sort_keys=True)


def entidades(a: dict) -> set[str]:
    e = a.get("entities", {})
    out = set()
    for x in e.get("hosts", []):
        if x.get("hostname"):
            out.add("host:" + x["hostname"].lower())
    for x in e.get("users", []):
        if "@" in x.get("upn", ""):  # descarta marcadores como "(12 cuentas)"
            out.add("user:" + x["upn"].lower())
    out |= {"ip:" + ip for ip in e.get("ips", [])}
    out |= {"dom:" + d.lower() for d in e.get("domains", [])}
    out |= {"hash:" + f["sha256"] for f in e.get("files", []) if f.get("sha256")}
    nube = e.get("cloud") if isinstance(e.get("cloud"), dict) else {}
    out |= {"cloud:" + nube[k] for k in ("identity", "bucket") if nube.get(k)}
    return out


def _fecha(a: dict) -> dt.datetime:
    return dt.datetime.fromisoformat(a["created_at"].replace("Z", "+00:00"))


def construir() -> dict[str, list[str]]:
    global _INCIDENTES
    if _INCIDENTES is not None:
        return _INCIDENTES
    alertas = todas_las_alertas()
    frec_patron = collections.Counter(p for a in alertas.values() if (p := _patron(a)))
    senal = [a for a in alertas.values() if not ((p := _patron(a)) and frec_patron[p] >= UMBRAL_RUIDO)]
    from . import cambios
    ent_alerta = {a["alert_id"]: entidades(a) | {"chg:" + c for c in cambios.ids_que_cubren(a)} for a in senal}
    frec_ent = collections.Counter(x for a in senal for x in ent_alerta[a["alert_id"]])

    padre = {a["alert_id"]: a["alert_id"] for a in senal}

    def raiz(x):
        while padre[x] != x:
            padre[x] = padre[padre[x]]
            x = padre[x]
        return x

    por_entidad = collections.defaultdict(list)
    for a in senal:
        for x in ent_alerta[a["alert_id"]]:
            if x.startswith("chg:") or frec_ent[x] <= MAX_ALERTAS_ENTIDAD:
                por_entidad[x].append(a)
    for x, lista in por_entidad.items():
        lista.sort(key=_fecha)
        for p, q in zip(lista, lista[1:]):
            if x.startswith("chg:") or (_fecha(q) - _fecha(p)).total_seconds() <= VENTANA_H * 3600:
                padre[raiz(p["alert_id"])] = raiz(q["alert_id"])

    grupos = collections.defaultdict(list)
    for aid in padre:
        grupos[raiz(aid)].append(aid)
    _INCIDENTES = {}
    for ids in grupos.values():
        if len(ids) > 1:
            ids.sort(key=lambda i: alertas[i]["created_at"])
            for i in ids:
                _INCIDENTES[i] = ids
    return _INCIDENTES


def incidente_de(alert_id: str) -> list[str]:
    """Alertas del incidente candidato de esta alerta (incluida), o [] si está sola o es ruido."""
    return construir().get(alert_id, [])


def resumen(alert_ids: list[str], excluir: str = "", maximo: int = 12) -> str:
    """Las alertas del incidente en formato compacto para el modelo (las más graves primero si hay que recortar)."""
    alertas = todas_las_alertas()
    orden = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    otras = [alertas[i] for i in alert_ids if i != excluir]
    elegidas = sorted(sorted(otras, key=lambda a: orden.get(a["severity"], 5))[:maximo], key=lambda a: a["created_at"])
    campos = ("alert_id", "created_at", "rule_id", "rule_name", "severity", "entities", "evidence", "related_events")
    lineas = [json.dumps({k: a.get(k) for k in campos}, ensure_ascii=False, separators=(",", ":")) for a in elegidas]
    if len(otras) > maximo:
        lineas.append(f"(y {len(otras) - maximo} alertas más de menor severidad; consúltalas con consultar_alerta)")
    return "\n".join(lineas)


def listar() -> list[list[str]]:
    vistos, out = set(), []
    for ids in construir().values():
        if ids[0] not in vistos:
            vistos.add(ids[0])
            out.append(ids)
    return sorted(out, key=lambda ids: todas_las_alertas()[ids[0]]["created_at"])
