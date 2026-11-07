"""Criticidad real y ajuste de la matriz de severidad (politica_soc.md, apartado 2), calculados por código.

El modelo propone el activo más crítico, su criticidad y el ajuste; aquí se recalculan con el inventario:
- Criticidad = la más alta entre los equipos afectados (CMDB), los servicios de negocio afectados
  (servicios_negocio.csv, también para recursos cloud como s3://tarvia-backups-prod) y las identidades.
- Identidades: Media. La política ya sube un nivel (+1) por identidad VIP o privilegiada; contarla además como
  criticidad Alta penalizaría dos veces.
- Ajuste -1 («un control lo bloqueó antes de producir efecto»): solo si todas las alertas del ticket constan como
  bloqueadas o en cuarentena.
- Ajuste +1 por identidad VIP o privilegiada afectada (directorio), en verdaderos positivos.
Si no hay ningún dato de inventario, se conserva la propuesta del modelo. Cada corrección se devuelve como nota.
"""
import csv

from . import herramientas as h
from .prompts import DATASET

ORDEN = ["Baja", "Media", "Alta", "Crítica"]
BLOQUEO = {"blocked", "quarantined", "bloqueado", "en cuarentena"}

with open(DATASET / "02_inventario" / "servicios_negocio.csv", encoding="utf-8") as _f:
    SERVICIOS = list(csv.DictReader(_f))


def _servicio(nombre_o_recurso: str) -> dict | None:
    """Servicio de negocio por nombre (prefijo, la CMDB añade texto) o por recurso listado en `activos`."""
    x = nombre_o_recurso.lower().strip()
    if not x:
        return None
    for s in SERVICIOS:
        if x.startswith(s["servicio"].lower()) or s["servicio"].lower().startswith(x):
            return s
    for s in SERVICIOS:
        if x in s["activos"].lower():
            return s
    return None


def _bloqueada(alerta: dict) -> bool:
    ev = alerta.get("evidence", {})
    acciones = {str(ev.get(k, "")).lower() for k in ("action", "edr_action", "dlp_action")}
    return bool(acciones & BLOQUEO) or ev.get("executed") is False


def revisar(t: dict, alertas: list[dict]) -> tuple[dict, list[str]]:
    """Devuelve la salida del modelo con criticidad/ajuste corregidos y las notas de lo que se cambió."""
    notas: list[str] = []
    candidatos: list[tuple[str, str, str]] = []  # (criticidad, objeto, fuente)
    origen_previo = h.ORIGEN
    h.ORIGEN = "politica"
    try:
        hosts = list(dict.fromkeys(t["affected"].get("hosts", []) + [
            x["hostname"] for a in alertas for x in a.get("entities", {}).get("hosts", []) if x.get("hostname")]))
        for host in hosts:
            activo, _ = h.consultar_api("activo", f"/assets/{host}")
            if activo and activo.get("criticality") in ORDEN:
                candidatos.append((activo["criticality"], host, "CMDB"))
                s = _servicio(activo.get("business_service", ""))
                if s and s["criticidad"] in ORDEN:
                    candidatos.append((s["criticidad"], s["servicio"], "servicios_negocio"))
        for nombre in t["affected"].get("business_services", []):
            s = _servicio(nombre)
            if s and s["criticidad"] in ORDEN:
                candidatos.append((s["criticidad"], s["servicio"], "servicios_negocio"))
        for a in alertas:
            nube = a.get("entities", {}).get("cloud")
            if isinstance(nube, dict) and nube.get("bucket"):
                s = _servicio(nube["bucket"])
                if s and s["criticidad"] in ORDEN:
                    candidatos.append((s["criticidad"], f"s3://{nube['bucket']} ({s['servicio']})", "servicios_negocio"))

        usuarios = list(dict.fromkeys(t["affected"].get("users", []) + [
            x["upn"] for a in alertas for x in a.get("entities", {}).get("users", []) if "@" in x.get("upn", "")]))
        privilegiados = []
        for upn in usuarios:
            u, _ = h.consultar_api("usuario", f"/users/{upn}")
            if u:
                candidatos.append(("Media", upn, "identidad"))
                if u.get("privileged") == "True" or u.get("vip") == "True":
                    privilegiados.append(f"{upn} ({'VIP' if u.get('vip') == 'True' else 'privilegiada'})")
    finally:
        h.ORIGEN = origen_previo

    t = dict(t)
    if candidatos:
        crit, objeto, fuente = max(candidatos, key=lambda c: ORDEN.index(c[0]))
        if (crit, objeto) != (t["criticidad"], t["activo_mas_critico"]):
            if crit != t["criticidad"]:
                notas.append(f"Criticidad {t['criticidad']} ({t['activo_mas_critico']}) → {crit} ({objeto}, según "
                             f"{fuente}) (apartado 2)")
            t.update(criticidad=crit, activo_mas_critico=objeto)
    else:
        notas.append(f"Sin datos de inventario de los afectados: se usa la criticidad propuesta ({t['criticidad']})")

    # Ajustes (apartado 2): máximo un nivel arriba o abajo en total
    baja = t["ajuste"] == "-1"
    if baja and not (alertas and all(_bloqueada(a) for a in alertas)):
        notas.append("Ajuste -1 descartado: no consta que un control bloqueara todas las alertas (apartado 2)")
        baja = False
    sube = t["ajuste"] == "+1"
    motivos = [t["motivo_ajuste"]] if t["ajuste"] != "0" and t["motivo_ajuste"] else []
    if not sube and privilegiados and t.get("verdict") == "true_positive":
        sube = True
        motivos = [f"identidad {privilegiados[0]}"]
        notas.append(f"Ajuste +1 por identidad {privilegiados[0]} (apartado 2)")
    neto = int(sube) - int(baja)
    nuevo = {1: "+1", 0: "0", -1: "-1"}[neto]
    if nuevo == "0" and sube and baja:
        notas.append("Ajustes +1 y -1 se compensan: ajuste neto 0 (apartado 2)")
        motivos = []
    t.update(ajuste=nuevo, motivo_ajuste="; ".join(motivos) if nuevo != "0" else "")
    return t, notas
