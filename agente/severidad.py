"""[Nivel 2 · matriz con criticidad real] Criticidad real y ajuste de la matriz de severidad (politica_soc.md,
apartado 2), calculados por código.

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
from . import herramientas as h
from .comun import fusionar, servicio as _servicio

ORDEN = ["Baja", "Media", "Alta", "Crítica"]

# =============================================================================================== matriz (apartado 2)

NIVELES = ["informational", "low", "medium", "high", "critical"]
ACCIONES_BLOQUEO = {"blocked", "quarantined", "bloqueado", "en cuarentena"}  # control que impidió el efecto

# Matriz del apartado 2 de politica_soc.md: severidad de la regla × criticidad del activo/identidad
MATRIZ = {
    "informational": {"Baja": "informational", "Media": "informational", "Alta": "low", "Crítica": "low"},
    "low": {"Baja": "informational", "Media": "low", "Alta": "low", "Crítica": "medium"},
    "medium": {"Baja": "low", "Media": "medium", "Alta": "medium", "Crítica": "high"},
    "high": {"Baja": "medium", "Media": "high", "Alta": "high", "Crítica": "critical"},
    "critical": {"Baja": "high", "Media": "critical", "Alta": "critical", "Crítica": "critical"},
}


def calcular_severidad(severidad_regla: str, t: dict) -> tuple[str, str]:
    """Aplica la matriz y los ajustes de la política. Devuelve (severidad, explicación)."""
    base = MATRIZ.get(severidad_regla, MATRIZ["medium"])[t["criticidad"]]
    texto = f"Regla {severidad_regla} × {t['activo_mas_critico']} ({t['criticidad']}) = {base}"
    if t["verdict"] == "false_positive":
        return "informational", texto + "; falso positivo → informational"
    if t["verdict"] == "benign_true_positive":
        final = "low" if NIVELES.index(base) >= NIVELES.index("high") else "informational"
        return final, texto + f"; actividad autorizada → {final}"
    paso = int(t["ajuste"])
    final = NIVELES[max(0, min(len(NIVELES) - 1, NIVELES.index(base) + paso))]
    if paso:
        texto += f"; {t['ajuste']} ({t['motivo_ajuste']}) → {final}"
    return final, texto


# ==================== criticidad real y ajustes


def _bloqueada(alerta: dict) -> bool:
    ev = alerta.get("evidence", {})
    acciones = {str(ev.get(k, "")).lower() for k in ("action", "edr_action", "dlp_action")}
    # «Bloqueado antes de producir efecto»: acción de bloqueo, no ejecutado, o ataque de credenciales sin ningún éxito
    return bool(acciones & ACCIONES_BLOQUEO) or ev.get("executed") is False or ev.get("success_count") == 0


def candidatos_criticidad(hosts, servicios, buckets, usuarios, activo_de, usuario_de):
    """Criticidades de lo afectado y las identidades VIP/privilegiadas. `activo_de` y `usuario_de` dicen de dónde
    leer la ficha: la API tras el triaje (revisar) o el inventario local para la cola (cola.py).
    Devuelve ([(criticidad, objeto, fuente)], [identidades VIP o privilegiadas])."""
    candidatos, privilegiados = [], []

    def por_servicio(nombre, etiqueta=None):
        s = _servicio(nombre)
        if s and s["criticidad"] in ORDEN:
            candidatos.append((s["criticidad"], etiqueta or s["servicio"], "servicios_negocio"))

    for host in hosts:
        activo = activo_de(host)
        if activo and activo.get("criticality") in ORDEN:
            candidatos.append((activo["criticality"], host, "CMDB"))
            por_servicio(activo.get("business_service", ""))
    for nombre in servicios:
        por_servicio(nombre)
    for bucket in buckets:
        s = _servicio(bucket)
        por_servicio(bucket, f"s3://{bucket} ({s['servicio']})" if s else None)
    for upn in usuarios:
        u = usuario_de(upn)
        if u:
            candidatos.append(("Media", upn, "identidad"))
            if u.get("privileged") == "True" or u.get("vip") == "True":
                privilegiados.append(f"{upn} ({'VIP' if u.get('vip') == 'True' else 'privilegiada'})")
    return candidatos, privilegiados


def _buckets(alertas: list[dict]) -> list[str]:
    nubes = (a.get("entities", {}).get("cloud") for a in alertas)
    return [n["bucket"] for n in nubes if isinstance(n, dict) and n.get("bucket")]


def revisar(t: dict, alertas: list[dict]) -> tuple[dict, list[str]]:
    """Devuelve la salida del modelo con criticidad/ajuste corregidos y las notas de lo que se cambió."""
    notas: list[str] = []
    e = fusionar(alertas) if alertas else {"hosts": [], "users": [], "cloud": {}}
    with h.origen("politica"):
        candidatos, privilegiados = candidatos_criticidad(
            hosts=list(dict.fromkeys(t["affected"].get("hosts", []) + e["hosts"])),
            servicios=t["affected"].get("business_services", []),
            buckets=_buckets(alertas),
            usuarios=list(dict.fromkeys(t["affected"].get("users", []) + e["users"])),
            activo_de=lambda x: h.consultar_api("activo", f"/assets/{x}")[0],
            usuario_de=lambda x: h.consultar_api("usuario", f"/users/{x}")[0])

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
