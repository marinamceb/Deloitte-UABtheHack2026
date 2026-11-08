"""[Nivel 1 · priorización] Cola de triaje ordenada por prioridad, sin LLM.

Para cada incidente candidato (o alerta suelta) se estima la severidad con la matriz de la política (regla más grave ×
criticidad real según la CMDB y el directorio (API, con caché), +1 por identidad VIP o privilegiada), suponiendo lo peor (true_positive)
salvo que todas sus alertas estén cubiertas por un cambio aprobado (entonces, actividad autorizada), y el plazo del
SLA (politica_soc.md, apartado 3) desde la alerta más antigua. Orden:
  1. severidad estimada (critical primero),
  2. señal antes que ruido de fondo (patrones repetidos que resuelven las plantillas),
  3. incidentes de varias alertas antes que alertas sueltas (la correlación es una señal más fuerte),
  4. plazo del SLA (el que vence antes).
El ajuste -1 («un control lo bloqueó sin efecto») se aplica si todas las alertas constan bloqueadas.
Las alertas que ya están en un ticket se omiten, y un incidente ocupa un solo puesto (se tría una vez).
Así la cuota del LLM se gasta primero en lo importante; el ruido de baja severidad queda al final, donde además
lo resuelven las plantillas sin llamar al modelo.
"""
import datetime as dt

from . import api, incidentes
from .comun import fusionar, utc
from .severidad import NIVELES, ORDEN, _bloqueada, _buckets, calcular_severidad, candidatos_criticidad

# Fuentes cuyo objetivo es un servicio aunque la alerta no nombre ningún equipo (empresa_tarvia.md: el WAF protege la
# tienda online; Vela es el asistente de la web; los builds de la tienda corren en el CI)
SERVICIO_POR_FUENTE = {"WAF": "Tienda online y app", "ECOM": "Tienda online y app",
                       "AI_GATEWAY": "Asistente de compra con IA «Vela»", "CICD": "Integración continua"}
SLA = {"critical": dt.timedelta(minutes=15), "high": dt.timedelta(minutes=30), "medium": dt.timedelta(hours=4),
       "low": dt.timedelta(hours=24), "informational": dt.timedelta(hours=24)}  # informational: revisión diaria


def estimar(alertas: list[dict]) -> dict:
    """Severidad estimada, criticidad y plazo del SLA de un grupo de alertas (sin LLM; CMDB e identidades por la API,
    con caché: unas 2.000 consultas de ~1 ms la primera vez para toda la cola)."""
    e = fusionar(alertas)
    servicios = list(dict.fromkeys(SERVICIO_POR_FUENTE[f] for a in alertas
                                   if (f := a.get("source_product")) in SERVICIO_POR_FUENTE))
    candidatos, privilegiados = candidatos_criticidad(
        hosts=e["hosts"], servicios=servicios, buckets=_buckets(alertas), usuarios=e["users"],
        activo_de=lambda x: api.activo(x, trazar=False), usuario_de=lambda x: api.usuario(x, trazar=False))
    crit, objeto, _ = max(candidatos, key=lambda c: ORDEN.index(c[0])) if candidatos else ("Media", "sin inventario", "")
    regla = max((a.get("severity", "medium") for a in alertas), key=lambda s: NIVELES.index(s) if s in NIVELES else 2)
    cambios = set().union(*(incidentes.cubierta_por_cambio(a["alert_id"]) for a in alertas))
    autorizada = all(incidentes.cubierta_por_cambio(a["alert_id"]) for a in alertas)
    bloqueada = all(_bloqueada(a) for a in alertas)
    ajuste = int(bool(privilegiados)) - int(bloqueada)          # apartado 2: máximo un nivel en total
    motivo_ajuste = (f"identidad {privilegiados[0]}" if privilegiados and not bloqueada
                     else "bloqueado por un control" if bloqueada and not privilegiados else "")
    estimada, motivo = calcular_severidad(regla, {
        "verdict": "benign_true_positive" if autorizada else "true_positive", "criticidad": crit,
        "activo_mas_critico": objeto, "ajuste": {1: "+1", 0: "0", -1: "-1"}[ajuste], "motivo_ajuste": motivo_ajuste})
    if autorizada:
        motivo += f" ({', '.join(sorted(cambios))})"
    inicio = min(utc(a["created_at"]) for a in alertas)
    return {"severidad": estimada, "criticidad": crit, "activo": objeto, "motivo": motivo, "autorizada": autorizada,
            "ruido": all(incidentes.es_ruido(a["alert_id"]) for a in alertas),
            "inicio": inicio, "vence": inicio + SLA[estimada]}


def priorizar(alertas: list[dict], omitir: set[str] = frozenset()) -> list[dict]:
    """Entradas de la cola ordenadas por prioridad: {"alerta" (la que se tría), "alert_ids", estimación...}."""
    todas = incidentes.todas_las_alertas()
    vistas, entradas = set(), []
    for a in alertas:
        if a["alert_id"] in vistas or a["alert_id"] in omitir:
            continue
        ids = [i for i in incidentes.incidente_de(a["alert_id"]) or [a["alert_id"]] if i not in omitir]
        vistas |= set(ids) | {a["alert_id"]}
        grupo = [todas.get(i, a) for i in ids]
        # Se tría la alerta más grave del grupo (y la más antigua entre las de igual severidad)
        lider = min(grupo, key=lambda x: (-NIVELES.index(x.get("severity", "medium")), x["created_at"]))
        entradas.append({"alerta": lider, "alert_ids": ids, **estimar(grupo)})
    entradas.sort(key=lambda x: (-NIVELES.index(x["severidad"]), x["ruido"], len(x["alert_ids"]) == 1, x["vence"]))
    return entradas
