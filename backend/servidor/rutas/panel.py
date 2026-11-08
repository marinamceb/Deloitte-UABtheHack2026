"""[Web] Resumen para la página de inicio y la de implementación, adaptado a los permisos de quien lo pide: cada
persona recibe solo las cifras de lo que puede ver (el N1 no recibe avisos; la detección, los huecos de detección)."""
import collections

from fastapi import APIRouter, Depends

from agente import acciones, almacen, api, avisos, incidentes, indice, ingesta, motores
from servidor.rutas.avisos import sincronizar as sincronizar_avisos
from servidor.rutas.acciones import sincronizar as sincronizar_acciones
from servidor.rutas.consulta import cola_cacheada
from servidor.seguridad import permisos, persona_actual

router = APIRouter(prefix="/api", tags=["panel"])


@router.get("/resumen")
def resumen(persona: dict = Depends(persona_actual)):
    p = permisos(persona)
    sincronizar_acciones()
    sincronizar_avisos()
    out: dict = {"permisos": p}

    solicitudes = acciones.listar()
    out["acciones"] = {"pendientes_mias": len(acciones.pendientes_de(persona)),
                       "por_estado": collections.Counter(s["estado"] for s in solicitudes)}
    if p["avisos"] or p["supervisar"]:
        mios = avisos.para(persona)
        abiertos = [a for a in mios if a["estado"] == "abierto"]
        out["avisos"] = {"abiertos": len(abiertos), "por_atender": sum(avisos.puede_atender(a, persona) for a in mios),
                         "urgentes": sorted((a for a in abiertos if a["plazo"]), key=lambda a: a["plazo"])[:4]}
    recibidas = ingesta.leer()
    out["entrada"] = {"recibidas": len(recibidas),
                      "ultimas": [{k: a.get(k) for k in ("alert_id", "rule_name", "severity", "created_at")}
                                  | {"en": a["recibida"]["en"], "por": a["recibida"]["por"]}
                                  for a in sorted(recibidas, key=lambda a: a["recibida"]["en"], reverse=True)[:4]]}
    if p["ver"]:
        cola = cola_cacheada()
        senal = [x for x in cola if not x["ruido"]]
        out["cola"] = {"total": len(cola), "ruido": len(cola) - len(senal),
                       "por_severidad": collections.Counter(x["severidad"] for x in senal),
                       "primeros": senal[:5]}
        tickets = list(almacen.tickets().values())
        out["tickets"] = {"total": len(tickets),
                          "por_veredicto": collections.Counter(r["ticket"].get("verdict", "?") for r in tickets),
                          "escalados": sum(1 for r in tickets if r["ticket"].get("escalation", {}).get("escalate")),
                          "heredados": sum(1 for r in tickets if r.get("heredado_de"))}
        informes = almacen.informes()
        out["incidentes"] = {"informes": len(informes), "candidatos": len(incidentes.listar()),
                             "huecos": [{"incidente": iid, "hueco": g} for iid, r in informes.items()
                                        for g in r["informe"].get("detection_gaps", [])][:12]}
        out["ejecutadas"] = sorted(api.registro_contencion(), key=lambda r: r.get("timestamp", ""), reverse=True)[:5]
        e = indice.estado()
        out["sistema"] = {"alertas": len(incidentes.todas_las_alertas()),
                          "indice": {"eventos": e["eventos"], "mb": e["mb"]} if e else None,
                          "llm": f"{motores.PROVEEDOR}/{motores.MODELO}"}
    return out
