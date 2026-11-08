"""[Niveles 1-3 · web] Vistas de solo lectura para el SOC: la cola priorizada (nivel 1), los tickets de triaje con la
traza de lo que consultó el sistema y por qué decidió (niveles 1-2), los informes de incidente (nivel 3) y el
detalle de una alerta (por la API simulada). Las acciones propuestas se enlazan con su solicitud de contención."""
import threading
import time

from fastapi import APIRouter, Depends, HTTPException

from agente import acciones, almacen, cola, incidentes
from agente.herramientas import alerta_por_id
from servidor.seguridad import persona_actual, ve_todo

router = APIRouter(prefix="/api", tags=["consulta"])
COLA_CADA_S = 120
_COLA: dict = {"ts": 0.0, "entradas": []}
_CERROJO_COLA = threading.Lock()


def lector(persona: dict = Depends(persona_actual)) -> dict:
    if not ve_todo(persona):
        raise HTTPException(403, "Solo el SOC")
    return persona


def _solicitud(accion: str, objetivo: str) -> dict | None:
    if not acciones.es_contencion(accion) or not objetivo:
        return None
    s = acciones.obtener(acciones.id_de(accion, objetivo))
    return {"id": s["id"], "estado": s["estado"]} if s else None


# =============================================================================================== cola (nivel 1)

def _entrada(x: dict) -> dict:
    a = x["alerta"]
    return {"alert_id": a["alert_id"], "rule_id": a.get("rule_id"), "rule_name": a.get("rule_name"),
            "created_at": a.get("created_at"), "severidad_regla": a.get("severity"), "severidad": x["severidad"],
            "criticidad": x["criticidad"], "activo": x["activo"], "motivo": x["motivo"],
            "vence": x["vence"].isoformat(),
            "ruido": x["ruido"], "autorizada": x["autorizada"], "n": len(x["alert_ids"]),
            "alert_ids": x["alert_ids"][:30]}


def invalidar_cola() -> None:
    """La próxima consulta recalcula la cola (alertas nuevas, alertas triadas)."""
    with _CERROJO_COLA:
        _COLA["ts"] = 0.0


def cola_cacheada() -> list[dict]:
    """Entradas de la cola, recalculadas como mucho cada COLA_CADA_S (la primera vez tarda unos segundos)."""
    with _CERROJO_COLA:
        if time.time() - _COLA["ts"] > COLA_CADA_S:
            _COLA["entradas"] = [_entrada(x) for x in cola.actual()]
            _COLA["ts"] = time.time()
        return _COLA["entradas"]


@router.get("/cola")
def ver_cola(limite: int = 50, persona: dict = Depends(lector)):
    """Cola priorizada sin LLM (severidad estimada con la matriz y la CMDB, SLA); se recalcula cada 2 min."""
    entradas = cola_cacheada()
    return {"total": len(entradas), "calculada": _COLA["ts"], "entradas": entradas[:max(1, min(limite, 2000))]}


@router.get("/alertas/{alert_id}")
def alerta(alert_id: str, persona: dict = Depends(lector)):
    datos, error, _ = alerta_por_id(alert_id)
    if datos is None:
        raise HTTPException(404, error or "No existe esa alerta")
    return {**datos, "incidente": incidentes.incidente_de(alert_id),
            "ticket": almacen.ticket_que_cubre(alert_id) or (
                almacen.ticket_id_de(alert_id) if almacen.ticket(almacen.ticket_id_de(alert_id)) else None)}


# =============================================================================================== tickets (niveles 1-2)

@router.get("/tickets")
def tickets(persona: dict = Depends(lector)):
    out = []
    for tid, r in almacen.tickets().items():
        t = r["ticket"]
        out.append({"ticket_id": tid, "title": t.get("title"), "verdict": t.get("verdict"),
                    "severity": t.get("severity"),
                    "escalate": t.get("escalation", {}).get("escalate"), "alert_ids": t.get("alert_ids", []),
                    "triado_en": r.get("triado_en"), "modelo": r.get("modelo"), "heredado_de": r.get("heredado_de")})
    return sorted(out, key=lambda x: x["triado_en"] or "", reverse=True)


@router.get("/tickets/{ticket_id}")
def ticket(ticket_id: str, persona: dict = Depends(lector)):
    r = almacen.ticket(ticket_id)
    if r is None:
        raise HTTPException(404, "No existe ese ticket")
    t = dict(r["ticket"])
    t["recommended_actions"] = [{**a, "solicitud": _solicitud(a["action"], a["target"])}
                                for a in t.get("recommended_actions", [])]
    return {**r, "ticket": t}


# =============================================================================================== informes (nivel 3)

@router.get("/informes")
def informes(persona: dict = Depends(lector)):
    lista = [{"incident_id": iid, "title": r["informe"].get("title"), "alert_ids": r["informe"].get("alert_ids", []),
              "generado_en": r.get("generado_en"), "con_llm": r.get("con_llm"), "modelo": r.get("modelo"),
              "confidence": r["informe"].get("confidence")} for iid, r in almacen.informes().items()]
    return sorted(lista, key=lambda x: x["generado_en"] or "", reverse=True)


@router.get("/informes/{incident_id}")
def informe(incident_id: str, persona: dict = Depends(lector)):
    r = almacen.informe(incident_id)
    if r is None:
        raise HTTPException(404, "No existe ese informe")
    inf = dict(r["informe"])
    inf["containment_plan"] = [{**a, "solicitud": _solicitud(a["action"], a["target"])}
                               for a in inf.get("containment_plan", [])]
    h = r.get("hechos", {})
    resumen = {k: h.get(k) for k in ("ventana", "estadisticas", "iocs", "concentradores", "acceso_inicial_candidatos",
                                     "paciente_cero_candidato", "alcance", "relacionados", "huecos",
                                     "contexto_descartado")}
    resumen["entidades"] = [{"entidad": k, **v} for k, v in (h.get("entidades") or {}).items()
                            if v.get("salto") == 0 or v.get("notables")]
    return {"informe": inf, "hechos": resumen, "cronologia_completa": h.get("cronologia", []),
            "traza": r.get("traza", []), "uso": r.get("uso"), "modelo": r.get("modelo"), "con_llm": r.get("con_llm"),
            "generado_en": r.get("generado_en"), "segundos": r.get("segundos"), "huella": r.get("huella"),
            "con_herramientas": r.get("con_herramientas"),
            "acciones_ejecutadas": r.get("acciones_ejecutadas", [])}
