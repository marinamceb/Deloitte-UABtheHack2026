"""[Nivel 1 · web] Entrada de alertas y triaje desde la consola.

- POST /api/alertas {alertas: [...]}: alertas nuevas (agente/ingesta.py). Entran en la cola con la prioridad
  implementada y se correlacionan con las demás; la respuesta dice en qué puesto ha quedado cada una.
- POST /api/alertas/{id}/triar: el agente tría la alerta (y su incidente) en segundo plano. Un único trabajador
  procesa los encargos de uno en uno (el plan gratuito del LLM limita las peticiones por minuto) y el resultado es un
  ticket normal, con sus solicitudes de contención y avisos.
- GET /api/trabajos: estado de los triajes encargados (en cola, triando, hecho, error).
Recibir y triar: cualquiera del SOC que pueda operar (no la ingeniería de detección, que es de solo lectura).
"""
import queue
import threading
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from agente import almacen, ingesta
from agente.herramientas import ahora_iso, alerta_por_id
from agente.prompts import CATALOGO
from servidor.rutas import consulta
from servidor.seguridad import exigir_soc, persona_actual

router = APIRouter(prefix="/api", tags=["entrada"])


class Envio(BaseModel):
    alertas: list[dict]


def _puestos(ids: list[str]) -> dict[str, dict]:
    """Puesto de cada alerta en la cola recién recalculada (o si ya forma parte de un incidente con otras)."""
    consulta.invalidar_cola()
    cola = consulta.cola_cacheada()
    out = {}
    for n, x in enumerate(cola, 1):
        for aid in set(ids) & set(x["alert_ids"]):
            out[aid] = {"puesto": n, "de": len(cola), "severidad": x["severidad"], "lider": x["alert_id"],
                        "alertas_en_incidente": x["n"], "ruido": x["ruido"], "vence": x["vence"]}
    return out


@router.post("/alertas")
def recibir(envio: Envio, persona: dict = Depends(persona_actual)):
    exigir_soc(persona)
    try:
        nuevas = ingesta.recibir(envio.alertas, persona)
    except ingesta.AlertaNoValida as e:
        raise HTTPException(422, str(e))
    puestos = _puestos([a["alert_id"] for a in nuevas])
    return [{"alert_id": a["alert_id"], "rule_id": a["rule_id"], "rule_name": a["rule_name"], "severity": a["severity"],
             "created_at": a["created_at"], "fuera_de_catalogo": a["recibida"]["fuera_de_catalogo"],
             "cola": puestos.get(a["alert_id"])} for a in nuevas]


@router.get("/alertas/recibidas")
def recibidas(persona: dict = Depends(persona_actual)):
    return sorted(ingesta.leer(), key=lambda a: a["recibida"]["en"], reverse=True)[:100]


@router.get("/catalogo")
def catalogo(persona: dict = Depends(persona_actual)):
    """Reglas del catálogo de casos de uso (para el formulario de alertas nuevas) y una alerta de ejemplo."""
    reglas = [{"rule_id": k, "nombre": r["nombre"], "fuente": r["fuente"], "severidad": r["severidad_base"]}
              for k, r in sorted(CATALOGO.items())]
    return {"reglas": reglas, "ejemplo": ingesta.EJEMPLO}


# ========================================================================================== triaje en segundo plano

_TRABAJOS: dict[str, dict] = {}
_COLA_TRABAJOS: queue.Queue = queue.Queue()
_TRABAJADOR: threading.Thread | None = None
_CERROJO = threading.Lock()


def _triar(t: dict) -> None:
    from agente import informe, triaje
    alerta, error, _ = alerta_por_id(t["alert_id"])
    if alerta is None:
        raise RuntimeError(error or "la alerta no existe")
    res = triaje.triar(alerta)
    tk = res["ticket"]
    t.update(estado="hecho", ticket_id=tk["ticket_id"], veredicto=tk["verdict"], severidad=tk["severity"],
             heredado_de=res.get("heredado_de"))
    consulta.invalidar_cola()   # la alerta ya tiene ticket: sale de la cola
    # [Nivel 3 · automático] escalado alto o crítico: los hechos de la cadena quedan listos para el N2 (sin LLM)
    if incidente := informe.preparar(res):
        t["informe_preparado"] = incidente


def _investigar(t: dict) -> None:
    from agente import informe
    r = informe.generar(t["ids"], usar_llm=t["llm"], forzar=t.get("forzar", False))
    t.update(estado="hecho", incident_id=r["informe"]["incident_id"], con_llm=r["con_llm"],
             reutilizado=r.get("reutilizado", False), uso=r.get("uso"), motivo=r.get("motivo"),
             no_guardado=r.get("no_guardado"))


def _trabajar() -> None:
    from agente.motores import CuotaAgotada
    while True:
        tid = _COLA_TRABAJOS.get()
        t = _TRABAJOS[tid]
        t.update(estado="investigando" if t["tipo"] == "investigar" else "triando", inicio=ahora_iso())
        try:
            (_investigar if t["tipo"] == "investigar" else _triar)(t)
        except CuotaAgotada as e:
            t.update(estado="error", error=f"Cuota del LLM agotada: {e}")
        except (Exception, SystemExit) as e:  # noqa: BLE001 - p. ej. falta la clave del LLM (SystemExit en motores)
            t.update(estado="error", error=str(e) or type(e).__name__)
        finally:
            t["fin"] = ahora_iso()
            _COLA_TRABAJOS.task_done()


def _arrancar_trabajador() -> None:
    global _TRABAJADOR
    with _CERROJO:
        if _TRABAJADOR is None or not _TRABAJADOR.is_alive():
            _TRABAJADOR = threading.Thread(target=_trabajar, name="triaje", daemon=True)
            _TRABAJADOR.start()


@router.post("/alertas/{alert_id}/triar")
def triar(alert_id: str, persona: dict = Depends(persona_actual)):
    exigir_soc(persona)
    if alerta_por_id(alert_id)[0] is None:
        raise HTTPException(404, "No existe esa alerta")
    if previo := (almacen.ticket_que_cubre(alert_id)
                  or (almacen.ticket_id_de(alert_id) if almacen.ticket(almacen.ticket_id_de(alert_id)) else None)):
        raise HTTPException(409, f"Ya está triada en {previo}")
    activo = next((t for t in _TRABAJOS.values()
                   if t["alert_id"] == alert_id and t["estado"] in ("en_cola", "triando")), None)
    if activo:
        return activo
    return _encargar({"tipo": "triar", "alert_id": alert_id}, persona)


def _encargar(trabajo: dict, persona: dict) -> dict:
    tid = "TRB-" + uuid.uuid4().hex[:8]
    _TRABAJOS[tid] = {**trabajo, "id": tid, "estado": "en_cola", "pedido": ahora_iso(), "por": persona["email"],
                      "pendientes_delante": _COLA_TRABAJOS.qsize()}
    _arrancar_trabajador()
    _COLA_TRABAJOS.put(tid)
    return _TRABAJOS[tid]


class Investigacion(BaseModel):
    ids: list[str]           # alertas (ALR-…) o un ticket (TKT-…): se investiga su incidente
    llm: bool = False        # False: solo hechos (rastreo por código, segundos); True: informe redactado por el LLM
    forzar: bool = False     # True: redactar aunque haya un informe del LLM con los mismos hechos


@router.post("/investigar")
def investigar(datos: Investigacion, persona: dict = Depends(persona_actual)):
    """[Nivel 3] Investigación en segundo plano (mismo trabajador que el triaje: el LLM limita peticiones/min)."""
    exigir_soc(persona)
    from agente import indice
    if not indice.disponible():
        raise HTTPException(503, "No hay índice de logs: créalo con «python agent.py --construir-indice»")
    if not datos.ids or len(datos.ids) > 50:
        raise HTTPException(422, "Indica entre 1 y 50 IDs de alertas o un ticket")
    activo = next((t for t in _TRABAJOS.values() if t.get("ids") == datos.ids and t["estado"] in
                   ("en_cola", "investigando")), None)
    return activo or _encargar({"tipo": "investigar", "ids": datos.ids, "llm": datos.llm, "forzar": datos.forzar,
                                "alert_id": datos.ids[0]}, persona)


@router.get("/trabajos")
def trabajos(persona: dict = Depends(persona_actual)):
    return sorted(_TRABAJOS.values(), key=lambda t: t["pedido"], reverse=True)[:30]


def esperar_trabajos(segundos: float = 30) -> None:
    """Para los tests: espera a que se vacíe la cola de triajes."""
    fin = time.time() + segundos
    while _COLA_TRABAJOS.unfinished_tasks and time.time() < fin:
        time.sleep(0.05)
