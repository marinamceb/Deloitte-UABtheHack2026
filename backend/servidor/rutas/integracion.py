"""[Nivel 1 · entrada] Ruta pública para que otros sistemas (un SIEM, un script, la demo) envíen alertas en JSON.

    POST /api/ingesta/alertas
    X-API-Key: <INGESTA_TOKEN>            (obligatoria)
    X-Origen: siem-x                      (opcional: queda como «recibida.por = integracion:siem-x»)
    Content-Type: application/json
    cuerpo: una alerta {...}, una lista [{...}, ...] o {"alertas": [...]}      (como mucho 200 por envío)
    ?posicion=true                        (opcional: responde con el puesto de cada una en la cola; tarda segundos)

Responde 202 con los IDs asignados. Las alertas siguen el mismo camino que las demás (agente/ingesta.py): cola
priorizada, correlación con incidentes, triaje, contención y avisos. Formato mínimo: {"rule_id": "UC-EDR-004"}.

Pensada para exponer el backend en la demo, así que se protege sola:
- Desactivada (503) mientras no se defina INGESTA_TOKEN en el entorno (.env). Token comparado en tiempo constante.
- Sin cookies ni sesión: no la alcanza el CSRF y no da acceso a nada más que a añadir alertas.
- Límite de envíos por IP y minuto (INGESTA_POR_MINUTO, 30 por defecto) y de tamaño (2 MB).
- Cada envío, aceptado o rechazado, queda en salidas/accesos.jsonl.
"""
import hmac
import json
import os
import threading
import time
from collections import defaultdict, deque

from fastapi import APIRouter, HTTPException, Request

from agente import ingesta
from servidor.seguridad import registrar_acceso

router = APIRouter(prefix="/api/ingesta", tags=["integración"])
MAX_BYTES = 2 * 1024 * 1024
_ENVIOS: dict[str, deque] = defaultdict(deque)
_CERROJO = threading.Lock()


def _token() -> str:
    return os.environ.get("INGESTA_TOKEN", "")


def _limite() -> int:
    return int(os.environ.get("INGESTA_POR_MINUTO", "30"))


def _ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def _dentro_del_limite(ip: str) -> bool:
    ahora = time.time()
    with _CERROJO:
        cola = _ENVIOS[ip]
        while cola and ahora - cola[0] > 60:
            cola.popleft()
        if len(cola) >= _limite():
            return False
        cola.append(ahora)
        return True


def _alertas(cuerpo) -> list:
    if isinstance(cuerpo, list):
        return cuerpo
    if isinstance(cuerpo, dict):
        return cuerpo["alertas"] if isinstance(cuerpo.get("alertas"), list) else [cuerpo]
    raise HTTPException(422, 'El cuerpo debe ser una alerta, una lista de alertas o {"alertas": [...]}')


@router.post("/alertas", status_code=202)
async def recibir(request: Request, posicion: bool = False):
    token = _token()
    origen = "integracion:" + (request.headers.get("x-origen") or "externa")[:40]
    if not token:
        raise HTTPException(503, "Entrada externa desactivada: define INGESTA_TOKEN en el entorno del backend")
    if not hmac.compare_digest(request.headers.get("x-api-key", "").encode(), token.encode()):
        registrar_acceso("ingesta_rechazada", origen, request, "token incorrecto")
        raise HTTPException(401, "Falta X-API-Key o no es válida")
    if not _dentro_del_limite(_ip(request)):
        raise HTTPException(429, f"Demasiados envíos: como mucho {_limite()} por minuto")
    if int(request.headers.get("content-length") or 0) > MAX_BYTES:
        raise HTTPException(413, "Cuerpo demasiado grande (máximo 2 MB)")
    crudo = await request.body()
    if len(crudo) > MAX_BYTES:
        raise HTTPException(413, "Cuerpo demasiado grande (máximo 2 MB)")
    try:
        cuerpo = json.loads(crudo)
    except ValueError:
        raise HTTPException(400, "El cuerpo no es JSON válido")
    try:
        nuevas = ingesta.recibir(_alertas(cuerpo), {"email": origen})
    except ingesta.AlertaNoValida as e:
        registrar_acceso("ingesta_rechazada", origen, request, str(e)[:200])
        raise HTTPException(422, str(e))
    ids = ", ".join(a["alert_id"] for a in nuevas[:5])
    registrar_acceso("ingesta", origen, request, f"{len(nuevas)} alertas: {ids}")

    from servidor.rutas import consulta, entrada
    puestos = entrada._puestos([a["alert_id"] for a in nuevas]) if posicion else (consulta.invalidar_cola() or {})
    return {"recibidas": len(nuevas),
            "alertas": [{"alert_id": a["alert_id"], "rule_id": a["rule_id"], "rule_name": a["rule_name"],
                         "severity": a["severity"], "created_at": a["created_at"],
                         "fuera_de_catalogo": a["recibida"]["fuera_de_catalogo"],
                         **({"cola": puestos.get(a["alert_id"])} if posicion else {})} for a in nuevas]}
