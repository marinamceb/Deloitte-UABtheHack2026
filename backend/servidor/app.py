"""[Nivel 4 · web] Backend de la consola del SOC: monta la seguridad común y las rutas de la API JSON.

    cd backend && .venv/bin/uvicorn servidor.app:app --port 8001     (necesita la API simulada en SOC_API_URL)

Rutas en servidor/rutas/ (una por área; las nuevas van ahí y se registran en el bucle de abajo):
    sesion.py     /api/login, /api/logout, /api/yo
    acciones.py   /api/acciones/...  (nivel 4: bandeja, detalle, aprobar, rechazar, hecha, reintentar)
    contencion.py /api/contencion/registro  (lo ejecutado según la API simulada)
    avisos.py     /api/avisos  (escalados, SLA y notificaciones a terceros por rol)
    consulta.py   /api/cola, /api/alertas/{id}, /api/tickets[/{id}], /api/informes[/{id}]  (vistas de los niveles 1-3)
    panel.py      /api/resumen  (inicio e implementación, según los permisos)
    entrada.py    /api/alertas (recibir), /api/alertas/{id}/triar, /api/trabajos, /api/catalogo
    integracion.py /api/ingesta/alertas  (pública, para otros sistemas: X-API-Key = INGESTA_TOKEN)
    estado.py     /api/salud
El frontend (HTML/CSS/JS en <repo>/frontend/public) lo sirve nginx en Docker. En desarrollo, si existe la carpeta
(FRONTEND_DIR), también lo sirve este mismo servidor en «/», para no necesitar nginx.
"""
import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from agente import config, usuarios_soc
from servidor.rutas import acciones, avisos, consulta, contencion, entrada, estado, integracion, panel, sesion
from servidor.seguridad import COOKIE, SECRETO, solo_json_en_post

log = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def ciclo_de_vida(_app: FastAPI):
    """Al arrancar: tabla `users` y usuarios de ejemplo (idempotente). Si PostgreSQL aún no responde, la web arranca
    igualmente y el login devolverá 503 hasta que responda."""
    try:
        log.info("PostgreSQL: %d usuarios del SOC", usuarios_soc.inicializar())
    except usuarios_soc.BaseDeDatosNoDisponible as e:
        log.warning("%s", e)
    # la cola tarda unos segundos la primera vez: se calcula en segundo plano para que el inicio no espere
    threading.Thread(target=_precalcular_cola, daemon=True).start()
    yield


def _precalcular_cola() -> None:
    from servidor.rutas.consulta import cola_cacheada
    try:
        log.info("Cola precalculada: %d puestos", len(cola_cacheada()))
    except Exception as e:  # noqa: BLE001 - p. ej. la API simulada aún no responde: se calculará al pedirla
        log.warning("No se pudo precalcular la cola: %s", e)


app = FastAPI(title="Tarvia SOC · consola", version="1.0", docs_url="/api/docs", openapi_url="/api/openapi.json",
              lifespan=ciclo_de_vida)


@app.exception_handler(usuarios_soc.BaseDeDatosNoDisponible)
async def sin_base_de_datos(_request: Request, e: usuarios_soc.BaseDeDatosNoDisponible):
    return JSONResponse({"detail": "La base de datos de usuarios del SOC no responde"}, status_code=503)
app.add_middleware(BaseHTTPMiddleware, dispatch=solo_json_en_post)
app.add_middleware(SessionMiddleware, secret_key=SECRETO, **COOKIE)

for modulo in (sesion, panel, entrada, integracion, acciones, avisos, consulta, contencion, estado):
    app.include_router(modulo.router)

if config.FRONTEND.is_dir():
    app.mount("/", StaticFiles(directory=config.FRONTEND, html=True), name="frontend")
