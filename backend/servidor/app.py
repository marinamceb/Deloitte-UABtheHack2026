"""[Nivel 4 · web] Backend de la consola del SOC: monta la seguridad común y las rutas de la API JSON.

    cd backend && ../.venv/bin/uvicorn servidor.app:app --port 8001     (necesita la API simulada en SOC_API_URL)

Rutas en servidor/rutas/ (una por área; las futuras —avisos, cola, tickets, informes— van ahí y se registran abajo):
    sesion.py     /api/login, /api/logout, /api/yo
    acciones.py   /api/acciones/...  (nivel 4: bandeja, detalle, aprobar, rechazar, hecha, reintentar)
    estado.py     /api/salud
El frontend (HTML/CSS/JS en <repo>/frontend/public) lo sirve nginx en Docker. En desarrollo, si existe la carpeta
(FRONTEND_DIR), también lo sirve este mismo servidor en «/», para no necesitar nginx.
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from agente import config
from servidor.rutas import acciones, estado, sesion
from servidor.seguridad import COOKIE, SECRETO, solo_json_en_post

app = FastAPI(title="Tarvia SOC · consola", version="1.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
app.add_middleware(BaseHTTPMiddleware, dispatch=solo_json_en_post)
app.add_middleware(SessionMiddleware, secret_key=SECRETO, **COOKIE)

for modulo in (sesion, acciones, estado):
    app.include_router(modulo.router)

if config.FRONTEND.is_dir():
    app.mount("/", StaticFiles(directory=config.FRONTEND, html=True), name="frontend")
