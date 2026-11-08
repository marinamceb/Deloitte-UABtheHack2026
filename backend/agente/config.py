"""[Común] Configuración: rutas y URL de la API simulada, con valores por defecto para ejecutar desde el repositorio y
variables de entorno para Docker.

    DATASET_DIR    carpeta del reto (DTT-UAB-The-Hack-main), solo lectura      por defecto: <repo>/DTT-UAB-The-Hack-main
    SALIDAS_DIR    tickets, informes, índice de logs, acciones, accesos       por defecto: backend/salidas
    FRONTEND_DIR   HTML/CSS/JS que sirve el backend en desarrollo             por defecto: <repo>/frontend/public
    SOC_API_URL    API simulada del SOC                                       por defecto: http://localhost:8000
    DATABASE_URL   PostgreSQL con los usuarios del SOC (tabla users)
                   por defecto: postgresql://soc:socdemo@localhost:5432/soc

DTT-UAB-The-Hack-main es de solo lectura y el agente solo lee de ahí lo que la API no ofrece: los documentos del SOC
(política, ficha de empresa, catálogo, runbooks), dos tablas de referencia (zonas de red y servicios de negocio con
sus responsables) y los IDs de la muestra de desarrollo. Alertas, logs, inventario, identidades, RRHH, cambios,
inteligencia y sandbox llegan por la API.
"""
import os
import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent      # backend/
REPO = BACKEND.parent                                 # raíz del repositorio


def _ruta(variable: str, defecto: Path) -> Path:
    return Path(os.environ[variable]).resolve() if os.environ.get(variable) else defecto


DATASET = _ruta("DATASET_DIR", REPO / "DTT-UAB-The-Hack-main")
CONTEXTO = DATASET / "01_contexto"
INVENTARIO = DATASET / "02_inventario"
SALIDAS = _ruta("SALIDAS_DIR", BACKEND / "salidas")
FRONTEND = _ruta("FRONTEND_DIR", REPO / "frontend" / "public")
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://soc:socdemo@localhost:5432/soc")
DATABASE_URL_SIN_CLAVE = re.sub(r"://([^:/@]+):[^@]*@", r"://\1:***@", DATABASE_URL)   # para mensajes y logs
API_URL = os.environ.get("SOC_API_URL", "http://localhost:8000")
