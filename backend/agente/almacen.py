"""[Común] Resultados guardados en salidas/: tickets de triaje (niveles 1-2, salidas/tickets/TKT-….json), informes
de incidente (nivel 3, salidas/informes/INC-….json) y solicitudes de contención (nivel 4, salidas/acciones.json).

Antes seis módulos leían y analizaban los JSON de tickets por su cuenta (y `cubierta_por` los releía todos por cada
alerta). Aquí se leen una vez y se recargan solo los ficheros que cambian (por fecha de modificación). Los tests
redirigen el almacén cambiando `almacen.SALIDAS`.
"""
import json
import os
import threading
from pathlib import Path

from . import config

SALIDAS = config.SALIDAS
_CACHE: dict[Path, tuple[float, dict | None]] = {}


def dir_tickets() -> Path:
    return SALIDAS / "tickets"


def dir_informes() -> Path:
    return SALIDAS / "informes"


def _leer(p: Path) -> dict | None:
    mtime = p.stat().st_mtime
    if p not in _CACHE or _CACHE[p][0] != mtime:
        try:
            datos = json.loads(p.read_text(encoding="utf-8"))
            datos = datos if isinstance(datos.get("ticket"), dict) else None
        except (json.JSONDecodeError, OSError):
            datos = None
        _CACHE[p] = (mtime, datos)
    return _CACHE[p][1]


# --------------------------------------------------------------------------------------------- tickets

def tickets() -> dict[str, dict]:
    """ticket_id (nombre del fichero) → resultado guardado (alerta, ticket, traza...), en orden de ticket_id."""
    d = dir_tickets()
    return {p.stem: r for p in sorted(d.glob("TKT-*.json")) if (r := _leer(p))} if d.exists() else {}


def ticket(ticket_id: str) -> dict | None:
    p = dir_tickets() / f"{ticket_id}.json"
    return _leer(p) if p.exists() else None


def ticket_id_de(alert_id: str) -> str:
    return "TKT-" + alert_id.removeprefix("ALR-")


def ticket_que_cubre(alert_id: str) -> str | None:
    """[Nivel 2] Otro ticket que ya incluye esta alerta (p. ej. triada como parte de un incidente)."""
    propio = ticket_id_de(alert_id)
    return next((tid for tid, r in tickets().items()
                 if tid != propio and alert_id in r["ticket"].get("alert_ids", [])), None)


def alertas_en_tickets() -> set[str]:
    return {a for r in tickets().values() for a in r["ticket"].get("alert_ids", [])}


def guardar_ticket(resultado: dict) -> Path:
    """Un JSON por ticket (se sobrescribe al re-triar o al ejecutar acciones)."""
    d = dir_tickets()
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{resultado['ticket']['ticket_id']}.json"
    p.write_text(json.dumps(resultado, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


# --------------------------------------------------------------------------------------------- informes

def informe(incident_id: str) -> dict | None:
    p = dir_informes() / f"{incident_id}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def guardar_informe(resultado: dict) -> Path:
    d = dir_informes()
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{resultado['informe']['incident_id']}.json"
    p.write_text(json.dumps(resultado, ensure_ascii=False, indent=2, default=sorted), encoding="utf-8")
    return p


def informes() -> dict[str, dict]:
    """incident_id → resultado guardado (informe, hechos...)."""
    d = dir_informes()
    out = {}
    for p in sorted(d.glob("INC-*.json")) if d.exists() else []:
        try:
            out[p.stem] = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
    return out


# --------------------------------------------------------------------------------------------- acciones (nivel 4)
# Un solo fichero con todas las solicitudes. La web y el CLI pueden escribir a la vez desde hilos distintos: se
# serializa con un cerrojo y se escribe en un temporal que se renombra (nunca queda un fichero a medias). Pensado para
# un único proceso (la web corre en uno).

CERROJO = threading.RLock()


def ruta_acciones() -> Path:
    return SALIDAS / "acciones.json"


def acciones() -> dict[str, dict]:
    p = ruta_acciones()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def guardar_acciones(datos: dict[str, dict]) -> None:
    p = ruta_acciones()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(datos, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def registrar_acceso(evento: dict) -> None:
    """Auditoría de la consola web (login, logout, rechazos): una línea JSON por evento en salidas/accesos.jsonl."""
    with CERROJO:
        SALIDAS.mkdir(parents=True, exist_ok=True)
        with open(SALIDAS / "accesos.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(evento, ensure_ascii=False) + "\n")
