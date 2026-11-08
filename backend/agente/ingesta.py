"""[Nivel 1 · entrada] Alertas nuevas recibidas por el backend (no por la API simulada).

La API simulada del reto no se puede modificar y no tiene forma de añadir alertas: carga las 11.061 de su fichero al
arrancar. Para que el SOC pueda recibir alertas nuevas (otro SIEM, una prueba, la demo), el backend guarda las suyas
en salidas/alertas_recibidas.jsonl y `incidentes.todas_las_alertas()` las suma a las de la API. A partir de ahí siguen
el mismo camino que cualquier otra: cola priorizada (severidad estimada, ruido, incidentes, SLA), correlación en
incidentes, triaje con el agente, solicitudes de contención y avisos.

Cada alerta se valida y se completa con el catálogo de casos de uso (nombre de la regla, severidad base, MITRE,
runbook, fuente) y recibe un ID propio con el formato del SIEM: ALR-AAAAMMDD-9NNNNN (el 9 inicial no choca con los
del dataset). El ID que traiga la alerta se conserva como `external_id`, nunca se usa como clave. Su contenido es dato
no confiable (como el de cualquier alerta): se muestra con textContent y el modelo lo recibe marcado como tal.
"""
import datetime as dt
import json
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from . import almacen
from .herramientas import ahora_iso
from .prompts import CATALOGO

FICHERO = "alertas_recibidas.jsonl"
MAX_POR_ENVIO = 200
Severidad = Literal["informational", "low", "medium", "high", "critical"]


class AlertaEntrante(BaseModel):
    """Lo mínimo es la regla (rule_id del catálogo); el resto se completa o es opcional."""
    rule_id: str = Field(min_length=3, max_length=40)
    rule_name: str = Field("", max_length=200)
    severity: Severidad | None = None
    created_at: str | None = Field(None, description="ISO 8601; por defecto, ahora")
    source_product: str = Field("", max_length=40)
    description: str = Field("", max_length=2000)
    entities: dict = Field(default_factory=dict)
    evidence: dict = Field(default_factory=dict)
    related_events: list[str] = Field(default_factory=list, max_length=200)
    mitre: dict | None = None
    runbook: str = Field("", max_length=20)
    alert_id: str | None = Field(None, max_length=60, description="ID en el sistema de origen (se guarda aparte)")

    @field_validator("created_at")
    @classmethod
    def _fecha_iso(cls, v):
        if v is None:
            return v
        try:
            fecha = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("created_at debe ser una fecha ISO 8601, p. ej. 2026-11-08T10:30:00Z")
        if fecha.tzinfo is None:
            fecha = fecha.replace(tzinfo=dt.timezone.utc)
        return fecha.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class AlertaNoValida(ValueError):
    pass


def leer() -> list[dict]:
    p = almacen.SALIDAS / FICHERO
    if not p.exists():
        return []
    return [json.loads(linea) for linea in p.read_text(encoding="utf-8").splitlines() if linea.strip()]


def por_id(alert_id: str) -> dict | None:
    return next((a for a in leer() if a["alert_id"] == alert_id), None)


def _completar(e: AlertaEntrante, n: int, persona: dict) -> dict:
    regla = CATALOGO.get(e.rule_id)
    if regla is None and not (e.rule_name and e.severity):
        raise AlertaNoValida(f"{e.rule_id} no está en el catálogo de casos de uso: indica también rule_name y severity")
    regla = regla or {}
    creada = e.created_at or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    alerta = {
        "alert_id": f"ALR-{creada[:10].replace('-', '')}-{900000 + n:06d}",
        "created_at": creada,
        "source_product": e.source_product or regla.get("fuente", ""),
        "rule_id": e.rule_id,
        "rule_name": e.rule_name or regla.get("nombre", e.rule_id),
        "severity": e.severity or regla.get("severidad_base", "medium"),
        "status": "new",
        "mitre": e.mitre or ({"tactic": regla.get("tactica", ""), "technique_id": regla.get("tecnica_id", ""),
                              "technique": regla.get("tecnica", "")} if regla else {}),
        "description": e.description or regla.get("logica", ""),
        "entities": e.entities,
        "evidence": e.evidence,
        "related_events": e.related_events,
        "runbook": e.runbook or regla.get("runbook", ""),
        "recibida": {"en": ahora_iso(), "por": persona.get("email", ""), "external_id": e.alert_id or "",
                     "fuera_de_catalogo": e.rule_id not in CATALOGO},
    }
    return alerta


def recibir(datos: list[dict], persona: dict) -> list[dict]:
    """Valida, completa y guarda alertas nuevas. Todo o nada: si una no vale, no se guarda ninguna."""
    if not datos:
        raise AlertaNoValida("No hay ninguna alerta")
    if len(datos) > MAX_POR_ENVIO:
        raise AlertaNoValida(f"Como mucho {MAX_POR_ENVIO} alertas por envío")
    entrantes = []
    for i, d in enumerate(datos, 1):
        try:
            entrantes.append(AlertaEntrante.model_validate(d))
        except Exception as e:  # noqa: BLE001 - se informa del error de validación con su posición
            raise AlertaNoValida(f"Alerta {i}: {e}") from e
    with almacen.CERROJO:
        previas = len(leer())
        nuevas = [_completar(e, previas + i, persona) for i, e in enumerate(entrantes, 1)]
        p = almacen.SALIDAS / FICHERO
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            for a in nuevas:
                f.write(json.dumps(a, ensure_ascii=False) + "\n")
    from . import incidentes
    incidentes.reiniciar()   # la cola y la correlación deben verlas ya
    return nuevas


EJEMPLO = {
    "rule_id": "UC-EDR-004",
    "source_product": "EDR",
    "entities": {"hosts": [{"hostname": "WS-BCN-1770", "ip": "10.10.3.95"}],
                 "users": [{"upn": "marta.puig@tarvia.example"}]},
    "evidence": {"technique": "comsvcs.dll MiniDump", "edr_action": "detected_only"},
    "related_events": [],
}
