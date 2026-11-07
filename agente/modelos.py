"""Salida estructurada del agente, alineada con 01_contexto/ticket_salida.schema.json.

El LLM rellena `TicketTriaje`; `ticket_id`, `executed_actions` y `triage_seconds` los añade el código,
porque no son decisiones del modelo.
"""
from typing import Literal

from pydantic import BaseModel, Field

Veredicto = Literal["true_positive", "benign_true_positive", "false_positive", "needs_more_info"]
Severidad = Literal["informational", "low", "medium", "high", "critical"]


class Afectados(BaseModel):
    users: list[str]
    hosts: list[str]
    business_services: list[str]
    customers: list[str]


class Evidencia(BaseModel):
    source: str = Field(description="Fuente consultada (p. ej. edr_events, proxy, alerta)")
    event_id: str = Field(description="ID del evento o de la alerta; vacío si no aplica")
    finding: str = Field(description="Qué muestra ese evento y por qué importa")


class Enriquecimiento(BaseModel):
    indicator: str
    type: str = Field(description="ip, domain, url, sha256, user, host...")
    source: str = Field(description="ti_feed, geoip_asn, sandbox, cmdb, directorio...")
    result: str = Field(description="Resultado. 'sin coincidencias' no significa limpio.")


class AccionRecomendada(BaseModel):
    action: str = Field(
        description="Usa el nombre exacto de la API cuando exista: isolate_host, disable_user, revoke_sessions, "
        "reset_password, block_ioc, purge_email, disable_access_key. Si no, texto corto: close, escalate_n2, "
        "notify_treasury, notify_dpo, escalate_operations, monitor_24h, full_scan..."
    )
    target: str = Field(description="Hostname, UPN, indicador, message_id o access key exactos")
    requires_approval: bool = Field(description="Según la tabla del apartado 4 de la política")
    justification: str


class Escalado(BaseModel):
    escalate: bool
    to: str = Field(description="N2, N2 guardia (teléfono), Operaciones, DPO, Tesorería... vacío si no se escala")
    reason: str


class TicketTriaje(BaseModel):
    alert_ids: list[str] = Field(description="La alerta triada y cualquier otra que pertenezca al mismo incidente")
    title: str = Field(description="Una línea que diga qué pasa, no qué regla saltó")
    verdict: Veredicto
    confidence: float = Field(description="Entre 0 y 1")
    severity: Severidad
    severity_rationale: str = Field(description="Cómo se aplicó la matriz: regla x criticidad = base; ajustes ±1")
    affected: Afectados
    summary: str = Field(description="Qué ha pasado, en 3-5 frases, para el N2")
    evidence: list[Evidencia]
    enrichment: list[Enriquecimiento]
    mitre: list[str]
    recommended_actions: list[AccionRecomendada]
    escalation: Escalado
    open_questions: list[str] = Field(description="Lo que no se pudo resolver y debe mirar un humano")
