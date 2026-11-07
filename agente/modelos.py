"""[Nivel 1] Esquema de la salida del modelo (Pydantic).

El LLM rellena `TicketTriaje`. La severidad final no la decide el modelo: aporta el activo más crítico, su criticidad y
el ajuste, y severidad.py los verifica y aplica la matriz. El ticket final (formato de
01_contexto/ticket_salida.schema.json) lo compone triaje.py.
"""
from typing import Literal

from pydantic import BaseModel, Field

Veredicto = Literal["true_positive", "benign_true_positive", "false_positive", "needs_more_info"]
Criticidad = Literal["Baja", "Media", "Alta", "Crítica"]
class Afectados(BaseModel):
    users: list[str]
    hosts: list[str]
    business_services: list[str]
    customers: list[str]


class Evidencia(BaseModel):
    source: str = Field(description="Fuente de log")
    event_id: str
    finding: str = Field(description="Una frase")


class Enriquecimiento(BaseModel):
    indicator: str = Field(description="IP, dominio, URL o hash")
    type: str = Field(description="ip, domain, url, sha256")
    source: str = Field(description="ti_feed, geoip_asn, sandbox")
    result: str = Field(description="Pocas palabras")


class AccionRecomendada(BaseModel):
    action: str = Field(
        description="isolate_host, disable_user, revoke_sessions, reset_password, block_ioc, purge_email, "
        "disable_access_key, o bien close, escalate_n2, notify_dpo, notify_treasury, monitor_24h, patch..."
    )
    target: str = Field(description="Valor exacto")
    requires_approval: bool = Field(description="Según el apartado 4")
    justification: str = Field(description="Una frase")


class Escalado(BaseModel):
    escalate: bool
    to: str = Field(description="N2, N2 guardia (teléfono), Operaciones, DPO... o vacío")
    reason: str = Field(description="Una frase o vacío")


class TicketTriaje(BaseModel):
    alert_ids: list[str] = Field(description="Esta alerta y las del mismo ataque")
    title: str = Field(description="Máx. 90 caracteres: qué pasa")
    verdict: Veredicto
    confidence: float = Field(description="Entre 0 y 1")
    activo_mas_critico: str = Field(description="Hostname, UPN o recurso")
    criticidad: Criticidad = Field(description="Según CMDB o servicio de negocio; identidades: Media")
    ajuste: Literal["-1", "0", "+1"] = Field(description="Ajuste de la política")
    motivo_ajuste: str = Field(description="Pocas palabras o vacío")
    affected: Afectados
    summary: str = Field(description="2-4 frases")
    evidence: list[Evidencia] = Field(description="Máx. 5 eventos de log")
    enrichment: list[Enriquecimiento]
    mitre: list[str]
    recommended_actions: list[AccionRecomendada]
    escalation: Escalado
    open_questions: list[str] = Field(description="Pendiente para el humano")
    patron_generalizable: bool = Field(description="true solo si el veredicto vale para cualquier alerta con la misma "
                                                   "regla y evidencia, sea cual sea la IP, entidad o fecha")
