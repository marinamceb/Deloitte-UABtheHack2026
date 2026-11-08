"""[Nivel 1 y 3] Esquemas de la salida del modelo (Pydantic): ticket de triaje (nivel 1) e informe (nivel 3).

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


# =============================================================================================== [Nivel 3] informe
# El LLM rellena `InformeLLM` a partir de los hechos que reúne investigacion.py. Fechas, técnicas MITRE y aprobadores
# no los decide el modelo: informe.py los toma de los hechos y de la política (formato informe_incidente.schema.json).

class PasoCronologia(BaseModel):
    event_id: str = Field(description="ID exacto de un evento de <cronologia>")
    description: str = Field(description="Qué hizo el atacante en este paso, una frase")


class AlcanceInforme(BaseModel):
    users: list[str]
    hosts: list[str]
    data: str = Field(description="Qué datos y cuántos (filas, GB, ficheros), o «no consta salida de datos»")
    business_impact: str = Field(description="Una o dos frases, con el servicio de negocio afectado")


class AccionContencion(BaseModel):
    action: str = Field(description="isolate_host, disable_user, revoke_sessions, reset_password, block_ioc, "
                                    "purge_email, disable_access_key, delete_inbox_rule, remove_mfa_method...")
    target: str = Field(description="Valor exacto")
    business_impact: str = Field(description="Qué se para si se ejecuta, o «ninguno»")
    justification: str = Field(description="Una frase")


class EventoDescartado(BaseModel):
    event_id: str
    motivo: str = Field(description="Por qué no forma parte del ataque, una frase")


class InformeLLM(BaseModel):
    title: str = Field(description="Máx. 100 caracteres")
    alert_ids: list[str] = Field(description="Alertas del incidente confirmadas (de <alertas>)")
    patient_zero: str = Field(description="Primer equipo o cuenta comprometidos")
    initial_access: str = Field(description="Cómo entró el atacante, con el event_id que lo prueba")
    initial_access_event_id: str = Field(description="event_id del acceso inicial (de <cronologia>)")
    timeline: list[PasoCronologia] = Field(description="Pasos clave del ataque en orden, de 5 a 25")
    scope: AlcanceInforme
    root_cause: str = Field(description="Causa raíz: qué permitió el ataque (2-4 frases)")
    containment_plan: list[AccionContencion]
    eradication_and_recovery: list[str]
    notifications: list[str] = Field(description="Quién debe enterarse y en qué plazo")
    detection_gaps: list[str] = Field(description="Qué no detectamos y qué regla crear o afinar")
    related_incidents: list[str] = Field(description="Incidentes de <relacionados> que son parte de la misma historia")
    descartados: list[EventoDescartado] = Field(description="Eventos de <cronologia> que NO son del ataque")
    confidence: float = Field(description="Entre 0 y 1")
    open_questions: list[str]
