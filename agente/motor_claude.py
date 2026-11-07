"""Motor Claude: Anthropic SDK + tool runner, con el ticket como salida estructurada (output_format)."""
import os

from . import herramientas
from .modelos import TicketTriaje

MODELO = os.environ.get("TRIAJE_MODELO", "claude-opus-5-5")
_client = None


def ejecutar(sistema: str, mensaje: str, effort: str, max_iteraciones: int) -> dict:
    global _client
    import anthropic
    if _client is None:
        _client = anthropic.Anthropic()

    extra = {}
    if not MODELO.startswith("claude-haiku"):
        # Si un clasificador de seguridad rechaza (el contenido SOC puede parecer ofensivo), reintenta en otro modelo.
        # Haiku no admite fallbacks en servidor.
        extra = {"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"}

    runner = _client.beta.messages.tool_runner(
        model=MODELO,
        max_tokens=16000,
        system=sistema,
        cache_control={"type": "ephemeral"},
        tools=herramientas.HERRAMIENTAS,
        messages=[{"role": "user", "content": mensaje}],
        output_format=TicketTriaje,
        output_config={"effort": effort},
        max_iterations=max_iteraciones,
        **extra,
    )

    uso = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0, "llamadas_modelo": 0}
    razonamiento: list[str] = []
    final = None
    for msg in runner:
        final = msg
        uso["llamadas_modelo"] += 1
        for k in ("input_tokens", "output_tokens", "cache_read_input_tokens"):
            uso[k] += getattr(msg.usage, k, 0) or 0
        if msg.stop_reason == "tool_use":
            razonamiento += [b.text.strip() for b in msg.content if b.type == "text" and b.text.strip()]

    out = {"ticket": None, "motivo": "", "uso": uso, "razonamiento": razonamiento,
           "modelo": getattr(final, "model", MODELO)}
    if final is None:
        out["motivo"] = "sin respuesta del modelo"
    elif final.stop_reason == "refusal":
        cat = final.stop_details.category if final.stop_details else None
        out["motivo"] = f"el modelo rechazó la petición (categoría: {cat})"
    elif final.stop_reason == "tool_use":
        out["motivo"] = f"se alcanzó el máximo de {max_iteraciones} iteraciones"
    elif getattr(final, "parsed_output", None) is None:
        out["motivo"] = f"salida no válida (stop_reason={final.stop_reason})"
    else:
        out["ticket"] = final.parsed_output.model_dump()
    return out
