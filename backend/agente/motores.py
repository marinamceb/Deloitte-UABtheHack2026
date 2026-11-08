"""[Nivel 1, también nivel 3] Conexión con el LLM. Dos motores con la misma interfaz
`ejecutar(sistema, mensaje, effort, max_iter, salida=TicketTriaje, herramienta_salida="emitir_ticket")`, que devuelven
{"salida", "motivo", "uso", "razonamiento", "modelo"}; "salida" es la salida validada con el esquema `salida` (el ticket
de triaje o, en el nivel 3, el informe de incidente). El proveedor se elige con TRIAJE_PROVEEDOR:

- gemini (por defecto), groq, openrouter, ollama: API compatible con OpenAI. Bucle de herramientas escrito a mano; el
  ticket se entrega llamando a la herramienta `emitir_ticket`, se valida con Pydantic y, si no es válido, se le
  devuelve el error al modelo. Los planes gratuitos limitan peticiones por minuto y por día: ante un 429 por minuto se
  espera lo que indica el proveedor; ante la cuota diaria agotada se lanza CuotaAgotada para parar el lote.
- anthropic: SDK de Anthropic con el tool runner y el ticket como salida estructurada (output_format).
"""
import json
import os
import re
import time

import openai
from pydantic import BaseModel, ValidationError

from . import herramientas
from .modelos import TicketTriaje

PROVEEDORES = {  # proveedor → (URL compatible con OpenAI, variable con la clave, modelo por defecto)
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/", "GEMINI_API_KEY", "gemini-3.5-flash"),
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY", ""),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY", ""),
    "ollama": ("http://localhost:11434/v1", "", ""),
    "anthropic": ("", "ANTHROPIC_API_KEY", "claude-opus-5-5"),
}
PROVEEDOR = os.environ.get("TRIAJE_PROVEEDOR", "gemini")
_URL, _VAR_CLAVE, _MODELO_DEF = PROVEEDORES[PROVEEDOR]
MODELO = os.environ.get("TRIAJE_MODELO", _MODELO_DEF)
# Peticiones por minuto permitidas. El plan gratuito de Gemini da 5 RPM: se espacian las llamadas para no recibir 429.
RPM = float(os.environ.get("TRIAJE_RPM", "5" if PROVEEDOR == "gemini" else "0"))


def ejecutar(sistema: str, mensaje: str, effort: str, max_iteraciones: int, salida: type[BaseModel] = TicketTriaje,
             herramienta_salida: str = "emitir_ticket", con_herramientas: bool = True) -> dict:
    """`con_herramientas=False`: el modelo solo puede entregar el resultado (una llamada, salvo que haya que corregir
    la validación). Lo usa el informe del nivel 3, cuyos hechos ya vienen reunidos por código: cada vuelta de
    herramientas reenvía todo el contexto y multiplicaba los tokens por 5-10."""
    herramientas_modelo = herramientas.HERRAMIENTAS if con_herramientas else []
    if PROVEEDOR == "anthropic":
        return _ejecutar_claude(sistema, mensaje, effort, max_iteraciones, salida, herramientas_modelo)
    return _ejecutar_openai(sistema, mensaje, effort, max_iteraciones, salida, herramienta_salida, herramientas_modelo)


# =============================================================================================== Claude (Anthropic)

_cliente_claude = None


def _ejecutar_claude(sistema: str, mensaje: str, effort: str, max_iteraciones: int, salida=TicketTriaje,
                     herramientas_modelo=None) -> dict:
    global _cliente_claude
    import anthropic
    if _cliente_claude is None:
        _cliente_claude = anthropic.Anthropic()
    extra = {}
    if not MODELO.startswith("claude-haiku"):
        # Si un clasificador de seguridad rechaza (el contenido SOC puede parecer ofensivo), reintenta en otro modelo.
        # Haiku no admite fallbacks en servidor.
        extra = {"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"}

    runner = _cliente_claude.beta.messages.tool_runner(
        model=MODELO,
        max_tokens=16000,
        system=sistema,
        cache_control={"type": "ephemeral"},
        tools=herramientas.HERRAMIENTAS if herramientas_modelo is None else herramientas_modelo,
        messages=[{"role": "user", "content": mensaje}],
        output_format=salida,
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

    out = {"salida": None, "motivo": "", "uso": uso, "razonamiento": razonamiento,
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
        out["salida"] = final.parsed_output.model_dump()
    return out


# ==================== compatibles con OpenAI (Gemini...)

_cliente_openai = None
_ultima_peticion = 0.0


class CuotaAgotada(Exception):
    """Cuota diaria del proveedor agotada: no tiene sentido seguir triando hasta que se reinicie."""


CIERRE = ("Cuando hayas terminado de investigar, entrega el resultado llamando a la herramienta `{h}` "
          "(una sola vez, como última acción). No lo escribas como texto.")


def cliente() -> openai.OpenAI:
    global _cliente_openai
    if _cliente_openai is None:
        clave = os.environ.get(_VAR_CLAVE, "") if _VAR_CLAVE else "ollama"
        if not clave:
            raise SystemExit(f"Falta la variable de entorno {_VAR_CLAVE} para el proveedor '{PROVEEDOR}'.")
        if not MODELO:
            raise SystemExit(f"Indica el modelo con TRIAJE_MODELO para el proveedor '{PROVEEDOR}'.")
        # Los 429 se gestionan en _llamar (distinguir límite por minuto de cuota diaria); el SDK solo reintenta red/5xx
        _cliente_openai = openai.OpenAI(base_url=_URL, api_key=clave, max_retries=2, timeout=90)
    return _cliente_openai


def _respetar_rpm() -> None:
    global _ultima_peticion
    if RPM > 0:
        espera = 60 / RPM - (time.time() - _ultima_peticion)
        if espera > 0:
            print(f"    … esperando {espera:.0f} s (límite de {RPM:g} peticiones/min)", flush=True)
            time.sleep(espera)
    _ultima_peticion = time.time()


def _llamar(**kw):
    """Una petición al modelo respetando el ritmo y los 429 del plan gratuito."""
    for intento in range(4):
        _respetar_rpm()
        try:
            return cliente().with_options(max_retries=0 if intento else 2).chat.completions.create(**kw)
        except openai.RateLimitError as e:
            texto = e.response.text
            if "per day" in texto or "PerDay" in texto:
                espera = re.search(r"retry in ([0-9hms.]+)", texto)
                raise CuotaAgotada(f"cuota diaria de {MODELO} agotada"
                                   + (f"; se reinicia en {espera.group(1)}" if espera else "")
                                   + ". Prueba otro modelo (TRIAJE_MODELO), que tiene su propia cuota, o espera.")
            m = re.search(r"retry in ([0-9.]+)s", texto)
            espera = float(m.group(1)) + 1 if m else 30
            print(f"    … límite por minuto alcanzado, reintento en {espera:.0f} s", flush=True)
            time.sleep(espera)
    raise CuotaAgotada(f"{MODELO} sigue devolviendo 429 tras varios reintentos")


def _limpiar_esquema(esquema: dict) -> dict:
    """Gemini acepta un subconjunto de JSON Schema: se resuelven los $ref y se quitan claves que rechaza."""
    defs = esquema.get("$defs", {})

    def resolver(n, es_properties=False):
        if isinstance(n, dict):
            if es_properties:  # aquí las claves son nombres de campo (p. ej. el campo `title` del ticket): se conservan
                return {k: resolver(v) for k, v in n.items()}
            if "$ref" in n:
                return resolver(defs[n["$ref"].split("/")[-1]])
            return {k: resolver(v, es_properties=(k == "properties")) for k, v in n.items()
                    if k not in ("$defs", "title", "additionalProperties", "default")}
        if isinstance(n, list):
            return [resolver(x) for x in n]
        return n

    return resolver(esquema)


def _herramientas_openai(salida=TicketTriaje, herramienta_salida: str = "emitir_ticket",
                         herramientas_modelo=None) -> list[dict]:
    tools = []
    for t in herramientas.HERRAMIENTAS if herramientas_modelo is None else herramientas_modelo:
        d = t.to_dict()
        tools.append({"type": "function", "function": {"name": d["name"], "description": d["description"],
                                                       "parameters": _limpiar_esquema(d["input_schema"])}})
    tools.append({"type": "function", "function": {
        "name": herramienta_salida,
        "description": "Entrega el resultado final. Llámala una sola vez, al terminar la investigación.",
        "parameters": _limpiar_esquema(salida.model_json_schema())}})
    return tools


def _ejecutar_openai(sistema: str, mensaje: str, effort: str, max_iteraciones: int, salida=TicketTriaje,
                     herramienta_salida: str = "emitir_ticket", herramientas_modelo=None) -> dict:
    disponibles = herramientas.HERRAMIENTAS if herramientas_modelo is None else herramientas_modelo
    por_nombre = {t.name: t for t in disponibles}
    tools = _herramientas_openai(salida, herramienta_salida, disponibles)
    cierre = CIERRE.format(h=herramienta_salida)
    mensajes = [{"role": "system", "content": sistema + "\n\n" + cierre}, {"role": "user", "content": mensaje}]
    extra = {"reasoning_effort": {"xhigh": "high", "max": "high"}.get(effort, effort)} if PROVEEDOR == "gemini" else {}

    uso = {"input_tokens": 0, "output_tokens": 0, "llamadas_modelo": 0}
    razonamiento: list[str] = []
    out = {"salida": None, "motivo": "", "uso": uso, "razonamiento": razonamiento, "modelo": f"{PROVEEDOR}/{MODELO}"}

    for _ in range(max_iteraciones):
        try:
            r = _llamar(model=MODELO, messages=mensajes, tools=tools, tool_choice="auto", **extra)
        except openai.APIStatusError as e:
            out["motivo"] = f"error del proveedor ({e.status_code}): {e.response.text[:300]}"
            return out
        except openai.APITimeoutError:
            out["motivo"] = f"el modelo {MODELO} no respondió a tiempo (prueba otro con TRIAJE_MODELO)"
            return out
        uso["llamadas_modelo"] += 1
        if r.usage:
            uso["input_tokens"] += r.usage.prompt_tokens or 0
            uso["output_tokens"] += r.usage.completion_tokens or 0

        msg = r.choices[0].message
        # model_dump conserva campos extra del proveedor (p. ej. firmas de pensamiento de Gemini) necesarios al reenviar
        mensajes.append(msg.model_dump(exclude_none=True))
        if msg.content and msg.content.strip():
            razonamiento.append(msg.content.strip())

        if not msg.tool_calls:
            mensajes.append({"role": "user", "content": cierre})
            continue

        for tc in msg.tool_calls:
            nombre = tc.function.name
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError as e:
                resultado = f"Error: argumentos JSON no válidos ({e}). Repite la llamada."
            else:
                if nombre == herramienta_salida:
                    try:
                        out["salida"] = salida.model_validate(args).model_dump()
                        resultado = "Recibido."
                    except ValidationError as e:
                        resultado = f"Resultado no válido, corrígelo y vuelve a llamar a {herramienta_salida}:\n{e}"
                elif nombre in por_nombre:
                    try:
                        resultado = por_nombre[nombre].call(args)
                    except Exception as e:  # el error vuelve al modelo, como hace el tool runner de Anthropic
                        resultado = f"Error: {e}"
                else:
                    resultado = f"Error: herramienta desconocida '{nombre}'."
            mensajes.append({"role": "tool", "tool_call_id": tc.id, "content": str(resultado)})

        if out["salida"] is not None:
            return out

    out["motivo"] = f"se alcanzó el máximo de {max_iteraciones} iteraciones"
    return out


def listar_modelos() -> list[str]:
    return sorted(m.id for m in cliente().models.list())
