"""Motor para APIs compatibles con OpenAI (Gemini por defecto; también Groq, OpenRouter u Ollama cambiando la URL).

Diferencias con el motor Claude:
- El bucle de herramientas está escrito a mano.
- El ticket se entrega llamando a la herramienta `emitir_ticket`; se valida con Pydantic y, si no es válido, se le
  devuelve el error al modelo para que lo corrija.
- Los planes gratuitos tienen límites por minuto y por día: el cliente reintenta con espera ante 429.
"""
import json
import os
import time

import openai
from pydantic import ValidationError

from . import herramientas
from .modelos import TicketTriaje

PROVEEDORES = {
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/", "GEMINI_API_KEY", "gemini-3.5-flash"),
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY", ""),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY", ""),
    "ollama": ("http://localhost:11434/v1", "", ""),
}
PROVEEDOR = os.environ.get("TRIAJE_PROVEEDOR", "gemini")
_URL, _VAR_CLAVE, _MODELO_DEF = PROVEEDORES[PROVEEDOR]
MODELO = os.environ.get("TRIAJE_MODELO", _MODELO_DEF)
# Peticiones por minuto permitidas. El plan gratuito de Gemini da 5 RPM: se espacian las llamadas para no recibir 429.
RPM = float(os.environ.get("TRIAJE_RPM", "5" if PROVEEDOR == "gemini" else "0"))
_client = None
_ultima_peticion = 0.0

CIERRE = ("Cuando hayas terminado de investigar, entrega el resultado llamando a la herramienta `emitir_ticket` "
          "(una sola vez, como última acción). No escribas el ticket como texto.")


def cliente() -> openai.OpenAI:
    global _client
    if _client is None:
        clave = os.environ.get(_VAR_CLAVE, "") if _VAR_CLAVE else "ollama"
        if not clave:
            raise SystemExit(f"Falta la variable de entorno {_VAR_CLAVE} para el proveedor '{PROVEEDOR}'.")
        if not MODELO:
            raise SystemExit(f"Indica el modelo con TRIAJE_MODELO para el proveedor '{PROVEEDOR}'.")
        # max_retries con espera exponencial (respeta retry-after) para los 429 de los planes gratuitos
        _client = openai.OpenAI(base_url=_URL, api_key=clave, max_retries=3, timeout=90)
    return _client


def _respetar_rpm() -> None:
    global _ultima_peticion
    if RPM > 0:
        espera = 60 / RPM - (time.time() - _ultima_peticion)
        if espera > 0:
            print(f"    … esperando {espera:.0f} s (límite de {RPM:g} peticiones/min)", flush=True)
            time.sleep(espera)
    _ultima_peticion = time.time()


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


def _herramientas_openai() -> list[dict]:
    tools = []
    for t in herramientas.HERRAMIENTAS:
        d = t.to_dict()
        tools.append({"type": "function", "function": {"name": d["name"], "description": d["description"],
                                                       "parameters": _limpiar_esquema(d["input_schema"])}})
    tools.append({"type": "function", "function": {
        "name": "emitir_ticket",
        "description": "Entrega el ticket de triaje final. Llámala una sola vez, al terminar la investigación.",
        "parameters": _limpiar_esquema(TicketTriaje.model_json_schema())}})
    return tools


def ejecutar(sistema: str, mensaje: str, effort: str, max_iteraciones: int) -> dict:
    por_nombre = {t.name: t for t in herramientas.HERRAMIENTAS}
    tools = _herramientas_openai()
    mensajes = [{"role": "system", "content": sistema + "\n\n" + CIERRE}, {"role": "user", "content": mensaje}]
    extra = {"reasoning_effort": {"xhigh": "high", "max": "high"}.get(effort, effort)} if PROVEEDOR == "gemini" else {}

    uso = {"input_tokens": 0, "output_tokens": 0, "llamadas_modelo": 0}
    razonamiento: list[str] = []
    out = {"ticket": None, "motivo": "", "uso": uso, "razonamiento": razonamiento, "modelo": f"{PROVEEDOR}/{MODELO}"}

    for _ in range(max_iteraciones):
        _respetar_rpm()
        try:
            r = cliente().chat.completions.create(model=MODELO, messages=mensajes, tools=tools, tool_choice="auto",
                                                  **extra)
        except openai.RateLimitError as e:
            out["motivo"] = f"límite de uso del proveedor agotado (429): {e.message}"
            return out
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
            mensajes.append({"role": "user", "content": CIERRE})
            continue

        for tc in msg.tool_calls:
            nombre = tc.function.name
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError as e:
                resultado = f"Error: argumentos JSON no válidos ({e}). Repite la llamada."
            else:
                if nombre == "emitir_ticket":
                    try:
                        out["ticket"] = TicketTriaje.model_validate(args).model_dump()
                        resultado = "Ticket recibido."
                    except ValidationError as e:
                        resultado = f"Ticket no válido, corrígelo y vuelve a llamar a emitir_ticket:\n{e}"
                elif nombre in por_nombre:
                    try:
                        resultado = por_nombre[nombre].call(args)
                    except Exception as e:  # el error vuelve al modelo, como hace el tool runner de Anthropic
                        resultado = f"Error: {e}"
                else:
                    resultado = f"Error: herramienta desconocida '{nombre}'."
            mensajes.append({"role": "tool", "tool_call_id": tc.id, "content": str(resultado)})

        if out["ticket"] is not None:
            return out

    out["motivo"] = f"se alcanzó el máximo de {max_iteraciones} iteraciones"
    return out


def listar_modelos() -> list[str]:
    return sorted(m.id for m in cliente().models.list())
