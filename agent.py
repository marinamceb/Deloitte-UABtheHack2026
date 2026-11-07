"""CLI del agente de triaje N1 del SOC de Tarvia.

Ejemplos:
  python agent.py ALR-20261005-000301            # tría una o varias alertas por ID (vía API simulada)
  python agent.py --muestra 5                    # tría las 5 primeras de la muestra de desarrollo
  python agent.py --cola 10                      # tría las 10 primeras de la cola de la API
  python agent.py --muestra 3 --aprobar          # además, pide aprobación humana para la contención propuesta
  python agent.py --listar-modelos               # modelos disponibles en el proveedor configurado

Proveedor: TRIAJE_PROVEEDOR=gemini (por defecto, necesita GEMINI_API_KEY) | groq | openrouter | ollama | anthropic.
Modelo: TRIAJE_MODELO (por defecto gemini-3.5-flash con Gemini, claude-opus-5-5 con Anthropic).
"""
import argparse
import json
import sys
import time

import requests

from agente.herramientas import API_URL
from agente.prompts import DATASET
from agente.triaje import triar

MUESTRA = DATASET / "03_alertas" / "alertas_muestra_desarrollo.jsonl"


def cargar_alertas(args) -> list[dict]:
    alertas = []
    for aid in args.alert_ids:
        r = requests.get(f"{API_URL}/alerts/{aid}", timeout=30)
        if r.status_code == 404:
            sys.exit(f"La alerta {aid} no existe. Revisa el ID (formato ALR-AAAAMMDD-NNNNNN, "
                     f"p. ej. ALR-20261005-000301) o usa --muestra N.")
        r.raise_for_status()
        alertas.append(r.json())
    if args.muestra:
        with open(MUESTRA, encoding="utf-8") as f:
            alertas += [json.loads(l) for l in f if l.strip()][args.desde:args.desde + args.muestra]
    if args.cola:
        r = requests.get(f"{API_URL}/alerts", params={"status": "new", "limit": args.cola, "offset": args.desde},
                         timeout=30)
        r.raise_for_status()
        alertas += r.json()["items"]
    return alertas


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("alert_ids", nargs="*")
    p.add_argument("--muestra", type=int, default=0, help="N alertas de alertas_muestra_desarrollo.jsonl")
    p.add_argument("--cola", type=int, default=0, help="N alertas de la cola de la API")
    p.add_argument("--desde", type=int, default=0, help="desplazamiento dentro de la muestra o la cola")
    p.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    p.add_argument("--aprobar", action="store_true", help="revisar y ejecutar la contención propuesta (humano)")
    p.add_argument("--pausa", type=float, default=0, help="segundos de espera entre alertas (límites del plan gratuito)")
    p.add_argument("--listar-modelos", action="store_true", help="lista los modelos del proveedor y sale")
    p.add_argument("--aprobador", default="analista.n1", help="nombre que queda registrado en las aprobaciones")
    args = p.parse_args()

    if args.listar_modelos:
        from agente import motor_openai
        print("\n".join(motor_openai.listar_modelos()))
        return

    alertas = cargar_alertas(args)
    if not alertas:
        p.error("indica alert_ids, --muestra o --cola")

    for i, alerta in enumerate(alertas, 1):
        if i > 1 and args.pausa:
            time.sleep(args.pausa)
        print(f"[{i}/{len(alertas)}] {alerta['alert_id']}  {alerta['rule_id']}  {alerta['rule_name']} "
              f"(regla: {alerta['severity']})", flush=True)
        res = triar(alerta, effort=args.effort)
        t = res["ticket"]
        print(f"  → {t['verdict']} · {t['severity']} · conf {t['confidence']:.2f} · "
              f"{'ESCALAR a ' + t['escalation']['to'] if t['escalation']['escalate'] else 'cerrar'}")
        print(f"    {t['title']}")
        print(f"    {len(res['traza'])} consultas · {t['triage_seconds']} s · "
              f"tokens in/out {res['uso']['input_tokens']}/{res['uso']['output_tokens']} "
              f"· {res['modelo']}")
        if args.aprobar:
            from agente.contencion import revisar_acciones
            revisar_acciones(res, args.aprobador)
    print("\nTickets guardados en salidas/tickets/")


if __name__ == "__main__":
    sys.exit(main())
