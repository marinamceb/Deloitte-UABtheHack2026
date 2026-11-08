"""[Nivel 3] Evaluación de la reconstrucción de cadenas de ataque sobre casos verificados (casos_nivel3.json).

    python tests/evaluacion/evaluar_nivel3.py            # rastreo por código (sin LLM, segundos)
    python tests/evaluacion/evaluar_nivel3.py --llm      # además, redacta los informes que falten (gasta cuota)

Mide por caso, sin LLM:
- sensibilidad: eventos que deben estar en la cronología (cuenta también si están agrupados como repetición);
- ruido: eventos legítimos verificados que no deberían aparecer;
- acceso inicial: si alguno de los candidatos es un acceso inicial válido;
- huecos de detección, entidades clave (pivotes), incidente relacionado, indicadores que no deben serlo y tamaño.
Si hay un informe del LLM guardado, mide además su acceso inicial y la sensibilidad de su cronología.
Escribe resultado_nivel3.json (ignorado por git).
"""
import json
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ))

from agente import almacen, incidentes, informe, investigacion  # noqa: E402

CASOS = json.loads((Path(__file__).parent / "casos_nivel3.json").read_text(encoding="utf-8"))["casos"]


def ids_cronologia(cronologia: list[dict]) -> set[str]:
    return {i for x in cronologia for i in [x.get("event_id"), *x.get("event_ids", [])] if i}


def evaluar(caso: dict, usar_llm: bool = False) -> dict:
    ids = incidentes.incidente_de(caso["semilla"]) or [caso["semilla"]]
    t0 = time.time()
    h = investigacion.investigar(ids)
    segundos = round(time.time() - t0, 1)
    presentes = ids_cronologia(h["cronologia"])
    faltan = [e for e in caso["deben_estar"] if e not in presentes]
    ruido = [e for e in caso.get("no_deben_estar", []) if e in presentes]
    candidatos = [c["event_id"] for c in h["acceso_inicial_candidatos"]]
    r = {
        "caso": caso["nombre"], "semilla": caso["semilla"], "segundos": segundos,
        "sensibilidad": round(1 - len(faltan) / len(caso["deben_estar"]), 3), "faltan": faltan,
        "ruido": ruido, "acceso_inicial": bool(set(candidatos) & set(caso["acceso_inicial"])),
        "candidatos": candidatos,
        "cronologia": len(h["cronologia"]), "max_cronologia": caso.get("max_cronologia"),
        "tamano_ok": not caso.get("max_cronologia") or len(h["cronologia"]) <= caso["max_cronologia"],
        "nucleo": sum(1 for x in h["cronologia"] if x["nivel"] == "núcleo"),
        "pivote": sum(1 for x in h["cronologia"] if x["nivel"] == "pivote"),
        "huecos_ok": set(caso.get("huecos", [])) <= {g["fuente"] for g in h["huecos"]},
        "entidades_ok": all(e in h["entidades"] for e in caso.get("entidades", [])),
        "relacionado_ok": not caso.get("relacionado_con_alerta") or any(
            caso["relacionado_con_alerta"] in x["alertas"] for x in h["relacionados"]),
        "iocs_ok": not set(caso.get("iocs_prohibidos", [])) & set(h["iocs"]),
        "mensaje_llm_caracteres": len(informe.mensaje(h)),
    }
    r["ok"] = (not faltan and not ruido and r["acceso_inicial"] and r["tamano_ok"] and r["huecos_ok"]
               and r["entidades_ok"] and r["relacionado_ok"] and r["iocs_ok"])

    incident_id = "INC-" + h["alert_ids"][0].removeprefix("ALR-")
    guardado = almacen.informe(incident_id)
    if usar_llm and not (guardado and guardado.get("con_llm")):
        guardado = informe.generar(ids, usar_llm=True)
    if guardado and guardado.get("con_llm"):
        inf = guardado["informe"]
        en_informe = {p["event_id"] for p in inf["timeline"]}
        r["informe_llm"] = {
            "acceso_inicial_ok": any(e in inf["initial_access"] for e in caso["acceso_inicial"]),
            "sensibilidad_timeline": round(sum(e in en_informe for e in caso["deben_estar"])
                                           / len(caso["deben_estar"]), 3),
            "ruido_en_timeline": [e for e in caso.get("no_deben_estar", []) if e in en_informe],
            "tokens_entrada": (guardado.get("uso") or {}).get("input_tokens"),
            "llamadas": (guardado.get("uso") or {}).get("llamadas_modelo"),
            "con_herramientas": guardado.get("con_herramientas", "¿? (informe anterior a la optimización)"),
        }
    return r


def main() -> int:
    usar_llm = "--llm" in sys.argv
    resultados = [evaluar(c, usar_llm) for c in CASOS]
    print(f"{'caso':55} {'ok':3} {'sens.':>5} {'ruido':>5} {'acceso':>6} {'crono':>5} {'núc/piv':>7} {'s':>5}")
    for r in resultados:
        print(f"{r['caso'][:55]:55} {'✓' if r['ok'] else '✗':3} {r['sensibilidad']:5.0%} {len(r['ruido']):5} "
              f"{'✓' if r['acceso_inicial'] else '✗':>6} {r['cronologia']:5} {r['nucleo']:>3}/{r['pivote']:<3} "
              f"{r['segundos']:5}")
        for k in ("faltan", "ruido"):
            if r[k]:
                print(f"    {k}: {', '.join(r[k])}")
        for k in ("tamano_ok", "huecos_ok", "entidades_ok", "relacionado_ok", "iocs_ok"):
            if not r[k]:
                print(f"    ✗ {k}")
        if "informe_llm" in r:
            i = r["informe_llm"]
            print(f"    informe LLM: acceso inicial {'✓' if i['acceso_inicial_ok'] else '✗'} · cronología "
                  f"{i['sensibilidad_timeline']:.0%} · ruido {len(i['ruido_en_timeline'])} · "
                  f"{i['tokens_entrada']} tokens de entrada en {i['llamadas']} llamada(s)")
    ok = sum(r["ok"] for r in resultados)
    sens = sum(r["sensibilidad"] for r in resultados) / len(resultados)
    print(f"\n{ok}/{len(resultados)} casos correctos · sensibilidad media {sens:.0%} · "
          f"ruido total {sum(len(r['ruido']) for r in resultados)} eventos")
    (Path(__file__).parent / "resultado_nivel3.json").write_text(json.dumps(resultados, ensure_ascii=False, indent=1),
                                                                 encoding="utf-8")
    return 0 if ok == len(resultados) else 1


if __name__ == "__main__":
    sys.exit(main())
