"""[Niveles 1 y 2, de principio a fin] Mide los aciertos del agente sobre los casos verificados de casos.json.

    python tests/evaluacion/evaluar.py           # puntúa los tickets que ya hay en salidas/tickets (sin LLM)
    python tests/evaluacion/evaluar.py --triar   # tría con el LLM los casos que aún no tienen ticket (gasta cuota)

Por caso se comprueba:
- código (sin LLM): que el incidente candidato contenga las alertas de «incluye» y ninguna de «excluye»;
- ticket (con LLM): veredicto, severidad, escalado y agrupación final (alert_ids del ticket).
Un caso cuya alerta forma parte de otro ticket (triada dentro de un incidente) se puntúa con ese ticket.
"""
import argparse
import json
import sys
import time
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]  # raíz del proyecto (tests/evaluacion/evaluar.py)
sys.path.insert(0, str(RAIZ))

from agente import incidentes  # noqa: E402
from agente.triaje import SALIDAS, cubierta_por  # noqa: E402

CASOS = json.loads((Path(__file__).parent / "casos.json").read_text(encoding="utf-8"))["casos"]


def ticket_de(alert_id: str) -> dict | None:
    for ticket_id in ("TKT-" + alert_id.removeprefix("ALR-"), cubierta_por(alert_id)):
        p = SALIDAS / "tickets" / f"{ticket_id}.json"
        if ticket_id and p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    return None


def agrupacion(ids: list[str], caso: dict) -> tuple[bool, str]:
    faltan = [x for x in caso["incluye"] if x not in ids]
    sobran = [x for x in caso["excluye"] if x in ids]
    detalle = (f"faltan {', '.join(faltan)}" if faltan else "") + (f" sobran {', '.join(sobran)}" if sobran else "")
    return not faltan and not sobran, detalle.strip()


def evaluar(caso: dict) -> dict:
    aid = caso["alerta"]
    grupo = incidentes.incidente_de(aid) or [aid]
    ok_codigo, det_codigo = agrupacion(grupo, caso)
    r = {"caso": caso["nombre"], "alerta": aid, "agrupacion_codigo": ok_codigo, "detalle_codigo": det_codigo}
    res = ticket_de(aid)
    if not res:
        return {**r, "ticket": None}
    t = res["ticket"]
    ok_grupo, det_grupo = agrupacion(t["alert_ids"], caso)
    return {**r, "ticket": t["ticket_id"], "modelo": res.get("modelo", ""),
            "veredicto": (t["verdict"] in caso["veredictos"], t["verdict"]),
            "severidad": (t["severity"] in caso["severidades"], t["severity"]),
            "escalado": (t["escalation"]["escalate"] == caso["escalar"], t["escalation"]["escalate"]),
            "agrupacion": (ok_grupo, det_grupo)}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--triar", action="store_true", help="triar con el LLM los casos sin ticket")
    p.add_argument("--pausa", type=float, default=0, help="segundos entre alertas al triar")
    args = p.parse_args()

    if args.triar:
        from agente.motores import CuotaAgotada
        from agente.triaje import triar
        pendientes = [c for c in CASOS if not ticket_de(c["alerta"])]
        print(f"Triando {len(pendientes)} casos sin ticket…")
        for c in pendientes:
            if ticket_de(c["alerta"]):  # puede haber quedado cubierto por el ticket de un caso anterior
                continue
            try:
                triar(incidentes.todas_las_alertas()[c["alerta"]])
            except CuotaAgotada as e:
                print(f"  ✗ {e}. Se evalúa lo que haya.")
                break
            time.sleep(args.pausa)

    resultados = [evaluar(c) for c in CASOS]
    marca = lambda ok: "✓" if ok else "✗"  # noqa: E731
    print(f"\n{'caso':58} {'grupo(código)':14} {'veredicto':24} {'severidad':16} {'escalado':9} grupo(ticket)")
    for r in resultados:
        fila = f"{r['caso'][:57]:58} {marca(r['agrupacion_codigo']):14} "
        if r["ticket"] is None:
            fila += "(sin ticket)"
        else:
            fila += (f"{marca(r['veredicto'][0])} {r['veredicto'][1]:22} {marca(r['severidad'][0])} "
                     f"{r['severidad'][1]:14} {marca(r['escalado'][0]):9} {marca(r['agrupacion'][0])} "
                     f"{r['agrupacion'][1]}")
        print(fila)
        if not r["agrupacion_codigo"]:
            print(f"{'':58} └ código: {r['detalle_codigo']}")

    con_ticket = [r for r in resultados if r["ticket"]]
    print(f"\nAgrupación por código (sin LLM): {sum(r['agrupacion_codigo'] for r in resultados)}/{len(resultados)}")
    print(f"Casos con ticket: {len(con_ticket)}/{len(resultados)}")
    for clave in ("veredicto", "severidad", "escalado", "agrupacion"):
        aciertos = sum(r[clave][0] for r in con_ticket)
        print(f"  {clave:11} {aciertos}/{len(con_ticket)}" + (f"  ({100 * aciertos / len(con_ticket):.0f} %)"
                                                              if con_ticket else ""))
    (Path(__file__).parent / "resultado.json").write_text(json.dumps(resultados, ensure_ascii=False, indent=1),
                                                          encoding="utf-8")


if __name__ == "__main__":
    main()
