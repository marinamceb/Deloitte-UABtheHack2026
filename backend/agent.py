"""CLI del agente de triaje N1 del SOC de Tarvia.

Ejemplos:
  python agent.py ALR-20261005-000301            # tría una o varias alertas por ID (vía API simulada)
  python agent.py --muestra 5                    # tría las 5 primeras de la muestra de desarrollo
  python agent.py --cola 10                      # tría las 10 más prioritarias de la cola (severidad estimada y SLA)
  python agent.py --ver-cola 20                  # muestra la cola priorizada sin llamar al modelo
  python agent.py --muestra 3 --aprobar --aprobador n2   # y decide la contención propuesta (pide contraseña)
  python agent.py --pendientes n2                  # nivel 4: acciones que ese usuario del SOC puede decidir
  python agent.py --listar-modelos               # modelos disponibles en el proveedor configurado
  python agent.py --listar-incidentes            # alertas agrupadas en incidentes candidatos (sin LLM)
  python agent.py --construir-indice             # descarga los logs por la API a salidas/indice_logs.sqlite
  python agent.py --estado-indice                # resumen del índice local de logs
  python agent.py --investigar ALR-20261015-011819   # nivel 3: cadena de ataque e informe de incidente
  python agent.py --investigar TKT-20261006-011826 --sin-llm   # solo los hechos reunidos por código

Proveedor: TRIAJE_PROVEEDOR=gemini (por defecto, necesita GEMINI_API_KEY) | groq | openrouter | ollama | anthropic.
Modelo: TRIAJE_MODELO (por defecto gemini-3.5-flash con Gemini, claude-opus-5-5 con Anthropic).
"""
import argparse
import json
import sys
import time

from agente import almacen, cola
from agente.config import DATASET
from agente.herramientas import alerta_por_id
from agente.motores import CuotaAgotada
from agente.triaje import triar

MUESTRA = DATASET / "03_alertas" / "alertas_muestra_desarrollo.jsonl"   # solo se leen sus IDs
ETIQUETA_TIPO = {"regla_interna": "regla interna", "cambio": "cambio", "rrhh": "RRHH", "linea_base": "línea base"}


def _alerta_api(aid: str) -> dict:
    alerta, error, _ = alerta_por_id(aid)
    if alerta is None:
        sys.exit(f"La alerta {aid} no existe ({error}). Revisa el ID (formato ALR-AAAAMMDD-NNNNNN, "
                 f"p. ej. ALR-20261005-000301) o usa --muestra N.")
    return alerta


def ids_muestra() -> list[str]:
    """IDs de la muestra de desarrollo (el contenido de cada alerta se pide a la API, como en producción)."""
    with open(MUESTRA, encoding="utf-8") as f:
        return [json.loads(l)["alert_id"] for l in f if l.strip()]


def cargar_alertas(args) -> list[dict]:
    alertas = [_alerta_api(aid) for aid in args.alert_ids]
    if args.muestra:
        alertas += [_alerta_api(aid) for aid in ids_muestra()[args.desde:args.desde + args.muestra]]
    if args.cola:
        alertas += [x["alerta"] for x in cola.actual()[args.desde:args.desde + args.cola]]
    elif args.priorizar and len(alertas) > 1:
        alertas = [x["alerta"] for x in cola.priorizar(alertas)]
    return alertas


def ver_cola(n: int) -> None:
    entradas = cola.actual()
    print(f"Cola priorizada: {len(entradas)} puestos (incidentes y alertas sueltas) sin ticket. Los {n} primeros:\n")
    print(f"{'#':>3} {'sev. estimada':13} {'vence (SLA)':17} {'alerta a triar':20} {'n':>3} {'regla':11} "
          "activo más crítico")
    for i, x in enumerate(entradas[:n], 1):
        a = x["alerta"]
        print(f"{i:3} {x['severidad']:13} {x['vence']:%d/%m %H:%M} UTC  {a['alert_id']:20} {len(x['alert_ids']):3} "
              f"{a['rule_id']:11} {x['activo']} ({x['criticidad']})"
              + ("  [ruido]" if x["ruido"] else "") + ("  [autorizada]" if x["autorizada"] else ""))


def indice_cli(fuentes: str | None) -> None:
    """[Nivel 3 · infraestructura] Construye (vía API) o resume el índice local de logs."""
    from agente import indice
    if fuentes:
        lista = None if fuentes == "todas" else fuentes.split(",")
        print(f"Descargando {'todas las fuentes' if lista is None else ', '.join(lista)} por la API...")
        t0 = time.time()
        indice.construir(lista)
        print(f"Índice construido en {time.time() - t0:.0f} s.\n")
    e = indice.estado()
    if e is None:
        print("No hay índice. Créalo con: python agent.py --construir-indice")
        return
    print(f"{e['ruta']} · {e['mb']} MB · {e['eventos']} eventos · construido {e['construido']} desde {e['api_url']}")
    for f, x in e["fuentes"].items():
        print(f"  {f:13} {x['eventos']:>7}  {x['primero'][:16]} → {x['ultimo'][:16]}")


def investigar_cli(ids: list[str], usar_llm: bool, effort: str, forzar: bool = False,
                   con_herramientas: bool = False) -> int | None:
    """[Nivel 3] Reconstruye la cadena de ataque y genera el informe de incidente."""
    from agente import informe
    try:
        r = informe.generar(ids, usar_llm=usar_llm, effort=effort, forzar=forzar, con_herramientas=con_herramientas)
    except CuotaAgotada as e:
        print(f"✗ {e}\n  Usa --sin-llm para obtener al menos los hechos reunidos por código.")
        return 1
    inf, h = r["informe"], r["hechos"]
    if r.get("reutilizado"):
        print(f"≡ Mismos hechos que el informe del {r['generado_en'][:16]}: se reutiliza sin llamar al LLM "
              "(--forzar para redactarlo de nuevo).")
    if r.get("no_guardado"):
        print(f"ℹ {r['no_guardado']}.")
    est = h["estadisticas"]
    print(f"{inf['incident_id']} · {inf['title']}")
    print(f"  {len(inf['alert_ids'])} alertas · {est['entidades']} entidades rastreadas en {est['consultas_indice']} "
          f"consultas al índice · {len(h['cronologia'])} entradas de cronología · {est['segundos']} s de rastreo")
    print(f"  Paciente cero: {inf['patient_zero']}")
    print(f"  Acceso inicial: {inf['initial_access']}")
    print("  Cronología:")
    for x in inf["timeline"]:
        print(f"    {x['timestamp'][:16]} {x['event_id']:13} {x['mitre'] or '':10} {x['description']}")
    print(f"  Causa raíz: {inf['root_cause']}")
    for a in inf["containment_plan"]:
        print(f"  ⛨ {a['action']} {a['target']}  (aprueba: {a['approver']})")
    for n in inf["notifications"]:
        print(f"  ✉ {n}")
    for g in inf["detection_gaps"]:
        print(f"  ◌ hueco: {g}")
    for rel in inf["related_incidents"]:
        print(f"  ↔ relacionado: {rel}")
    for d in inf["descartados"]:
        print(f"  ✗ descartado {d['event_id']}: {d['motivo']}")
    for aj in inf["ajustes_politica"]:
        print(f"  ⚖ {aj}")
    for q in inf["open_questions"]:
        print(f"  ? {q}")
    print(f"  {'LLM: ' + r['modelo'] if r['con_llm'] else 'Sin LLM (' + r['motivo'] + ')'} · tokens in/out "
          f"{r['uso']['input_tokens']}/{r['uso']['output_tokens']} · {r['segundos']} s")
    print(f"\nInforme guardado en salidas/informes/{inf['incident_id']}.json")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("alert_ids", nargs="*")
    p.add_argument("--muestra", type=int, default=0, help="N alertas de alertas_muestra_desarrollo.jsonl")
    p.add_argument("--cola", type=int, default=0, help="las N alertas más prioritarias de la cola")
    p.add_argument("--ver-cola", type=int, default=0, metavar="N", help="muestra la cola priorizada y sale (sin LLM)")
    p.add_argument("--priorizar", action="store_true", help="ordena por prioridad el lote de --muestra o de IDs")
    p.add_argument("--desde", type=int, default=0, help="desplazamiento dentro de la muestra o la cola")
    p.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    p.add_argument("--aprobar", action="store_true", help="revisar y ejecutar la contención propuesta (humano)")
    p.add_argument("--pausa", type=float, default=0, help="segundos de espera entre alertas (límites del plan gratuito)")
    p.add_argument("--sin-plantillas", action="store_true",
                   help="triar cada alerta con el modelo aunque repita el patrón de un ticket anterior")
    p.add_argument("--forzar", action="store_true",
                   help="triar aunque la alerta ya esté en otro ticket; con --investigar, redactar aunque haya caché")
    p.add_argument("--listar-incidentes", action="store_true",
                   help="muestra los incidentes candidatos (alertas agrupadas por entidades) y sale")
    p.add_argument("--listar-modelos", action="store_true", help="lista los modelos del proveedor y sale")
    p.add_argument("--construir-indice", nargs="?", const="todas", metavar="FUENTES",
                   help="descarga los logs por la API e indexa sus entidades (todas o 'proxy,dns,...') y sale")
    p.add_argument("--estado-indice", action="store_true", help="muestra el estado del índice local de logs y sale")
    p.add_argument("--investigar", nargs="+", metavar="ID",
                   help="nivel 3: investiga el incidente de una alerta (ALR-…) o ticket (TKT-…) y redacta el informe")
    p.add_argument("--sin-llm", action="store_true", help="con --investigar: informe solo con los hechos del código")
    p.add_argument("--con-herramientas", action="store_true",
                   help="con --investigar: deja que el LLM use herramientas (más lento y más tokens; antes por defecto)")
    p.add_argument("--aprobador", metavar="USUARIO",
                   help="con --aprobar: usuario del SOC que decide (pide su contraseña; su rol fija qué puede aprobar)")
    p.add_argument("--pendientes", metavar="USUARIO",
                   help="nivel 4: revisa las acciones de contención pendientes de ese usuario del SOC y sale")
    args = p.parse_args()

    if args.listar_modelos:
        from agente import motores
        print("\n".join(motores.listar_modelos()))
        return

    if args.construir_indice or args.estado_indice:
        return indice_cli(args.construir_indice)

    if args.pendientes:
        from agente.contencion import revisar
        revisar(args.pendientes)
        return

    if args.aprobar and not args.aprobador:
        p.error("--aprobar necesita --aprobador USUARIO del SOC (p. ej. n2; ver backend/db/usuarios_soc.sql)")

    if args.investigar:
        return investigar_cli(args.investigar, not args.sin_llm, args.effort, args.forzar, args.con_herramientas)

    if args.ver_cola:
        ver_cola(args.ver_cola)
        return

    if args.listar_incidentes:
        from agente import incidentes
        todas = incidentes.todas_las_alertas()
        grupos = incidentes.listar()
        print(f"{len(grupos)} incidentes candidatos con {sum(map(len, grupos))} alertas:\n")
        for ids in grupos:
            a = [todas[i] for i in ids]
            reglas = ", ".join(sorted({x["rule_id"] for x in a}))
            print(f"{ids[0]} … {len(ids)} alertas · {a[0]['created_at'][:16]} → {a[-1]['created_at'][:16]} · {reglas}")
        return

    alertas = cargar_alertas(args)
    if not alertas:
        p.error("indica alert_ids, --muestra o --cola")

    ultima_heredada = False
    for i, alerta in enumerate(alertas, 1):
        if i > 1 and args.pausa and not ultima_heredada:
            time.sleep(args.pausa)
        print(f"[{i}/{len(alertas)}] {alerta['alert_id']}  {alerta['rule_id']}  {alerta['rule_name']} "
              f"(regla: {alerta['severity']})", flush=True)
        ticket_previo = None if args.forzar else almacen.ticket_que_cubre(alerta["alert_id"])
        if ticket_previo:
            print(f"  ⊂ ya incluida en {ticket_previo} (mismo incidente); se omite. Usa --forzar para triarla aparte.")
            ultima_heredada = True
            continue
        try:
            res = triar(alerta, effort=args.effort, usar_plantillas=not args.sin_plantillas)
        except CuotaAgotada as e:
            print(f"  ✗ {e}\n  Se detiene el lote: quedan {len(alertas) - i + 1} alertas sin triar (no se ha creado ticket).")
            return 1
        t = res["ticket"]
        ultima_heredada = bool(res.get("heredado_de"))
        if ultima_heredada:
            print(f"  ≡ mismo patrón que {res['heredado_de']} → {t['verdict']} · {t['severity']} (sin llamar al modelo)")
            continue
        print(f"  → {t['verdict']} · {t['severity']} · conf {t['confidence']:.2f} · "
              f"{'ESCALAR a ' + t['escalation']['to'] if t['escalation']['escalate'] else 'cerrar'}")
        print(f"    {t['title']}")
        for c in t.get("comprobaciones_internas", []):
            print(f"    {dict(permitida='✓', sospechosa='⚠', requiere_info='?', informativa='ℹ')[c['estado']]} "
                  f"{ETIQUETA_TIPO.get(c.get('tipo'), 'regla interna')}: "
                  f"{c['regla']} — {c['sujeto']}: {c['estado']}")
        for r in t.get("relacionado_con", []):
            print(f"    ↔ relacionado con {r['ticket_id']} (comparte {', '.join(r['entidades'][:2])})")
        from agente import informe
        if incidente := informe.preparar(res):   # nivel 3: hechos de la cadena listos para el N2 (sin LLM)
            print(f"    🧭 escalado: hechos de la cadena preparados en {incidente} "
                  f"(--investigar {t['ticket_id']} para el informe)")
        for aj in t.get("ajustes_politica", []):
            print(f"    ⚖ política: {aj}")
        print(f"    {len(res['traza'])} consultas · {t['triage_seconds']} s · "
              f"tokens in/out {res['uso']['input_tokens']}/{res['uso']['output_tokens']} "
              f"· {res['modelo']}")
        if args.aprobar:
            from agente.contencion import revisar_acciones
            revisar_acciones(res, args.aprobador)
    print("\nTickets guardados en salidas/tickets/")


if __name__ == "__main__":
    sys.exit(main())
