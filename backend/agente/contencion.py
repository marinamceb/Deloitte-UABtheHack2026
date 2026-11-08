"""[Nivel 4 · respuesta] Punto de decisión humana en la consola: el agente propone, la persona (identificada por su
email del directorio) aprueba o rechaza según su rol y acciones.py ejecuta cuando están todas las aprobaciones.
La web usa el mismo módulo acciones.py; esto es solo la interfaz de texto."""
from . import acciones, roles

SIMBOLO = {"pendiente": "…", "aprobada": "✓", "ejecutada": "✔", "fallida": "✗", "rechazada": "⊘", "prohibida": "⛔",
           "hecha": "✔"}


def describir(sol: dict) -> str:
    firmas = {a["requisito"]: a for a in sol["aprobaciones"]}
    reqs = "; ".join(f"{'✓' if i in firmas else '·'} {r['etiqueta']}"
                     + (f" ({firmas[i]['nombre']})" if i in firmas else "")
                     for i, r in enumerate(sol["requisitos"])) or "la ejecuta el N1"
    origen = ", ".join(o["id"] for o in sol["origenes"])
    return (f"{SIMBOLO.get(sol['estado'], '?')} {sol['id']} · {sol['action']} → {sol['target']}  [{sol['estado']}]"
            f"{'  (tarea manual)' if sol['tipo'] == 'manual' else ''}\n"
            f"     por qué: {sol['justificacion'] or '—'}   (de {origen})\n"
            f"     impacto: {sol['impacto']}\n"
            f"     aprobaciones: {reqs}")


def revisar(persona_email: str, origen: str | None = None) -> None:
    """Recorre lo que esta persona puede decidir (de un ticket/informe concreto o todo) y pregunta una a una."""
    persona = roles.identificar(persona_email)
    if persona is None:
        print(f"  ✗ {persona_email} no existe en el directorio o no tiene un rol con acceso "
              "(p. ej. neus.benitez@tarvia.example es N1 y pablo.coll@tarvia.example es N2).")
        return
    acciones.sincronizar()
    lista = [s for s in acciones.pendientes_de(persona) if not origen or origen in {o["id"] for o in s["origenes"]}]
    print(f"\n  {persona['nombre']} ({persona['cargo']}; roles: {', '.join(persona['roles'])}): "
          f"{len(lista)} acciones pendientes de tu decisión" + (f" en {origen}" if origen else ""))
    for sol in lista:
        print("   " + describir(sol).replace("\n", "\n   "))
        ops = acciones.que_puede_hacer(sol, persona)
        opciones = {"aprobar": "[a]probar", "marcar_hecha": "[h]echa", "reintentar": "re[i]ntentar",
                    "rechazar": "[r]echazar"}
        texto = " / ".join(v for k, v in opciones.items() if k in ops) + " / [s]altar"
        r = input(f"     ¿Qué haces? {texto}: ").strip().lower()[:1]
        try:
            if r == "a" and "aprobar" in ops:
                sol = acciones.aprobar(sol["id"], persona["email"], input("     Comentario (opcional): ").strip())
            elif r == "h" and "marcar_hecha" in ops:
                sol = acciones.marcar_hecha(sol["id"], persona["email"], input("     Nota: ").strip())
            elif r == "i" and "reintentar" in ops:
                sol = acciones.reintentar(sol["id"], persona["email"])
            elif r == "r" and "rechazar" in ops:
                sol = acciones.rechazar(sol["id"], persona["email"], input("     Motivo: ").strip() or "sin motivo")
            else:
                continue
        except (acciones.PermisoDenegado, acciones.EstadoNoValido) as e:
            print(f"     ✗ {e}")
            continue
        detalle = sol.get("resultado") or {}
        texto = detalle.get("result") or detalle.get("error") or ""
        print(f"     → {sol['estado']}" + (f": {texto}" if texto else "")
              + ("" if sol["estado"] != "pendiente" else
                 f" (faltan: {', '.join(sol['requisitos'][i]['etiqueta'] for i in acciones._faltan(sol))})"))


def revisar_acciones(resultado: dict, persona_email: str) -> None:
    """Tras triar (agent.py --aprobar): decide sobre las acciones propuestas en ese ticket."""
    revisar(persona_email, resultado["ticket"]["ticket_id"])
