"""[Nivel 4 · respuesta] Punto de decisión humana en la terminal: el agente propone, la persona del SOC (usuario y
contraseña de la consola) aprueba o rechaza según su rol y acciones.py ejecuta cuando están todas las aprobaciones.
La web usa el mismo módulo acciones.py; esto es solo la interfaz de texto."""
from getpass import getpass

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


def revisar(usuario: str, origen: str | None = None) -> None:
    """Recorre lo que esta persona puede decidir (de un ticket/informe concreto o todo) y pregunta una a una."""
    persona = roles.autenticar(usuario, getpass(f"  Contraseña de {usuario}: "))
    if persona is None:
        print("  ✗ Usuario o contraseña incorrectos (usuarios de la demo en backend/db/usuarios_soc.sql).")
        return
    acciones.sincronizar()
    lista = [s for s in acciones.pendientes_de(persona) if not origen or origen in {o["id"] for o in s["origenes"]}]
    print(f"\n  {persona['nombre']} ({persona['cargo']}; roles: {', '.join(persona['roles'])}): "
          f"{len(lista)} acciones pendientes de tu decisión" + (f" en {origen}" if origen else ""))
    for sol in lista:
        print("   " + describir(sol).replace("\n", "\n   "))
        ops = acciones.que_puede_hacer(sol, persona)
        opciones = {"aprobar": "[a]probar", "registrar_responsable": "registrar aprobación de [n]egocio",
                    "marcar_hecha": "[h]echa", "reintentar": "re[i]ntentar", "rechazar": "[r]echazar"}
        texto = " / ".join(v for k, v in opciones.items() if k in ops) + " / [s]altar"
        r = input(f"     ¿Qué haces? {texto}: ").strip().lower()[:1]
        try:
            if r == "a" and "aprobar" in ops:
                sol = acciones.aprobar(sol["id"], persona["email"], input("     Comentario (opcional): ").strip())
            elif r == "n" and "registrar_responsable" in ops:
                req = sol["requisitos"][acciones._requisito_negocio(sol)]
                quien = input(f"     Email de Tarvia de {req['cargo']} ({req['servicio']}) que lo aprobó: ").strip()
                como = input("     Cómo y cuándo lo aprobó (p. ej. «por teléfono, 10:42»): ").strip()
                sol = acciones.aprobar(sol["id"], persona["email"], como, en_nombre_de=quien)
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


def revisar_acciones(resultado: dict, usuario: str) -> None:
    """Tras triar (agent.py --aprobar): decide sobre las acciones propuestas en ese ticket."""
    revisar(usuario, resultado["ticket"]["ticket_id"])
