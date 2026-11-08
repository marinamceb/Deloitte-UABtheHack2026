"""[Nivel 4 · respuesta] Solicitudes de contención: el agente propone, las personas aprueban según su rol y solo
entonces se ejecuta en la API simulada. Lo usan por igual el CLI (agent.py --aprobar / --pendientes) y la web.

Ciclo de una solicitud:
    sincronizar()    las acciones de contención de tickets (recommended_actions) e informes (containment_plan) pasan a
                     solicitudes, una por acción + objetivo aunque la propongan varios (se acumulan los orígenes)
    pendiente ──aprobar()×N──▶ ejecutada | fallida      (acciones de la API; con la última aprobación se ejecuta)
    pendiente ──aprobar()×N──▶ aprobada ──marcar_hecha()──▶ hecha   (tareas fuera de la API: regla de buzón, MFA...)
    pendiente / aprobada / fallida ──rechazar()──▶ rechazada
    prohibida        la política no la permite (aislar un activo OT): solo se escala a Operaciones
    fallida ──reintentar()──▶ ejecutada | fallida       (p. ej. la API no respondía)

Qué aprobaciones hacen falta lo decide politica.requisitos (apartado 4); quién puede darlas, roles.cumple. Reglas:
- Las personas que deciden en la consola son del SOC (usuarios_soc.py). La aprobación del responsable de un servicio
  de Tarvia (aislar un servidor) la registra un N2 o superior en su nombre (`en_nombre_de`): se comprueba en el
  directorio de la empresa que esa persona es la responsable y queda quién la registró.
- Cuatro ojos: cada aprobación la da una persona distinta (el N2 no puede firmar también como responsable).
- Sin aprobaciones requeridas (bloquear un IOC malicioso, purgar un correo) la ejecuta directamente cualquiera del SOC.
- Antes de ejecutar se mira /containment/log para no repetir una acción ya hecha.
- La API pide su propio token (/approvals) con los nombres y roles de quienes aprobaron; si rechaza la acción (OT,
  token inválido), la solicitud queda «fallida» con su motivo.
Cada paso queda en el historial de la solicitud (quién, con qué rol, cuándo, comentario) y lo ejecutado se anota en
el ticket (`executed_actions`) o el informe (`acciones_ejecutadas`) de origen.
"""
import hashlib

from . import almacen, api, politica, roles
from . import herramientas as h
from .comun import servicio
from .herramientas import ahora_iso

ACCIONES_API = {"isolate_host", "disable_user", "revoke_sessions", "reset_password", "block_ioc", "purge_email",
                "disable_access_key"}
NECESITA_TOKEN = ACCIONES_API - {"block_ioc", "purge_email"}   # como la API (NO_APPROVAL)
NO_CONTENCION = ("close", "escalate", "notify", "monitor")       # decisiones de triaje y avisos: van por otro camino

PENDIENTE, APROBADA, EJECUTADA, FALLIDA = "pendiente", "aprobada", "ejecutada", "fallida"
RECHAZADA, PROHIBIDA, HECHA = "rechazada", "prohibida", "hecha"
ABIERTAS = {PENDIENTE, APROBADA, FALLIDA}
NOMBRE_ROL = {"N1": "N1", "N2": "N2", "responsable_soc": "Responsable SOC"}


class PermisoDenegado(Exception):
    """La persona no tiene el rol que pide esta aprobación (o ya firmó)."""


class EstadoNoValido(Exception):
    """La solicitud no está en un estado que admita esa operación."""


# =============================================================================================== creación

def es_contencion(accion: str) -> bool:
    return bool(accion) and not accion.startswith(NO_CONTENCION)


def id_de(accion: str, objetivo: str) -> str:
    return "ACC-" + hashlib.sha1(f"{accion}|{objetivo.strip().lower()}".encode()).hexdigest()[:10]


def impacto(accion: str, objetivo: str, propuesto: str = "") -> str:
    """Qué se para si se ejecuta: lo que dijo el modelo más lo que dicen la CMDB, el directorio y el TIP."""
    partes = [propuesto] if propuesto and propuesto.strip().lower() not in ("ninguno", "ninguno.", "-") else []
    if accion == "isolate_host":
        a = api.activo(objetivo)
        if not a:
            partes.append("Equipo no gestionado (no está en la CMDB)")
        else:
            s = servicio(a.get("business_service", ""))
            partes.append(f"{a.get('type')} de criticidad {a.get('criticality')}"
                          + (f": se para «{s['servicio']}» ({s['impacto']})" if s else ""))
    elif accion == "disable_user":
        u = api.usuario(objetivo)
        if not u:
            partes.append("La cuenta no está en el directorio")
        elif u.get("account_type") == "service":
            partes.append(f"Cuenta de servicio: puede parar un proceso de negocio ({u.get('display_name')})")
        else:
            partes.append(f"{u.get('display_name')} ({u.get('title')}) se queda sin acceso"
                          + (" — usuario VIP" if str(u.get("vip")) == "True" else ""))
    elif accion == "disable_access_key":
        partes.append("Dejan de funcionar las cargas que usan la clave (despliegues, integraciones)")
    elif accion == "revoke_sessions":
        partes.append("El usuario tendrá que volver a iniciar sesión en todas sus aplicaciones")
    elif accion == "reset_password":
        partes.append("El usuario tendrá que cambiar la contraseña")
    elif accion == "block_ioc":
        tip = api.intel(objetivo).get("tip") or {}
        etiquetas = set(str(tip.get("tags", "")).split(",")) & politica.ETIQUETAS_USO_DUAL
        partes.append(f"Servicio de uso dual ({', '.join(sorted(etiquetas))}): se cortan también sus usos legítimos"
                      if etiquetas else "Ninguno esperado: se bloquea en proxy, correo y EDR")
    elif accion == "purge_email":
        partes.append("Se elimina el correo de todos los buzones")
    return " · ".join(dict.fromkeys(partes)) or "Sin datos de impacto"


def _etiqueta(requisito: dict) -> str:
    if requisito["rol"] == "responsable_servicio":
        return f"{requisito.get('cargo')} (responsable de {requisito.get('servicio')})"
    return NOMBRE_ROL.get(requisito["rol"], requisito["rol"])


def _nueva(accion: str, objetivo: str, justificacion: str, impacto_propuesto: str, origen: dict) -> dict:
    with h.origen("acciones"):
        if accion == "isolate_host" and (a := api.activo(objetivo)):
            objetivo = a["hostname"]   # la API compara el nombre exacto de la CMDB
        r = politica.requisitos(accion, objetivo)
        texto_impacto = impacto(accion, objetivo, impacto_propuesto)
    return {
        "id": id_de(accion, objetivo), "action": accion, "target": objetivo,
        "tipo": "api" if accion in ACCIONES_API else "manual",
        "justificacion": justificacion, "impacto": texto_impacto,
        "origenes": [origen],
        "requisitos": [{**q, "etiqueta": _etiqueta(q)} for q in r["aprobaciones"]],
        "politica": r["texto"] or "la ejecuta el N1", "motivo_politica": r["motivo"],
        "aprobaciones": [],
        "estado": PENDIENTE if r["permitida"] else PROHIBIDA,
        "resultado": None if r["permitida"] else {"motivo": r["motivo"]},
        "creada": ahora_iso(),
        "historial": [{"ts": ahora_iso(), "email": "agente", "rol": "sistema", "evento": "propuesta",
                       "detalle": f"Propuesta en {origen['tipo']} {origen['id']}"
                                  + ("" if r["permitida"] else f"; prohibida: {r['motivo']}")}],
    }


def _incorporar(datos: dict, accion: str, objetivo: str, justificacion: str, impacto_propuesto: str,
                origen: dict) -> bool:
    if not es_contencion(accion) or not (objetivo or "").strip():
        return False
    k = id_de(accion, objetivo)
    if k in datos:
        if origen not in datos[k]["origenes"]:
            datos[k]["origenes"].append(origen)
        return False
    datos[k] = _nueva(accion, objetivo.strip(), justificacion, impacto_propuesto, origen)
    return True


def sincronizar() -> int:
    """Crea las solicitudes que falten a partir de los tickets e informes guardados. Devuelve cuántas son nuevas."""
    with almacen.CERROJO:
        datos, nuevas = almacen.acciones(), 0
        for tid, res in almacen.tickets().items():
            for a in res["ticket"].get("recommended_actions", []):
                nuevas += _incorporar(datos, a.get("action", ""), a.get("target", ""), a.get("justification", ""),
                                      "", {"tipo": "ticket", "id": tid})
        for iid, res in almacen.informes().items():
            for a in res.get("informe", {}).get("containment_plan", []):
                nuevas += _incorporar(datos, a.get("action", ""), a.get("target", ""), a.get("justification", ""),
                                      a.get("business_impact", ""), {"tipo": "informe", "id": iid})
        almacen.guardar_acciones(datos)
    return nuevas


# =============================================================================================== consulta

def listar(estados: set[str] | None = None) -> list[dict]:
    return sorted((s for s in almacen.acciones().values() if not estados or s["estado"] in estados),
                  key=lambda s: s["creada"])


def obtener(id_solicitud: str) -> dict | None:
    return almacen.acciones().get(id_solicitud)


def _faltan(sol: dict) -> list[int]:
    hechos = {a["requisito"] for a in sol["aprobaciones"] if a.get("requisito") is not None}
    return [i for i in range(len(sol["requisitos"])) if i not in hechos]


def _requisito_para(sol: dict, persona: dict) -> int | None:
    return next((i for i in _faltan(sol) if roles.cumple(persona, sol["requisitos"][i])), None)


def _requisito_negocio(sol: dict) -> int | None:
    """Primer requisito pendiente que es la aprobación de un responsable de servicio de la empresa."""
    return next((i for i in _faltan(sol) if sol["requisitos"][i]["rol"] == "responsable_servicio"), None)


def que_puede_hacer(sol: dict, persona: dict) -> set[str]:
    """Operaciones que esta persona puede hacer ahora sobre la solicitud (para la web y el CLI)."""
    ops = set()
    ya_firmo = any(a["email"] == persona["email"] for a in sol["aprobaciones"])
    soc = roles.es_soc(persona)
    if sol["estado"] == PENDIENTE:
        if not ya_firmo and ((not sol["requisitos"] and soc) or _requisito_para(sol, persona) is not None):
            ops |= {"aprobar", "rechazar"}
        if _requisito_negocio(sol) is not None and roles.registra_en_nombre(persona):
            ops |= {"registrar_responsable", "rechazar"}
    if sol["estado"] == APROBADA and soc:
        ops |= {"marcar_hecha", "rechazar"}
    if sol["estado"] == FALLIDA and soc:
        ops |= {"reintentar", "rechazar"}
    return ops


def pendientes_de(persona: dict) -> list[dict]:
    """Solicitudes abiertas en las que esta persona tiene algo que hacer («Mis pendientes»)."""
    return [s for s in listar(ABIERTAS) if que_puede_hacer(s, persona)]


# =============================================================================================== decisiones

def _persona(email: str) -> dict:
    persona = roles.identificar(email)
    if persona is None:
        raise PermisoDenegado(f"{email} no es un usuario activo del SOC")
    return persona


def _anotar(sol: dict, persona: dict, evento: str, detalle: str = "", rol: str = "") -> None:
    sol["historial"].append({"ts": ahora_iso(), "email": persona["email"], "nombre": persona["nombre"],
                             "rol": rol or ", ".join(persona["roles"]), "evento": evento, "detalle": detalle})


def _modificar(id_solicitud: str, cambio) -> dict:
    """Lee, aplica `cambio(sol)` y guarda, todo bajo el cerrojo del almacén."""
    with almacen.CERROJO:
        datos = almacen.acciones()
        if id_solicitud not in datos:
            raise KeyError(f"No existe la solicitud {id_solicitud}")
        cambio(datos[id_solicitud])
        almacen.guardar_acciones(datos)
        return datos[id_solicitud]


def aprobar(id_solicitud: str, email: str, comentario: str = "", en_nombre_de: str = "") -> dict:
    """Añade la aprobación de esta persona (la del requisito que cumpla) y, si ya están todas, ejecuta.
    Con `en_nombre_de` (email de Tarvia), registra la aprobación de ese responsable de servicio."""
    persona = _persona(email)

    def cambio(sol):
        if sol["estado"] != PENDIENTE:
            raise EstadoNoValido(f"La solicitud está {sol['estado']}")
        if en_nombre_de:
            _registrar_responsable(sol, persona, en_nombre_de, comentario)
        else:
            _aprobar_como_soc(sol, persona, comentario)
        if not _faltan(sol):
            if sol["tipo"] == "api":
                _ejecutar(sol, persona)
            else:
                sol["estado"] = APROBADA
                _anotar(sol, persona, "aprobada", "Tarea manual: falta realizarla y marcarla como hecha")

    return _modificar(id_solicitud, cambio)


def _registrar_responsable(sol: dict, persona: dict, email_empresa: str, comentario: str) -> None:
    """Aprobación de un responsable de servicio de Tarvia, obtenida y registrada por un N2 o superior del SOC."""
    if not roles.registra_en_nombre(persona):
        raise PermisoDenegado("Solo un N2, el Responsable SOC o el CISO pueden registrar la aprobación de negocio")
    i = _requisito_negocio(sol)
    if i is None:
        raise PermisoDenegado("Esta acción no necesita (o ya tiene) la aprobación de un responsable de servicio")
    req = sol["requisitos"][i]
    ficha = roles.responsable_de(email_empresa, req["servicio"])
    if ficha is None:
        raise PermisoDenegado(f"{email_empresa} no es {req['cargo']}, responsable de {req['servicio']}, según el "
                              "directorio de la empresa")
    email = ficha["upn"].lower()
    if any(a["email"] == email for a in sol["aprobaciones"]):
        raise PermisoDenegado(f"{email} ya consta como aprobador de esta acción")
    sol["aprobaciones"].append({"requisito": i, "email": email, "nombre": ficha.get("display_name", email),
                                "rol": req["etiqueta"], "ts": ahora_iso(), "comentario": comentario,
                                "registrado_por": persona["email"]})
    _anotar(sol, persona, "aprobación de negocio registrada",
            f"{ficha.get('display_name', email)} <{email}> ({req['etiqueta']}): {comentario}".rstrip(": "))


def _aprobar_como_soc(sol: dict, persona: dict, comentario: str) -> None:
    if any(a["email"] == persona["email"] for a in sol["aprobaciones"]):
        raise PermisoDenegado("Ya has aprobado esta acción: la siguiente aprobación debe darla otra persona")
    if sol["requisitos"]:
        i = _requisito_para(sol, persona)
        if i is None:
            faltan = ", ".join(sol["requisitos"][j]["etiqueta"] for j in _faltan(sol))
            pista = (" (la del responsable de servicio se registra en su nombre)"
                     if _requisito_negocio(sol) is not None else "")
            raise PermisoDenegado(f"Tu rol ({', '.join(persona['roles'])}) no cubre lo que falta: {faltan}{pista}")
        etiqueta = sol["requisitos"][i]["etiqueta"]
    elif roles.es_soc(persona):
        i, etiqueta = None, "SOC (ejecución directa del N1)"
    else:
        raise PermisoDenegado("Solo el personal del SOC puede ejecutar esta acción")
    sol["aprobaciones"].append({"requisito": i, "email": persona["email"], "nombre": persona["nombre"],
                                "rol": etiqueta, "ts": ahora_iso(), "comentario": comentario})
    _anotar(sol, persona, "aprobación", comentario, etiqueta)


def rechazar(id_solicitud: str, email: str, motivo: str) -> dict:
    persona = _persona(email)

    def cambio(sol):
        if sol["estado"] not in ABIERTAS:
            raise EstadoNoValido(f"La solicitud está {sol['estado']}")
        if "rechazar" not in que_puede_hacer(sol, persona):
            raise PermisoDenegado("Solo puede rechazarla quien podría aprobarla")
        sol["estado"] = RECHAZADA
        sol["resultado"] = {"motivo": motivo}
        _anotar(sol, persona, "rechazo", motivo)

    return _modificar(id_solicitud, cambio)


def marcar_hecha(id_solicitud: str, email: str, nota: str = "") -> dict:
    persona = _persona(email)

    def cambio(sol):
        if sol["estado"] != APROBADA:
            raise EstadoNoValido(f"La solicitud está {sol['estado']}")
        if not roles.es_soc(persona):
            raise PermisoDenegado("Solo el personal del SOC puede cerrar una tarea manual")
        sol["estado"] = HECHA
        sol["resultado"] = {"nota": nota, "hecha_por": persona["email"], "ts": ahora_iso()}
        _anotar(sol, persona, "hecha", nota)
        _anotar_en_origenes(sol, "hecha (manual)", persona)

    return _modificar(id_solicitud, cambio)


def reintentar(id_solicitud: str, email: str) -> dict:
    persona = _persona(email)

    def cambio(sol):
        if sol["estado"] != FALLIDA:
            raise EstadoNoValido(f"La solicitud está {sol['estado']}")
        if not roles.es_soc(persona):
            raise PermisoDenegado("Solo el personal del SOC puede reintentar")
        _anotar(sol, persona, "reintento")
        _ejecutar(sol, persona)

    return _modificar(id_solicitud, cambio)


# =============================================================================================== ejecución

def _ya_ejecutada(sol: dict) -> dict | None:
    return next((r for r in api.registro_contencion()
                 if r.get("action") == sol["action"] and r.get("target") == sol["target"]
                 and str(r.get("result", "")).startswith("ok")), None)


def _ejecutar(sol: dict, persona: dict) -> None:
    """Token de aprobación (si la API lo pide) + contención. Deja la solicitud ejecutada o fallida."""
    with h.origen("acciones"):
        if previo := _ya_ejecutada(sol):
            sol.update(estado=EJECUTADA, resultado={**previo, "ya_constaba": True})
            _anotar(sol, persona, "ejecutada", "Ya constaba en /containment/log: no se repite")
            return
        firmantes = "; ".join(f"{a['nombre']} <{a['email']}> ({a['rol']})" for a in sol["aprobaciones"])
        origen = sol["origenes"][0]["id"] if sol["origenes"] else ""
        token = ""
        if sol["action"] in NECESITA_TOKEN:
            datos, error = api.solicitar_aprobacion(sol["action"], sol["target"], firmantes, sol["justificacion"])
            if error:
                sol.update(estado=FALLIDA, resultado={"error": f"/approvals: {error}"})
                _anotar(sol, persona, "fallo", f"/approvals: {error}")
                return
            token = datos["approval_token"]
        datos, error = api.contener(sol["action"], sol["target"], sol["justificacion"], token, origen)
    if error:
        sol.update(estado=FALLIDA, resultado={"error": error})
        _anotar(sol, persona, "fallo", error)
        return
    sol.update(estado=EJECUTADA, resultado=datos)
    _anotar(sol, persona, "ejecutada", datos.get("result", ""))
    _anotar_en_origenes(sol, datos.get("result", "ok"), persona)


def _anotar_en_origenes(sol: dict, resultado: str, persona: dict) -> None:
    """Deja constancia en el ticket o el informe que propuso la acción."""
    registro = {"action": sol["action"], "target": sol["target"], "result": resultado, "solicitud": sol["id"],
                "decided_by": [a["email"] for a in sol["aprobaciones"]] or [persona["email"]],
                "timestamp": ahora_iso()}
    for o in sol["origenes"]:
        if o["tipo"] == "ticket" and (res := almacen.ticket(o["id"])):
            res["ticket"].setdefault("executed_actions", []).append(registro)
            almacen.guardar_ticket(res)
        elif o["tipo"] == "informe" and (res := almacen.informe(o["id"])):
            res.setdefault("acciones_ejecutadas", []).append(registro)
            almacen.guardar_informe(res)
