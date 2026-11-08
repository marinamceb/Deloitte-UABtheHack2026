"""[Nivel 4 · avisos] Avisos para cada rol del SOC, derivados por código de los tickets e informes guardados.

Dos clases (politica_soc.md, apartados 3 y 5; empresa_tarvia.md):
- Internos: escalado a N2 de un ticket escalado (plazo: crítico 15 min por teléfono, alto en la jornada) y
  notificaciones del SLA al Responsable SOC y al CISO. Quien los recibe confirma que los ha visto («enterado»).
- A terceros de Tarvia: DPO (brecha de datos personales: AEPD/CNPD en 72 h desde que se tiene constancia),
  Tesorería (fraude), Operaciones (OT), adquirente (PCI DSS), proveedor... Los recibe el SOC (Responsable SOC y N2),
  que debe hacer la notificación y registrar a quién y cómo («notificado»).

La clasificación de las notificaciones de los informes (texto libre del LLM) es por palabras clave; un texto puede
generar varios avisos («Responsable del SOC y CISO»). Un aviso por origen y categoría (no se duplican al resincronizar).
El plazo cuenta desde que el SOC tuvo constancia: cuándo se trió el ticket o se generó el informe.
Persistencia: salidas/avisos.json (almacen).
"""
import datetime as dt
import hashlib

from . import almacen, incidentes
from .comun import local, utc
from .herramientas import ahora_iso
from .severidad import NIVELES

# categoría → (palabras clave, interno, roles del SOC que lo reciben, horas de plazo, a quién en Tarvia, título)
CATEGORIAS = {
    "dpo": (("dpo", "delegado de protección", "aepd", "cnpd", "datos personales"), False,
            ["responsable_soc", "N2"], 72, "DPO", "Notificar al DPO (posible brecha de datos personales)"),
    "tesoreria": (("tesorer", "fraude", "iban"), False, ["responsable_soc", "N2"], 4, "Responsable de Tesorería",
                  "Avisar a Tesorería (posible fraude)"),
    "operaciones": (("operaciones", "red ot", " ot "), False, ["responsable_soc", "N2"], 4,
                    "Directora de Operaciones", "Escalar a Operaciones (OT)"),
    "pci": (("adquirente", "pci"), False, ["responsable_soc"], 24, "Director Financiero",
            "Avisar al adquirente / Director Financiero (PCI DSS)"),
    "proveedor": (("proveedor",), False, ["responsable_soc", "N2"], 24, "Proveedor afectado",
                  "Avisar al proveedor implicado"),
    "ciso": (("ciso",), True, ["ciso"], None, "", "Notificación al CISO"),
    "responsable_soc": (("responsable soc", "responsable del soc"), True, ["responsable_soc"], None, "",
                        "Notificación al Responsable SOC"),
}
INTERNOS_SIN_CATEGORIA = ("legal", "devops", "infraestructura", "equipo")   # «Notificar al equipo de DevOps...»


def id_de(origen: str, categoria: str) -> str:
    return "AV-" + hashlib.sha1(f"{origen}|{categoria}".encode()).hexdigest()[:10]


def clasificar(texto: str) -> list[str]:
    """Categorías que menciona una notificación (puede haber varias); [] si no encaja en ninguna."""
    t = f" {texto.lower()} "
    return [c for c, (palabras, *_r) in CATEGORIAS.items() if any(p in t for p in palabras)]


def _plazo_escalado(severidad: str, desde: str) -> str | None:
    """Apartado 3: crítico, inmediato (15 min) por teléfono; alto, en la misma jornada (hasta las 20:00 en España)."""
    t = utc(desde)
    if severidad == "critical":
        return (t + dt.timedelta(minutes=15)).isoformat()
    if severidad == "high":
        fin = local(desde).replace(hour=20, minute=0, second=0, microsecond=0)
        if local(desde) >= fin:
            fin += dt.timedelta(days=1)
        return fin.astimezone(dt.timezone.utc).isoformat()
    return None


def _nuevo(categoria: str, origen: dict, severidad: str, desde: str, detalle: str, titulo: str = "",
           destinatarios: list[str] | None = None, plazo: str | None = None, interno: bool | None = None) -> dict:
    palabras, es_interno, roles, horas, contacto, titulo_def = CATEGORIAS.get(
        categoria, ((), False, ["responsable_soc"], None, "", "Notificación"))
    if plazo is None and horas:
        plazo = (utc(desde) + dt.timedelta(hours=horas)).isoformat()
    return {"id": id_de(origen["id"], categoria), "categoria": categoria, "titulo": titulo or titulo_def,
            "interno": es_interno if interno is None else interno, "destinatarios": destinatarios or roles,
            "contacto": contacto, "detalle": [detalle], "origen": origen, "severidad": severidad,
            "desde": desde, "plazo": plazo, "estado": "abierto", "creado": ahora_iso(), "leido_por": [],
            "atendido": None}


def _severidad_informe(res: dict) -> str:
    todas = incidentes.todas_las_alertas()
    sevs = [todas[a]["severity"] for a in res["informe"].get("alert_ids", []) if a in todas]
    return max(sevs, key=lambda s: NIVELES.index(s) if s in NIVELES else 2) if sevs else "high"


def generar() -> dict[str, dict]:
    """Avisos que corresponden a los tickets e informes guardados (sin estado: lo conserva sincronizar)."""
    avisos: dict[str, dict] = {}

    def anadir(a: dict) -> None:
        if a["id"] in avisos:
            avisos[a["id"]]["detalle"] += [d for d in a["detalle"] if d not in avisos[a["id"]]["detalle"]]
        else:
            avisos[a["id"]] = a

    for tid, res in almacen.tickets().items():
        t, desde = res["ticket"], res.get("triado_en") or res.get("ticket", {}).get("triado_en") or ahora_iso()
        origen = {"tipo": "ticket", "id": tid, "titulo": t.get("title", "")}
        sev = t.get("severity", "medium")
        if t.get("escalation", {}).get("escalate"):
            esc = t["escalation"]
            anadir(_nuevo("escalado", origen, sev, desde, esc.get("reason", ""),
                          titulo=f"Escalado a {esc.get('to') or 'N2'}", destinatarios=["N2", "responsable_soc"],
                          plazo=_plazo_escalado(sev, desde), interno=True))
        for a in t.get("recommended_actions", []):
            if a["action"].startswith("notify"):
                for c in clasificar(f"{a['action']} {a['target']}") or ["responsable_soc"]:
                    anadir(_nuevo(c, origen, sev, desde, a.get("justification") or a["target"]))
    for iid, res in almacen.informes().items():
        inf, desde = res["informe"], res.get("generado_en") or ahora_iso()
        origen = {"tipo": "informe", "id": iid, "titulo": inf.get("title", "")}
        sev = _severidad_informe(res)
        for texto in inf.get("notifications", []):
            categorias = clasificar(texto)
            if not categorias and not any(p in texto.lower() for p in INTERNOS_SIN_CATEGORIA):
                categorias = ["otros"]
            for c in categorias:
                anadir(_nuevo(c, origen, sev, desde, texto))
    return avisos


def sincronizar() -> int:
    """Incorpora los avisos nuevos conservando el estado de los existentes. Devuelve cuántos son nuevos."""
    with almacen.CERROJO:
        actuales = almacen.leer_json("avisos.json", {})
        nuevos = 0
        for k, a in generar().items():
            if k in actuales:
                actuales[k]["detalle"] = a["detalle"]
            else:
                actuales[k] = a
                nuevos += 1
        almacen.guardar_json("avisos.json", actuales)
    return nuevos


# =============================================================================================== por persona

def puede_ver(aviso: dict, persona: dict) -> bool:
    roles = set(persona["roles"])
    return bool(roles & set(aviso["destinatarios"])) or bool(roles & {"ciso", "responsable_soc"})


def puede_atender(aviso: dict, persona: dict) -> bool:
    return aviso["estado"] == "abierto" and bool(set(persona["roles"]) & (set(aviso["destinatarios"]) | {"ciso"}))


def para(persona: dict) -> list[dict]:
    """Avisos visibles para esta persona, abiertos primero y por plazo."""
    lista = [a for a in almacen.leer_json("avisos.json", {}).values() if puede_ver(a, persona)]
    return sorted(lista, key=lambda a: (a["estado"] != "abierto", a["plazo"] or "9999", a["creado"]))


class NoPermitido(Exception):
    pass


def atender(id_aviso: str, persona: dict, nota: str) -> dict:
    """Internos: «enterado». A terceros: «notificado», con nota obligatoria (a quién, cómo y cuándo)."""
    with almacen.CERROJO:
        datos = almacen.leer_json("avisos.json", {})
        if id_aviso not in datos:
            raise KeyError(id_aviso)
        a = datos[id_aviso]
        if not puede_atender(a, persona):
            raise NoPermitido("Este aviso no te corresponde o ya está atendido")
        if not a["interno"] and not nota.strip():
            raise NoPermitido("Indica a quién se notificó, cómo y cuándo")
        a["estado"] = "enterado" if a["interno"] else "notificado"
        a["atendido"] = {"email": persona["email"], "nombre": persona["nombre"], "ts": ahora_iso(), "nota": nota}
        if persona["email"] not in a["leido_por"]:
            a["leido_por"].append(persona["email"])
        almacen.guardar_json("avisos.json", datos)
        return a
