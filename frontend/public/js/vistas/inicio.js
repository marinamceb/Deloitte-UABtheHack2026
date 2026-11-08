// Inicio: panel adaptado a los permisos de quien entra. El servidor solo envía las cifras que esa persona puede ver
// (/api/resumen); aquí, además, cada bloque se muestra solo si su permiso está activo.
import { api } from "../api.js";
import { accion, barras, chipPlazo, chipSeveridad, ESTADOS, fecha, h, hace, icono, SEVERIDADES, VEREDICTOS } from "../ui.js";

/** Hora de España: saludo, fecha y si el SOC está en horario (L-V 8-20, politica_soc.md / empresa_tarvia.md). */
function ahoraEnEspana() {
  const ahora = new Date();
  const partes = Object.fromEntries(new Intl.DateTimeFormat("en-GB", { timeZone: "Europe/Madrid", weekday: "short",
    hour: "numeric", hour12: false }).formatToParts(ahora).map((p) => [p.type, p.value]));
  const horaNum = Number(partes.hour) % 24;
  const laborable = !["Sat", "Sun"].includes(partes.weekday);
  return {
    saludo: horaNum < 6 ? "Buenas noches" : horaNum < 14 ? "Buenos días" : horaNum < 21 ? "Buenas tardes" : "Buenas noches",
    fecha: new Intl.DateTimeFormat("es-ES", { timeZone: "Europe/Madrid", weekday: "long", day: "numeric", month: "long",
      year: "numeric", hour: "2-digit", minute: "2-digit" }).format(ahora),
    enHorario: laborable && horaNum >= 8 && horaNum < 20,
  };
}

function plural(n, uno, varios) {
  return `${n} ${n === 1 ? uno : varios}`;
}

const DESCRIPCION = {
  N1: "Triaje y primera respuesta. Ejecutas lo que la política permite al N1 (bloquear indicadores, purgar correos); lo disruptivo lo aprueba un N2.",
  N2: "Investigación y aprobación. Apruebas las acciones disruptivas, registras el visto bueno de los responsables de negocio y atiendes los escalados.",
  responsable_soc: "Supervisión del SOC. Ves todo, recibes las notificaciones del SLA y decides cuando un servicio no tiene responsable.",
  ciso: "Visión ejecutiva. Recibes las notificaciones críticas y puedes aprobar como un N2.",
  deteccion: "Ingeniería de detección (solo lectura). Revisa los huecos de detección de los incidentes para crear o afinar reglas.",
};
const PERMISOS = [["ver", "Ver colas e investigaciones"], ["decidir", "Ejecutar acciones del N1"],
  ["aprobar_n2", "Aprobar acciones disruptivas"], ["registrar_negocio", "Registrar aprobaciones de negocio"],
  ["avisos", "Atender avisos"], ["supervisar", "Supervisión"]];

function kpi(valor, nombre, ico, enlace, color = "") {
  return h("a", { class: `kpi ${color}`, href: enlace }, h("div", { class: "ico-kpi" }, icono(ico)),
    h("div", { class: "valor" }, String(valor ?? 0)), h("div", { class: "nombre" }, nombre));
}

function panel(titulo, enlace, ...contenido) {
  const ancho = titulo.startsWith("Huecos");
  return h("section", { class: `panel${ancho ? " ancho" : ""}` },
    h("div", { class: "titulo" }, h("h2", {}, titulo), enlace ? h("a", { href: enlace[0] }, enlace[1]) : null), contenido);
}

async function pagina(ctx) {
  const r = await ctx.llamar(api.resumen());
  if (!r) return null;
  const p = r.permisos;
  const yo = ctx.persona;
  const rol = yo.roles[0];
  const pend = r.acciones.pendientes_mias;
  const porEstado = r.acciones.por_estado || {};

  const kpis = [];
  if (p.ver) {
    const sev = r.cola.por_severidad || {};
    kpis.push(kpi((r.cola.total || 0) - (r.cola.ruido || 0), "Alertas en cola (sin ruido)", "cola", "#/cola"),
      kpi(sev.critical, "Críticas estimadas", "alerta", "#/cola", "rojo"));
  }
  if (p.decidir) kpis.push(kpi(pend, "Mis aprobaciones", "aprobar", "#/pendientes", pend ? "ambar" : "verde"));
  if (r.avisos) kpis.push(kpi(r.avisos.por_atender, "Avisos por atender", "avisos", "#/avisos", r.avisos.por_atender ? "ambar" : "verde"));
  if (p.ver) {
    kpis.push(kpi(r.tickets.total, "Tickets triados", "tickets", "#/tickets"),
      kpi(r.incidentes.informes, "Incidentes investigados", "incidentes", "#/incidentes"),
      kpi(porEstado.ejecutada || 0, "Acciones ejecutadas", "rayo", "#/cerradas", "verde"));
  }

  const paneles = [];
  if (p.ver) {
    paneles.push(panel("Lo más urgente de la cola", ["#/cola", "Ver la cola"], r.cola.primeros.length
      ? h("ul", { class: "mini" }, r.cola.primeros.map((x) => h("li", {}, chipSeveridad(x.severidad),
        h("a", { href: `#/cola/${x.alert_id}` }, x.rule_name),
        h("span", { class: "derecha suave" }, x.n > 1 ? `${x.n} alertas` : x.activo))))
      : h("div", { class: "vacio" }, "No queda nada sin triar.")));
  }
  if (r.avisos) {
    paneles.push(panel("Avisos con plazo", ["#/avisos", "Ver avisos"], r.avisos.urgentes.length
      ? h("ul", { class: "mini" }, r.avisos.urgentes.map((a) => h("li", {},
        h("a", { href: `#/avisos/${a.id}` }, a.titulo), h("span", { class: "derecha" }, chipPlazo(a.plazo)))))
      : h("div", { class: "vacio" }, "Ningún aviso abierto con plazo.")));
  }
  if (p.ver) {
    const orden = ["pendiente", "aprobada", "fallida", "ejecutada", "hecha", "rechazada", "prohibida"];
    const clases = { pendiente: "pendiente", fallida: "mal", prohibida: "mal", ejecutada: "ok", hecha: "ok" };
    paneles.push(panel("Solicitudes de contención", ["#/abiertas", "Ver abiertas"],
      barras(orden.filter((e) => porEstado[e]).map((e) => ({ etiqueta: ESTADOS[e], valor: porEstado[e], clase: clases[e] })))));
    const sev = r.cola.por_severidad || {};
    paneles.push(panel("Cola por severidad estimada", ["#/cola", "Abrir"],
      barras(["critical", "high", "medium", "low", "informational"].filter((s) => sev[s])
        .map((s) => ({ etiqueta: SEVERIDADES[s], valor: sev[s], clase: `sev-${s}` })))));
    const ver = r.tickets.por_veredicto || {};
    paneles.push(panel("Veredictos de los tickets", ["#/tickets", "Ver tickets"],
      barras(Object.keys(VEREDICTOS).filter((v) => ver[v]).map((v) => ({ etiqueta: VEREDICTOS[v], valor: ver[v],
        clase: v === "true_positive" ? "mal" : v === "needs_more_info" ? "pendiente" : "ok" })))));
    paneles.push(panel("Últimas acciones ejecutadas", ["#/registro", "Registro de la API"], r.ejecutadas.length
      ? h("ul", { class: "mini" }, r.ejecutadas.map((x) => h("li", {}, h("strong", {}, accion(x.action).texto),
        h("span", { class: "mono" }, x.target), h("span", { class: "derecha suave" }, fecha(x.timestamp)))))
      : h("div", { class: "vacio" }, "Todavía no se ha ejecutado ninguna acción.")));
  }
  if (p.ver && (rol === "deteccion" || p.supervisar)) {
    paneles.push(panel("Huecos de detección (para crear o afinar reglas)", ["#/incidentes", "Ver incidentes"],
      r.incidentes.huecos.length ? h("ul", { class: "mini" }, r.incidentes.huecos.map((x) => h("li", {},
        h("span", { class: "texto" }, x.hueco), h("a", { class: "derecha mono", href: `#/incidentes/${x.incidente}` }, x.incidente))))
        : h("div", { class: "vacio" }, "Sin huecos registrados.")));
  }

  const t = ahoraEnEspana();
  const frase = [];
  if (p.decidir) frase.push(pend ? `tienes ${plural(pend, "acción pendiente", "acciones pendientes")} de decidir` : "no tienes acciones pendientes");
  if (r.avisos) frase.push(r.avisos.por_atender ? `${plural(r.avisos.por_atender, "aviso", "avisos")} por atender` : "ningún aviso por atender");
  if (p.ver) {
    const crit = (r.cola.por_severidad || {}).critical || 0;
    frase.push(`${((r.cola.total || 0) - (r.cola.ruido || 0)).toLocaleString("es-ES")} alertas en la cola` +
      (crit ? ` (${crit} críticas)` : ""));
  }
  const accesos = [
    p.ver ? h("a", { class: "boton", href: "#/cola" }, icono("cola"), "Abrir la cola") : null,
    p.decidir ? h("a", { class: "boton", href: "#/cola/nueva" }, icono("rayo"), "Recibir alertas") : null,
    p.decidir ? h("a", { class: "boton", href: "#/pendientes" }, icono("aprobar"), "Mis aprobaciones") : null,
    r.avisos ? h("a", { class: "boton", href: "#/avisos" }, icono("avisos"), "Avisos") : null,
    h("a", { class: "boton", href: "#/implementacion" }, icono("implementacion"), "Cómo funciona"),
  ];
  if (r.entrada && r.entrada.recibidas && p.ver) {
    paneles.unshift(panel(`Alertas recibidas (${r.entrada.recibidas})`, ["#/cola", "Ver la cola"],
      h("ul", { class: "mini" }, r.entrada.ultimas.map((a) => h("li", {}, chipSeveridad(a.severity),
        h("a", { href: `#/cola/${a.alert_id}` }, a.rule_name), h("span", { class: "derecha suave" }, hace(a.en)))))));
  }

  return h("div", {},
    h("section", { class: "saludo" },
      h("div", { class: "fecha-saludo" }, t.fecha.replace(/^./, (c) => c.toUpperCase())),
      h("h2", {}, `${t.saludo}, ${yo.nombre}`),
      h("p", {}, frase.length ? `${frase.join(" · ").replace(/^./, (c) => c.toUpperCase())}.` : ""),
      h("div", { class: "permisos" },
        h("span", {}, t.enHorario ? "● SOC en horario (L-V 8:00-20:00)" : "○ Fuera de horario: guardia N2 por teléfono"),
        h("span", {}, `Tu turno: ${yo.turno || "—"}`),
        h("span", {}, yo.acceso_anterior ? `Último acceso: ${hace(yo.acceso_anterior)} (${fecha(yo.acceso_anterior)})`
          : "Primer acceso: ¡bienvenido/a!")),
      h("div", { class: "accesos" }, accesos)),
    h("section", { class: "panel rol" },
      h("div", { class: "titulo" }, h("h2", {}, `Tu rol: ${yo.cargo}`)),
      h("div", { class: "cuerpo-panel" }, h("p", {}, DESCRIPCION[rol] || ""),
        h("div", { class: "permisos-rol" }, PERMISOS.map(([k, tx]) => h("span", { class: `etiqueta ${p[k] ? "ok" : ""}` },
          `${p[k] ? "✓" : "✕"} ${tx}`))))),
    h("div", { class: "kpis" }, kpis),
    h("div", { class: "rejilla" }, paneles));
}

export const vistas = {
  inicio: { grupo: "General", titulo: "Inicio", icono: "inicio", subtitulo: "Tu panel según tu rol", pagina },
};
