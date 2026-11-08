// Niveles 1-3 · vistas de operación para la demo: la cola priorizada (qué mirar primero y por qué), los tickets de
// triaje con lo que consultó el sistema y por qué decidió, y los informes de incidente con la cadena de ataque.
import { api } from "../api.js";
import {
  accion, chipSeveridad, chipVeredicto, datos, enlace, etiquetaEstado, fecha, h, hace, lista, seccion, tabla, vaciar,
} from "../ui.js";

const ICONO_SEV = { critical: "🔴", high: "🟠", medium: "🟡", low: "🟢", informational: "⚪" };
const ESTADO_CHECK = { permitida: ["✓", "ok"], sospechosa: ["⚠", "mal"], requiere_info: ["?", "pendiente"],
  informativa: ["ℹ", ""] };

function solicitud(sol) {
  if (!sol) return h("span", { class: "suave" }, "—");
  return h("span", {}, enlace(`#/abiertas/${encodeURIComponent(sol.id)}`, sol.id, "mono"), " ", etiquetaEstado(sol.estado));
}

function json(valor, max = 160) {
  const t = typeof valor === "string" ? valor : JSON.stringify(valor);
  return t && t.length > max ? `${t.slice(0, max)}…` : t;
}

// =============================================================================================== cola (nivel 1)

export async function detalleCola(id, ctx) {
  const x = (ctx.lista || []).find((e) => e.alert_id === id) || {};
  const a = await ctx.llamar(api.alerta(id));
  if (!a) return null;
  const ent = a.entities || {};
  const nombres = (l, k) => (l || []).map((e) => (typeof e === "string" ? e : e[k] || JSON.stringify(e)));
  return h("article", { class: "detalle" },
    h("div", { class: "suave mono" }, a.alert_id),
    h("h2", {}, a.rule_name),
    h("div", {}, chipSeveridad(x.severidad || a.severity), " ",
      h("span", { class: "etiqueta" }, `regla: ${a.severity}`), " ",
      a.ticket ? enlace(`#/tickets/${a.ticket}`, `ticket ${a.ticket}`, "etiqueta ok") : h("span", { class: "etiqueta pendiente" }, "sin triar")),
    seccion("Por qué está en este puesto", x.motivo ? h("div", { class: "bloque" },
      `Severidad estimada ${x.severidad} (${x.motivo}). Activo más crítico: ${x.activo} (${x.criticidad}). ` +
      `Plazo del SLA: ${fecha(x.vence, true)}.${x.ruido ? " Patrón de ruido de fondo." : ""}`) : null),
    seccion("Alerta", datos([["Regla", `${a.rule_id} · ${a.rule_name}`], ["Creada", fecha(a.created_at, true)],
      ["Origen", a.source_product], ["MITRE", a.mitre ? `${a.mitre.technique_id || ""} ${a.mitre.technique_name || ""}` : null],
      ["Runbook", a.runbook]])),
    seccion("Entidades", datos([["Equipos", nombres(ent.hosts, "hostname").join(", ")],
      ["Cuentas", nombres(ent.users, "upn").join(", ")], ["IPs", (ent.ips || []).join(", ")],
      ["Dominios", (ent.domains || []).join(", ")], ["Ficheros", nombres(ent.files, "name").join(", ")]])),
    seccion("Evidencia", h("div", { class: "bloque mono" }, json(a.evidence, 2000))),
    seccion("Eventos relacionados", h("p", { class: "mono" }, (a.related_events || []).join(", "))),
    seccion("Incidente candidato (correlación del nivel 2)", a.incidente && a.incidente.length > 1
      ? h("p", { class: "mono" }, a.incidente.join(", ")) : null),
    a.ticket ? null : seccion("Triaje", botonTriar(a.alert_id, ctx)));
}

/** Sigue un trabajo en segundo plano (triaje o investigación) hasta que termina, pintando su estado en `zona`. */
function seguirTrabajo(zona, t, ctx, alTerminar) {
  const pintar = (x) => {
    if (x.estado === "hecho") { vaciar(zona, alTerminar(x)); return true; }
    if (x.estado === "error") { vaciar(zona, h("span", { class: "etiqueta mal" }, "Error"), ` ${x.error}`); return true; }
    const textos = { en_cola: `En cola${x.pendientes_delante ? ` (${x.pendientes_delante} delante)` : ""}…`,
      triando: "El agente está triando la alerta (consultas, reglas internas, LLM)…",
      investigando: x.llm ? "Reuniendo los hechos y redactando el informe con el LLM (1-2 min)…"
        : "Rastreando la cadena de ataque en los logs (segundos)…" };
    vaciar(zona, h("span", { class: "etiqueta pendiente" }, "⏳"), ` ${textos[x.estado] || x.estado}`);
    return false;
  };
  if (pintar(t)) return;
  (async () => {
    for (let i = 0; i < 200; i += 1) {
      await new Promise((r) => setTimeout(r, 2500));
      if (!zona.isConnected) return;
      const lista = await ctx.llamar(api.trabajos()).catch(() => null);
      const x = lista && lista.find((y) => y.id === t.id);
      if (x && pintar(x)) return;
    }
  })();
}

/** Encarga el triaje de una alerta al agente (segundo plano) y sigue su estado hasta que hay ticket. */
export function botonTriar(alertId, ctx) {
  const zona = h("div", { class: "bloque" });
  if (!ctx.persona.permisos.decidir) {
    vaciar(zona, "Sin ticket todavía. Tu rol es de solo lectura: el triaje lo lanza un analista.");
    return zona;
  }
  const fin = (t) => [h("strong", {}, "Triada: "), chipVeredicto(t.veredicto), " ", chipSeveridad(t.severidad), " ",
    enlace(`#/tickets/${t.ticket_id}`, `Ver ${t.ticket_id}`),
    t.heredado_de ? h("span", { class: "suave" }, ` (mismo patrón que ${t.heredado_de}, sin LLM)`) : "",
    t.informe_preparado ? h("div", {}, "Escalado: hechos de la cadena preparados en ",
      enlace(`#/incidentes/${t.informe_preparado}`, t.informe_preparado), ".") : ""];
  vaciar(zona, h("p", {}, "Sin ticket todavía. El agente puede triarla ahora: reglas internas, correlación, " +
    "investigación con el LLM y validación de la política. Tarda entre unos segundos y un par de minutos."),
  h("button", { class: "boton primario", onclick: async (ev) => {
    ev.target.disabled = true;
    try {
      const t = await ctx.llamar(api.triar(alertId));
      if (t) seguirTrabajo(zona, t, ctx, fin);
    } catch (e) {
      vaciar(zona, h("span", { class: "etiqueta mal" }, "No se pudo encargar"), ` ${e.message}`);
    }
  } }, "Triar con el agente"));
  return zona;
}

/** [Nivel 3] Investigar un incidente desde un ticket o reinvestigar/redactar un informe. */
export function botonesInvestigar(ids, ctx, { informeConLlm = null } = {}) {
  const zona = h("div", { class: "bloque" });
  if (!ctx.persona.permisos.decidir) return null;
  const fin = (t) => [h("strong", {}, t.reutilizado ? "Mismos hechos: se reutiliza el informe ya redactado. "
    : t.con_llm ? "Informe redactado. " : "Hechos reunidos. "),
  enlace(`#/incidentes/${t.incident_id}`, `Abrir ${t.incident_id}`),
  t.uso && t.uso.input_tokens ? h("span", { class: "suave" }, ` · ${t.uso.input_tokens.toLocaleString("es-ES")} tokens de entrada, ` +
    `${t.uso.llamadas_modelo} llamada${t.uso.llamadas_modelo === 1 ? "" : "s"}`) : "",
  t.no_guardado ? h("div", { class: "suave" }, t.no_guardado) : "",
  !t.con_llm && t.motivo && t.motivo !== "--sin-llm" ? h("div", { class: "suave" }, `LLM: ${t.motivo}`) : ""];
  const lanzar = (llm, forzar = false) => async (ev) => {
    ev.target.disabled = true;
    try {
      const t = await ctx.llamar(api.investigar(ids, llm, forzar));
      if (t) seguirTrabajo(zona, t, ctx, fin);
    } catch (e) {
      vaciar(zona, h("span", { class: "etiqueta mal" }, "No se pudo encargar"), ` ${e.message}`);
    }
  };
  const botones = informeConLlm === null
    ? [h("button", { class: "boton", onclick: lanzar(false) }, "Reunir hechos (sin LLM, segundos)"),
      h("button", { class: "boton primario", onclick: lanzar(true) }, "Investigar con informe del LLM")]
    : informeConLlm
      ? [h("button", { class: "boton", onclick: lanzar(false) }, "Volver a rastrear (sin LLM)"),
        h("button", { class: "boton", onclick: lanzar(true, true) }, "Redactar de nuevo con el LLM")]
      : [h("button", { class: "boton primario", onclick: lanzar(true) }, "Redactar el informe con el LLM"),
        h("button", { class: "boton", onclick: lanzar(false) }, "Volver a rastrear (sin LLM)")];
  vaciar(zona, h("p", {}, "Nivel 3: reconstruye la cadena de ataque en los logs (código) y, si quieres, el LLM " +
    "redacta el informe en una sola llamada con esos hechos. Si los hechos no han cambiado, se reutiliza el informe."),
  h("div", { class: "botones" }, botones));
  return zona;
}

// =============================================================================================== tickets (niveles 1-2)

function filaTicket(t) {
  return {
    icono: { true_positive: "🚨", benign_true_positive: "✅", false_positive: "➖", needs_more_info: "❓" }[t.verdict] || "•",
    principal: t.title,
    chip: chipSeveridad(t.severity),
    secundaria: [t.ticket_id, chipTexto(t.verdict), `${t.alert_ids.length} alerta${t.alert_ids.length > 1 ? "s" : ""}`,
      t.escalate ? "escalado" : "", t.heredado_de ? `heredado de ${t.heredado_de}` : t.modelo, hace(t.triado_en)]
      .filter(Boolean).join(" · "),
  };
}

const chipTexto = (v) => ({ true_positive: "verdadero positivo", benign_true_positive: "benigno",
  false_positive: "falso positivo", needs_more_info: "faltan datos" }[v] || v);

async function detalleTicket(id, ctx) {
  const r = await ctx.llamar(api.ticket(id));
  if (!r) return null;
  const t = r.ticket;
  const uso = r.uso || {};
  return h("article", { class: "detalle" },
    h("div", { class: "suave mono" }, t.ticket_id),
    h("h2", {}, t.title),
    h("div", {}, chipVeredicto(t.verdict), " ", chipSeveridad(t.severity), " ",
      h("span", { class: "etiqueta" }, `confianza ${Math.round((t.confidence || 0) * 100)} %`), " ",
      t.escalation && t.escalation.escalate ? h("span", { class: "etiqueta mal" }, `escalado a ${t.escalation.to}`) : null),
    seccion("Qué ha pasado", h("div", { class: "bloque" }, t.summary)),
    seccion("Severidad (matriz de la política)", h("p", {}, t.severity_rationale)),
    t.escalation && t.escalation.escalate ? seccion("Escalado", h("p", {}, t.escalation.reason)) : null,
    seccion("Alertas del ticket", h("p", { class: "mono" }, t.alert_ids.map((a, i) => [i ? ", " : "",
      enlace(`#/cola/${a}`, a)]))),
    seccion("Comprobaciones por código (reglas internas, cambios, RRHH, líneas base)",
      (t.comprobaciones_internas || []).length ? h("ul", { class: "requisitos" }, t.comprobaciones_internas.map((c) => {
        const [marca, clase] = ESTADO_CHECK[c.estado] || ["•", ""];
        return h("li", { class: clase === "ok" ? "hecho" : "" }, h("span", { class: `marca-req ${clase}` }, marca),
          h("div", {}, h("strong", {}, `${c.regla} — ${c.sujeto}`), h("small", {}, `${c.estado}: ${c.motivo}`
            + (c.evidencias && c.evidencias.length ? ` (evidencias: ${c.evidencias.slice(0, 4).join(", ")})` : "")
            + (c.dato_faltante ? ` · falta: ${c.dato_faltante}` : ""))));
      })) : null),
    seccion("Evidencias", tabla(["Fuente", "Evento", "Hallazgo"],
      (t.evidence || []).map((e) => [e.source, h("span", { class: "mono" }, e.event_id), e.finding]))),
    seccion("Enriquecimiento", tabla(["Indicador", "Tipo", "Fuente", "Resultado"],
      (t.enrichment || []).map((e) => [h("span", { class: "mono" }, e.indicator), e.type, e.source, e.result]))),
    seccion("Acciones recomendadas", tabla(["Acción", "Objetivo", "Por qué", "Solicitud"],
      (t.recommended_actions || []).map((a) => [accion(a.action).texto, h("span", { class: "mono" }, a.target),
        a.justification, solicitud(a.solicitud)]))),
    t.verdict === "true_positive" ? seccion("Investigación del incidente (nivel 3)", botonesInvestigar([t.ticket_id], ctx)) : null,
    seccion("Correcciones de la política sobre la salida del modelo", lista(t.ajustes_politica)),
    seccion("Preguntas abiertas para el analista", lista(t.open_questions)),
    seccion("Relacionado con", lista((t.relacionado_con || []).map((x) => [enlace(`#/tickets/${x.ticket_id}`, x.ticket_id),
      ` (comparte ${x.entidades.slice(0, 3).join(", ")})`]))),
    seccion(`Qué consultó el sistema (${(r.traza || []).length} consultas)`, tabla(["Herramienta", "Quién", "Argumentos", "ms", "Resultado"],
      (r.traza || []).map((c) => [c.tool, c.origen, h("span", { class: "mono" }, json(c.args, 120)), c.ms,
        c.error ? h("span", { class: "etiqueta mal" }, json(c.error, 60)) : `${c.chars} car.`]))),
    seccion("Razonamiento del modelo", lista(r.razonamiento)),
    seccion("Ejecución", datos([["Modelo", r.heredado_de ? `plantilla (sin LLM), heredado de ${r.heredado_de}` : r.modelo],
      ["Tokens", uso.input_tokens !== undefined ? `${uso.input_tokens} entrada / ${uso.output_tokens} salida · ` +
        `${uso.llamadas_modelo ?? "?"} llamadas` : null],
      ["Duración", t.triage_seconds !== undefined ? `${t.triage_seconds} s` : null], ["Triado", fecha(r.triado_en, true)],
      ["Acciones ejecutadas", (t.executed_actions || []).length ? t.executed_actions.map((x) =>
        `${accion(x.action).texto} ${x.target}: ${x.result}`).join(" · ") : null]])));
}

// =============================================================================================== incidentes (nivel 3)

function filaInforme(i) {
  return {
    icono: "🧭",
    principal: i.title,
    chip: h("span", { class: "etiqueta" }, `confianza ${Math.round((i.confidence || 0) * 100)} %`),
    secundaria: [i.incident_id, `${i.alert_ids.length} alertas`, i.con_llm ? i.modelo : "sin LLM (solo hechos)",
      hace(i.generado_en)].filter(Boolean).join(" · "),
  };
}

async function detalleInforme(id, ctx) {
  const r = await ctx.llamar(api.informe(id));
  if (!r) return null;
  const inf = r.informe;
  const hechos = r.hechos || {};
  const est = hechos.estadisticas || {};
  const alc = inf.scope || {};
  return h("article", { class: "detalle" },
    h("div", { class: "suave mono" }, inf.incident_id),
    h("h2", {}, inf.title),
    h("div", {}, h("span", { class: "etiqueta" }, `confianza ${Math.round((inf.confidence || 0) * 100)} %`), " ",
      h("span", { class: `etiqueta ${r.con_llm ? "ok" : "pendiente"}` }, r.con_llm ? `redactado por ${r.modelo}` : "solo hechos (sin LLM)")),
    seccion("Investigar de nuevo", botonesInvestigar(inf.alert_ids, ctx, { informeConLlm: !!r.con_llm })),
    seccion("Origen", datos([["Paciente cero", inf.patient_zero], ["Acceso inicial", inf.initial_access]])),
    seccion("Causa raíz", h("div", { class: "bloque" }, inf.root_cause)),
    seccion("Cronología del ataque", tabla(["Cuándo", "Evento", "MITRE", "Qué hizo el atacante"],
      (inf.timeline || []).map((p) => [fecha(p.timestamp, true), h("span", { class: "mono" }, p.event_id),
        h("span", { class: "mono" }, p.mitre || "—"),
        p.description]))),
    seccion("Alcance", datos([["Cuentas", (alc.users || []).join(", ")], ["Equipos", (alc.hosts || []).join(", ")],
      ["Datos", alc.data], ["Impacto en el negocio", alc.business_impact]])),
    seccion("Plan de contención (aprobadores según la política)", tabla(["Acción", "Objetivo", "Aprueba", "Impacto", "Solicitud"],
      (inf.containment_plan || []).map((a) => [accion(a.action).texto, h("span", { class: "mono" }, a.target),
        a.approver, a.business_impact, solicitud(a.solicitud)]))),
    seccion("Erradicación y recuperación", lista(inf.eradication_and_recovery)),
    seccion("Notificaciones", lista(inf.notifications)),
    seccion("Huecos de detección", lista(inf.detection_gaps)),
    seccion("Incidentes relacionados", lista(inf.related_incidents)),
    seccion("Descartado por el analista (no es del ataque)", tabla(["Evento", "Motivo"],
      (inf.descartados || []).map((d) => [h("span", { class: "mono" }, d.event_id), d.motivo]))),
    seccion("Correcciones de la política", lista(inf.ajustes_politica)),
    seccion("Preguntas abiertas", lista(inf.open_questions)),
    seccion("Cómo se investigó (código, sin LLM)", datos([
      ["Ventana", hechos.ventana ? `${fecha(hechos.ventana.desde, true)} → ${fecha(hechos.ventana.hasta, true)}` : null],
      ["Rastreo", `${est.entidades ?? "?"} entidades · ${est.consultas_indice ?? "?"} consultas · ${est.segundos ?? "?"} s`],
      ["Eventos notables", est.eventos_notables], ["Indicadores del ataque", (hechos.iocs || []).join(", ")],
      ["Concentradores", (hechos.concentradores || []).join(", ")]]),
    tabla(["Entidad", "Salto", "Eventos", "Notables", "De dónde salió"], (hechos.entidades || []).map((e) => [
      h("span", { class: "mono" }, e.entidad), e.salto, e.eventos, e.notables, e.via]))),
    seccion("Ejecución", datos([["Generado", fecha(r.generado_en, true)], ["Duración", r.segundos ? `${r.segundos} s` : null],
      ["Tokens", r.uso ? `${r.uso.input_tokens} entrada / ${r.uso.output_tokens} salida · ` +
        `${r.uso.llamadas_modelo ?? "?"} llamada(s)${r.con_herramientas ? " con herramientas" : ""}` : null],
      ["Huella de los hechos", r.huella || "—"],
      ["Acciones ejecutadas", (r.acciones_ejecutadas || []).map((x) => `${accion(x.action).texto} ${x.target}`).join(" · ")]])));
}

export const vistas = {
  tickets: { grupo: "Investigación", titulo: "Tickets", icono: "tickets", permiso: "ver",
    subtitulo: "Triaje de cada alerta: qué consultó el sistema y por qué decidió", vacio: "Todavía no hay tickets.",
    cargar: () => api.tickets(), id: (t) => t.ticket_id, fila: filaTicket, detalle: detalleTicket,
    filtro: (t) => `${t.ticket_id} ${t.title} ${t.alert_ids.join(" ")}` },
  incidentes: { grupo: "Investigación", titulo: "Incidentes", icono: "incidentes", permiso: "ver",
    subtitulo: "Cadenas de ataque reconstruidas (nivel 3)", vacio: "Todavía no hay informes de incidente.",
    cargar: () => api.informes(), id: (i) => i.incident_id, fila: filaInforme, detalle: detalleInforme,
    filtro: (i) => `${i.incident_id} ${i.title} ${i.alert_ids.join(" ")}` },
};
