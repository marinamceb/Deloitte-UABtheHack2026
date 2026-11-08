// Implementación: qué hace el sistema en cada nivel del reto, con cifras reales de esta instalación, y dónde decide
// la IA y dónde el humano (lo que pide la demo: qué consultó el sistema, por qué decidió y dónde interviene la persona).
import { api } from "../api.js";
import { h, icono } from "../ui.js";

const PASOS = [
  ["Alertas del SIEM", "API simulada del SOC", ""],
  ["Código determinista", "reglas internas, cambios, RRHH, correlación, severidad", ""],
  ["IA (LLM)", "investiga con herramientas y redacta", "ia"],
  ["Política en código", "valida veredicto, severidad y aprobadores", ""],
  ["Persona del SOC", "aprueba o rechaza en esta consola", "humano"],
  ["Contención", "/approvals + /containment en la API", ""],
];

const NIVELES = [
  { num: 1, titulo: "Triaje", enlace: ["#/cola", "Cola de alertas"],
    puntos: ["Veredicto, severidad con la matriz de la política y recomendación por alerta",
      "Las 7 reglas internas de Tarvia comprobadas por código antes del LLM",
      "Investigación previa automática (activos, identidades, inteligencia, eventos) para ahorrar llamadas",
      "Plantillas: el ruido repetido hereda el veredicto sin llamar al modelo",
      "Cola priorizada sin LLM: severidad estimada, ruido, incidentes y SLA"],
    metricas: (r) => [`${r.sistema.alertas.toLocaleString("es-ES")} alertas`, `${r.cola.total.toLocaleString("es-ES")} en cola`,
      `${r.tickets.total} tickets`, `${r.tickets.heredados} por plantilla`] },
  { num: 2, titulo: "Triaje con criterio", enlace: ["#/tickets", "Tickets"],
    puntos: ["Correlación: alertas del mismo ataque en un único ticket (entidades exactas, entidades fuertes 14 días)",
      "Criticidad real del activo (CMDB y servicios de negocio) y ajustes verificados",
      "Actividad autorizada descartada con argumentos: calendario de cambios, RRHH, líneas base",
      "Validación de la política sobre la salida del modelo (cada corrección queda anotada)"],
    metricas: (r) => [`${r.incidentes.candidatos} incidentes candidatos`, `${r.tickets.escalados} escalados`] },
  { num: 3, titulo: "Investigación", enlace: ["#/incidentes", "Incidentes"],
    puntos: ["Índice local de los logs descargado por la API (consultas en milisegundos)",
      "Rastreo por saltos con pivote al origen habitual de una credencial robada",
      "Cronología con MITRE, acceso inicial, alcance, incidentes relacionados y huecos de detección",
      "Informe redactado por el LLM y verificado por código (IDs, fechas, aprobadores, notificaciones)"],
    metricas: (r) => [`${r.incidentes.informes} informes`,
      r.sistema.indice ? `${r.sistema.indice.eventos.toLocaleString("es-ES")} eventos indexados` : "índice sin construir",
      `${r.incidentes.huecos.length} huecos de detección`] },
  { num: 4, titulo: "Respuesta", enlace: ["#/pendientes", "Mis aprobaciones"],
    puntos: ["Solicitudes de contención con las aprobaciones que exige la política (cuatro ojos)",
      "El visto bueno de negocio lo registra un N2 en nombre del responsable, verificado en el directorio",
      "Nada sobre OT; uso dual con N2; sin repetir lo ya ejecutado",
      "Avisos por rol: escalados, SLA y notificaciones a terceros (DPO con 72 h)"],
    metricas: (r) => {
      const e = r.acciones.por_estado || {};
      return [`${Object.values(e).reduce((a, b) => a + b, 0)} solicitudes`, `${e.ejecutada || 0} ejecutadas`,
        `${e.pendiente || 0} pendientes`];
    } },
];

async function pagina(ctx) {
  const r = await ctx.llamar(api.resumen());
  if (!r) return null;
  const pasos = [];
  PASOS.forEach(([t, d, c], i) => {
    if (i) pasos.push(h("span", { class: "flecha", "aria-hidden": "true" }, "→"));
    pasos.push(h("div", { class: `paso-flujo ${c}` }, h("strong", {}, t), h("span", {}, d)));
  });
  return h("div", {},
    h("section", { class: "panel" }, h("div", { class: "titulo" }, h("h2", {}, "Cómo fluye una alerta")),
      h("div", { class: "flujo" }, pasos)),
    h("div", { class: "niveles-impl" }, NIVELES.map((n) => h("section", { class: "panel nivel" },
      h("div", { class: "cabeza" }, h("div", { class: "num" }, String(n.num)), h("h3", {}, `Nivel ${n.num} · ${n.titulo}`)),
      h("ul", {}, n.puntos.map((p) => h("li", {}, p))),
      r.sistema ? h("div", { class: "metricas" }, n.metricas(r).map((m) => h("span", {}, m))) : null,
      h("a", { href: n.enlace[0] }, `${n.enlace[1]} →`)))),
    h("div", { class: "dos-col" },
      h("section", { class: "panel" }, h("h3", {}, "Lo decide la IA (y lo revisa el código)"),
        h("ul", { class: "puntos" }, ["Veredicto y resumen de cada alerta", "Qué alertas forman un mismo ataque",
          "Relato del incidente, causa raíz y plan de contención propuesto", "Qué eventos de la cronología descartar"]
          .map((x) => h("li", {}, x)))),
      h("section", { class: "panel" }, h("h3", {}, "Lo decide una persona"),
        h("ul", { class: "puntos" }, ["Ejecutar cualquier acción de contención", "Aprobar lo disruptivo (N2) y el visto bueno de negocio",
          "Notificar a terceros (DPO, Tesorería, proveedor)", "Cerrar tareas manuales y rechazar propuestas"]
          .map((x) => h("li", {}, x))))),
    r.sistema ? h("p", { class: "suave" }, icono("escudo"), ` Modelo: ${r.sistema.llm}. Los datos llegan por la API simulada; ` +
      "el agente nunca ejecuta contención sin aprobación humana.") : null);
}

export const vistas = {
  implementacion: { grupo: "Sistema", titulo: "Implementación", icono: "implementacion",
    subtitulo: "Qué hace el sistema en cada nivel del reto, con cifras de esta instalación", pagina },
};
