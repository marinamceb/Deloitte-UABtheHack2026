// Nivel 4 · solicitudes de contención: bandejas, detalle y decisiones. El servidor decide qué puede hacer cada persona
// (campo `puedo`) y lo vuelve a comprobar al recibir la decisión: aquí solo se muestran los botones que corresponden.
import { api } from "../api.js";
import { accion, avisar, datos, enlace, etiquetaEstado, fecha, h, hace, tabla, vaciar } from "../ui.js";

function fila(s) {
  const a = accion(s.action);
  const firmadas = s.aprobaciones.filter((x) => x.requisito !== null && x.requisito !== undefined).length;
  const progreso = s.requisitos.length ? `${firmadas}/${s.requisitos.length} aprobaciones` : "sin aprobación previa";
  return {
    icono: a.icono,
    principal: [`${a.texto} · `, h("span", { class: "mono" }, s.target)],
    chip: etiquetaEstado(s.estado),
    secundaria: [progreso, s.faltan.length && s.estado === "pendiente" ? `falta: ${s.faltan.join(", ")}` : "",
      s.origenes.map((o) => o.id).join(", "), hace(s.creada)].filter(Boolean).join(" · "),
  };
}

const filtro = (s) => `${s.target} ${s.action} ${accion(s.action).texto} ${s.origenes.map((o) => o.id).join(" ")}`;

function origenEnlace(o) {
  return enlace(o.tipo === "ticket" ? `#/tickets/${o.id}` : `#/incidentes/${o.id}`, `${o.tipo} ${o.id}`, "mono");
}

// =============================================================================================== detalle

async function detalle(id, ctx) {
  const s = await ctx.llamar(api.accion(id));
  if (!s) return null;
  const a = accion(s.action);
  return h("article", { class: "detalle" },
    h("div", { class: "suave mono" }, s.id),
    h("h2", {}, `${a.icono} ${a.texto}`),
    h("div", {}, h("span", { class: "mono" }, s.target), " ", etiquetaEstado(s.estado),
      s.tipo === "manual" ? h("span", { class: "etiqueta" }, "fuera de la API: tarea manual") : null),
    h("h3", {}, "Por qué lo propone el agente"),
    h("div", { class: "bloque" }, s.justificacion || "Sin justificación."),
    h("h3", {}, "Impacto si se ejecuta"),
    h("div", { class: "bloque impacto" }, h("strong", {}, "⚠ "), s.impacto),
    h("h3", {}, "Qué exige la política (apartado 4)"),
    datos([["Aprobación", s.politica], ["Motivo", s.motivo_politica || "—"],
      ["Propuesta en", h("span", {}, s.origenes.map((o, i) => [i ? " · " : "", origenEnlace(o)]))],
      ["Creada", `${fecha(s.creada, true)} (${hace(s.creada)})`]]),
    h("h3", {}, "Aprobaciones"),
    requisitos(s),
    resultado(s),
    decision(s, ctx),
    h("h3", {}, "Historial"),
    h("ol", { class: "historial" }, s.historial.slice().reverse().map((x) => h("li", {
      class: ["aprobación", "aprobación de negocio registrada", "ejecutada", "hecha", "rechazo", "fallo"]
        .includes(x.evento) ? "importante" : "",
    },
    h("div", {}, h("strong", {}, x.evento), " · ", x.nombre || x.email,
      x.rol ? h("span", { class: "suave" }, ` (${x.rol})`) : ""),
    x.detalle ? h("div", {}, x.detalle) : null,
    h("div", { class: "cuando" }, fecha(x.ts, true))))));
}

function requisitos(s) {
  if (!s.requisitos.length) {
    const directa = s.aprobaciones.find((x) => x.requisito === null || x.requisito === undefined);
    return h("div", { class: "bloque" }, directa
      ? `Ejecutada directamente por ${directa.nombre} (${fecha(directa.ts)}).`
      : "No necesita aprobación previa: la puede ejecutar cualquier analista del SOC (política, apartado 4).");
  }
  const firmas = new Map(s.aprobaciones.filter((x) => x.requisito !== null).map((x) => [x.requisito, x]));
  return h("ul", { class: "requisitos" }, s.requisitos.map((r, i) => {
    const f = firmas.get(i);
    return h("li", { class: f ? "hecho" : "" },
      h("span", { class: "marca-req", "aria-hidden": "true" }, f ? "✓" : "○"),
      h("div", {}, h("strong", {}, r.etiqueta),
        f ? h("small", {}, `${f.nombre} · ${fecha(f.ts)}${f.registrado_por ? ` · registrada por ${f.registrado_por}` : ""}`
          + (f.comentario ? ` · «${f.comentario}»` : ""))
          : h("small", {}, r.rol === "responsable_servicio"
            ? "Pendiente: la obtiene un N2 o superior y la registra en su nombre" : "Pendiente")));
  }));
}

function resultado(s) {
  const r = s.resultado;
  if (!r) return null;
  const filas = {
    ejecutada: ["exito", r.ya_constaba ? "Ya constaba como ejecutada en la API: no se ha repetido."
      : `La API respondió: ${r.result || "ok"}${r.timestamp ? ` (${fecha(r.timestamp, true)})` : ""}.`],
    fallida: ["error", `La API rechazó o no respondió: ${r.error}. Puedes reintentarlo.`],
    prohibida: ["error", `No se puede ejecutar: ${r.motivo}.`],
    rechazada: ["", `Rechazada: ${r.motivo}`],
    hecha: ["exito", `Hecha${r.nota ? `: ${r.nota}` : ""} (${r.hecha_por || ""}).`],
  }[s.estado];
  return filas ? [h("h3", {}, "Resultado"), h("div", { class: `bloque ${filas[0]}` }, filas[1])] : null;
}

// =============================================================================================== decisiones

function decision(s, ctx) {
  if (!s.puedo.length) {
    return ["pendiente", "aprobada", "fallida"].includes(s.estado)
      ? h("div", { class: "decision suave" }, "Tu rol no puede decidir ahora sobre esta solicitud.") : null;
  }
  const zona = h("div", {});
  const ultima = s.tipo === "api" && s.faltan.length <= 1;
  const botones = {
    aprobar: [s.requisitos.length ? "Aprobar" : "Ejecutar ahora", "primario", () => formulario(zona, s, ctx, "aprobar", {
      pista: ultima ? "Es la última aprobación que falta: la acción se ejecutará en la API al confirmar."
        : "Quedará registrada tu aprobación; faltará la del resto.",
      campo: "Comentario (opcional)", obligatorio: false, boton: ultima ? "Aprobar y ejecutar" : "Aprobar",
      confirmar: ultima ? `Se ejecutará «${accion(s.action).texto}» sobre ${s.target}.\n\nImpacto: ${s.impacto}` : "",
    })],
    registrar_responsable: ["Registrar aprobación de negocio", "", () => formularioNegocio(zona, s, ctx)],
    marcar_hecha: ["Marcar como hecha", "primario", () => formulario(zona, s, ctx, "hecha", {
      pista: "Confirma que la tarea manual ya está hecha.", campo: "Qué se ha hecho", obligatorio: true,
      boton: "Marcar como hecha" })],
    reintentar: ["Reintentar", "primario",
      () => enviar(s, ctx, "reintentar", "", "", `¿Reintentar «${accion(s.action).texto}» sobre ${s.target}?`)],
    rechazar: ["Rechazar", "peligro", () => formulario(zona, s, ctx, "rechazar", {
      pista: "La solicitud se cerrará y no se ejecutará.", campo: "Motivo del rechazo", obligatorio: true,
      boton: "Rechazar", estilo: "peligro" })],
  };
  const orden = Object.keys(botones);
  return h("div", { class: "decision" },
    h("h3", {}, "Tu decisión"),
    h("div", { class: "botones" }, s.puedo.filter((op) => botones[op]).sort((x, y) => orden.indexOf(x) - orden.indexOf(y))
      .map((op) => h("button", { class: `boton ${botones[op][1]}`, onclick: botones[op][2] }, botones[op][0]))),
    zona);
}

function formulario(zona, s, ctx, operacion, { pista, campo, obligatorio, boton, estilo = "primario", confirmar = "" }) {
  const texto = h("textarea", { class: "campo", id: "texto-decision", required: obligatorio });
  const error = h("p", { class: "error-form oculto" });
  vaciar(zona, h("form", {
    class: "formulario",
    onsubmit: (ev) => { ev.preventDefault(); enviar(s, ctx, operacion, texto.value.trim(), "", confirmar, error); },
  },
  h("p", { class: "pista" }, pista), h("label", { for: "texto-decision" }, campo), texto, error,
  h("div", { class: "botones" }, h("button", { class: `boton ${estilo}`, type: "submit" }, boton),
    h("button", { class: "boton sutil", type: "button", onclick: () => vaciar(zona) }, "Cancelar"))));
  texto.focus();
}

function formularioNegocio(zona, s, ctx) {
  const n = s.negocio || {};
  const email = h("input", { class: "campo", id: "email-negocio", type: "email", required: true,
    placeholder: "nombre.apellido@tarvia.example" });
  const como = h("textarea", { class: "campo", id: "como-negocio", required: true,
    placeholder: "p. ej. «Por teléfono a las 10:42; asume la parada del servicio»" });
  const error = h("p", { class: "error-form oculto" });
  vaciar(zona, h("form", {
    class: "formulario",
    onsubmit: (ev) => { ev.preventDefault(); enviar(s, ctx, "aprobar", como.value.trim(), email.value.trim(), "", error); },
  },
  h("p", { class: "pista" }, `La política exige el visto bueno de ${n.cargo || "el responsable del servicio"}` +
    `${n.servicio ? ` (${n.servicio})` : ""}. Obtenlo (teléfono, correo) y regístralo aquí: se comprobará en el ` +
    "directorio de Tarvia que esa persona es la responsable."),
  h("label", { for: "email-negocio" }, "Email de Tarvia de quien aprueba"), email,
  h("label", { for: "como-negocio" }, "Cómo y cuándo lo aprobó"), como, error,
  h("div", { class: "botones" }, h("button", { class: "boton primario", type: "submit" }, "Registrar aprobación"),
    h("button", { class: "boton sutil", type: "button", onclick: () => vaciar(zona) }, "Cancelar"))));
  email.focus();
}

async function enviar(s, ctx, operacion, texto, enNombreDe = "", confirmar = "", error = null) {
  if (confirmar && !window.confirm(confirmar)) return;
  const llamadas = {
    aprobar: () => api.aprobar(s.id, texto, enNombreDe),
    rechazar: () => api.rechazar(s.id, texto),
    hecha: () => api.hecha(s.id, texto),
    reintentar: () => api.reintentar(s.id),
  };
  try {
    const r = await ctx.llamar(llamadas[operacion]());
    if (!r) return;
    const mensajes = {
      ejecutada: "Ejecutada en la API", fallida: "La API no la ha ejecutado: revisa el resultado",
      pendiente: "Aprobación registrada", aprobada: "Aprobada: falta realizar la tarea",
      rechazada: "Solicitud rechazada", hecha: "Tarea marcada como hecha",
    };
    avisar(`${mensajes[r.estado] || r.estado} · ${accion(r.action).texto} ${r.target}`, r.estado === "fallida" ? "error" : "");
    await ctx.recargar();
  } catch (e) {
    if (error) { error.textContent = e.message; error.classList.remove("oculto"); } else avisar(e.message, "error");
  }
}

// =============================================================================================== vistas

export const vistas = {
  pendientes: { grupo: "Colas", titulo: "Mis aprobaciones", contador: "pendientes", icono: "aprobar", permiso: "decidir",
    subtitulo: "Solicitudes de contención que puedes decidir ahora",
    vacio: "No tienes nada pendiente de decidir.", cargar: () => api.pendientes(), fila, filtro, detalle },
  abiertas: { grupo: "Respuesta", titulo: "Solicitudes abiertas", icono: "abiertas", permiso: "ver",
    subtitulo: "Contención propuesta pendiente de aprobación, de hacer o fallida", vacio: "No hay solicitudes abiertas.",
    cargar: () => api.acciones("pendiente,aprobada,fallida"), fila, filtro, detalle },
  cerradas: { grupo: "Respuesta", titulo: "Solicitudes cerradas", icono: "cerradas", permiso: "ver",
    subtitulo: "Ejecutadas, hechas, rechazadas o prohibidas por la política", vacio: "Todavía no se ha cerrado ninguna.",
    cargar: () => api.acciones("ejecutada,hecha,rechazada,prohibida"), fila, filtro, detalle },
  registro: { grupo: "Respuesta", titulo: "Registro de la API", icono: "registro", permiso: "ver",
    subtitulo: "Lo que de verdad ha ejecutado /containment", vacio: "La API simulada no ha ejecutado ninguna acción.",
    cargar: () => api.registro(),
    pintar: (items) => tabla(["Cuándo", "Acción", "Objetivo", "Origen", "Resultado"], items.map((r) => [
      fecha(r.timestamp), accion(r.action).texto, h("span", { class: "mono" }, r.target),
      h("span", { class: "mono" }, r.ticket_id || "—"),
      h("span", { class: `etiqueta ${String(r.result).startsWith("ok") ? "ok" : "mal"}` }, r.result || "—")])),
    ayuda: "Cada fila es una llamada real a /containment de la API simulada. Las solicitudes cerradas muestran el " +
      "mismo resultado en su detalle." },
};
