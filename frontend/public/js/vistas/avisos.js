// Nivel 4 · avisos por rol: escalados y notificaciones del SLA (internos: «enterado») y notificaciones a terceros de
// Tarvia (DPO con 72 h, Tesorería, Operaciones, proveedor...: el SOC las hace y registra a quién y cómo).
import { api } from "../api.js";
import { avisar, chipPlazo, chipSeveridad, datos, enlace, fecha, h, hace, lista, vaciar } from "../ui.js";

const ICONOS = { escalado: "📞", dpo: "🛡", tesoreria: "💶", operaciones: "🏭", pci: "💳", proveedor: "🤝",
  ciso: "📣", responsable_soc: "📣", otros: "✉" };

function chipEstado(a) {
  const textos = { abierto: "Abierto", enterado: "Enterado", notificado: "Notificado" };
  return h("span", { class: `etiqueta ${a.estado === "abierto" ? "pendiente" : "ok"}` }, textos[a.estado] || a.estado);
}

function fila(a) {
  return {
    icono: ICONOS[a.categoria] || "✉",
    principal: a.titulo,
    chip: a.estado === "abierto" && a.plazo ? chipPlazo(a.plazo) : chipEstado(a),
    secundaria: [a.interno ? "interno" : `notificar a ${a.contacto || "terceros"}`, `${a.origen.id}`,
      a.origen.titulo, hace(a.desde)].filter(Boolean).join(" · "),
  };
}

function origen(o) {
  return enlace(o.tipo === "ticket" ? `#/tickets/${o.id}` : `#/incidentes/${o.id}`, `${o.tipo} ${o.id}`, "mono");
}

async function detalle(id, ctx) {
  const a = (ctx.lista || []).find((x) => x.id === id) || (await ctx.llamar(api.avisos()) || []).find((x) => x.id === id);
  if (!a) return h("div", { class: "vacio" }, "Ese aviso no existe o no te corresponde.");
  const zona = h("div", {});
  return h("article", { class: "detalle" },
    h("div", { class: "suave mono" }, a.id),
    h("h2", {}, `${ICONOS[a.categoria] || "✉"} ${a.titulo}`),
    h("div", {}, chipEstado(a), " ", chipSeveridad(a.severidad), " ", a.estado === "abierto" ? chipPlazo(a.plazo) : null),
    h("h3", {}, a.interno ? "Qué hay que saber" : "Qué hay que notificar"),
    h("div", { class: `bloque ${a.interno ? "" : "impacto"}` }, lista(a.detalle)),
    h("h3", {}, "Datos"),
    datos([
      ["Origen", h("span", {}, origen(a.origen), a.origen.titulo ? ` · ${a.origen.titulo}` : "")],
      ["Para", a.destinatarios.map((r) => ({ N2: "N2", responsable_soc: "Responsable SOC", ciso: "CISO" }[r] || r)).join(", ")],
      ["A quién en Tarvia", a.interno ? null : a.contacto],
      ["Constancia", `${fecha(a.desde, true)} (${hace(a.desde)})`],
      ["Plazo", a.plazo ? `${fecha(a.plazo, true)}${a.categoria === "dpo" ? " · RGPD: 72 h desde la constancia" : ""}` : null],
    ]),
    a.atendido ? [h("h3", {}, "Atendido"), h("div", { class: "bloque exito" },
      `${a.atendido.nombre} · ${fecha(a.atendido.ts, true)}${a.atendido.nota ? ` · ${a.atendido.nota}` : ""}`)] : null,
    a.puedo.includes("atender") ? h("div", { class: "decision" }, h("h3", {}, "Tu acción"),
      h("div", { class: "botones" }, h("button", { class: "boton primario", onclick: () => formulario(zona, a, ctx) },
        a.interno ? "Enterado" : "Registrar notificación")), zona) : null);
}

function formulario(zona, a, ctx) {
  const texto = h("textarea", { class: "campo", id: "nota-aviso", required: !a.interno,
    placeholder: a.interno ? "" : "p. ej. «Llamada a la DPO a las 10:15; acuse por correo a las 10:30»" });
  const error = h("p", { class: "error-form oculto" });
  vaciar(zona, h("form", {
    class: "formulario",
    onsubmit: async (ev) => {
      ev.preventDefault();
      try {
        const r = await ctx.llamar(api.atenderAviso(a.id, texto.value.trim()));
        if (!r) return;
        avisar(r.estado === "notificado" ? "Notificación registrada" : "Marcado como enterado");
        await ctx.recargar();
      } catch (e) { error.textContent = e.message; error.classList.remove("oculto"); }
    },
  },
  h("label", { for: "nota-aviso" }, a.interno ? "Comentario (opcional)" : "A quién se notificó, cómo y cuándo"),
  texto, error,
  h("div", { class: "botones" }, h("button", { class: "boton primario", type: "submit" }, "Guardar"),
    h("button", { class: "boton sutil", type: "button", onclick: () => vaciar(zona) }, "Cancelar"))));
  texto.focus();
}

export const vistas = {
  avisos: { grupo: "Colas", titulo: "Avisos", contador: "avisos", icono: "avisos", permiso: ["avisos", "supervisar"],
    subtitulo: "Escalados, SLA y notificaciones a terceros que te tocan", vacio: "No tienes avisos.",
    cargar: () => api.avisos(), fila, detalle,
    filtro: (a) => `${a.titulo} ${a.origen.id} ${a.origen.titulo} ${a.contacto}` },
};
