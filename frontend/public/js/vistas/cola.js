// Nivel 1 · cola de alertas a pantalla completa: todo lo que falta por triar, ordenado sin LLM (severidad estimada con
// la matriz y la CMDB, señal antes que ruido, incidentes antes que alertas sueltas, plazo del SLA). Filtros por
// severidad, ruido y texto; el detalle se abre en un cajón lateral sin perder la posición en la tabla.
import { api } from "../api.js";
import { avisar, chipSeveridad, enlace, fecha, h, icono, SEVERIDADES, vaciar } from "../ui.js";
import { botonTriar, detalleCola } from "./operacion.js";

const RECIBIDA = /-9\d{5}$/;   // IDs asignados por el backend a las alertas recibidas (agente/ingesta.py)

const estado = { entradas: [], total: 0, cargada: 0, sev: "", ocultarRuido: true, texto: "", mostrar: 60, nodos: null };

function filtradas() {
  const t = estado.texto;
  return estado.entradas.filter((x) => (!estado.sev || x.severidad === estado.sev) && (!estado.ocultarRuido || !x.ruido)
    && (!t || `${x.alert_id} ${x.rule_id} ${x.rule_name} ${x.activo}`.toLowerCase().includes(t)));
}

function pintarTabla() {
  const n = estado.nodos;
  const lista = filtradas();
  const visibles = lista.slice(0, estado.mostrar);
  vaciar(n.cuerpo, visibles.length ? visibles.map((x) => h("tr", {
    class: "clicable", tabindex: "0",
    onclick: () => { location.hash = `#/cola/${encodeURIComponent(x.alert_id)}`; },
    onkeydown: (ev) => { if (ev.key === "Enter") location.hash = `#/cola/${encodeURIComponent(x.alert_id)}`; },
  },
  h("td", {}, chipSeveridad(x.severidad)),
  h("td", {}, h("strong", {}, x.rule_name), h("div", { class: "suave mono" }, x.alert_id)),
  h("td", {}, x.n > 1 ? `${x.n} alertas` : "suelta"),
  h("td", {}, x.activo, h("div", { class: "suave" }, x.criticidad)),
  h("td", {}, fecha(x.vence)),
  h("td", {}, [x.alert_ids.some((i) => RECIBIDA.test(i)) ? h("span", { class: "etiqueta aprobada" }, "recibida") : null,
    x.ruido ? h("span", { class: "etiqueta" }, "ruido") : null,
    x.autorizada ? h("span", { class: "etiqueta ok" }, "autorizada") : null]))) : h("tr", {}, h("td", { colspan: "6" },
    h("div", { class: "vacio" }, "Nada coincide con los filtros."))));
  vaciar(n.pie, h("span", {}, `${visibles.length} de ${lista.length} puestos` +
    (estado.ocultarRuido ? ` · ${estado.entradas.filter((x) => x.ruido).length} de ruido ocultos` : "") +
    (estado.total > estado.entradas.length ? ` · cargados los ${estado.entradas.length} más prioritarios de ` +
      `${estado.total.toLocaleString("es-ES")}` : "")),
  visibles.length < lista.length ? h("button", { class: "boton", onclick: () => { estado.mostrar += 60; pintarTabla(); } },
    "Mostrar más") : null);
  n.chips.forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.sev === estado.sev)));
}

async function cargar(ctx, forzar = false) {
  if (!forzar && Date.now() - estado.cargada < 120000) return true;
  const r = await ctx.llamar(api.cola(2000));
  if (!r) return false;
  estado.entradas = r.entradas;
  estado.total = r.total;
  estado.cargada = Date.now();
  return true;
}

async function pagina(ctx, id) {
  if (!(await cargar(ctx))) return null;
  const chips = [["", "Todas"], ...Object.entries(SEVERIDADES).filter(([k]) => k !== "informational")].map(([k, t]) =>
    h("button", { class: "boton chip", "data-sev": k, onclick: () => { estado.sev = k; estado.mostrar = 60; pintarTabla(); } }, t));
  const ruido = h("input", { type: "checkbox", checked: estado.ocultarRuido,
    onchange: (ev) => { estado.ocultarRuido = ev.target.checked; pintarTabla(); } });
  const buscar = h("input", { class: "campo", type: "search", placeholder: "Buscar regla, alerta o activo…", value: estado.texto,
    oninput: (ev) => { estado.texto = ev.target.value.toLowerCase(); estado.mostrar = 60; pintarTabla(); } });
  const cuerpo = h("tbody", {});
  const pie = h("div", { class: "pie-tabla" });
  estado.nodos = { cuerpo, pie, chips };
  const raiz = h("div", {},
    h("section", { class: "panel" },
      h("div", { class: "herramientas" }, chips, h("label", { class: "interruptor" }, ruido, "Ocultar ruido de fondo"), buscar,
        ctx.persona.permisos.decidir ? h("button", { class: "boton primario", onclick: () => { location.hash = "#/cola/nueva"; } },
          "+ Recibir alertas") : null),
      h("div", { class: "desplazable" }, h("table", { class: "tabla" },
        h("thead", {}, h("tr", {}, ["Severidad", "Alerta", "Incidente", "Activo más crítico", "SLA", ""].map((t) => h("th", {}, t)))),
        cuerpo)),
      pie),
    h("div", { id: "cajon" }));
  pintarTabla();
  if (id) abrir(id, ctx, raiz);
  return raiz;
}

async function abrir(id, ctx, raiz = document) {
  const zona = raiz.querySelector ? raiz.querySelector("#cajon") : document.getElementById("cajon");
  if (!zona) return;
  if (!id) { vaciar(zona); return; }
  const cerrar = () => { location.hash = "#/cola"; };
  const caja = h("aside", { class: "cajon", role: "dialog", "aria-label": id === "nueva" ? "Recibir alertas" : "Detalle de la alerta" },
    h("div", { class: "cerrar" }, h("button", { class: "boton sutil", onclick: cerrar, "aria-label": "Cerrar" }, icono("cerrar"))),
    h("div", { class: "vacio" }, "Cargando…"));
  vaciar(zona, h("div", { class: "cajon-fondo", onclick: cerrar }), caja);
  const nodo = id === "nueva" ? await formularioRecibir(ctx) : await detalleCola(id, { ...ctx, lista: estado.entradas });
  if (nodo) caja.replaceChild(nodo, caja.lastChild);
}

// =============================================================================================== recibir alertas

async function formularioRecibir(ctx) {
  const cat = await ctx.llamar(api.catalogo());
  if (!cat) return null;
  const texto = h("textarea", { class: "campo mono", id: "json-alertas", rows: "14", spellcheck: "false" });
  texto.value = JSON.stringify([cat.ejemplo], null, 2);
  const regla = h("select", { class: "campo", id: "regla-alerta" },
    h("option", { value: "" }, "Elegir una regla del catálogo para la plantilla…"),
    cat.reglas.map((r) => h("option", { value: r.rule_id }, `${r.rule_id} · ${r.nombre} (${r.severidad})`)));
  regla.addEventListener("change", () => {
    if (!regla.value) return;
    texto.value = JSON.stringify([{ ...cat.ejemplo, rule_id: regla.value, evidence: {}, entities: { hosts: [], users: [] } }], null, 2);
  });
  const error = h("p", { class: "error-form oculto" });
  const resultado = h("div", {});
  const enviar = h("button", { class: "boton primario", type: "submit" }, "Enviar a la cola");
  return h("div", { class: "detalle" },
    h("h2", {}, "Recibir alertas"),
    h("p", { class: "suave" }, "Alertas de otro SIEM o de prueba. Se validan, se completan con el catálogo (nombre, " +
      "severidad, MITRE, runbook), reciben un ID propio y entran en la cola con la misma prioridad que las demás: " +
      "severidad estimada con la CMDB, correlación con incidentes y plazo del SLA. Sin created_at, la hora actual."),
    h("form", {
      class: "formulario",
      onsubmit: async (ev) => {
        ev.preventDefault();
        error.classList.add("oculto");
        let datos;
        try {
          datos = JSON.parse(texto.value);
        } catch (e) {
          error.textContent = `JSON no válido: ${e.message}`;
          error.classList.remove("oculto");
          return;
        }
        enviar.disabled = true;
        enviar.textContent = "Calculando la prioridad…";
        try {
          const r = await ctx.llamar(api.recibirAlertas(Array.isArray(datos) ? datos : [datos]));
          if (!r) return;
          avisar(`${r.length} alerta${r.length > 1 ? "s" : ""} en la cola`);
          await cargar(ctx, true);
          pintarTabla();
          vaciar(resultado, h("h3", {}, "Resultado"), h("ul", { class: "requisitos" }, r.map((a) => h("li", { class: "hecho" },
            h("span", { class: "marca-req" }, "✓"),
            h("div", {}, h("strong", {}, `${a.alert_id} · ${a.rule_name}`),
              h("small", {}, a.cola ? `Puesto ${a.cola.puesto} de ${a.cola.de.toLocaleString("es-ES")} · ` +
                `severidad estimada ${SEVERIDADES[a.cola.severidad]}` +
                (a.cola.alertas_en_incidente > 1 ? ` · se une a un incidente de ${a.cola.alertas_en_incidente} alertas` : "") +
                (a.cola.ruido ? " · patrón de ruido" : "") : "Sin puesto en la cola"),
              a.fuera_de_catalogo ? h("small", {}, "Regla fuera del catálogo: sin runbook") : null,
              h("div", { class: "botones" }, enlace(`#/cola/${a.cola ? a.cola.lider : a.alert_id}`, "Ver en la cola")),
              botonTriar(a.alert_id, ctx))))));
        } catch (e) {
          error.textContent = e.message;
          error.classList.remove("oculto");
        } finally {
          enviar.disabled = false;
          enviar.textContent = "Enviar a la cola";
        }
      },
    },
    h("label", { for: "regla-alerta" }, "Plantilla"), regla,
    h("label", { for: "json-alertas" }, "Alertas (JSON: un objeto o una lista)"), texto, error,
    h("div", { class: "botones" }, enviar,
      h("button", { class: "boton sutil", type: "button", onclick: () => { texto.value = JSON.stringify([cat.ejemplo], null, 2); } },
        "Restaurar el ejemplo"))),
    resultado);
}

export const vistas = {
  cola: { grupo: "Colas", titulo: "Cola de alertas", icono: "cola", permiso: "ver",
    subtitulo: "Lo que falta por triar, en orden de prioridad (severidad estimada, ruido, incidentes, SLA)",
    pagina, alCambiarId: (id, ctx) => abrir(id, ctx) },
};
