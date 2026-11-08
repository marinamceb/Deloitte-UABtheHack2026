// Utilidades de interfaz. Todo el texto se inserta con textContent (nunca innerHTML): las justificaciones, objetivos
// e historiales pueden contener texto escrito por un atacante (asuntos de correo, comandos...) y no deben ejecutarse.

/** Crea un elemento: h("button", {class: "boton", onclick: fn}, "texto", otroNodo...) */
export function h(etiqueta, atributos = {}, ...hijos) {
  const el = document.createElement(etiqueta);
  for (const [clave, valor] of Object.entries(atributos || {})) {
    if (valor === null || valor === undefined || valor === false) continue;
    if (clave.startsWith("on") && typeof valor === "function") el.addEventListener(clave.slice(2), valor);
    else if (clave === "class") el.className = valor;
    else if (valor === true) el.setAttribute(clave, "");
    else el.setAttribute(clave, String(valor));
  }
  for (const hijo of hijos.flat(Infinity)) {
    if (hijo === null || hijo === undefined || hijo === false) continue;
    el.append(hijo instanceof Node ? hijo : document.createTextNode(String(hijo)));
  }
  return el;
}

export function vaciar(el, ...hijos) {
  el.replaceChildren(...hijos.flat(Infinity).filter((x) => x !== null && x !== undefined && x !== false));
  return el;
}

// ------------------------------------------------------------------------------------------- formatos

const ZONA = "Europe/Madrid";   // el SOC trabaja en hora de España (los datos están en UTC)

export function fecha(iso, conAnio = false) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("es-ES", {
    timeZone: ZONA, day: "2-digit", month: "2-digit", ...(conAnio ? { year: "numeric" } : {}),
    hour: "2-digit", minute: "2-digit",
  });
}

export function hace(iso) {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (!Number.isFinite(s)) return "";
  if (s < 60) return "hace un momento";
  if (s < 3600) return `hace ${Math.round(s / 60)} min`;
  if (s < 86400) return `hace ${Math.round(s / 3600)} h`;
  return `hace ${Math.round(s / 86400)} d`;
}

export const ACCIONES = {
  isolate_host: { texto: "Aislar equipo", icono: "🖥" },
  disable_user: { texto: "Deshabilitar cuenta", icono: "👤" },
  revoke_sessions: { texto: "Revocar sesiones", icono: "🔑" },
  reset_password: { texto: "Forzar cambio de contraseña", icono: "🔑" },
  block_ioc: { texto: "Bloquear indicador", icono: "⛔" },
  purge_email: { texto: "Purgar correo de los buzones", icono: "✉" },
  disable_access_key: { texto: "Desactivar clave cloud", icono: "☁" },
};

export function accion(nombre) {
  return ACCIONES[nombre] || { texto: `${nombre.replaceAll("_", " ")} (tarea manual)`, icono: "🛠" };
}

export const ESTADOS = {
  pendiente: "Pendiente",
  aprobada: "Aprobada · falta hacerla",
  ejecutada: "Ejecutada",
  fallida: "Fallida",
  rechazada: "Rechazada",
  prohibida: "Prohibida por la política",
  hecha: "Hecha",
};

export function etiquetaEstado(estado) {
  return h("span", { class: `etiqueta ${estado}` }, ESTADOS[estado] || estado);
}

// ------------------------------------------------------------------------------------------- avisos

export function avisar(texto, tipo = "") {
  const caja = document.getElementById("avisos");
  const aviso = h("div", { class: `aviso ${tipo}` }, texto);
  caja.append(aviso);
  while (caja.children.length > 3) caja.firstElementChild.remove();   // como mucho tres a la vez
  setTimeout(() => aviso.remove(), tipo === "error" ? 7000 : 4000);
}

// ------------------------------------------------------------------------------------------- piezas comunes

export const SEVERIDADES = { critical: "Crítica", high: "Alta", medium: "Media", low: "Baja", informational: "Info" };
export const VEREDICTOS = {
  true_positive: "Verdadero positivo", benign_true_positive: "Benigno (autorizado)",
  false_positive: "Falso positivo", needs_more_info: "Faltan datos",
};

export function chipSeveridad(sev) {
  return h("span", { class: `etiqueta sev-${sev}` }, SEVERIDADES[sev] || sev || "—");
}

export function chipVeredicto(v) {
  return h("span", { class: `etiqueta ver-${v}` }, VEREDICTOS[v] || v || "—");
}

/** «vence en 2 h 10 min» / «vencido hace 3 h» */
export function restante(iso) {
  if (!iso) return null;
  const s = (new Date(iso).getTime() - Date.now()) / 1000;
  const texto = (x) => (x < 3600 ? `${Math.max(1, Math.round(x / 60))} min`
    : x < 172800 ? `${Math.floor(x / 3600)} h ${Math.round((x % 3600) / 60)} min` : `${Math.round(x / 86400)} d`);
  return s >= 0 ? { vencido: false, texto: `vence en ${texto(s)}` } : { vencido: true, texto: `vencido hace ${texto(-s)}` };
}

export function chipPlazo(iso) {
  const r = restante(iso);
  if (!r) return null;
  return h("span", { class: `etiqueta ${r.vencido ? "mal" : "pendiente"}`, title: fecha(iso, true) }, `⏱ ${r.texto}`);
}

export function seccion(titulo, ...contenido) {
  const hijos = contenido.flat(Infinity).filter((x) => x !== null && x !== undefined && x !== false && x !== "");
  return hijos.length ? [h("h3", {}, titulo), ...hijos] : null;
}

export function lista(items, vacio = null) {
  if (!items || !items.length) return vacio ? h("p", { class: "suave" }, vacio) : null;
  return h("ul", { class: "puntos" }, items.map((x) => h("li", {}, x)));
}

export function tabla(cabeceras, filas) {
  if (!filas.length) return null;
  return h("div", { class: "desplazable" }, h("table", { class: "tabla" },
    h("thead", {}, h("tr", {}, cabeceras.map((c) => h("th", {}, c)))),
    h("tbody", {}, filas.map((f) => h("tr", {}, f.map((c) => (c instanceof Node ? h("td", {}, c) : h("td", {}, c ?? "—"))))))));
}

export function datos(pares) {
  return h("dl", { class: "datos" }, pares.filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
}

export function enlace(hash, texto, clase = "") {
  return h("a", { href: hash, class: clase }, texto);
}

// ------------------------------------------------------------------------------------------- iconos y gráficos

// Trazos de iconos de línea (24×24). Se crean con createElementNS: sin HTML ni estilos en línea (CSP).
const TRAZOS = {
  inicio: ["M3 11l9-8 9 8", "M5 10v10h14V10", "M10 20v-6h4v6"],
  cola: ["M4 6h16", "M4 12h16", "M4 18h10"],
  aprobar: ["M9 11l3 3 8-8", "M20 12v7a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h11"],
  avisos: ["M6 8a6 6 0 0 1 12 0c0 7 3 8 3 8H3s3-1 3-8", "M10 20a2 2 0 0 0 4 0"],
  tickets: ["M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8z", "M14 3v5h5", "M9 13h6", "M9 17h6"],
  incidentes: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "M16 8l-2 6-6 2 2-6z"],
  abiertas: ["M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z", "M12 6v6l4 2"],
  cerradas: ["M21 8v13H3V8", "M1 3h22v5H1z", "M10 12h4"],
  registro: ["M4 5c0-1 4-2 8-2s8 1 8 2-4 2-8 2-8-1-8-2z", "M4 5v6c0 1 4 2 8 2s8-1 8-2V5",
    "M4 11v6c0 1 4 2 8 2s8-1 8-2v-6"],
  implementacion: ["M12 2l9 5-9 5-9-5z", "M3 12l9 5 9-5", "M3 17l9 5 9-5"],
  salir: ["M9 21H5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h4", "M16 17l5-5-5-5", "M21 12H9"],
  menu: ["M3 6h18", "M3 12h18", "M3 18h18"],
  alerta: ["M12 3l10 18H2z", "M12 10v4", "M12 18h.01"],
  escudo: ["M12 2l8 3v6c0 5-3.5 9.5-8 11-4.5-1.5-8-6-8-11V5z"],
  rayo: ["M13 2L4 14h7l-1 8 9-12h-7z"],
  cerrar: ["M18 6L6 18", "M6 6l12 12"],
};

export function icono(nombre) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "ico");
  svg.setAttribute("aria-hidden", "true");
  for (const d of TRAZOS[nombre] || TRAZOS.cola) {
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", d);
    svg.append(p);
  }
  return svg;
}

/** Barras horizontales: [{etiqueta, valor, clase}] (anchura por CSSOM, que la CSP permite). */
export function barras(items) {
  const max = Math.max(1, ...items.map((x) => x.valor));
  return h("div", { class: "barras" }, items.map((x) => {
    const relleno = h("div", { class: `relleno ${x.clase || ""}` });
    relleno.style.width = `${Math.round((100 * x.valor) / max)}%`;
    return h("div", { class: "barra-dato" }, h("span", {}, x.etiqueta), h("div", { class: "pista-barra" }, relleno),
      h("span", { class: "num" }, String(x.valor)));
  }));
}
