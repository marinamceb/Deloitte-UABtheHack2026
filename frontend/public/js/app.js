// Consola del SOC: armazón común. Login, menú lateral según los permisos de la persona, barra superior, rutas por
// #hash y dos tipos de vista (módulos de vistas/):
//   · página completa: {pagina(ctx, id), alCambiarId?(id, ctx)}           (inicio, cola de alertas, implementación)
//   · lista + detalle: {cargar(), fila(item), id(item), detalle(id, ctx), filtro(item)} o {pintar(items)} para tablas
// Todas declaran {grupo, titulo, subtitulo, icono, permiso}. El menú solo muestra lo permitido; el servidor vuelve a
// comprobar cada permiso en cada petición (esto no da acceso, solo evita enseñar lo que no se puede usar).
import { api, ErrorApi } from "./api.js";
import { h, icono, vaciar } from "./ui.js";
import { vistas as vAcciones } from "./vistas/acciones.js";
import { vistas as vAvisos } from "./vistas/avisos.js";
import { vistas as vCola } from "./vistas/cola.js";
import { vistas as vImplementacion } from "./vistas/implementacion.js";
import { vistas as vInicio } from "./vistas/inicio.js";
import { vistas as vOperacion } from "./vistas/operacion.js";

// Orden del menú
const TODAS = { ...vInicio, cola: vCola.cola, pendientes: vAcciones.pendientes, ...vAvisos, ...vOperacion,
  abiertas: vAcciones.abiertas, cerradas: vAcciones.cerradas, registro: vAcciones.registro, ...vImplementacion };
const INICIO = "inicio";
const app = document.getElementById("app");
const estado = { persona: null, vistas: {}, el: null, lista: [], filtro: "", vista: null };
let temporizadores = [];

// =============================================================================================== sesión

async function arrancar() {
  try {
    estado.persona = await api.yo();
    montarConsola();
  } catch (e) {
    if (e instanceof ErrorApi && e.estado === 401) pantallaLogin();
    else vaciar(app, h("p", { class: "cargando" }, `No se puede cargar la consola: ${e.message}`));
  }
}

function pararTemporizadores() {
  temporizadores.forEach(clearInterval);
  temporizadores = [];
}

/** Ejecuta una llamada a la API; si la sesión ya no vale, vuelve al login y devuelve null. */
async function llamar(promesa) {
  try {
    return await promesa;
  } catch (e) {
    if (e instanceof ErrorApi && e.estado === 401) {
      pararTemporizadores();
      estado.persona = null;
      pantallaLogin("La sesión ha caducado o se ha cerrado. Vuelve a entrar.");
      return null;
    }
    throw e;
  }
}

function pantallaLogin(mensaje = "") {
  const usuario = h("input", { class: "campo", id: "usuario", name: "usuario", autocomplete: "username", required: true });
  const password = h("input", { class: "campo", id: "password", name: "password", type: "password",
    autocomplete: "current-password", required: true });
  const error = h("p", { class: "error-form" + (mensaje ? "" : " oculto") }, mensaje);
  const boton = h("button", { class: "boton primario", type: "submit" }, "Entrar");
  const formulario = h("form", {
    onsubmit: async (ev) => {
      ev.preventDefault();
      boton.disabled = true;
      error.classList.add("oculto");
      try {
        estado.persona = await api.login(usuario.value.trim(), password.value);
        montarConsola();
      } catch (e) {
        error.textContent = e.message;
        error.classList.remove("oculto");
        password.value = "";
        password.focus();
      } finally {
        boton.disabled = false;
      }
    },
  },
  h("h2", {}, "Iniciar sesión"),
  h("p", { class: "suave" }, "Acceso para el equipo del SOC."),
  h("label", { for: "usuario" }, "Usuario o email"), usuario,
  h("label", { for: "password" }, "Contraseña"), password,
  error, boton,
  h("p", { class: "nota suave" }, "Demo: usuarios de backend/db/usuarios_soc.sql (n1, n2, responsable, ciso, deteccion)."));

  const niveles = [["Triaje", "Veredicto, severidad y recomendación de cada alerta"],
    ["Criterio", "Correlación, criticidad real y actividad autorizada"],
    ["Investigación", "Cadenas de ataque de varios días, origen y alcance"],
    ["Respuesta", "Contención en la API, siempre con aprobación humana"]];
  vaciar(app, h("main", { class: "login" },
    h("section", { class: "marca-lateral" },
      h("div", { class: "logo" }, h("img", { src: "img/escudo.svg", alt: "" }), "Tarvia SOC"),
      h("div", { class: "lema" },
        h("h1", {}, "Triaje y respuesta asistidos por IA"),
        h("p", {}, "La IA investiga y propone. El código aplica la política. Las personas deciden."),
        h("ul", { class: "niveles" }, niveles.map(([t, d], i) => h("li", {}, h("span", { class: "num" }, String(i + 1)),
          h("div", {}, h("strong", {}, t), h("span", {}, d)))))),
      h("div", { class: "pie" }, "Deloitte × UAB · The Hack 2026 · IA en ciberseguridad")),
    h("section", { class: "formulario-login" }, formulario)));
  usuario.focus();
}

async function salir() {
  try { await api.logout(); } catch { /* se descarta la sesión igualmente */ }
  pararTemporizadores();
  estado.persona = null;
  history.replaceState(null, "", location.pathname);
  pantallaLogin();
}

// =============================================================================================== estructura

function permitido(v, permisos) {
  if (!v.permiso) return true;
  return [].concat(v.permiso).some((p) => permisos[p]);
}

function iniciales(nombre) {
  return nombre.split(/\s+/).filter((x) => /^[\p{L}\d]/u.test(x)).slice(0, 2).map((x) => x[0].toUpperCase()).join("");
}

function montarConsola() {
  const p = estado.persona;
  estado.vistas = Object.fromEntries(Object.entries(TODAS).filter(([, v]) => permitido(v, p.permisos)));
  const contadores = { pendientes: h("span", { class: "contador cero" }, "0"), avisos: h("span", { class: "contador cero" }, "0") };
  const grupos = {};
  for (const [clave, v] of Object.entries(estado.vistas)) {
    (grupos[v.grupo] ||= []).push(h("button", {
      class: "enlace-nav", "data-vista": clave, onclick: () => { location.hash = `#/${clave}`; },
    }, icono(v.icono), h("span", {}, v.titulo), v.contador ? contadores[v.contador] : null));
  }
  const consola = h("div", { class: "consola" });
  const el = {
    consola, contadores, titulo: h("h1", {}), subtitulo: h("div", { class: "subtitulo" }),
    servicios: h("div", { class: "estado-servicios" }), contenido: h("main", { class: "contenido" }),
  };
  vaciar(consola,
    h("aside", { class: "lateral", "aria-label": "Menú" },
      h("div", { class: "logo" }, h("img", { src: "img/escudo.svg", alt: "" }),
        h("div", {}, "Tarvia SOC", h("small", {}, "Consola de respuesta"))),
      h("nav", {}, Object.entries(grupos).map(([g, botones]) => [h("div", { class: "grupo" }, g), botones])),
      h("div", { class: "usuario" }, h("div", { class: "avatar", "aria-hidden": "true" }, iniciales(p.nombre)),
        h("div", {}, h("strong", {}, p.nombre), h("span", {}, p.cargo)),
        h("button", { class: "salir", onclick: salir, title: "Cerrar sesión", "aria-label": "Cerrar sesión" }, icono("salir")))),
    h("div", { class: "velo-menu", onclick: () => consola.classList.remove("menu-abierto") }),
    h("div", { class: "principal-consola" },
      h("header", { class: "barra" },
        h("button", { class: "boton sutil boton-menu", "aria-label": "Menú",
          onclick: () => consola.classList.toggle("menu-abierto") }, icono("menu")),
        h("div", {}, el.titulo, el.subtitulo), el.servicios),
      el.contenido));
  vaciar(app, consola);
  el.enlaces = [...consola.querySelectorAll(".enlace-nav")];
  estado.el = el;
  estado.vista = null;
  window.onhashchange = navegar;
  if (!estado.vistas[ruta().vista] || !location.hash) history.replaceState(null, "", `#/${INICIO}`);
  navegar();
  actualizarContadores();
  comprobarServicios();
  temporizadores.push(setInterval(actualizarContadores, 20000), setInterval(comprobarServicios, 60000));
}

document.addEventListener("keydown", (ev) => {   // Escape cierra el cajón de detalle
  const { vista, id } = ruta();
  if (ev.key === "Escape" && id && estado.vistas[vista] && estado.vistas[vista].alCambiarId) location.hash = `#/${vista}`;
});

function ruta() {
  const [, vista = INICIO, ...resto] = location.hash.split("/");
  return { vista: estado.vistas[vista] ? vista : INICIO, id: decodeURIComponent(resto.join("/")) };
}

const contexto = () => ({
  persona: estado.persona, lista: estado.lista, llamar,
  recargar: async () => {
    const { vista, id } = ruta();
    await cargarLista(vista);
    if (id) await pintarDetalle(vista, id);
    actualizarContadores();
  },
});

async function navegar() {
  if (!estado.persona) return;
  const { vista, id } = ruta();
  const v = estado.vistas[vista];
  const el = estado.el;
  el.consola.classList.remove("menu-abierto");
  el.enlaces.forEach((b) => (b.dataset.vista === vista ? b.setAttribute("aria-current", "page") : b.removeAttribute("aria-current")));
  if (estado.vista === vista && v.alCambiarId) { v.alCambiarId(id, contexto()); return; }
  const mismaLista = estado.vista === vista && !v.pagina;
  estado.vista = vista;
  el.titulo.textContent = v.titulo;
  el.subtitulo.textContent = v.subtitulo || "";
  document.title = `${v.titulo} · Tarvia SOC`;

  if (v.pagina) {
    vaciar(el.contenido, h("div", { class: "vacio" }, "Cargando…"));
    try {
      const nodo = await v.pagina(contexto(), id);
      if (nodo && estado.vista === vista) vaciar(el.contenido, nodo);
    } catch (e) {
      vaciar(el.contenido, h("div", { class: "vacio" }, `No se pudo cargar: ${e.message}`));
    }
    return;
  }
  if (!mismaLista) montarListaDetalle(v);
  await cargarLista(vista);
  if (id && v.detalle) await pintarDetalle(vista, id);
  else vaciar(el.detalle, h("div", { class: "vacio" }, v.ayuda || "Elige un elemento de la lista para ver el detalle."));
}

function montarListaDetalle(v) {
  const el = estado.el;
  estado.filtro = "";
  el.filtroCampo = h("input", { class: "campo", type: "search", placeholder: "Filtrar…", "aria-label": "Filtrar",
    oninput: (ev) => { estado.filtro = ev.target.value.toLowerCase(); pintarLista(); } });
  el.lista = h("ul", { class: "lista", role: "list" });
  el.detalle = h("section", { class: "panel", "aria-label": "Detalle" });
  vaciar(el.contenido, h("div", { class: "cuerpo" },
    h("section", { class: "panel", "aria-label": "Lista" },
      h("div", { class: "titulo" }, h("h2", {}, v.titulo), v.pintar ? null : el.filtroCampo), el.lista),
    el.detalle));
}

async function actualizarContadores() {
  const ver = (clave) => estado.vistas[clave];
  const [pend, avs] = await Promise.all([
    ver("pendientes") ? llamar(api.pendientes()).catch(() => null) : null,
    ver("avisos") ? llamar(api.avisos()).catch(() => null) : null]);
  if (!estado.el) return;
  const poner = (c, n) => { if (n === null) return; c.textContent = String(n); c.classList.toggle("cero", n === 0); };
  poner(estado.el.contadores.pendientes, pend ? pend.length : null);
  poner(estado.el.contadores.avisos, avs ? avs.filter((a) => a.puedo.includes("atender")).length : null);
}

async function comprobarServicios() {
  const s = await api.salud().catch(() => null);
  if (!estado.el) return;
  const chip = (ok, texto) => h("span", { class: `etiqueta ${ok ? "ok" : "mal"}`,
    title: ok ? `${texto}: responde` : `${texto}: no responde` }, `${ok ? "●" : "○"} ${texto}`);
  vaciar(estado.el.servicios, s ? [chip(s.api_soc, "API SOC"), chip(s.db, "BD usuarios")] : chip(false, "backend"));
}

// =============================================================================================== lista + detalle

async function cargarLista(vista) {
  const el = estado.el;
  vaciar(el.lista, h("li", { class: "vacio" }, "Cargando…"));
  try {
    const datos = await llamar(estado.vistas[vista].cargar());
    if (datos === null || ruta().vista !== vista) return;
    estado.lista = datos;
    pintarLista();
  } catch (e) {
    vaciar(el.lista, h("li", { class: "vacio" }, `No se pudo cargar: ${e.message}`));
  }
}

function pintarLista() {
  const { vista, id } = ruta();
  const v = estado.vistas[vista];
  const el = estado.el;
  if (v.pintar) {
    vaciar(el.lista, estado.lista.length ? h("li", {}, v.pintar(estado.lista)) : h("li", { class: "vacio" }, v.vacio));
    return;
  }
  const f = estado.filtro;
  const visibles = estado.lista.filter((x) => !f || (v.filtro ? v.filtro(x) : JSON.stringify(x)).toLowerCase().includes(f));
  if (!visibles.length) {
    vaciar(el.lista, h("li", { class: "vacio" }, f ? "Nada coincide con el filtro." : v.vacio));
    return;
  }
  vaciar(el.lista, visibles.map((x) => {
    const clave = v.id ? v.id(x) : x.id;
    const d = v.fila(x);
    const ir = () => { location.hash = `#/${vista}/${encodeURIComponent(clave)}`; };
    return h("li", {
      class: "fila", tabindex: "0", role: "button", "aria-current": String(clave === id), onclick: ir,
      onkeydown: (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); ir(); } },
    },
    h("span", { class: "icono", "aria-hidden": "true" }, d.icono),
    h("span", { class: "principal" }, d.principal),
    d.chip || h("span", {}),
    h("span", { class: "secundaria" }, d.secundaria));
  }));
}

async function pintarDetalle(vista, id) {
  const el = estado.el;
  vaciar(el.detalle, h("div", { class: "vacio" }, "Cargando…"));
  try {
    const nodo = await estado.vistas[vista].detalle(id, contexto());
    if (nodo && ruta().vista === vista) vaciar(el.detalle, nodo);
  } catch (e) {
    vaciar(el.detalle, h("div", { class: "vacio" }, e.estado === 404 ? "No existe o no tienes acceso." : e.message));
  }
}

arrancar();
