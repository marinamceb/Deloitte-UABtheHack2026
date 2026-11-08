// Llamadas a la API del backend (/api). La sesión va en una cookie HttpOnly del mismo origen: el JS no la ve.
// Los POST siempre en JSON (el backend rechaza otros formatos: protección CSRF).

export class ErrorApi extends Error {
  constructor(estado, mensaje) {
    super(mensaje);
    this.estado = estado;
  }
}

function mensajeDe(datos, estado) {
  const d = datos && datos.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map((e) => e.msg || JSON.stringify(e)).join("; ");   // validación (422)
  return `Error ${estado}`;
}

async function llamar(ruta, metodo = "GET", cuerpo) {
  const opciones = { method: metodo, headers: { Accept: "application/json" }, credentials: "same-origin" };
  if (metodo !== "GET") {
    opciones.headers["Content-Type"] = "application/json";
    opciones.body = JSON.stringify(cuerpo || {});
  }
  let respuesta;
  try {
    respuesta = await fetch(`/api${ruta}`, opciones);
  } catch {
    throw new ErrorApi(0, "No se puede contactar con el servidor");
  }
  let datos = null;
  try { datos = await respuesta.json(); } catch { /* sin cuerpo JSON */ }
  if (!respuesta.ok) throw new ErrorApi(respuesta.status, mensajeDe(datos, respuesta.status));
  return datos;
}

export const api = {
  login: (usuario, password) => llamar("/login", "POST", { usuario, password }),
  logout: () => llamar("/logout", "POST"),
  yo: () => llamar("/yo"),
  salud: () => llamar("/salud"),
  pendientes: () => llamar("/acciones/pendientes"),
  acciones: (estados) => llamar(`/acciones${estados ? `?estado=${encodeURIComponent(estados)}` : ""}`),
  accion: (id) => llamar(`/acciones/${encodeURIComponent(id)}`),
  aprobar: (id, comentario, enNombreDe = "") =>
    llamar(`/acciones/${encodeURIComponent(id)}/aprobar`, "POST", { comentario, en_nombre_de: enNombreDe }),
  rechazar: (id, comentario) => llamar(`/acciones/${encodeURIComponent(id)}/rechazar`, "POST", { comentario }),
  hecha: (id, comentario) => llamar(`/acciones/${encodeURIComponent(id)}/hecha`, "POST", { comentario }),
  reintentar: (id) => llamar(`/acciones/${encodeURIComponent(id)}/reintentar`, "POST", {}),
  sincronizar: () => llamar("/acciones/sincronizar", "POST"),
  registro: () => llamar("/contencion/registro"),
  avisos: () => llamar("/avisos"),
  atenderAviso: (id, comentario) => llamar(`/avisos/${encodeURIComponent(id)}/atender`, "POST", { comentario }),
  cola: (limite = 100) => llamar(`/cola?limite=${limite}`),
  alerta: (id) => llamar(`/alertas/${encodeURIComponent(id)}`),
  tickets: () => llamar("/tickets"),
  ticket: (id) => llamar(`/tickets/${encodeURIComponent(id)}`),
  informes: () => llamar("/informes"),
  informe: (id) => llamar(`/informes/${encodeURIComponent(id)}`),
  resumen: () => llamar("/resumen"),
  recibirAlertas: (alertas) => llamar("/alertas", "POST", { alertas }),
  recibidas: () => llamar("/alertas/recibidas"),
  catalogo: () => llamar("/catalogo"),
  triar: (id) => llamar(`/alertas/${encodeURIComponent(id)}/triar`, "POST", {}),
  investigar: (ids, llm = false, forzar = false) => llamar("/investigar", "POST", { ids, llm, forzar }),
  trabajos: () => llamar("/trabajos"),
};
