"""Agente de triaje del SOC de Tarvia. Módulos agrupados por el nivel del reto (README.md) que implementan.

Nivel 1 · Triaje básico: entender, enriquecer, veredicto, severidad y recomendación (cerrar o escalar)
    triaje.py            orquesta el triaje de una alerta (integra también los niveles 2 y 4)
    cola.py              cola priorizada: severidad estimada sin LLM (matriz + inventario) y plazo del SLA
    motores.py           conexión con el LLM (Gemini/compatibles OpenAI o Claude)
    prompts.py           prompt de sistema (política + empresa) y contexto de la regla (catálogo + runbook)
    modelos.py           esquema de la salida del modelo (TicketTriaje)
    herramientas.py      consultas del modelo a la API simulada, búsqueda exacta y traza
    reglas_internas.py   las 7 reglas internas de empresa_tarvia.md comprobadas por código
    preinvestigacion.py  [optimización] consultas básicas hechas por código antes del LLM
    plantillas.py        [optimización] reutiliza el veredicto en alertas de ruido con patrón idéntico
    politica.py          escalado obligatorio y SLA; no dar por buena una regla incumplida  (_no_dar_por_buena…,
                         _preguntar_datos_faltantes, _escalado_y_sla)

Nivel 2 · Triaje con criterio: correlación, matriz con la criticidad real, descartar con argumentos lo autorizado
    incidentes.py        agrupa alertas del mismo ataque (entidades exactas 72 h; entidades fuertes 14 días; ruido
                         excluido; actividad autorizada aparte) y avisa si otro ticket comparte una entidad fuerte
    severidad.py         matriz de severidad, criticidad real (CMDB, servicios) y ajustes verificados
    cambios.py           cruce con el calendario de cambios aprobados (ventana, origen, alcance)
    contexto.py          RRHH (viajes, teletrabajo, vacaciones, bajas, altas) y líneas base (origen habitual del
                         usuario, relé Private Relay, prevalencia de dominios, CDN)
    (tests/evaluacion/   casos verificados y script que mide aciertos: veredicto, severidad, escalado, agrupación)
    politica.py          un benign_true_positive debe citar qué lo autoriza  (_exigir_argumento)

Nivel 3 · Investigación: reconstruir la cadena de ataque (aunque dure días), con origen, alcance y relación con otros
    incidentes; informe en el formato de informe_incidente.schema.json
    indice.py            [infraestructura] copia local de los logs descargada POR LA API e índice de entidades
                         (SQLite en salidas/); misma búsqueda exacta que la API, en todas las fuentes y en ms
    investigacion.py     rastreo por saltos desde las alertas (con pivote al origen habitual de una credencial),
                         señales por evento (alerta, ioc, raro, operación rara, origen nuevo), niveles núcleo/pivote,
                         cronología agrupada con MITRE, candidatos a acceso inicial, alcance, relacionados y huecos
    informe.py           el LLM interpreta los hechos y redacta; el código verifica IDs, pone fechas/MITRE, aplica la
                         política a la contención y añade las notificaciones obligatorias (DPO/AEPD 72 h, CISO...)
    motores.py, prompts.py, modelos.py  (InformeLLM, INSTRUCCIONES_INFORME; el motor acepta cualquier esquema)

Nivel 4 · Respuesta: proponer contención y ejecutarla con aprobación humana
    acciones.py          solicitudes de contención: aprobaciones por rol (cuatro ojos), estados, ejecución en la API
                         simulada sin repetir, tareas manuales, historial; lo usan el CLI y la web
    roles.py             rol de cada persona a partir de su ficha del directorio (login por email, sin contraseña)
    contencion.py        interfaz de texto de acciones.py (--pendientes EMAIL, --aprobar --aprobador EMAIL)
    ../servidor/         consola web (FastAPI): login por email, sesión firmada, rol comprobado en cada ruta
    politica.py          quién aprueba cada acción (requisitos), nada sobre OT, uso dual, IOC sin bloquear  (aprobar_acciones,
                         bloqueos_pendientes)

Común: config.py (rutas y URL de la API), api.py (CMDB, identidades, TIP, sandbox y cambios por la API, con caché y
    traza), almacen.py (tickets e informes guardados en salidas/), comun.py (fechas en Europe/Madrid, tablas de
    referencia que la API no ofrece, entidades de una alerta, formato de hallazgos)

Pruebas: tests/nivel1, tests/nivel2, tests/nivel3, tests/nivel4 (pytest) y tests/evaluacion (aciertos sobre casos verificados).
"""
