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

Nivel 3 · Investigación: (en curso; plan en propuesta.txt: rastreo por saltos, cronología, alcance, relación con
    otros incidentes, informe_incidente.schema.json)
    indice.py            [infraestructura] copia local de los logs descargada POR LA API e índice de entidades
                         (SQLite en salidas/); misma búsqueda exacta que la API, en todas las fuentes y en ms

Nivel 4 · Respuesta: proponer contención y ejecutarla con aprobación humana
    contencion.py        aprobación humana y ejecución en la API simulada
    politica.py          quién aprueba cada acción, nada sobre OT, uso dual, IOC sin bloquear  (_aprobaciones,
                         _bloqueos_pendientes)

Común: comun.py (fechas en Europe/Madrid, inventario, entidades de una alerta, formato de hallazgos)

Pruebas: tests/nivel1, tests/nivel2, tests/nivel3 (pytest) y tests/evaluacion (aciertos sobre casos verificados).
"""
