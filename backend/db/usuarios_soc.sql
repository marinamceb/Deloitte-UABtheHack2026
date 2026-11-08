-- Usuarios de la consola del SOC (nuestro equipo), separados del directorio de Tarvia (usuarios.csv, la empresa que
-- monitorizamos). PostgreSQL.
--   · Docker: el contenedor «db» lo ejecuta al crear la base (/docker-entrypoint-initdb.d/).
--   · Además el backend lo vuelve a ejecutar al arrancar (es idempotente), por si la base ya existía.
--
-- ⚠ SOLO PARA LA DEMO: las contraseñas están en claro. En producción: hash con sal (argon2/bcrypt) o, mejor, SSO.
--
-- Roles (de menos a más; cada uno puede todo lo del anterior al aprobar):
--   N1               triaje; ejecuta lo que la política permite al N1 (bloquear IOC maliciosos, purgar correos)
--   N2               aprueba acciones disruptivas (aislar, deshabilitar cuentas, claves cloud...) y registra la
--                    aprobación de los responsables de servicio de la empresa
--   responsable_soc  todo lo anterior; decide cuando un servicio no tiene responsable registrado
--   ciso             todo lo anterior
--   deteccion        ingeniería de detección: solo lectura

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    usuario       VARCHAR(50)  NOT NULL UNIQUE,                 -- nombre de login
    email         VARCHAR(120) NOT NULL UNIQUE,
    nombre        VARCHAR(120) NOT NULL,
    rol           VARCHAR(20)  NOT NULL CHECK (rol IN ('N1', 'N2', 'responsable_soc', 'ciso', 'deteccion')),
    password      VARCHAR(100) NOT NULL,                        -- EN CLARO: solo demo
    activo        BOOLEAN      NOT NULL DEFAULT TRUE,
    turno         VARCHAR(20)  NOT NULL DEFAULT 'L-V 8-20',     -- 'guardia' = localizable fuera de horario
    telefono      VARCHAR(20),                                  -- escalado crítico por teléfono (SLA, apartado 3)
    creado        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    ultimo_login  TIMESTAMPTZ
);

-- Búsqueda por login sin distinguir mayúsculas (usuario o email)
CREATE UNIQUE INDEX IF NOT EXISTS users_usuario_lower ON users (lower(usuario));
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower ON users (lower(email));

-- Un usuario de ejemplo por rol
INSERT INTO users (usuario, email, nombre, rol, password, turno, telefono) VALUES
    ('n1',          'n1@soc.example',          'Analista N1 (demo)',     'N1',              'n1demo',   'L-V 8-20', '+34 600 000 001'),
    ('n2',          'n2@soc.example',          'Analista N2 (demo)',     'N2',              'n2demo',   'guardia',  '+34 600 000 002'),
    ('responsable', 'responsable@soc.example', 'Responsable SOC (demo)', 'responsable_soc', 'rsocdemo', 'L-V 8-20', '+34 600 000 003'),
    ('ciso',        'ciso@soc.example',        'CISO (demo)',            'ciso',            'cisodemo', 'L-V 8-20', '+34 600 000 004'),
    ('deteccion',   'deteccion@soc.example',   'Detección (demo)',       'deteccion',       'detdemo',  'L-V 8-20', NULL)
ON CONFLICT (usuario) DO NOTHING;
