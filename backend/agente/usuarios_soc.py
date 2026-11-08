"""[Nivel 4 · personas] Usuarios de la consola del SOC: nuestro equipo, no el directorio de la empresa monitorizada.

Tabla `users` en PostgreSQL (DATABASE_URL), definida y sembrada por db/usuarios_soc.sql con un usuario de ejemplo por
rol. En Docker la crea el contenedor «db» al inicializarse; `inicializar()` (lo llama el backend al arrancar) vuelve a
ejecutar el mismo script, que es idempotente, por si la base ya existía.

⚠ Demo: las contraseñas están en claro en la tabla. La comparación es en tiempo constante (hmac.compare_digest) y la
respuesta es la misma si el usuario no existe o la contraseña no coincide, pero eso no sustituye a un hash con sal
(argon2/bcrypt) o al SSO en producción.

Acceso a datos en tres funciones (_buscar, _marcar_login, _todos): es lo que sustituyen los tests sin base de datos.
"""
import hmac

import psycopg
from psycopg.rows import dict_row

from . import config

SQL = config.BACKEND / "db" / "usuarios_soc.sql"
CARGO = {"N1": "Analista SOC N1", "N2": "Analista SOC N2", "responsable_soc": "Responsable SOC", "ciso": "CISO",
         "deteccion": "Ingeniería de detección"}
COLUMNAS = "id, usuario, email, nombre, rol, password, turno, telefono, ultimo_login"


class BaseDeDatosNoDisponible(RuntimeError):
    """PostgreSQL no responde (¿está arrancado el contenedor «db»? ¿DATABASE_URL es correcta?)."""


def _conectar() -> psycopg.Connection:
    try:
        return psycopg.connect(config.DATABASE_URL, row_factory=dict_row, connect_timeout=5)
    except psycopg.OperationalError as e:
        raise BaseDeDatosNoDisponible(f"No se puede conectar a PostgreSQL ({config.DATABASE_URL_SIN_CLAVE}): "
                                      f"{str(e).strip().splitlines()[0]}") from e


def inicializar() -> int:
    """Crea la tabla y los usuarios de ejemplo si faltan. Devuelve cuántos usuarios hay."""
    with _conectar() as con:
        con.execute(SQL.read_text(encoding="utf-8"))
        return con.execute("SELECT count(*) AS n FROM users").fetchone()["n"]


# --------------------------------------------------------------------------------------------- acceso a datos

def _buscar(clave: str) -> dict | None:
    """Fila activa cuyo usuario o email coincide (sin distinguir mayúsculas)."""
    with _conectar() as con:
        return con.execute(f"SELECT {COLUMNAS} FROM users WHERE activo AND (lower(usuario) = %s OR lower(email) = %s)",
                           (clave, clave)).fetchone()


def _marcar_login(id_usuario: int) -> None:
    with _conectar() as con:
        con.execute("UPDATE users SET ultimo_login = now() WHERE id = %s", (id_usuario,))


def _todos() -> list[dict]:
    with _conectar() as con:
        return con.execute(f"SELECT {COLUMNAS} FROM users WHERE activo ORDER BY id").fetchall()


# --------------------------------------------------------------------------------------------- consultas

def _persona(fila: dict) -> dict:
    """Formato común de una persona con sesión (sin la contraseña): lo usan roles.py, acciones.py y la web."""
    previo = fila.get("ultimo_login")
    return {"usuario": fila["usuario"], "email": fila["email"].lower(), "nombre": fila["nombre"],
            "cargo": CARGO.get(fila["rol"], fila["rol"]), "roles": [fila["rol"]], "turno": fila["turno"],
            "telefono": fila["telefono"],
            "ultimo_login": previo.isoformat() if hasattr(previo, "isoformat") else previo}


def autenticar(usuario_o_email: str, password: str) -> dict | None:
    """Persona si el usuario existe, está activo y la contraseña coincide; None en cualquier otro caso."""
    fila = _buscar((usuario_o_email or "").strip().lower())
    if fila is None or not hmac.compare_digest(fila["password"].encode(), (password or "").encode()):
        return None
    _marcar_login(fila["id"])
    return _persona(fila)


def por_email(usuario_o_email: str) -> dict | None:
    """Persona activa (para revalidar la sesión en cada petición, sin contraseña)."""
    fila = _buscar((usuario_o_email or "").strip().lower())
    return _persona(fila) if fila else None


def listar() -> list[dict]:
    return [_persona(f) for f in _todos()]
