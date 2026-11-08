"""[Nivel 4] Tabla `users` real en PostgreSQL (db/usuarios_soc.sql + agente/usuarios_soc.py).

Necesita PostgreSQL en DATABASE_URL (p. ej. `docker compose up -d db`); si no responde, se salta. Usa los usuarios
de ejemplo y deja todo como estaba (solo actualiza su `ultimo_login`)."""
import psycopg
import pytest

from agente import config, usuarios_soc


def _postgres_disponible() -> bool:
    try:
        with psycopg.connect(config.DATABASE_URL, connect_timeout=2):
            return True
    except psycopg.OperationalError:
        return False


pytestmark = pytest.mark.skipif(not _postgres_disponible(),
                                reason=f"PostgreSQL no disponible en {config.DATABASE_URL_SIN_CLAVE}")


def _sql(consulta: str, *params):
    with psycopg.connect(config.DATABASE_URL) as con:
        return con.execute(consulta, params).fetchall() if consulta.lstrip().upper().startswith("SELECT") \
            else con.execute(consulta, params)


def test_script_idempotente_con_un_usuario_por_rol():
    usuarios_soc.inicializar()
    n = usuarios_soc.inicializar()                       # segunda vez: ni error ni duplicados
    roles = {u["roles"][0] for u in usuarios_soc.listar()}
    assert n >= 5 and {"N1", "N2", "responsable_soc", "ciso", "deteccion"} <= roles


def test_login_contra_postgres():
    p = usuarios_soc.autenticar("N2@soc.example", "n2demo")
    assert p["usuario"] == "n2" and p["roles"] == ["N2"] and "password" not in p
    assert usuarios_soc.autenticar("n2", "N2DEMO") is None and usuarios_soc.autenticar("nadie", "x") is None
    assert _sql("SELECT ultimo_login IS NOT NULL FROM users WHERE usuario = %s", "n2")[0][0]


def test_cuenta_desactivada_no_entra():
    try:
        _sql("UPDATE users SET activo = FALSE WHERE usuario = %s", "n1")
        assert usuarios_soc.por_email("n1@soc.example") is None
        assert usuarios_soc.autenticar("n1", "n1demo") is None
    finally:
        _sql("UPDATE users SET activo = TRUE WHERE usuario = %s", "n1")
    assert usuarios_soc.por_email("n1")["roles"] == ["N1"]


def test_restricciones_de_la_tabla():
    with pytest.raises(psycopg.errors.CheckViolation):            # rol fuera de la lista
        _sql("INSERT INTO users (usuario, email, nombre, rol, password) VALUES "
             "('x', 'x@soc.example', 'X', 'admin', 'x')")
    with pytest.raises(psycopg.errors.UniqueViolation):           # email repetido aunque cambien las mayúsculas
        _sql("INSERT INTO users (usuario, email, nombre, rol, password) VALUES "
             "('otro', 'N1@SOC.example', 'X', 'N1', 'x')")
