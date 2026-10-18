import os

from psycopg2.pool import PoolError, ThreadedConnectionPool


class StorageUnavailableError(RuntimeError):
    pass


class Pools:
    def __init__(self) -> None:
        self.ops: ThreadedConnectionPool | None = None
        self.answers_write: ThreadedConnectionPool | None = None
        self.answers_admin: ThreadedConnectionPool | None = None


POOLS = Pools()


def _env_int(name: str, default: int) -> int:
    raw = (os.environ.get(name, "") or "").strip()
    if not raw:
        return default
    return int(raw)


def _pool_limits(prefix: str, default_min: int, default_max: int) -> tuple[int, int]:
    pool_min = _env_int(f"{prefix}_POOL_MIN", default_min)
    pool_max = _env_int(f"{prefix}_POOL_MAX", default_max)
    if pool_min < 1:
        raise RuntimeError(f"{prefix}_POOL_MIN must be >= 1")
    if pool_max < pool_min:
        raise RuntimeError(f"{prefix}_POOL_MAX must be >= {prefix}_POOL_MIN")
    return pool_min, pool_max


def _pool_from_env(prefix: str, *, default_max: int = 10) -> ThreadedConnectionPool:
    user = os.environ[f"{prefix}_USER"]
    password = os.environ[f"{prefix}_PASS"]
    dbname = os.environ[f"{prefix}_NAME"]
    pool_min, pool_max = _pool_limits(prefix, 1, default_max)

    host = os.environ.get(f"{prefix}_HOST", "127.0.0.1")
    port = int(os.environ.get(f"{prefix}_PORT", "5432"))
    return ThreadedConnectionPool(
        pool_min,
        pool_max,
        user=user,
        password=password,
        dbname=dbname,
        host=host,
        port=port,
        connect_timeout=10,
        sslmode=os.environ.get(f"{prefix}_SSLMODE", "prefer"),
    )


def init_pools(*, include_admin_pools: bool = True) -> None:
    if POOLS.ops is None:
        POOLS.ops = _pool_from_env("OPS_DB", default_max=10)
    if os.environ.get("ANSWERS_DB_WRITE_USER") and POOLS.answers_write is None:
        POOLS.answers_write = _pool_from_env("ANSWERS_DB_WRITE", default_max=10)

    if not include_admin_pools:
        return

    if os.environ.get("ANSWERS_DB_ADMIN_USER") and POOLS.answers_admin is None:
        POOLS.answers_admin = _pool_from_env("ANSWERS_DB_ADMIN", default_max=5)


def _get_conn(pool: ThreadedConnectionPool | None, name: str):
    if pool is None:
        raise StorageUnavailableError(f"{name} pool not configured")
    try:
        return pool.getconn()
    except PoolError as e:
        raise StorageUnavailableError(f"{name} pool exhausted") from e


def _put_conn(pool: ThreadedConnectionPool | None, conn, name: str) -> None:
    if pool is None:
        raise StorageUnavailableError(f"{name} pool not configured")
    pool.putconn(conn)


def get_ops():
    return _get_conn(POOLS.ops, "ops")


def put_ops(conn):
    _put_conn(POOLS.ops, conn, "ops")


def get_answers_write():
    return _get_conn(POOLS.answers_write, "answers_write")


def put_answers_write(conn):
    _put_conn(POOLS.answers_write, conn, "answers_write")


def get_answers_admin():
    return _get_conn(POOLS.answers_admin, "answers_admin")


def put_answers_admin(conn):
    _put_conn(POOLS.answers_admin, conn, "answers_admin")
