"""Scoped pooled sessions: per-transaction SET LOCAL role + RLS GUCs.

The one guarantee everything rests on: SET LOCAL reverts at COMMIT/ROLLBACK
by Postgres itself — including on error paths the app never sees. The pool
therefore CANNOT hand a dirty elevated session to the next borrower.

Two pools, two logins (settings.db_dsn_human / db_dsn_agent): the human pool
can never produce an agent session and vice versa, because each login is a
member of exactly one data role.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from typing import Literal

from psycopg_pool import ConnectionPool

from app.settings import settings

_SUB_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")


def _validate_sub(sub: str) -> str:
    """GUC values go into SQL text — allowlist shape, no quoting games."""
    if not _SUB_RE.fullmatch(sub):
        raise ValueError("invalid subject for session binding")
    return sub


_pools: dict[str, ConnectionPool] = {}


def get_pool(kind: Literal["human", "agent"]) -> ConnectionPool:
    pool = _pools.get(kind)
    if pool is None:
        dsn = settings.db_dsn_human if kind == "human" else settings.db_dsn_agent
        # open=True pins current behavior (lazy open becomes opt-in upstream).
        pool = ConnectionPool(dsn, min_size=1, max_size=10, open=True,
                              kwargs={"autocommit": False})
        _pools[kind] = pool
    return pool


@contextmanager
def scoped_session(*, kind: Literal["human", "agent"], sub: str,
                   role_override: Literal["app_user", "agent_readonly",
                                          "human_admin"] | None = None,
                   statement_timeout_ms: int = 5000):
    """Yield a connection locked to (data role, app.sub, app.role) for one
    transaction. COMMIT on success, ROLLBACK on error — both reset the GUCs.

    role_override exists ONLY for narrow tests/admin paths; production callers
    pass kind and let the token's roles claim pick the pool.
    """
    role = role_override or ("app_user" if kind == "human" else "agent_readonly")
    app_role = "human_admin" if role == "human_admin" else (
        "human" if kind == "human" else "agent")
    pool = get_pool(kind)
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('statement_timeout', %s, true)",
                        (str(statement_timeout_ms),))
            cur.execute("SET LOCAL ROLE %s" % role)
            cur.execute("SELECT set_config('app.sub', %s, true)",
                        (_validate_sub(sub),))
            cur.execute("SELECT set_config('app.role', %s, true)", (app_role,))
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def close_pools() -> None:
    for pool in _pools.values():
        pool.close()
    _pools.clear()


__all__ = ["get_pool", "scoped_session", "close_pools"]
