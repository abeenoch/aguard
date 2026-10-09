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

from aguard.settings import settings

_SUB_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")


def _validate_sub(sub: str) -> str:
    """GUC values go into SQL text — allowlist shape, no quoting games."""
    if not _SUB_RE.fullmatch(sub):
        raise ValueError("invalid subject for session binding")
    return sub


_pools: dict[str, ConnectionPool] = {}


_DSN_BY_KIND = {
    "human": lambda: settings.db_dsn_human,
    "agent": lambda: settings.db_dsn_agent,
    "auth": lambda: settings.db_dsn_auth,
}


def get_pool(kind: Literal["human", "agent", "auth"]) -> ConnectionPool:
    pool = _pools.get(kind)
    if pool is None:
        # open=True pins current behavior (lazy open becomes opt-in upstream).
        pool = ConnectionPool(_DSN_BY_KIND[kind](), min_size=1, max_size=10,
                              open=True, kwargs={"autocommit": False})
        _pools[kind] = pool
    return pool


@contextmanager
def service_session(*, statement_timeout_ms: int = 5000,
                    acquire_timeout_ms: int | None = None):
    """Authorization-server session: the auth_service role, no tenant subject.

    Deliberately NOT scoped_session — the AS is not a tenant, so there is no
    app.sub to bind. It reaches only the token tables (auth_service holds no
    grants on documents/agent_audit). That asymmetry is the point: a
    compromised AS session cannot read tenant data, and a compromised tenant
    session cannot read or forge token state.

    acquire_timeout_ms bounds the wait for a POOLED connection, which is a
    different clock from statement_timeout: that one only starts once a
    connection exists. Without this, a caller asking "is the database up?"
    while it is down waits out the pool default (~30s) — so a readiness probe
    that must answer promptly passes a short value here.
    """
    pool = get_pool("auth")
    with pool.connection(
        timeout=None if acquire_timeout_ms is None else acquire_timeout_ms / 1000
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('statement_timeout', %s, true)",
                        (str(statement_timeout_ms),))
            cur.execute("SET LOCAL ROLE auth_service")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


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


__all__ = ["get_pool", "scoped_session", "service_session", "close_pools"]
