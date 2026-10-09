"""Store selection: the one place that decides where authorization state lives.

Why a factory rather than constructing stores in main.py: the choice has a
SECURITY consequence, not just an operational one. Single-use code tombstones
and refresh-family revocation are precisely the state that makes replay and
token theft *detectable*. If that state is per-process, a replay (or a stolen
refresh token) served by a different worker is silently accepted. So the
backend is an explicit, documented decision rather than an incidental one.

    STORE_BACKEND=memory    single process (default; zero setup for dev)
    STORE_BACKEND=postgres  shared + restart-durable; required for >1 worker
"""
from __future__ import annotations

from aguard.oidc.codes import (
    AuthCodeStore,
    InMemoryAuthCodeStore,
    PostgresAuthCodeStore,
)
from aguard.oidc.refresh import (
    InMemoryRefreshTokenStore,
    PostgresRefreshTokenStore,
    RefreshTokenStore,
)
from aguard.settings import settings

MEMORY = "memory"
POSTGRES = "postgres"


def build_stores() -> tuple[AuthCodeStore, RefreshTokenStore]:
    backend = settings.store_backend
    if backend == MEMORY:
        return InMemoryAuthCodeStore(), InMemoryRefreshTokenStore()
    if backend == POSTGRES:
        return PostgresAuthCodeStore(), PostgresRefreshTokenStore()
    raise ValueError(
        f"unknown STORE_BACKEND {backend!r} "
        f"(expected {MEMORY!r} or {POSTGRES!r})")


def stores_are_shared() -> bool:
    """True when authorization state is visible across processes.

    Anything that asserts "safe for multiple workers" should gate on this
    rather than on a comment."""
    return settings.store_backend == POSTGRES
