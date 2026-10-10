"""Shared (multi-worker) rate limiting and client-registry bounds.

The in-process limiter in tests/test_rate_limit.py is correct for ONE process:
with N workers the real ceiling is N x the configured count, because each
worker counts only what it sees. These tests cover the two places that made
a *horizontally scaled* deployment unsound, and prove the seam actually
delivers what the Protocol promises:

  * PostgresRateLimiter — two separate instances (two workers) that share the
    database must agree on ONE count. That is the entire point; an instance
    pair that each enforced its own limit would be no better than memory.
  * ClientRegistry — dynamic registrations are capped (rate limiting bounds
    the RATE of /register, not the total), and concurrent registrations cannot
    race a duplicate id past the check.

Postgres-backed cases skip cleanly when the token tables are absent, exactly
as tests/test_stores_persistence.py does — a shared feature must not make the
suite red on a machine without a database.
"""
from __future__ import annotations

import threading

import pytest

from aguard.db.session import close_pools, service_session
from aguard.oidc.clients import MAX_DYNAMIC_CLIENTS, Client, ClientRegistry
from aguard.ratelimit import PostgresRateLimiter, RateLimit


def _postgres_ready() -> bool:
    try:
        with service_session(statement_timeout_ms=1000) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM rate_limit_buckets LIMIT 1")
        return True
    except Exception:
        close_pools()
        return False


def _require_postgres() -> None:
    if not _postgres_ready():
        pytest.skip("rate_limit_buckets missing — apply aguard/db/schema.sql")


def _clear(key: str) -> None:
    with service_session() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM rate_limit_buckets WHERE bucket_key = %s",
                        (key,))


# --- shared counters ------------------------------------------------------

def test_two_workers_share_one_count():
    """Two limiter instances (two workers) must enforce a single limit.

    If each counted independently, an attacker splitting guesses across
    workers would get N x the allowance — the exact failure the shared
    backend exists to remove. We alternate hits between the instances and
    require that only `limit` of them are ever allowed.
    """
    _require_postgres()
    policy = "token"
    key = "ip:shared-count-test"
    limit = 3
    _clear(key)

    # Two independent instances == two processes with the same DB.
    w1 = PostgresRateLimiter({policy: RateLimit(limit, 60)})
    w2 = PostgresRateLimiter({policy: RateLimit(limit, 60)})

    try:
        allowed = sum(
            (w1 if i % 2 == 0 else w2).hit(policy, key).allowed
            for i in range(limit + 2)
        )
        assert allowed == limit, "workers must share ONE count, not N x limit"
    finally:
        _clear(key)


def test_decision_fields_are_exact():
    """remaining counts down; a denial reports a non-zero retry_after."""
    _require_postgres()
    policy = "token"
    key = "ip:fields-test"
    _clear(key)

    limiter = PostgresRateLimiter({policy: RateLimit(2, 60)})
    try:
        first = limiter.hit(policy, key)
        assert first.allowed and first.remaining == 1 and first.retry_after == 0
        second = limiter.hit(policy, key)
        assert second.allowed and second.remaining == 0
        third = limiter.hit(policy, key)
        assert not third.allowed
        assert third.remaining == 0
        assert third.retry_after >= 1  # "Retry-After: 0" invites instant retry
    finally:
        _clear(key)


def test_shared_limiter_fails_open_when_database_is_down():
    """Availability over enforcement: a DB outage must not deny every request.

    The limiter is a capacity control, not an authorizer — every request it
    guards still does real auth. Failing closed would turn a database blip
    into a full outage of the endpoints it protects, so it fails open (and
    logs, which the redaction layer catches).
    """
    import aguard.db.session as session

    # Simulate the database being down at the exact point the limiter reaches
    # for a connection. service_session is imported inside hit(), so replacing
    # the module attribute makes the limiter's next call raise — the same path
    # a real outage takes, without needing to actually kill a server.
    def _boom():
        raise RuntimeError("simulated database outage")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(session, "service_session", _boom)
    try:
        limiter = PostgresRateLimiter({"token": RateLimit(1, 60)})
        decision = limiter.hit("token", "ip:unreachable")
        assert decision.allowed, "a limiter outage must not deny traffic"
        assert decision.retry_after == 0
    finally:
        monkeypatch.undo()


# --- client-registry bounds ----------------------------------------------

def _client(client_id: str) -> Client:
    return Client(
        client_id=client_id,
        client_secret_hash=None,
        redirect_uris=(),
        allowed_scopes=frozenset(),
        grant_types=frozenset(),
        auth_method="none",
        kind="agent",
    )


def test_seeded_clients_survive_a_dynamic_registration_flood():
    """The ceiling evicts dynamic registrations, never seeded ones.

    Rate limiting bounds how fast /register can be called, not the running
    total — so a long-lived process needs a cap. That cap must not be able to
    evict the seeded lab clients the rest of the system depends on.
    """
    registry = ClientRegistry()
    registry.seed(_client("demo-spa"))
    registry.seed(_client("cli-agent"))

    for i in range(MAX_DYNAMIC_CLIENTS + 5):
        registry.register(_client(f"dyn-{i}"))

    assert registry.get("demo-spa") is not None
    assert registry.get("cli-agent") is not None
    # the oldest dynamic ones were evicted; the newest remain
    assert registry.get("dyn-0") is None
    assert registry.get(f"dyn-{MAX_DYNAMIC_CLIENTS + 4}") is not None


def test_concurrent_duplicate_registration_cannot_both_succeed():
    """The duplicate-id check must hold under concurrency (no TOCTOU)."""
    registry = ClientRegistry()
    errors: list[Exception] = []
    barrier = threading.Barrier(8)

    def attempt() -> None:
        barrier.wait()
        try:
            registry.register(_client("raced"))
        except ValueError as exc:      # the loser(s)
            errors.append(exc)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # exactly one winner: every other racer must have been rejected
    assert len(errors) == 7
    assert registry.get("raced") is not None
