"""The SHARED rate limiter: the multi-worker property the in-memory one lacks.

The whole reason ``PostgresRateLimiter`` exists is that per-process counters
enforce N x the configured limit when N workers run. These tests pin that
exactly: two separate limiter instances (which is precisely what two workers
are) must agree on ONE count, and a spent limit must still be spent when the
next worker asks.

Gated on the database the same way tests/test_stores_persistence.py is: the
table is created by aguard/db/schema.sql, so without it these tests skip
rather than fail — a missing table is an environment state, not a regression.
"""
from __future__ import annotations

import pytest

from aguard.db.session import close_pools, service_session
from aguard.ratelimit import POSTGRES, RateLimit, build_rate_limiter


def _postgres_ready() -> bool:
    try:
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM rate_limit_buckets LIMIT 1")
        return True
    except Exception:
        close_pools()
        return False


def _require_postgres() -> None:
    if not _postgres_ready():
        pytest.skip("rate_limit_buckets missing — apply aguard/db/schema.sql")


@pytest.fixture()
def pg_limiter():
    _require_postgres()
    from aguard.ratelimit import PostgresRateLimiter

    return PostgresRateLimiter({"token": RateLimit(limit=3, window_seconds=60)})


def _clear(*keys: str) -> None:
    with service_session() as conn:
        with conn.cursor() as cur:
            for key in keys:
                cur.execute("DELETE FROM rate_limit_buckets WHERE bucket_key = %s",
                            (key,))


def test_shared_limit_spans_two_instances(pg_limiter):
    """Two limiters = two workers. They must share ONE budget of 3.

    This is the property InMemoryRateLimiter cannot offer: with per-process
    counters each of these would get its own 3, so 6 attempts would pass.
    """
    from aguard.ratelimit import PostgresRateLimiter

    key = "ip:shared_two_workers"
    _clear(key)
    try:
        # a SECOND instance standing in for a second worker
        other = PostgresRateLimiter(
            {"token": RateLimit(limit=3, window_seconds=60)})

        decisions = []
        for i in range(4):
            limiter = pg_limiter if i % 2 == 0 else other  # alternate workers
            decisions.append(limiter.hit("token", key))

        assert [d.allowed for d in decisions] == [True, True, True, False], (
            "the 4th attempt must be denied even though it hit a different "
            "worker: the count is shared")
        # remaining decrements across the shared count, then floors at 0
        assert [d.remaining for d in decisions[:3]] == [2, 1, 0]
        assert decisions[3].remaining == 0
        assert decisions[3].retry_after >= 1
    finally:
        _clear(key)


def test_shared_limit_rolls_the_window(pg_limiter):
    """Fixed window: once it passes, the allowance returns — exactly once.

    ``base`` is aligned to the 60s window boundary on purpose: a fixed window
    keys on ``int(now) // window * window``, so a mid-window base would make
    ``base+59`` fall into the NEXT window and silently test the wrong thing.
    """
    key = "ip:shared_roll"
    base = 60 * 83_334          # exactly on a window boundary (5_000_040)
    _clear(key)
    try:
        for _ in range(3):
            assert pg_limiter.hit("token", key, now=base).allowed
        assert not pg_limiter.hit("token", key, now=base + 1).allowed

        # still inside the same window: the budget stays spent
        assert not pg_limiter.hit("token", key, now=base + 59).allowed
        # past the window: a fresh allowance, granted exactly once more
        assert pg_limiter.hit("token", key, now=base + 61).allowed
    finally:
        _clear(key)


def test_shared_tracked_keys_counts_live_identities(pg_limiter):
    """tracked_keys must report live identities (ops/metrics), not all rows."""
    keys = ["ip:track_a", "ip:track_b"]
    _clear(*keys)
    try:
        before = pg_limiter.tracked_keys
        for key in keys:
            pg_limiter.hit("token", key)  # real time = live window
        assert pg_limiter.tracked_keys >= before + 2
    finally:
        _clear(*keys)


def test_shared_limiter_fails_open_on_db_error(pg_limiter):
    """A limiter outage must not become the outage it exists to prevent."""
    close_pools()  # force the next connection to fail
    try:
        decision = pg_limiter.hit("token", "ip:db_down")
        assert decision.allowed, "an unreachable counter store must fail OPEN"
    finally:
        close_pools()


def test_unknown_backend_is_rejected(monkeypatch):
    """A typo'd backend must fail loudly at construction, not silently
    degrade to per-process counters.

    ``settings`` is a frozen dataclass, so the override replaces the module's
    ``settings`` name (dataclasses.replace returns a copy) rather than mutating
    the singleton every other module reads.
    """
    import dataclasses

    import aguard.ratelimit as rl

    monkeypatch.setattr(
        rl, "settings",
        dataclasses.replace(rl.settings, rate_limit_backend="redis"))
    with pytest.raises(ValueError, match="unknown RATE_LIMIT_BACKEND"):
        build_rate_limiter()


def test_postgres_backend_builds_the_shared_limiter(monkeypatch):
    """The switch must actually select the shared implementation."""
    import dataclasses

    import aguard.ratelimit as rl

    monkeypatch.setattr(
        rl, "settings",
        dataclasses.replace(rl.settings, rate_limit_backend=POSTGRES))
    assert isinstance(build_rate_limiter(), rl.PostgresRateLimiter)
