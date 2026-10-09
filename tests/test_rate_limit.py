"""Rate limiting: the limiter itself, and its effect on the three endpoints.

Split deliberately:

  * unit tests drive InMemoryRateLimiter directly with ``now`` injected, so
    window boundaries are tested exactly instead of by sleeping.
  * integration tests swap a strict limiter into ``app.state.rate_limiter`` and
    go through the real ASGI app, so what is verified is the wiring (a limiter
    that works but was never called on /login is not protection).

The app is a module-level singleton shared with every other test module, so
every swap is restored in a finally block. A leaked strict limiter would fail
unrelated tests later in the run — the kind of cross-test coupling that makes a
suite untrustworthy.
"""
from __future__ import annotations

import dataclasses
import threading
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

import aguard.main as main_module
import aguard.ratelimit as ratelimit_module
from aguard.db.session import service_session
from aguard.main import app
from aguard.ratelimit import (
    InMemoryRateLimiter,
    RateLimit,
    _identity_key,
    build_rate_limiter,
    default_policies,
)

client = TestClient(app)

#: Peak concurrency for the race test. High enough that an unsynchronised
#: read-then-append reliably overshoots the limit, low enough to stay fast.
_RACE_THREADS = 64


@contextmanager
def _strict_limiter(**policies: int):
    """Install a limiter with the given per-minute limits for one test.

    Every policy the endpoint under test consults must be listed: an unknown
    policy raises rather than being skipped, because a rate limit that
    silently disappears when it is misconfigured is not a rate limit.
    """
    original = app.state.rate_limiter
    app.state.rate_limiter = InMemoryRateLimiter(
        {name: RateLimit(limit, 60) for name, limit in policies.items()},
        max_keys=1000,
    )
    try:
        yield app.state.rate_limiter
    finally:
        app.state.rate_limiter = original


def _database_available() -> bool:
    """True when the auth pool can reach Postgres (readiness needs it)."""
    try:
        with service_session(statement_timeout_ms=1000) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        return True
    except Exception:
        return False


def _token_attempt(*, headers: dict[str, str] | None = None):
    """An unauthenticated /token POST: only the limiter's status code matters.

    Without a limiter this is a 401 (no client credentials), which is what
    makes a 429 on the second call unambiguous evidence that the limiter ran
    first — before client authentication, let alone the grant itself.
    """
    return client.post(
        "/token",
        data={"grant_type": "authorization_code", "code": "not-a-real-code"},
        headers=headers or {},
    )


def _login_attempt(email: str = "alice@example.com"):
    """A wrong-password /login POST: 401 when the limiter lets it through."""
    return client.post(
        "/login",
        data={"email": email, "password": "definitely-wrong", "next": "/"},
    )


def _register_attempt():
    return client.post(
        "/register",
        json={"redirect_uris": ["https://rate-limit-test.example/callback"]},
    )


def _settings_with(**changes):
    """Settings is a frozen dataclass, so tests replace, never mutate."""
    return dataclasses.replace(ratelimit_module.settings, **changes)


# --- the limiter itself ---------------------------------------------------

def _limiter(limit: int = 2, window: int = 10, max_keys: int = 100):
    return InMemoryRateLimiter({"p": RateLimit(limit, window)},
                               max_keys=max_keys)


def test_allows_exactly_the_limit_then_refuses():
    limiter = _limiter(limit=3)
    assert [limiter.hit("p", "k", now=0).allowed for _ in range(3)] == [True] * 3
    decision = limiter.hit("p", "k", now=0)
    assert decision.allowed is False
    assert decision.remaining == 0
    assert decision.limit == 3


def test_retry_after_counts_down_to_the_second():
    limiter = _limiter(limit=1, window=10)
    assert limiter.hit("p", "k", now=0).allowed
    assert limiter.hit("p", "k", now=1).retry_after == 9
    assert limiter.hit("p", "k", now=7).retry_after == 3
    # Floored at 1: "Retry-After: 0" invites an immediate retry.
    assert limiter.hit("p", "k", now=9.999).retry_after == 1
    assert limiter.hit("p", "k", now=10).allowed


def test_window_slides_rather_than_resetting_on_a_boundary():
    """A fixed window would hand out 2x the limit across the boundary."""
    limiter = _limiter(limit=2, window=10)
    assert limiter.hit("p", "k", now=0).allowed
    assert limiter.hit("p", "k", now=9).allowed
    # Both earlier attempts are still inside the window at t=9.5.
    assert limiter.hit("p", "k", now=9.5).allowed is False
    # t=10.1 retires the attempt from t=0: exactly one slot frees up.
    assert limiter.hit("p", "k", now=10.1).allowed is True
    assert limiter.hit("p", "k", now=10.2).allowed is False


def test_keys_and_policies_do_not_share_a_budget():
    limiter = InMemoryRateLimiter({"p": RateLimit(1, 10),
                                   "q": RateLimit(1, 10)})
    assert limiter.hit("p", "k", now=0).allowed is True
    assert limiter.hit("p", "k", now=0).allowed is False
    assert limiter.hit("q", "k", now=0).allowed is True       # other policy
    assert limiter.hit("p", "other", now=0).allowed is True    # other key
    assert limiter.tracked_keys == 3


def test_unknown_policy_is_an_error_not_a_free_pass():
    with pytest.raises(ValueError, match="unknown rate-limit policy"):
        _limiter().hit("nope", "k", now=0)


def test_invalid_configuration_fails_at_construction():
    with pytest.raises(ValueError):
        RateLimit(0, 60)
    with pytest.raises(ValueError):
        RateLimit(1, 0)
    with pytest.raises(ValueError):
        InMemoryRateLimiter({})


def test_key_cap_bounds_memory_under_key_rotation():
    limiter = _limiter(limit=5, max_keys=8)
    for i in range(50):
        limiter.hit("p", f"k{i}", now=0)
    assert limiter.tracked_keys <= 8


def test_concurrent_attempts_cannot_overshoot_the_limit():
    """check-then-append must be atomic: sync endpoints run in a threadpool."""
    limiter = InMemoryRateLimiter({"p": RateLimit(50, 60)}, max_keys=10)
    verdicts: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(_RACE_THREADS)

    def attempt() -> None:
        barrier.wait(timeout=10)               # maximise genuine overlap
        decision = limiter.hit("p", "same-key")
        with lock:
            verdicts.append(decision.allowed)

    threads = [threading.Thread(target=attempt) for _ in range(_RACE_THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert len(verdicts) == _RACE_THREADS
    assert sum(verdicts) == 50, f"{sum(verdicts)} allowed, expected exactly 50"


def test_identity_keys_are_hashed_not_stored_in_the_clear():
    """A memory dump must not enumerate the accounts being attacked."""
    key = _identity_key("account", "alice@example.com")
    assert "alice@example.com" not in key
    assert key.startswith("account:")
    assert len(key) == len("account:") + 32
    # Length is not a lever for inflating the key space.
    assert len(_identity_key("account", "x" * 100_000)) == len(key)


def test_build_rate_limiter_refuses_an_unimplemented_backend(monkeypatch):
    """Naming a shared backend must fail loudly, not quietly mean memory."""
    monkeypatch.setattr(ratelimit_module, "settings",
                        _settings_with(rate_limit_backend="postgres"))
    with pytest.raises(ValueError, match="not implemented yet"):
        build_rate_limiter()


def test_build_rate_limiter_rejects_an_unknown_backend(monkeypatch):
    monkeypatch.setattr(ratelimit_module, "settings",
                        _settings_with(rate_limit_backend="redis"))
    with pytest.raises(ValueError, match="unknown RATE_LIMIT_BACKEND"):
        build_rate_limiter()


def test_build_rate_limiter_yields_the_interface_a_store_backend_will_use():
    limiter = build_rate_limiter()
    assert isinstance(limiter, InMemoryRateLimiter)      # Protocol is structural
    for name in ("token", "login", "login_account", "register"):
        assert limiter.policy(name).limit >= 1


def test_policy_counts_come_from_settings():
    policies = default_policies()
    assert policies["token"].limit == ratelimit_module.settings.rate_limit_token
    assert policies["register"].window_seconds == 3600


# --- the endpoints --------------------------------------------------------

def test_token_is_rate_limited_with_an_oauth_shaped_429():
    with _strict_limiter(token=1):
        assert _token_attempt().status_code == 401        # allowed through
        blocked = _token_attempt()

    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1
    # RFC 6749 §5.2 vocabulary, and no caching of a rate-limit answer.
    assert blocked.json()["error"] == "temporarily_unavailable"
    assert blocked.headers["cache-control"] == "no-store"


def test_login_is_rate_limited_with_a_page_a_human_can_read():
    with _strict_limiter(login=1, login_account=1000):
        assert _login_attempt().status_code == 401
        blocked = _login_attempt()

    assert blocked.status_code == 429
    assert blocked.headers["content-type"].startswith("text/html")
    assert "Too many attempts" in blocked.text
    assert int(blocked.headers["retry-after"]) >= 1


def test_register_is_rate_limited_before_a_client_is_created():
    with _strict_limiter(register=1):
        created = _register_attempt()
        blocked = _register_attempt()

    assert created.status_code == 201
    assert blocked.status_code == 429
    assert blocked.json()["error"] == "temporarily_unavailable"


def test_login_account_limit_is_independent_of_the_source_address():
    """The per-address limit cannot see a botnet; the per-account one can."""
    with _strict_limiter(login=1000, login_account=1):
        first = _login_attempt("alice@example.com")       # spends alice's slot
        alice_again = _login_attempt("alice@example.com")
        bob = _login_attempt("bob@example.com")

    assert first.status_code == 401
    assert alice_again.status_code == 429
    assert bob.status_code == 401        # a different account is unaffected


def test_refusal_does_not_reveal_whether_the_account_exists():
    with _strict_limiter(login=1000, login_account=1):
        _login_attempt("alice@example.com")
        known = _login_attempt("alice@example.com")
        _login_attempt("nobody@example.com")
        unknown = _login_attempt("nobody@example.com")

    assert known.status_code == unknown.status_code == 429
    for response in (known, unknown):
        assert "alice" not in response.text
        assert "nobody" not in response.text


def test_spoofed_x_forwarded_for_does_not_buy_a_fresh_budget():
    """The header is client-supplied, so the default must ignore it."""
    with _strict_limiter(token=1):
        first = _token_attempt(headers={"X-Forwarded-For": "203.0.113.1"})
        spoofed = _token_attempt(headers={"X-Forwarded-For": "203.0.113.99"})

    assert first.status_code == 401
    assert spoofed.status_code == 429


def test_x_forwarded_for_is_honoured_only_when_explicitly_trusted(monkeypatch):
    monkeypatch.setattr(ratelimit_module, "settings",
                        _settings_with(rate_limit_trust_forwarded_for=True))
    with _strict_limiter(token=1):
        behind_proxy = _token_attempt(
            headers={"X-Forwarded-For": "203.0.113.1, 10.0.0.1"})
        another_client = _token_attempt(
            headers={"X-Forwarded-For": "203.0.113.2, 10.0.0.1"})

    assert behind_proxy.status_code == 401
    # Distinct clients behind the proxy get distinct budgets...
    assert another_client.status_code == 401


def test_limits_are_not_consulted_when_a_policy_is_missing():
    """Fail loudly rather than quietly skipping the check (a silent no-op
    limiter is worse than none, because it is believed)."""
    with _strict_limiter(token=1, login=1, login_account=1, register=1):
        app.state.rate_limiter = InMemoryRateLimiter({"unrelated": RateLimit(1, 60)})
        with pytest.raises(ValueError, match="unknown rate-limit policy"):
            _token_attempt()


# --- readiness vs liveness ------------------------------------------------

def test_readyz_reports_ready_when_dependencies_are_up():
    if not _database_available():
        pytest.skip("Postgres is not reachable; /readyz checks it by design")
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready",
                               "checks": {"keys": "ok", "database": "ok"}}
    assert response.headers["cache-control"] == "no-store"


def test_readyz_fails_while_liveness_stays_up(monkeypatch):
    """Separating the two probes is the point: a dead dependency must hold
    traffic back (503) without getting the process restarted (200)."""
    def unreachable(*_args, **_kwargs):
        raise RuntimeError("simulated: connection refused to 127.0.0.1:5432")

    monkeypatch.setattr(main_module, "service_session", unreachable)

    assert client.get("/healthz").status_code == 200
    failed = client.get("/readyz")
    assert failed.status_code == 503
    assert failed.json() == {"status": "not_ready",
                            "checks": {"keys": "ok", "database": "error"}}
    # Details belong in the (redacted) log, never in an unauthenticated body.
    assert "refused" not in failed.text


