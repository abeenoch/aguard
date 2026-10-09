"""Persistent stores: the state that makes replay and theft DETECTABLE.

Single-use code tombstones and refresh-family revocation are SECURITY state, not
cache. These tests pin two things: that the shared backend behaves like the
in-memory one, and that it keeps working across store *instances* — i.e. across
a restart or a second worker, which is exactly where per-process state fails.
"""
from __future__ import annotations

import pytest

from app.db.session import close_pools, service_session
from app.oidc.codes import (
    CodeError,
    CodeReplayError,
    InMemoryAuthCodeStore,
    PostgresAuthCodeStore,
)
from app.oidc.refresh import (
    InMemoryRefreshTokenStore,
    PostgresRefreshTokenStore,
    RefreshError,
    RefreshReuseError,
)

CODERS = {"memory": InMemoryAuthCodeStore, "postgres": PostgresAuthCodeStore}
REFRESHERS = {"memory": InMemoryRefreshTokenStore,
              "postgres": PostgresRefreshTokenStore}


def _postgres_ready() -> bool:
    try:
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM auth_codes LIMIT 1")
        return True
    except Exception:
        close_pools()
        return False


def _require_postgres() -> None:
    if not _postgres_ready():
        pytest.skip("token tables missing — apply app/db/schema.sql")


def _clear_tables() -> None:
    with service_session() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM auth_codes")
            cur.execute("DELETE FROM refresh_tokens")


@pytest.fixture(params=["memory", "postgres"])
def backend(request):
    name = request.param
    if name == "postgres":
        _require_postgres()
        _clear_tables()
    yield name
    close_pools()


def _issue_code(store):
    return store.issue(client_id="demo-spa", redirect_uri="http://x/cb",
                       subject="usr_alice", scope="openid",
                       code_challenge="abc", code_challenge_method="S256",
                       nonce="n", resource="http://localhost:8000/mcp")


# ------------------------------- auth codes --------------------------------


def test_code_single_use_and_replay_detected(backend):
    store = CODERS[backend]()
    raw = _issue_code(store)
    record = store.redeem(raw)
    assert record.subject == "usr_alice"
    assert record.resource == "http://localhost:8000/mcp"
    with pytest.raises(CodeReplayError):
        store.redeem(raw)          # detected, not a silent "unknown"


def test_unknown_and_expired_codes(backend):
    store = CODERS[backend]()
    with pytest.raises(CodeError):
        store.redeem("not-a-code")
    expired = CODERS[backend](ttl_seconds=0)
    with pytest.raises(CodeError):
        expired.redeem(_issue_code(expired))


# ----------------------------- refresh tokens ------------------------------


def test_rotation_and_family_burn(backend):
    store = REFRESHERS[backend]()
    raw1, rec1 = store.issue(client_id="demo-spa", subject="usr_alice",
                             scope="openid")
    raw2, rec2 = store.rotate(raw1, client_id="demo-spa")
    assert rec2.family_id == rec1.family_id
    assert store.peek(raw2) is not None
    with pytest.raises(RefreshReuseError):
        store.rotate(raw1, client_id="demo-spa")
    # the family burns whole — including the successor the legit client holds
    assert store.peek(raw2) is None


def test_revocation_and_unknown_token(backend):
    store = REFRESHERS[backend]()
    raw, _ = store.issue(client_id="demo-spa", subject="usr_alice", scope="openid")
    assert store.revoke_by_raw(raw) is True
    assert store.peek(raw) is None
    with pytest.raises(RefreshError):
        store.rotate(raw, client_id="demo-spa")
    assert store.revoke_by_raw("unknown-token") is False   # no validity oracle


def test_wrong_client_is_not_a_family_kill(backend):
    store = REFRESHERS[backend]()
    raw, _ = store.issue(client_id="demo-spa", subject="usr_alice", scope="openid")
    with pytest.raises(RefreshError) as excinfo:
        store.rotate(raw, client_id="demo-other")
    assert not isinstance(excinfo.value, RefreshReuseError)
    assert store.peek(raw) is not None        # still usable by the right client


# ------------------ why the shared backend exists at all -------------------


def test_postgres_code_survives_a_new_store_instance():
    """A second worker redeems what the first issued — and the first still
    sees the tombstone."""
    _require_postgres()
    _clear_tables()
    worker_a, worker_b = PostgresAuthCodeStore(), PostgresAuthCodeStore()
    raw = _issue_code(worker_a)
    assert worker_b.redeem(raw).subject == "usr_alice"
    with pytest.raises(CodeReplayError):
        worker_a.redeem(raw)


def test_postgres_reuse_detection_spans_store_instances():
    """The payoff: a stolen refresh token rotated against a DIFFERENT worker
    still burns the family."""
    _require_postgres()
    _clear_tables()
    worker_a, worker_b = PostgresRefreshTokenStore(), PostgresRefreshTokenStore()
    raw1, _ = worker_a.issue(client_id="demo-spa", subject="usr_alice",
                             scope="openid")
    raw2, _ = worker_b.rotate(raw1, client_id="demo-spa")
    with pytest.raises(RefreshReuseError):
        worker_a.rotate(raw1, client_id="demo-spa")   # thief, other worker
    assert worker_a.peek(raw2) is None                # family burned, cross-process


def test_inmemory_reuse_detection_does_NOT_span_instances():
    """Documents the exact gap the shared backend closes — and fails loudly if
    anyone ever 'optimises' the Postgres store back into process memory."""
    worker_a, worker_b = InMemoryRefreshTokenStore(), InMemoryRefreshTokenStore()
    raw1, _ = worker_a.issue(client_id="demo-spa", subject="usr_alice",
                             scope="openid")
    with pytest.raises(RefreshError) as excinfo:
        worker_b.rotate(raw1, client_id="demo-spa")
    # worker_b never issued it, so it cannot tell "stolen" from "unknown":
    # the family is NOT burned. That failure mode is asserted, not implied.
    assert not isinstance(excinfo.value, RefreshReuseError)

