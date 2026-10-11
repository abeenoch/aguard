"""Persistent stores: the state that makes replay and theft DETECTABLE.

Single-use code tombstones and refresh-family revocation are SECURITY state, not
cache. These tests pin two things: that the shared backend behaves like the
in-memory one, and that it keeps working across store *instances* — i.e. across
a restart or a second worker, which is exactly where per-process state fails.
"""
from __future__ import annotations

import pytest

from aguard.db.session import close_pools, service_session
from aguard.oidc.codes import (
    CodeError,
    CodeReplayError,
    InMemoryAuthCodeStore,
    PostgresAuthCodeStore,
)
from aguard.oidc.refresh import (
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
        pytest.skip("token tables missing — apply aguard/db/schema.sql")


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


def test_owner_of_reports_the_issuing_client_in_every_state(backend):
    """Revocation must work on a token the client has already rotated AWAY
    from (that is the post-theft case), so ownership has to be readable in
    every state. It answers only ownership — never usability — so it is not a
    validity oracle."""
    store = REFRESHERS[backend]()
    raw, _ = store.issue(client_id="demo-spa", subject="usr_alice", scope="openid")
    assert store.owner_of(raw) == "demo-spa"
    assert store.owner_of("unknown-token") is None

    raw2, _ = store.rotate(raw, client_id="demo-spa")
    assert store.owner_of(raw) == "demo-spa"        # retired, still owned
    assert store.owner_of(raw2) == "demo-spa"

    store.revoke_by_raw(raw2)
    assert store.peek(raw2) is None                 # revoked: no longer usable...
    assert store.owner_of(raw2) == "demo-spa"       # ...ownership is unchanged


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



# --------------- client registry: a DCR client survives a restart ----------


def _require_dynamic_clients() -> None:
    try:
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM dynamic_clients LIMIT 1")
    except Exception:
        close_pools()
        pytest.skip("dynamic_clients table missing — apply aguard/db/schema.sql")


def _clear_clients() -> None:
    with service_session() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM dynamic_clients")


def test_dynamic_clients_survive_a_restart():
    """A DCR client (RFC 7591) is state a THIRD PARTY holds.

    The host registers ONCE and caches the client_id, then presents it on every
    later /authorize and /token call. Held in process memory only, a restart (or
    a deploy, or a second worker) invalidates it and the host shows an
    un-fixable `invalid_client`. Postgres is what makes the registration outlive
    the process.
    """
    from aguard.oidc.clients import Client, PostgresClientRegistry

    _require_dynamic_clients()
    _clear_clients()

    redirect = "http://127.0.0.1:1456/mcp/oauth/callback"
    PostgresClientRegistry().register(Client(
        client_id="dcr-persist-test",
        client_secret_hash=None,
        redirect_uris=(redirect,),
        allowed_scopes=frozenset({"openid", "email"}),
        grant_types=frozenset({"authorization_code", "refresh_token"}),
        auth_method="none",
        kind="human",
    ))

    # A fresh instance stands in for the restarted / redeployed process.
    reborn = PostgresClientRegistry()
    got = reborn.get("dcr-persist-test")
    assert got is not None, "the dynamic client did not survive the restart"
    assert got.redirect_uris == (redirect,)
    assert got.allowed_scopes == frozenset({"openid", "email"})
    assert got.redirect_uri_matches(redirect)

    _clear_clients()


def test_inmemory_registry_loses_clients_across_instances():
    """Documents the gap the Postgres registry closes, so nobody 'optimises' it
    away: the in-memory registry is per-process by construction."""
    from aguard.oidc.clients import Client, ClientRegistry

    ClientRegistry().register(Client(
        client_id="dcr-volatile",
        client_secret_hash=None,
        redirect_uris=("http://127.0.0.1:1/cb",),
        allowed_scopes=frozenset({"openid"}),
        grant_types=frozenset({"authorization_code"}),
        auth_method="none",
        kind="human",
    ))
    assert ClientRegistry().get("dcr-volatile") is None

