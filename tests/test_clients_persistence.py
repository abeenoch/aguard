"""Seeded clients in Postgres (E2): the database owns the credential.

Pins the contract that makes rotation without a redeploy possible: seeding is
idempotent across boots, the STORED row beats the env default (so a rotated
secret survives a restart), the CLI rotation changes what the registry
accepts, and public clients refuse rotation.
"""
from __future__ import annotations

import re

import pytest

from aguard import cli as agctl
from aguard.db.session import close_pools, service_session
from aguard.oidc.clients import (
    Client,
    ClientRegistry,
    PostgresClientRegistry,
    hash_secret,
    seed_registry,
)

SEED_IDS = ("demo-spa", "demo-conf", "cli-agent", "chat-agent")


def _postgres_ready() -> bool:
    try:
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM clients LIMIT 1")
        return True
    except Exception:
        close_pools()
        return False


def _clear() -> None:
    with service_session() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM clients")
            cur.execute("DELETE FROM dynamic_clients")


@pytest.fixture
def clean_clients():
    if not _postgres_ready():
        pytest.skip("clients table missing — apply aguard/db/schema.sql")
    _clear()
    yield
    _clear()
    close_pools()


def _client(client_id: str = "cli-agent", secret: str | None = "cli-agent-secret") -> Client:
    return Client(
        client_id=client_id,
        client_secret_hash=hash_secret(secret) if secret else None,
        redirect_uris=(),
        allowed_scopes=frozenset({"orders:read"}),
        grant_types=frozenset({"client_credentials"}),
        auth_method="client_secret_basic" if secret else "none",
        kind="agent")


# ------------------------------- seeding -----------------------------------


def test_seed_is_idempotent_across_boots(clean_clients):
    r1 = PostgresClientRegistry()
    r1.seed(_client())
    r2 = PostgresClientRegistry()           # a restart: re-reads from the DB
    r2.seed(_client())                      # same env default again — no raise
    assert r2.authenticate("cli-agent", "cli-agent-secret", "client_secret_basic")


def test_seed_registry_installs_all_fixtures(clean_clients):
    registry = seed_registry(PostgresClientRegistry())
    for client_id in SEED_IDS:
        assert registry.get(client_id) is not None
    with service_session() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM clients")
            assert cur.fetchone()[0] == len(SEED_IDS)


def test_stored_row_beats_env_default(clean_clients):
    """A rotated secret must survive restarts; the env default must NOT win."""
    PostgresClientRegistry().seed(_client())
    with service_session() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE clients SET client_secret_hash = %s"
                        " WHERE client_id = 'cli-agent'",
                        (hash_secret("rotated-secret"),))
    r2 = PostgresClientRegistry()           # boots after the rotation
    r2.seed(_client(secret="cli-agent-secret"))   # stale env default
    assert r2.authenticate("cli-agent", "rotated-secret", "client_secret_basic")
    assert not r2.authenticate("cli-agent", "cli-agent-secret",
                               "client_secret_basic")


def test_memory_registry_seeding_unchanged():
    """The in-memory backend keeps its strict semantics — no silent coupling."""
    registry = seed_registry(ClientRegistry())
    assert registry.get("cli-agent") is not None
    with pytest.raises(ValueError):
        registry.seed(_client())            # duplicate still raises in memory


# --------------------------- CLI: clients ----------------------------------


def test_cli_list_shows_clients_never_hashes(clean_clients, capsys):
    seed_registry(PostgresClientRegistry())
    assert agctl.main(["clients", "list"]) == 0
    out = capsys.readouterr().out
    for client_id in SEED_IDS:
        assert client_id in out
    assert hash_secret("cli-agent-secret") not in out
    assert "demo-conf-secret" not in out


def test_cli_list_json(clean_clients, capsys):
    seed_registry(PostgresClientRegistry())
    assert agctl.main(["clients", "list", "--json"]) == 0
    import json
    records = json.loads(capsys.readouterr().out)
    assert {r["client_id"] for r in records} == set(SEED_IDS)
    assert all(r["confidential"] == (r["client_id"] != "demo-spa")
               for r in records)


def test_cli_rotate_changes_the_accepted_secret(clean_clients, capsys):
    PostgresClientRegistry().seed(_client())
    assert agctl.main(["clients", "rotate", "cli-agent"]) == 0
    out = capsys.readouterr().out
    match = re.search(r"^([A-Za-z0-9_-]{43})$", out, re.MULTILINE)
    assert match, f"no one-line secret in output: {out!r}"
    new_secret = match.group(1)
    assert out.count(new_secret) == 1       # printed exactly once, never twice
    r2 = PostgresClientRegistry()           # the AS restarts
    assert r2.authenticate("cli-agent", new_secret, "client_secret_basic")
    assert not r2.authenticate("cli-agent", "cli-agent-secret",
                               "client_secret_basic")


def test_cli_rotate_refuses_unknown_client(clean_clients, capsys):
    seed_registry(PostgresClientRegistry())
    assert agctl.main(["clients", "rotate", "no-such-client"]) == 2
    assert "no such seeded client" in capsys.readouterr().err


def test_cli_rotate_refuses_public_client(clean_clients, capsys):
    seed_registry(PostgresClientRegistry())
    assert agctl.main(["clients", "rotate", "demo-spa"]) == 2
    assert "PUBLIC client" in capsys.readouterr().err
