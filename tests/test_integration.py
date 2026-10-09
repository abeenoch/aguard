"""End-to-end integration: real tokens, real Postgres, real logs.

These tests close every loop the project promised:
  human token  -> writes OK, sees own rows only
  agent token  -> reads own tenant, writes rejected BY POSTGRES (not by mocks)
  scripted injection (prompt-shaped SQL) -> dies at the DB permission layer
  logs written during attack traffic -> contain zero fixture PII (canary)

DB note: tests re-run schema.sql per module for a deterministic start.
"""
from __future__ import annotations

import base64
import importlib
import logging
import os
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.db.session import close_pools
from app.oidc.pkce import challenge_s256, generate_verifier

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = PROJECT_ROOT / "app" / "db" / "schema.sql"
REDIRECT = "http://localhost:8000/demo/callback"


def _apply_schema() -> None:
    from app.settings import settings
    if not settings.pg_superuser_password:
        raise RuntimeError(
            "PG_SUPERUSER_PASSWORD not set — copy .env.example to .env "
            "and fill in the superuser password (tests apply schema.sql "
            "as the superuser; application code never does)."
        )
    env = dict(os.environ, PGPASSWORD=settings.pg_superuser_password)
    subprocess.run(
        ["psql", "-U", "postgres", "-h", "localhost", "-d", "agent_auth",
         "-v", "ON_ERROR_STOP=0", "-q", "-f", str(SCHEMA)],
        check=False, env=env, capture_output=True,
    )


@pytest.fixture(scope="module")
def api_client():
    _apply_schema()
    import app.main as main_module
    importlib.reload(main_module)          # fresh stores + redaction installed
    from app.main import app
    with TestClient(app) as tc:
        yield tc
    close_pools()


def _login(tc: TestClient, email: str, password: str) -> None:
    tc.cookies.clear()
    resp = tc.post("/login",
                   data={"email": email, "password": password, "next": "/"},
                   follow_redirects=False)
    assert resp.status_code == 303


def _get_tokens(tc: TestClient, *, client_id: str, secret: str | None,
                email: str, password: str, scope: str) -> dict:
    _login(tc, email, password)
    verifier = generate_verifier()
    challenge = challenge_s256(verifier)
    params = {
        "response_type": "code", "client_id": client_id,
        "redirect_uri": REDIRECT, "scope": scope, "state": "st",
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    assert tc.get("/authorize", params=params).status_code == 200
    data = {"decision": "approve", "client_id": client_id,
            "redirect_uri": REDIRECT, "scope": scope, "state": "st",
            "code_challenge": challenge, "code_challenge_method": "S256"}
    resp = tc.post("/consent", data=data, follow_redirects=False)
    assert resp.status_code == 302, resp.text
    code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]
    payload = {"grant_type": "authorization_code", "code": code,
               "redirect_uri": REDIRECT, "code_verifier": verifier}
    headers: dict = {}
    if secret:
        cred = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
        headers = {"Authorization": f"Basic {cred}"}
    else:
        payload["client_id"] = client_id
    resp = tc.post("/token", data=payload, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# -- human vs agent on the shared API --------------------------------------


def test_human_can_write(api_client):
    tokens = _get_tokens(api_client, client_id="demo-spa", secret=None,
                         email="alice@example.com",
                         password="correct-horse-battery",
                         scope="openid email orders:read orders:write")
    resp = api_client.post("/api/documents",
                           json={"title": "alice note", "body": "hello world"},
                           headers=_auth(tokens["access_token"]))
    assert resp.status_code == 201, resp.text
    assert resp.json()["owner_sub"] == "usr_alice"


def test_human_sees_only_own_rows(api_client):
    tokens = _get_tokens(api_client, client_id="demo-spa", secret=None,
                         email="bob@example.com", password="bob-not-a-real-secret",
                         scope="openid email orders:read orders:write")
    api_client.post("/api/documents", json={"title": "bob note", "body": "x"},
                    headers=_auth(tokens["access_token"]))
    resp = api_client.get("/api/documents", headers=_auth(tokens["access_token"]))
    assert resp.status_code == 200
    owners = {d["owner_sub"] for d in resp.json()["documents"]}
    assert owners == {"usr_bob"}


def test_agent_reads_own_tenant_only(api_client):
    tokens = _get_tokens(api_client, client_id="chat-agent",
                         secret="chat-agent-secret",
                         email="alice@example.com",
                         password="correct-horse-battery",
                         scope="openid email orders:read")
    resp = api_client.get("/api/documents", headers=_auth(tokens["access_token"]))
    assert resp.status_code == 200
    docs = resp.json()["documents"]
    assert docs, "expected alice's rows to be visible to her agent"
    assert {d["owner_sub"] for d in docs} == {"usr_alice"}
    assert "internal_notes" not in str(docs)   # projection hides the column


def test_agent_write_blocked_at_scope_and_db(api_client):
    tokens = _get_tokens(api_client, client_id="chat-agent",
                         secret="chat-agent-secret",
                         email="alice@example.com",
                         password="correct-horse-battery",
                         scope="openid email orders:read")
    resp = api_client.post("/api/documents",
                           json={"title": "pwned", "body": "x"},
                           headers=_auth(tokens["access_token"]))
    # Belt: orders:write missing => 403. Suspenders (proven directly below):
    # even with a write scope the GRANT denial would refuse the INSERT.
    assert resp.status_code == 403


def test_prompt_injection_delete_dies_at_database(api_client):
    """The money test: SQL shaped like a prompt-injection payload goes to the
    agent's session — and Postgres, not application code, says no."""
    import psycopg
    from app.db.session import scoped_session
    payload_title = "x'); DELETE FROM documents; --"
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with scoped_session(kind="agent", sub="usr_alice") as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO documents(owner_sub, title, body) "
                    "VALUES (%s, %s, %s)",
                    ("usr_alice", payload_title, "injection attempt"))
    with scoped_session(kind="agent", sub="usr_alice") as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM agent_documents")
            assert cur.fetchone()[0] >= 1


def test_invalid_token_is_401_missing_scope_is_403(api_client):
    assert api_client.get("/api/documents").status_code == 401
    assert api_client.get(
        "/api/documents",
        headers={"Authorization": "Bearer garbage"}).status_code == 401
    tokens = _get_tokens(api_client, client_id="chat-agent",
                         secret="chat-agent-secret",
                         email="alice@example.com",
                         password="correct-horse-battery",
                         scope="openid email orders:read")
    resp = api_client.post("/api/documents", json={"title": "t", "body": "b"},
                           headers=_auth(tokens["access_token"]))
    assert resp.status_code == 403


# -- the canary: no PII may reach written logs ------------------------------


def test_log_canary_no_pii_in_written_output(api_client, caplog):
    """canary: PII fired through a REAL request must never reach log output.

    Non-vacuous by construction: alice holds orders:write (so logger.info
    EXECUTES — the Phase 1 lesson: a 403 before the log line made the old
    canary pass while asserting nothing), and we assert the record EXISTS.
    """
    tokens = _get_tokens(api_client, client_id="demo-spa", secret=None,
                         email="alice@example.com",
                         password="correct-horse-battery",
                         scope="openid email orders:read orders:write")
    with caplog.at_level(logging.INFO, logger="agent-auth-lab.api"):
        resp = api_client.post(
            "/api/documents",
            json={"title": "call alice@example.com re card "
                           "4111111111111111",
                  "body": "notes"},
            headers=_auth(tokens["access_token"]))
    assert resp.status_code == 201
    api_records = [r for r in caplog.records
                   if r.name == "agent-auth-lab.api"]
    assert api_records, "canary vacuous: no log record was captured"
    dumped = "\n".join(r.getMessage() for r in api_records)
    assert "alice@example.com" not in dumped
    assert "4111111111111111" not in dumped
    assert "email[h:" in dumped          # proof redaction RAN, not absence
    assert "****-****-****-1111" in dumped

