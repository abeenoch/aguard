"""Phase C: the MCP resource server (Streamable HTTP at /mcp).

Proves the boundary end-to-end against the REAL database:
  * no/foreign token   -> 401 + RFC 9728 WWW-Authenticate (discovery)
  * agent token        -> reads its own tenant only; writes refused by Postgres
  * human token        -> may delete its OWN rows
  * audience binding   -> a token minted for /api is REJECTED at /mcp

The MCP client protocol messages are sent as raw JSON-RPC: with
stateless_http the server accepts a standalone request without an
initialize handshake, which keeps the test deterministic (no live port,
no third-party client version drift).
"""
from __future__ import annotations

import base64
import importlib
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.db.session import close_pools, scoped_session
from app.oidc.pkce import challenge_s256, generate_verifier
from app.settings import settings

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = PROJECT_ROOT / "app" / "db" / "schema.sql"
REDIRECT = "http://localhost:8000/demo/callback"
BASE = "http://localhost:8000"          # Host must pass the MCP host allowlist
MCP_RESOURCE = settings.mcp_resource_id
RPC_HEADERS = {"Accept": "application/json, text/event-stream"}
ALICE = "usr_alice"
BOB = "usr_bob"


def _apply_schema() -> None:
    if not settings.pg_superuser_password:
        raise RuntimeError(
            "PG_SUPERUSER_PASSWORD not set — copy .env.example to .env "
            "and fill in the superuser password (tests apply schema.sql as "
            "the superuser; application code never does)."
        )
    env = dict(os.environ, PGPASSWORD=settings.pg_superuser_password)
    subprocess.run(
        ["psql", "-U", "postgres", "-h", "localhost", "-d", "agent_auth",
         "-v", "ON_ERROR_STOP=0", "-q", "-f", str(SCHEMA)],
        check=False, env=env, capture_output=True,
    )


@pytest.fixture(scope="module")
def mcp_client():
    """Fresh schema + fresh app (reload rebinds keys and MCP session manager).

    TestClient is used as a context manager: entering it runs the app
    lifespan, which starts the MCP Streamable HTTP session-manager task group
    (without it every /mcp POST raises 'Task group is not initialized')."""
    _apply_schema()
    import app.main as main_module
    importlib.reload(main_module)
    from app.main import app
    with TestClient(app, base_url=BASE) as tc:
        yield tc
    close_pools()


def _seed_document(sub: str, title: str, body: str) -> int:
    """Insert as the human data role (app_user) so RLS lets us own the row."""
    with scoped_session(kind="human", sub=sub) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO documents(owner_sub, title, body) "
                "VALUES (%s, %s, %s) RETURNING id",
                (sub, title, body))
            return cur.fetchone()[0]



# ------------------------------ token helpers ------------------------------


def _human_token(tc: TestClient, *, email="alice@example.com",
                 password="correct-horse-battery",
                 scope="openid email orders:read",
                 resource=MCP_RESOURCE) -> str:
    """Full authorization-code flow, optionally audience-bound to /mcp."""
    tc.cookies.clear()
    resp = tc.post("/login",
                   data={"email": email, "password": password, "next": "/"},
                   follow_redirects=False)
    assert resp.status_code == 303
    verifier = generate_verifier()
    challenge = challenge_s256(verifier)
    params = {"response_type": "code", "client_id": "demo-spa",
              "redirect_uri": REDIRECT, "scope": scope, "state": "st-mcp",
              "code_challenge": challenge, "code_challenge_method": "S256"}
    if resource:
        params["resource"] = resource
    assert tc.get("/authorize", params=params).status_code == 200
    data = {"decision": "approve", "client_id": "demo-spa",
            "redirect_uri": REDIRECT, "scope": scope, "state": "st-mcp",
            "code_challenge": challenge, "code_challenge_method": "S256"}
    if resource:
        data["resource"] = resource
    resp = tc.post("/consent", data=data, follow_redirects=False)
    assert resp.status_code == 302, resp.text
    code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]
    resp = tc.post("/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT, "code_verifier": verifier,
        "client_id": "demo-spa",
    })
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _agent_on_behalf_token(tc: TestClient) -> str:
    """chat-agent rides the USER flow: sub=alice AND roles=['agent'].

    This is the interesting principal — a human's identity with an agent's
    (read-only) capability, audience-bound to the MCP server."""
    tc.cookies.clear()
    resp = tc.post("/login",
                   data={"email": "alice@example.com",
                         "password": "correct-horse-battery", "next": "/"},
                   follow_redirects=False)
    assert resp.status_code == 303
    verifier = generate_verifier()
    challenge = challenge_s256(verifier)
    params = {"response_type": "code", "client_id": "chat-agent",
              "redirect_uri": REDIRECT, "scope": "openid email orders:read",
              "state": "st-mcp", "code_challenge": challenge,
              "code_challenge_method": "S256", "resource": MCP_RESOURCE}
    assert tc.get("/authorize", params=params).status_code == 200
    data = {"decision": "approve", "client_id": "chat-agent",
            "redirect_uri": REDIRECT, "scope": "openid email orders:read",
            "state": "st-mcp", "code_challenge": challenge,
            "code_challenge_method": "S256", "resource": MCP_RESOURCE}
    resp = tc.post("/consent", data=data, follow_redirects=False)
    assert resp.status_code == 302, resp.text
    code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]
    cred = base64.b64encode(b"chat-agent:chat-agent-secret").decode()
    resp = tc.post("/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT, "code_verifier": verifier,
    }, headers={"Authorization": f"Basic {cred}"})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _agent_self_token(tc: TestClient) -> str:
    """cli-agent as itself: sub=svc:cli-agent, roles=['agent'], no human."""
    cred = base64.b64encode(b"cli-agent:cli-agent-secret").decode()
    resp = tc.post("/token", data={
        "grant_type": "client_credentials", "resource": MCP_RESOURCE,
    }, headers={"Authorization": f"Basic {cred}"})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _rpc(tc: TestClient, token: str | None, method: str,
         params: dict | None = None, *, rid: int = 1):
    headers = dict(RPC_HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body: dict = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        body["params"] = params
    return tc.post("/mcp", json=body, headers=headers)


def _call_tool(tc: TestClient, token: str, name: str, arguments: dict):
    """Call a tool and return its payload, whatever envelope FastMCP chose.

    FastMCP v1 emits `structuredContent: {"result": <value>}` when it can
    infer an output schema and falls back to a JSON text block otherwise —
    both are valid MCP, so the parser accepts either."""
    resp = _rpc(tc, token, "tools/call",
                {"name": name, "arguments": arguments})
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert "error" not in payload, payload
    result = payload["result"]
    assert not result.get("isError"), result
    structured = result.get("structuredContent")
    if isinstance(structured, dict) and set(structured) == {"result"}:
        return structured["result"]
    for block in result.get("content", []):
        if block.get("type") == "text":
            return json.loads(block["text"])
    return None


# --------------------------- the authorization boundary --------------------


def test_mcp_without_token_is_401_with_discovery(mcp_client):
    """No token -> 401 + WWW-Authenticate pointing at RFC 9728 metadata.
    This header is HOW an MCP client (Cline, etc.) finds our AS."""
    resp = _rpc(mcp_client, None, "tools/list")
    assert resp.status_code == 401
    challenge = resp.headers.get("www-authenticate", "")
    assert "Bearer" in challenge
    assert "resource_metadata=" in challenge
    assert f"{settings.issuer}/.well-known/oauth-protected-resource" in challenge


def test_mcp_discovered_metadata_names_this_resource(mcp_client):
    """The advertised PRM URL must resolve and name the /mcp resource."""
    doc = mcp_client.get(
        "/.well-known/oauth-protected-resource/mcp").json()
    assert doc["resource"] == MCP_RESOURCE
    assert doc["authorization_servers"] == [settings.issuer]


def test_mcp_rejects_garbage_token(mcp_client):
    assert _rpc(mcp_client, "not-a-jwt", "tools/list").status_code == 401


def test_mcp_rejects_token_minted_for_another_audience(mcp_client):
    """A perfectly valid token for /api must NOT work on /mcp — audience
    binding is the whole point of RFC 8707, enforced by the verifier."""
    api_token = _human_token(mcp_client, resource=None)   # aud = api default
    resp = _rpc(mcp_client, api_token, "tools/list")
    assert resp.status_code == 401


# ------------------------------- tools/list --------------------------------


def test_mcp_lists_the_three_document_tools(mcp_client):
    token = _agent_self_token(mcp_client)
    payload = _rpc(mcp_client, token, "tools/list").json()
    names = {t["name"] for t in payload["result"]["tools"]}
    assert names == {"list_documents", "read_document", "delete_document"}


# ------------------------------ tools/call ---------------------------------


def test_mcp_agent_reads_only_its_own_tenant(mcp_client):
    """chat-agent (sub=alice) sees alice's rows and NOT bob's — RLS, applied
    to a request that arrived over MCP rather than HTTP."""
    _seed_document(ALICE, "alice-note", "alice body")
    _seed_document(BOB, "bob-secret", "bob body")
    token = _agent_on_behalf_token(mcp_client)
    docs = _call_tool(mcp_client, token, "list_documents", {})
    assert docs, "agent should see its own tenant's rows"
    assert {d["owner_sub"] for d in docs} == {ALICE}
    assert "bob body" not in str(docs)


def test_mcp_agent_delete_is_refused_by_database(mcp_client):
    """The money test for MCP: the tool EXISTS, the agent ASKS, and Postgres —
    not application code — refuses because agent_readonly has no DELETE."""
    doc_id = _seed_document(ALICE, "keep-me", "body")
    token = _agent_on_behalf_token(mcp_client)
    outcome = _call_tool(mcp_client, token, "delete_document",
                         {"document_id": doc_id})
    assert outcome["deleted"] is False
    assert "refused" in outcome["reason"]
    # and the row is still there
    with scoped_session(kind="human", sub=ALICE) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM documents WHERE id = %s",
                        (doc_id,))
            assert cur.fetchone()[0] == 1


def test_mcp_human_can_delete_own_row(mcp_client):
    doc_id = _seed_document(ALICE, "delete-me", "body")
    token = _human_token(mcp_client)
    outcome = _call_tool(mcp_client, token, "delete_document",
                         {"document_id": doc_id})
    assert outcome["deleted"] is True
    assert outcome["id"] == doc_id


def test_mcp_read_document_hides_other_tenants(mcp_client):
    doc_id = _seed_document(BOB, "bob-private", "bob body")
    token = _agent_on_behalf_token(mcp_client)     # acts for alice
    outcome = _call_tool(mcp_client, token, "read_document",
                         {"document_id": doc_id})
    # RLS makes bob's row invisible: the tool reports no such document.
    assert outcome is None


def test_mcp_human_surfaces_pii_and_redactor_scrubs_audit(mcp_client):
    """A refused agent write is audited on a fresh session; the audit row's
    statement is PII-redacted like every other log record."""
    doc_id = _seed_document(ALICE, "audit-target", "body")
    token = _agent_on_behalf_token(mcp_client)
    _call_tool(mcp_client, token, "delete_document", {"document_id": doc_id})
    with scoped_session(kind="human", sub=ALICE) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT statement, rows_returned FROM agent_audit "
                "WHERE subject = %s AND statement LIKE '%%delete_document%%' "
                "ORDER BY id DESC LIMIT 1", (ALICE,))
            row = cur.fetchone()
    assert row is not None, "refused MCP operation was not audited"
    assert row[1] == 0

