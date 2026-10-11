"""Phase C: the MCP resource server as its OWN service (Streamable HTTP at /mcp).

Since the split, the resource server is NOT mounted on the AS app. These tests
build the standalone service (``aguard/mcp/service.py``) and drive tokens minted
by the AS ``TestClient`` through it, so the protocol boundary is exercised the
way it deploys. The ONLY substitution from production is that key material is
injected directly instead of fetched from the issuer's JWKS — that fetch path is
covered by tests/test_remote_keys.py.

Still proven against the REAL database:
  * no/foreign token   -> 401 + RFC 9728 WWW-Authenticate (discovery)
  * agent token        -> reads its own tenant only; writes refused by Postgres
  * human token        -> may delete its OWN rows
  * audience binding   -> a token minted for /api is REJECTED at /mcp
  * the split itself   -> the AS app serves no /mcp and no resource metadata

Raw JSON-RPC is used: with stateless_http the server accepts a standalone
request without an initialize handshake, so the test stays deterministic.
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

from aguard.db.session import close_pools, scoped_session
from aguard.oidc.pkce import challenge_s256, generate_verifier
from aguard.settings import settings

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = PROJECT_ROOT / "aguard" / "db" / "schema.sql"
REDIRECT = f"{settings.issuer}/demo/callback"
MCP_ORIGIN = settings.mcp_resource_url            # Host must pass the allowlist
MCP_RESOURCE = settings.mcp_resource_id
RPC_HEADERS = {"Accept": "application/json, text/event-stream"}
ALICE = "usr_alice"
BOB = "usr_bob"

#: RFC 9728 section 3.1 metadata URL, i.e. what the SDK advertises in the 401.
#: Derived here the same way the SDK derives it, so the test asserts the contract.
_parsed = urlparse(MCP_RESOURCE)
MCP_PRM_URL = (f"{_parsed.scheme}://{_parsed.netloc}"
               f"/.well-known/oauth-protected-resource{_parsed.path}")


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


class _McpEnv:
    """The two clients the split makes explicit: the AS that mints tokens and
    the resource server that consumes them."""

    def __init__(self, as_client: TestClient, mcp_client: TestClient):
        self.as_client = as_client
        self.mcp_client = mcp_client


@pytest.fixture(scope="module")
def env():
    """Fresh schema + fresh AS + the split MCP service sharing the AS keystore.

    The MCP app is built via create_mcp_app(as_app.state.keys): in production
    that argument is omitted and a RemoteKeyStore fetches the issuer's JWKS.
    Each TestClient is entered so its lifespan runs (the MCP app's starts the
    Streamable HTTP session-manager task group).
    """
    _apply_schema()
    import aguard.main as main_module
    importlib.reload(main_module)
    as_app = main_module.app

    import aguard.mcp.service as mcp_service
    mcp_app = mcp_service.create_mcp_app(as_app.state.keys)

    with TestClient(as_app) as as_client, \
            TestClient(mcp_app, base_url=MCP_ORIGIN) as mcp_client:
        yield _McpEnv(as_client, mcp_client)
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


def _human_token(env: _McpEnv, *, email="alice@example.com",
                 password="correct-horse-battery",
                 scope="openid email orders:read",
                 resource=MCP_RESOURCE) -> str:
    """Full authorization-code flow, optionally audience-bound to /mcp."""
    tc = env.as_client
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


def _agent_on_behalf_token(env: _McpEnv) -> str:
    """chat-agent rides the USER flow: sub=alice AND roles=['agent'].

    This is the interesting principal — a human's identity with an agent's
    (read-only) capability, audience-bound to the MCP server."""
    tc = env.as_client
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


def _agent_self_token(env: _McpEnv) -> str:
    """cli-agent as itself: sub=svc:cli-agent, roles=['agent'], no human."""
    cred = base64.b64encode(b"cli-agent:cli-agent-secret").decode()
    resp = env.as_client.post("/token", data={
        "grant_type": "client_credentials", "resource": MCP_RESOURCE,
    }, headers={"Authorization": f"Basic {cred}"})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _rpc(env: _McpEnv, token: str | None, method: str,
         params: dict | None = None, *, rid: int = 1):
    headers = dict(RPC_HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body: dict = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        body["params"] = params
    return env.mcp_client.post("/mcp", json=body, headers=headers)


def _call_tool(env: _McpEnv, token: str, name: str, arguments: dict):
    """Call a tool and return its payload, whatever envelope FastMCP chose.

    FastMCP emits `structuredContent: {"result": <value>}` when it can infer an
    output schema and falls back to a JSON text block otherwise — both are
    valid MCP, so the parser accepts either."""
    resp = _rpc(env, token, "tools/call",
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


def test_mcp_without_token_is_401_with_discovery(env):
    """No token -> 401 + WWW-Authenticate pointing at THIS resource's RFC 9728
    metadata. This header is HOW an MCP client (Cline, etc.) finds our AS."""
    resp = _rpc(env, None, "tools/list")
    assert resp.status_code == 401
    challenge = resp.headers.get("www-authenticate", "")
    assert "Bearer" in challenge
    assert "resource_metadata=" in challenge
    # The metadata URL names the RESOURCE's origin (its own service), not the AS.
    assert MCP_PRM_URL in challenge


def test_mcp_discovered_metadata_names_this_resource(env):
    """The advertised PRM URL must resolve (on the resource server) and name
    the /mcp resource and the AS that issues for it."""
    doc = env.mcp_client.get(
        "/.well-known/oauth-protected-resource/mcp").json()
    assert doc["resource"] == MCP_RESOURCE
    # SDK serializes AnyHttpUrl with a trailing slash; normalize before compare.
    assert [s.rstrip("/") for s in doc["authorization_servers"]] == [settings.issuer]


def test_as_no_longer_serves_the_resource_or_its_metadata(env):
    """The split invariant: the AS must not accept /mcp or advertise the
    resource's metadata. An AS that still spoke for the resource would undo the
    separation the split buys."""
    rpc = env.as_client.post("/mcp", json={"jsonrpc": "2.0", "id": 1,
                                           "method": "tools/list"})
    assert rpc.status_code == 404
    prm = env.as_client.get("/.well-known/oauth-protected-resource/mcp")
    assert prm.status_code == 404


def test_mcp_rejects_garbage_token(env):
    assert _rpc(env, "not-a-jwt", "tools/list").status_code == 401


def test_mcp_rejects_token_minted_for_another_audience(env):
    """A perfectly valid token for /api must NOT work on /mcp — audience
    binding is the whole point of RFC 8707, enforced by the verifier."""
    api_token = _human_token(env, resource=None)   # aud = api default
    resp = _rpc(env, api_token, "tools/list")
    assert resp.status_code == 401


# ------------------------------- tools/list --------------------------------


def test_mcp_lists_the_four_document_tools(env):
    token = _agent_self_token(env)
    payload = _rpc(env, token, "tools/list").json()
    names = {t["name"] for t in payload["result"]["tools"]}
    assert names == {"list_documents", "read_document", "delete_document",
                     "redact_text"}


# ------------------------------ tools/call ---------------------------------


def test_mcp_agent_reads_only_its_own_tenant(env):
    """chat-agent (sub=alice) sees alice's rows and NOT bob's — RLS, applied
    to a request that arrived over MCP rather than HTTP."""
    _seed_document(ALICE, "alice-note", "alice body")
    _seed_document(BOB, "bob-secret", "bob body")
    token = _agent_on_behalf_token(env)
    docs = _call_tool(env, token, "list_documents", {})
    assert docs, "agent should see its own tenant's rows"
    assert {d["owner_sub"] for d in docs} == {ALICE}
    assert "bob body" not in str(docs)


def test_mcp_agent_delete_is_refused_by_database(env):
    """The money test for MCP: the tool EXISTS, the agent ASKS, and Postgres —
    not application code — refuses because agent_readonly has no DELETE."""
    doc_id = _seed_document(ALICE, "keep-me", "body")
    token = _agent_on_behalf_token(env)
    outcome = _call_tool(env, token, "delete_document",
                         {"document_id": doc_id})
    assert outcome["deleted"] is False
    assert "refused" in outcome["reason"]
    with scoped_session(kind="human", sub=ALICE) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM documents WHERE id = %s",
                        (doc_id,))
            assert cur.fetchone()[0] == 1


def test_mcp_human_can_delete_own_row(env):
    doc_id = _seed_document(ALICE, "delete-me", "body")
    token = _human_token(env)
    outcome = _call_tool(env, token, "delete_document",
                         {"document_id": doc_id})
    assert outcome["deleted"] is True
    assert outcome["id"] == doc_id


def test_mcp_read_document_hides_other_tenants(env):
    doc_id = _seed_document(BOB, "bob-private", "bob body")
    token = _agent_on_behalf_token(env)     # acts for alice
    outcome = _call_tool(env, token, "read_document",
                         {"document_id": doc_id})
    # RLS makes bob's row invisible: the tool reports no such document.
    assert outcome is None


def test_mcp_human_surfaces_pii_and_redactor_scrubs_audit(env):
    """A refused agent write is audited on a fresh session; the audit row's
    statement is PII-redacted like every other log record."""
    doc_id = _seed_document(ALICE, "audit-target", "body")
    token = _agent_on_behalf_token(env)
    _call_tool(env, token, "delete_document", {"document_id": doc_id})
    with scoped_session(kind="human", sub=ALICE) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT statement, rows_returned FROM agent_audit "
                "WHERE subject = %s AND statement LIKE '%%delete_document%%' "
                "ORDER BY id DESC LIMIT 1", (ALICE,))
            row = cur.fetchone()
    assert row is not None, "refused MCP operation was not audited"
    assert row[1] == 0


# --------------------------- redact_text tool ------------------------------


def test_mcp_redact_text_masks_card_and_email(env):
    """The chat-facing tool: paste a card number and an email, get back the
    masked form and the finding counts — the same engine that scrubs the
    server's own audit trail."""
    token = _agent_self_token(env)
    chat = "My card is 4111 1111 1111 1111 and email alice@example.com"
    outcome = _call_tool(env, token, "redact_text", {"text": chat})
    redacted = outcome["redacted"]
    assert "4111 1111 1111 1111" not in redacted
    assert "****-****-****-1111" in redacted
    assert "alice@example.com" not in redacted
    assert "email[h:" in redacted
    by_type = {f["type"]: f["count"] for f in outcome["findings"]}
    assert by_type.get("card") == 1
    assert by_type.get("email") == 1


def test_mcp_redact_text_luhn_false_positives_survive(env):
    """A 16-digit run that fails Luhn is NOT a card (order ids, hashes) —
    the tool must not butcher it, proving it is not naive regex."""
    token = _agent_self_token(env)
    outcome = _call_tool(env, token, "redact_text",
                         {"text": "order 1234567812345678 shipped"})
    assert "1234567812345678" in outcome["redacted"]
    assert not any(f["type"] == "card" for f in outcome["findings"])


def test_mcp_redact_text_audit_row_holds_counts_not_content(env):
    """The tool exists to stop PII leaking into records — so its own audit
    row must contain counts only, never the submitted text."""
    token = _agent_self_token(env)
    secret = "api_key=sk-live-9f3a1b2c and 5555555555554444"
    _call_tool(env, token, "redact_text", {"text": secret})
    with scoped_session(kind="human", sub="svc:cli-agent") as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT statement FROM agent_audit "
                "WHERE statement LIKE '%%redact_text%%' "
                "ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
    assert row is not None, "redact_text call was not audited"
    statement = row[0]
    assert "chars=" in statement and "findings=" in statement
    for fragment in ("sk-live", "5555555555554444"):
        assert fragment not in statement


def test_mcp_redact_text_masks_address_from_chat(env):
    """The live finding that motivated the address pattern: a free-form
    street address passed through with 0 findings. It must now be masked."""
    token = _agent_self_token(env)
    chat = "my address is nos 4 oguntunde estate, deliveries only"
    outcome = _call_tool(env, token, "redact_text", {"text": chat})
    redacted = outcome["redacted"]
    assert "oguntunde" not in redacted
    assert "[ADDRESS_REDACTED]" in redacted
    by_type = {f["type"]: f["count"] for f in outcome["findings"]}
    assert by_type.get("address") == 1


def test_mcp_redact_text_idempotent_output(env):
    """Running redact_text on its own output changes nothing — an agent that
    re-scans a forwarded message must not double-mask or corrupt tags."""
    token = _agent_self_token(env)
    chat = "ping alice@example.com from 203.0.113.42"
    once = _call_tool(env, token, "redact_text", {"text": chat})["redacted"]
    twice = _call_tool(env, token, "redact_text", {"text": once})["redacted"]
    assert once == twice


# --------------------------- /redact playground ----------------------------
#
# Every playground test carries a unique X-Real-IP: the endpoint counts
# requests per caller address and the limiter is per-app-instance, so tests
# sharing an identity would spend each other's budget. The header is what the
# TLS proxy overwrites in production — in-process it plays that role.


def _redact(env, text=None, ip="203.0.113.101", raw=None):
    body = raw if raw is not None else {"text": text}
    return env.mcp_client.post(
        "/redact", json=body, headers={"X-Real-IP": ip},
    )


def test_redact_playground_masks_without_any_auth(env):
    """The adoption surface: a stranger with a curl, no OAuth, no client.
    Same engine, same counts-only discipline — the submitted text must not
    survive into the response as anything but redacted."""
    r = _redact(env, "card 4111 1111 1111 1111 and alice@example.com",
                ip="203.0.113.101")
    assert r.status_code == 200
    out = r.json()
    assert "4111 1111" not in out["redacted"]
    assert "alice@example.com" not in out["redacted"]
    by_type = {f["type"]: f["count"] for f in out["findings"]}
    assert by_type.get("card") == 1 and by_type.get("email") == 1


def test_redact_playground_rejects_malformed_bodies(env):
    """Counted-then-rejected: a bad body never reaches the regex engine."""
    for raw, status in (({}, 400), ({"text": 42}, 400),
                        ([1, 2, 3], 400)):
        r = _redact(env, raw=raw, ip="203.0.113.102")
        assert r.status_code == status, (raw, r.status_code)
        assert "error" in r.json()
    r = env.mcp_client.post(  # not JSON at all
        "/redact", content=b"not json",
        headers={"X-Real-IP": "203.0.113.102",
                 "Content-Type": "application/json"})
    assert r.status_code == 400


def test_redact_playground_refuses_oversized_text(env):
    """The size cap fires BEFORE any regex work (a CPU DoS with a body)."""
    r = _redact(env, "x" * (settings.redact_endpoint_max_chars + 1),
                ip="203.0.113.103")
    assert r.status_code == 413
    assert "payload_too_large" in r.json()["error"]


def test_redact_playground_rate_limited_per_address(env):
    """RATE_LIMIT_REDACT requests per 60s window, keyed on the proxy-provided
    address — and a different address is NOT affected (per-address, not global)."""
    ip = "203.0.113.104"
    codes = [_redact(env, "hi", ip=ip).status_code
             for _ in range(settings.rate_limit_redact + 1)]
    assert codes[:settings.rate_limit_redact] == [200] * settings.rate_limit_redact
    assert codes[-1] == 429
    assert int(env.mcp_client.post(
        "/redact", json={"text": "hi"},
        headers={"X-Real-IP": ip}).headers["Retry-After"]) >= 0
    # A different address keeps its own budget.
    assert _redact(env, "hi", ip="203.0.113.105").status_code == 200
