"""Live MCP smoke test: a REAL MCP client SDK against a REAL uvicorn server.

This is the end-to-end proof, using the same client library MCP hosts
(Cline, Claude Desktop, ...) build on:

  1. unauthenticated  -> 401 + RFC 9728 discovery header
  2. agent token      -> tools/list + list_documents (own tenant only)
  3. agent delete     -> REFUSED by Postgres (not by application code)
  4. human delete     -> allowed for its OWN row
  5. audience binding -> a token minted for /api is rejected at /mcp

Run the server first:  uvicorn app.main:app --port 8000
Then:                  python scripts/mcp_smoke.py
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import sys
from contextlib import asynccontextmanager
from urllib.parse import parse_qs, urlparse

import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

BASE = "http://localhost:8000"          # MUST match settings.issuer
MCP_URL = f"{BASE}/mcp"
REDIRECT = f"{BASE}/demo/callback"
RESOURCE_ID = f"{BASE}/mcp"
RPC_ACCEPT = {"Accept": "application/json, text/event-stream"}


def say(step: str, ok: bool, detail: str = "") -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {step}" + (f" — {detail}" if detail else ""))
    if not ok:
        sys.exit(1)


def basic(cid: str, secret: str) -> dict:
    cred = base64.b64encode(f"{cid}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {cred}"}


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def get_tokens(client: httpx.Client, *, client_id: str, secret: str | None,
               email: str, password: str, scope: str,
               resource: str | None = None) -> dict:
    """Authorization-code flow; `resource` binds the token's audience."""
    client.cookies.clear()
    verifier, challenge = pkce_pair()
    params = {"response_type": "code", "client_id": client_id,
              "redirect_uri": REDIRECT, "scope": scope, "state": "st-live",
              "code_challenge": challenge, "code_challenge_method": "S256"}
    if resource:
        params["resource"] = resource
    r = client.get(f"{BASE}/authorize", params=params, follow_redirects=False)
    if r.status_code == 302 and "/login" in r.headers.get("location", ""):
        client.post(f"{BASE}/login",
                    data={"email": email, "password": password, "next": "/"},
                    follow_redirects=False)
        r = client.get(f"{BASE}/authorize", params=params, follow_redirects=False)
    data = {"decision": "approve", "client_id": client_id,
            "redirect_uri": REDIRECT, "scope": scope, "state": "st-live",
            "code_challenge": challenge, "code_challenge_method": "S256"}
    if resource:
        data["resource"] = resource
    r = client.post(f"{BASE}/consent", data=data, follow_redirects=False)
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    payload = {"grant_type": "authorization_code", "code": code,
               "redirect_uri": REDIRECT, "code_verifier": verifier}
    headers: dict = {}
    if secret:
        headers = basic(client_id, secret)
    else:
        payload["client_id"] = client_id
    r = client.post(f"{BASE}/token", data=payload, headers=headers)
    say(f"token exchange ({client_id})", r.status_code == 200,
        f"status {r.status_code}")
    return r.json()


def agent_token(client: httpx.Client, **kw) -> dict:
    """chat-agent rides the USER flow: sub=alice AND roles=['agent'] — the
    on-behalf-of principal that makes RLS visible over MCP."""
    return get_tokens(client, client_id="chat-agent",
                      secret="chat-agent-secret", **kw)


def payload_of(result) -> object:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict) and set(structured) == {"result"}:
        return structured["result"]
    for block in result.content or []:
        if getattr(block, "type", None) == "text":
            return json.loads(block.text)
    return None


@asynccontextmanager
async def session(token: str):
    headers = {"Authorization": f"Bearer {token}"}
    async with streamablehttp_client(MCP_URL, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as s:
            await s.initialize()
            yield s


async def run() -> None:
    with httpx.Client(timeout=15) as http:
        say("server is up", http.get(f"{BASE}/healthz").status_code == 200)

        # -- 1. unauthenticated: 401 + RFC 9728 discovery ---------------------
        r = http.post(MCP_URL, json={"jsonrpc": "2.0", "id": 1,
                                     "method": "tools/list"},
                      headers=RPC_ACCEPT)
        challenge = r.headers.get("www-authenticate", "")
        say("unauthenticated -> 401 + resource_metadata",
            r.status_code == 401 and "resource_metadata=" in challenge,
            challenge[:90])

        # seed a row for alice through the REST API (default API audience)
        human = get_tokens(http, client_id="demo-spa", secret=None,
                           email="alice@example.com",
                           password="correct-horse-battery",
                           scope="openid email orders:read orders:write")
        title = f"mcp-smoke-{secrets.token_hex(4)}"
        hu = {"Authorization": f"Bearer {human['access_token']}"}
        r = http.post(f"{BASE}/api/documents",
                      json={"title": title, "body": "seeded for MCP smoke"},
                      headers=hu)
        say("seed document via REST", r.status_code == 201, title)
        doc_id = r.json()["id"]

        # -- 2. audience binding: an /api token must fail on /mcp -------------
        r = http.post(MCP_URL, json={"jsonrpc": "2.0", "id": 2,
                                     "method": "tools/list"},
                      headers={**RPC_ACCEPT, "Authorization":
                               f"Bearer {human['access_token']}"})
        say("api-audience token rejected at /mcp", r.status_code == 401,
            f"status {r.status_code}")

        # -- 3. agent over MCP: read own tenant, write refused by Postgres ----
        agent = agent_token(http, email="alice@example.com",
                            password="correct-horse-battery",
                            scope="openid email orders:read",
                            resource=RESOURCE_ID)
        async with session(agent["access_token"]) as s:
            tools = await s.list_tools()
            names = {t.name for t in tools.tools}
            say("tools/list over the MCP SDK",
                names == {"list_documents", "read_document", "delete_document"},
                ", ".join(sorted(names)))
            listed = payload_of(await s.call_tool("list_documents", {}))
            say("agent sees its own tenant only (RLS)",
                isinstance(listed, list) and listed
                and all(d["owner_sub"] == "usr_alice" for d in listed),
                f"{len(listed)} rows, tenant usr_alice")
            denied = payload_of(await s.call_tool("delete_document",
                                                  {"document_id": doc_id}))
            say("agent delete refused by the database",
                denied["deleted"] is False and "refused" in denied["reason"],
                denied["reason"])

        # -- 4. human over MCP: delete its OWN row ----------------------------
        human_mcp = get_tokens(http, client_id="demo-spa", secret=None,
                               email="alice@example.com",
                               password="correct-horse-battery",
                               scope="openid email orders:read",
                               resource=RESOURCE_ID)
        async with session(human_mcp["access_token"]) as s:
            allowed = payload_of(await s.call_tool("delete_document",
                                                   {"document_id": doc_id}))
            say("human deletes its own row", allowed.get("deleted") is True,
                json.dumps(allowed))

    print("\nAll MCP smoke checks passed.")


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - smoke tooling
        say("unexpected failure", False, f"{type(exc).__name__}: {exc}")

