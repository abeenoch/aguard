"""Use a-guard's MCP tools from plain Python.

Two moving parts:

  1. mint a token with the `client_credentials` grant — the headless,
     service-to-service flow: Basic-auth your client and name the
     `resource` you intend to call. Audience binding is enforced: a token
     minted for any other resource is refused at /mcp with 401, exactly
     like no token at all.
  2. hand the token to the official MCP SDK client and call tools.

For an INTERACTIVE user, don't hand-roll OAuth at all — point an MCP host
(Cline, Claude Desktop, ...) at the /mcp URL and it performs discovery,
Dynamic Client Registration and PKCE by itself. This file is the
machine-to-machine path: what a worker, cron job or pipeline needs.

Run it against any a-guard deployment:

    export AGUARD_M2M_CLIENT_ID=cli-agent              # seeded dev client
    export AGUARD_M2M_CLIENT_SECRET=cli-agent-secret   # override in prod
    python examples/call_aguard_from_python.py

The seeded `cli-agent` exists on every deployment so this runs out of the
box; it may only hold read scopes. For anything real, set CLI_AGENT_SECRET
in the AS's environment (or seed your own confidential client) first.
"""
from __future__ import annotations

import asyncio
import json
import os

import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

BASE = os.environ.get("AGUARD_BASE", "https://aguard.abeenoch.online/api").rstrip("/")
MCP_URL = os.environ.get("MCP_CONNECT_URL", "https://aguard.abeenoch.online/mcp")
CLIENT_ID = os.environ.get("AGUARD_M2M_CLIENT_ID", "cli-agent")
CLIENT_SECRET = os.environ.get("AGUARD_M2M_CLIENT_SECRET", "")
RESOURCE = MCP_URL  # audience binding: the token must name THIS resource

if not CLIENT_SECRET:
    raise SystemExit(
        "set AGUARD_M2M_CLIENT_SECRET "
        "(dev deployments: cli-agent-secret; production: your own)"
    )


def mint_token() -> str:
    """client_credentials: no browser, no cookies, no redirect URI."""
    r = httpx.post(
        f"{BASE}/token",
        auth=(CLIENT_ID, CLIENT_SECRET),
        data={
            "grant_type": "client_credentials",
            "scope": "orders:read",      # read scopes ONLY for agent clients
            "resource": RESOURCE,        # <- becomes aud; omit it and you fail
        },
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["access_token"]


async def main() -> None:
    token = mint_token()
    headers = {"Authorization": f"Bearer {token}"}
    async with streamablehttp_client(MCP_URL, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as mcp:
            await mcp.initialize()
            tools = await mcp.list_tools()
            print("tools:", ", ".join(sorted(t.name for t in tools.tools)))

            out = await mcp.call_tool(
                "redact_text",
                {"text": "card 4111 1111 1111 1111, mail jane@example.com"},
            )
            result = json.loads(out.content[0].text)
            print("redacted:", result["redacted"])
            print("findings:", result["findings"])


if __name__ == "__main__":
    asyncio.run(main())
