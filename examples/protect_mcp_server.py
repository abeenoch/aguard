"""A minimal MCP server protected by a-guard — the entire integration.

The interesting line is `Depends(guard.dependency())`: everything else is
ordinary MCP plumbing. No signing key, no shared secret, no session table —
the guard fetches the issuer's JWKS and checks the audience.

1) Start the authorization server:

       python -m uvicorn aguard.main:app --port 8080

2) Tell it this resource exists (the AS validates `resource` against an
   exact-match allowlist, so an unknown audience is refused):

       # in .env
       ALLOWED_RESOURCES=http://localhost:8081/mcp,http://localhost:8080/api,http://localhost:9000/mcp

3) Run this server:

       python examples/protect_mcp_server.py       # :9000

4) Call it with a token whose `aud` names THIS resource. Minting one is the
   normal client_credentials / authorization_code flow with
   `resource=http://localhost:9000/mcp`. Then:

       curl -sS -X POST http://localhost:9000/mcp \\
         -H 'Authorization: Bearer <token>' \\
         -H 'Content-Type: application/json' \\
         -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

Call it with no token and you get a 401 carrying
`WWW-Authenticate: Bearer resource_metadata=...` — which is how an MCP client
discovers the authorization server without being configured with it.
"""
from __future__ import annotations

import os

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from aguard.resource_server import ResourceServerGuard

# Read the issuer from the environment so this example tracks the AS it is
# pointed at (OIDC_ISSUER, loaded from .env by aguard.settings) instead of
# hardcoding a port that the operator may have moved.
ISSUER = os.environ.get("OIDC_ISSUER", "http://localhost:8080").rstrip("/")
THIS_RESOURCE = os.environ.get("MCP_EXAMPLE_RESOURCE",
                               "http://localhost:9000/mcp")

guard = ResourceServerGuard(issuer=ISSUER, audience=THIS_RESOURCE)

app = FastAPI(title="protected-mcp-server", version="0.1.0")

TOOLS = [
    {"name": "whoami",
     "description": "Return the verified caller identity",
     "inputSchema": {"type": "object", "properties": {}}},
]


@app.post("/mcp")
async def mcp(request: Request,
              claims: dict = Depends(guard.dependency())) -> JSONResponse:
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse({"error": "body must be JSON"}, status_code=400)

    request_id = body.get("id")
    method = body.get("method")

    if method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        # `claims` came from a verified token: audience-checked, signature-
        # checked, not from anything the caller asserted.
        result = {"content": [{
            "type": "text",
            "text": f"sub={claims['sub']} client_id={claims.get('client_id')}",
        }]}
    else:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": request_id,
             "error": {"code": -32601, "message": f"unsupported method {method!r}"}},
            status_code=200)
    return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": result})


@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/mcp")
def protected_resource_metadata() -> dict:
    """RFC 9728: THIS resource's metadata, naming the authorization server.

    This is the document the guard's 401 points at (the URL is derived from the
    audience with the well-known segment inserted before the resource path). It
    lives on the RESOURCE, not the AS — that is what lets an MCP client discover
    which AS issues tokens for this server without being configured with one."""
    return {
        "resource": THIS_RESOURCE,
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
    }


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=9000)
