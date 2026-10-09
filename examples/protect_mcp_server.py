"""A minimal MCP server protected by a-guard — the entire integration.

The interesting line is `Depends(guard.dependency())`: everything else is
ordinary MCP plumbing. No signing key, no shared secret, no session table —
the guard fetches the issuer's JWKS and checks the audience.

1) Start the authorization server:

       python -m uvicorn aguard.main:app --port 8000

2) Tell it this resource exists (the AS validates `resource` against an
   exact-match allowlist, so an unknown audience is refused):

       # in .env
       ALLOWED_RESOURCES=http://localhost:8000/mcp,http://localhost:8000/api,http://localhost:9000/mcp

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

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from aguard.resource_server import ResourceServerGuard

ISSUER = "http://localhost:8000"
THIS_RESOURCE = "http://localhost:9000/mcp"

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


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=9000)
