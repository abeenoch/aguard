"""Standalone MCP resource server (its own deployable, its own port).

This is the split: the authorization server in ``aguard/main.py`` no longer
mounts ``/mcp``. The resource server runs as its own process, on its own port
(``MCP_RESOURCE_URL``), and — crucially — **holds no signing key**. It verifies
tokens exactly the way any third party does: it fetches the issuer's JWKS via
``RemoteKeyStore`` and checks signature / ``iss`` / ``aud`` / ``exp``.

Why the split matters (from SECURITY.md): a resource-server compromise must not
be an AS compromise. Before the split, one process could both mint and accept
tokens, so a bug in an MCP tool ran next to the private key. Now the resource
server can only *verify*; the worst a compromise buys is the DB privilege its
tokens already carry.

Surface:
  POST /mcp                                   Streamable HTTP (bearer-guarded)
  GET  /.well-known/oauth-protected-resource[/mcp]   RFC 9728 (SDK-provided)
  GET  /healthz                               liveness (dependency-free)
  GET  /readyz                                readiness (JWKS reachable + DB)

Run:
  uvicorn aguard.mcp.service:app --port 8081
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

from starlette.responses import JSONResponse

from aguard.db.session import get_pool
from aguard.mcp.server import build_mcp
from aguard.oidc.remote_keys import RemoteKeyStore
from aguard.oidc.validation import KeySet
from aguard.redact.logging import install as install_redaction
from aguard.redact.logging import wire_uvicorn
from aguard.settings import settings

logger = logging.getLogger("a-guard.mcp.service")


def _db_ready(acquire_timeout_ms: int = 1500) -> bool:
    """One cheap round-trip through a tenant pool. Raises if unreachable."""
    pool = get_pool("human")
    with pool.connection(timeout=acquire_timeout_ms / 1000) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
    return True


def create_mcp_app(key_source: KeySet | None = None):
    """Build the standalone MCP resource-server ASGI app.

    ``key_source`` defaults to a ``RemoteKeyStore`` bound to the issuer's JWKS.
    Tests (and any embedded use) may pass a local ``KeyManager`` instead; the
    only thing that must hold either way is that this service can VERIFY, not
    sign.
    """
    source: KeySet = key_source if key_source is not None else RemoteKeyStore(
        settings.issuer, jwks_uri=settings.jwks_uri or None)

    # Same PII choke point as the AS: every record this service emits (including
    # tool logs and uvicorn access lines) is redacted at creation time.
    install_redaction("", settings.log_pepper)
    wire_uvicorn(settings.log_pepper)

    server = build_mcp(source)

    @server.custom_route("/healthz", methods=["GET"])
    async def healthz(_request: Any) -> JSONResponse:
        """Liveness. Deliberately dependency-free — see aguard/main.py."""
        return JSONResponse({"status": "ok"})

    # Readiness is polled and costs a JWKS fetch (cache-miss) plus a DB
    # connection, so reuse the result for a very short window exactly like the
    # AS does, to keep a poll flood from becoming a fetch/pool storm.
    lock = threading.Lock()
    cache: dict[str, Any] = {"at": -1e18, "status": 200, "body": {}}

    def _probe() -> tuple[int, dict]:
        checks: dict[str, str] = {}
        healthy = True
        try:
            # Touches the JWKS (fetch on a cold/expired cache). If we cannot
            # verify tokens, we are not serving.
            if not source.all_keys:
                raise RuntimeError("issuer JWKS published no keys")
            checks["jwks"] = "ok"
        except Exception:
            checks["jwks"] = "error"
            healthy = False
            logger.exception("readiness: JWKS unusable")
        try:
            _db_ready()
            checks["database"] = "ok"
        except Exception:
            checks["database"] = "error"
            healthy = False
            logger.exception("readiness: database unreachable")
        return (200 if healthy else 503,
                {"status": "ready" if healthy else "not_ready",
                 "checks": checks})

    @server.custom_route("/readyz", methods=["GET"])
    async def readyz(_request: Any) -> JSONResponse:
        ttl = settings.readyz_cache_seconds
        with lock:
            if ttl > 0 and time.monotonic() - cache["at"] < ttl:
                status, body = cache["status"], cache["body"]
            else:
                status, body = _probe()
                if ttl > 0:
                    cache.update(at=time.monotonic(),
                                 status=status, body=body)
        return JSONResponse(body, status_code=status,
                            headers={"Cache-Control": "no-store"})

    # streamable_http_app() carries the bearer middleware (401 + RFC 9728
    # resource_metadata) AND the SDK's protected-resource metadata route,
    # derived from resource_server_url — so RFC 9728 discovery lives HERE,
    # with the resource, not with the AS.
    return server.streamable_http_app()


#: uvicorn target: `uvicorn aguard.mcp.service:app`
app = create_mcp_app()
