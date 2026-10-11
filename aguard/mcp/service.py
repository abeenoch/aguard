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
  POST /redact                                playground: the engine, no OAuth,
                                              rate-limited per caller address
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
from aguard.ratelimit import (
    _WINDOW_SECONDS,
    InMemoryRateLimiter,
    RateLimit,
    _client_ip,
    _identity_key,
)
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

    # ---- the playground: try the redaction engine with no OAuth at all -------
    #
    # Why this exists (the adoption story): every OTHER surface of a-guard
    # requires identity — an issuer, a client, tokens. The engine itself is
    # pure regex + keyed HMAC over a string, so it can be tried safely by a
    # stranger with one curl. A visitor who has FELT "card 4111… → ****-…"
    # reads the rest of the README as an answer, not a spec.
    #
    # Ground rules, each one a security decision:
    #   * unauthenticated — that is the point; the tightest rate-limit policy
    #     shipped (RATE_LIMIT_REDACT/60s, per caller address) is the cost.
    #   * stateless — no database, no audit row, no principal. There is no
    #     identity to audit, and the request body never touches a log line
    #     (the redaction choke point is installed for exactly the counts we
    #     DO emit: chars and findings, never the text).
    #   * size-capped before any regex work — an unbounded playground is a
    #     CPU DoS with a JSON body (REDACT_ENDPOINT_MAX_CHARS).
    limiter = InMemoryRateLimiter(
        {"redact": RateLimit(settings.rate_limit_redact,
                             _WINDOW_SECONDS["redact"])},
        max_keys=settings.rate_limit_max_keys,
    )
    max_chars = settings.redact_endpoint_max_chars

    @server.custom_route("/redact", methods=["POST"])
    async def redact_playground(request: Any) -> JSONResponse:
        # Identity discipline, adapted for life behind the TLS reverse proxy:
        # through nginx every socket peer is 127.0.0.1, so _client_ip alone
        # would put ALL visitors in one shared bucket. X-Real-IP is set by the
        # proxy from the real socket address (a client-supplied value is
        # overwritten), making it trustworthy here — the same discipline as
        # X-Forwarded-For behind a proxy that REPLACES it. On the raw port
        # (localhost-only in every shipped config) the header is absent and
        # _client_ip's socket-peer default applies.
        real_ip = request.headers.get("x-real-ip", "").strip()
        identity = _identity_key("ip", real_ip or _client_ip(request))
        decision = limiter.hit("redact", identity)
        if not decision.allowed:
            return JSONResponse(
                {"error": "temporarily_unavailable",
                 "error_description":
                     "rate limit exceeded; retry later"},
                status_code=429,
                headers={"Retry-After": str(decision.retry_after),
                         "Cache-Control": "no-store"})

        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(
                {"error": "invalid_request",
                 "error_description": "body must be JSON {\"text\": \"...\"}"},
                status_code=400, headers={"Cache-Control": "no-store"})
        text = payload.get("text") if isinstance(payload, dict) else None
        if not isinstance(text, str):
            return JSONResponse(
                {"error": "invalid_request",
                 "error_description": "missing \"text\" string field"},
                status_code=400, headers={"Cache-Control": "no-store"})
        if len(text) > max_chars:
            return JSONResponse(
                {"error": "payload_too_large",
                 "error_description":
                     f"text exceeds {max_chars} characters"},
                status_code=413, headers={"Cache-Control": "no-store"})

        from aguard.redact.patterns import redact_text as scrub
        from aguard.redact.patterns import scan_findings
        findings = scan_findings(text, settings.log_pepper)
        redacted = scrub(text, settings.log_pepper)
        # Counts only — the same audit discipline as the MCP tool: a log line
        # that could echo the submitted text back would make the playground
        # the exact leak the engine exists to prevent.
        logger.info({"event": "redact.playground",
                     "chars": len(text),
                     "findings": sum(f["count"] for f in findings)})
        return JSONResponse({"redacted": redacted, "findings": findings},
                            headers={"Cache-Control": "no-store"})


    # streamable_http_app() carries the bearer middleware (401 + RFC 9728
    # resource_metadata) AND the SDK's protected-resource metadata route,
    # derived from resource_server_url — so RFC 9728 discovery lives HERE,
    # with the resource, not with the AS.
    return server.streamable_http_app()


#: uvicorn target: `uvicorn aguard.mcp.service:app`
app = create_mcp_app()
