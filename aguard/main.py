"""FastAPI application factory.

Surface:
  GET /healthz                          liveness (deliberately static)
  GET /readyz                           readiness (database + keystore)
  GET /jwks                             public signing keys (rotation-aware)
  GET /.well-known/openid-configuration OIDC discovery document

Later milestones mount /authorize, /token, /userinfo, /introspect, the
protected resource API, and the MCP Streamable HTTP resource server at /mcp.
"""
from __future__ import annotations

import logging
import threading
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from aguard.api.routes import router as api_router
from aguard.db.session import service_session
from aguard.mcp.server import build_mcp
from aguard.oidc.clients import seed_registry
from aguard.oidc.keys import KeyManager
from aguard.oidc.metadata import router as metadata_router
from aguard.oidc.routes_auth import router as auth_router
from aguard.oidc.routes_register import router as register_router
from aguard.oidc.routes_revocable import router as revocable_router
from aguard.oidc.routes_token import router as token_router
from aguard.oidc.stores import build_stores, stores_are_shared
from aguard.ratelimit import build_rate_limiter
from aguard.redact.logging import install as install_redaction
from aguard.settings import settings


def _warn_if_dev_secrets() -> None:
    """Loud startup warning when running with well-known dev secrets.

    Defaults are fine locally (documented in .env.example) but catastrophic
    on a shared host: anyone who has read the source can forge session
    cookies or compute correlation hashes. Fail visible, not silent."""
    weak = [
        name for value, marker, name in (
            (settings.session_secret, b"dev-session-secret-change-me", "SESSION_SECRET"),
            (settings.log_pepper, b"dev-only-pepper-change-me", "LOG_HASH_PEPPER"),
        )
        if value == marker
    ]
    if weak:
        logging.getLogger("a-guard.startup").warning(
            "INSECURE DEV SECRETS ACTIVE — override before any shared "
            "deployment: %s (see .env.example)",
            ", ".join(weak),
        )


def _warn_if_limits_are_per_process() -> None:
    """Say out loud that rate limits do not span workers.

    ``stores_are_shared()`` is the flag that means "this deployment runs more
    than one worker" (its docstring says so, and it is what the store choice
    exists to gate). In exactly that configuration the in-process limiter is
    weakest: each worker enforces the full limit, so the real ceiling is
    N x RATE_LIMIT_*. Operators should hear that from the process, not from a
    comment in a file they never open.
    """
    if stores_are_shared():
        logging.getLogger("a-guard.startup").warning(
            "RATE LIMITS ARE PER-PROCESS: authorization state is shared "
            "(STORE_BACKEND=postgres), so more than one worker is running and "
            "each enforces the FULL limit — the effective ceiling is "
            "N x the configured counts. Rate-limit state has no shared "
            "backend yet; see aguard/ratelimit.py."
        )


def create_app() -> FastAPI:
    # The keystore prunes retired keys at startup, but only once it knows how
    # long a token may outlive the key that signed it: the longest JWT TTL we
    # issue, plus the clock-skew leeway every validator is allowed.
    keys = KeyManager(
        settings.key_dir,
        max_token_ttl=max(settings.access_token_ttl, settings.id_token_ttl)
        + settings.clock_skew_leeway,
    )

    # MCP resource server. build_mcp() wires the SDK's bearer middleware
    # (RFC 9728 discovery + audience binding); streamable_http_app() returns
    # the mountable Starlette app, and session_manager.run() must stay active
    # for the life of the process — hence the lifespan below.
    mcp_server = build_mcp(keys)
    mcp_app = mcp_server.streamable_http_app()
    mcp_session_manager = mcp_server.session_manager

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async with mcp_session_manager.run():
            yield

    application = FastAPI(title="a-guard", version="0.1.0", lifespan=lifespan)
    application.state.keys = keys
    application.state.registry = seed_registry()
    # Backend chosen by STORE_BACKEND: memory (single process) or postgres
    # (shared + restart-durable). See aguard/oidc/stores.py for why this is a
    # security decision, not just an operational one.
    codes, refresh = build_stores()
    application.state.codes = codes
    application.state.refresh = refresh
    # Attempt counters for /token, /login and /register. Per-process for now
    # (see aguard/ratelimit.py) — a deliberate choice, and a loud one:
    # _warn_if_limits_are_per_process() below says so at startup.
    application.state.rate_limiter = build_rate_limiter()

    # PII-redacting choke point: handler-level filters for every record the
    # app emits, PLUS uvicorn's own handlers (access log lines carry URLs).
    install_redaction("", settings.log_pepper)
    from aguard.redact.logging import wire_uvicorn
    wire_uvicorn(settings.log_pepper)

    _warn_if_dev_secrets()
    _warn_if_limits_are_per_process()

    application.include_router(auth_router)
    application.include_router(token_router)
    application.include_router(metadata_router)
    application.include_router(register_router)
    application.include_router(revocable_router)
    application.include_router(api_router)

    @application.get("/healthz")
    def healthz() -> dict:
        """Liveness. Deliberately does NOT touch the database.

        A liveness probe that fails when a dependency is down gets the process
        killed and restarted — which cannot fix the dependency, and turns a
        partial outage into a crash loop. Dependencies belong in /readyz,
        which gates traffic instead of the process.
        """
        return {"status": "ok"}

    # Readiness is polled by infrastructure every few seconds and costs a
    # pooled database connection, so a result is reused for a very short window
    # (settings.readyz_cache_seconds). Two consequences, both wanted: a probe
    # flood cannot consume the connection pool that /token also draws from, and
    # the lock means at most ONE probe holds a connection at a time.
    _readyz_lock = threading.Lock()
    _readyz_cache: dict[str, Any] = {"at": -1e18, "status": 200, "body": {}}

    def _probe_readiness() -> tuple[int, dict]:
        """One live check of everything this process needs to serve."""
        checks: dict[str, str] = {}
        healthy = True

        try:
            # Readiness means we can publish keys: force the keystore to be
            # loaded and parsed, and fail if it produced nothing to publish.
            if not keys.jwks.get("keys"):
                raise RuntimeError("keystore published no keys")
            checks["keys"] = "ok"
        except Exception:
            checks["keys"] = "error"
            healthy = False
            logging.getLogger("a-guard.startup").exception(
                "readiness: keystore unusable")

        try:
            # Both timeouts are short on purpose: a probe must answer promptly
            # even while the database is hanging, rather than hanging with it.
            # acquire_timeout bounds the wait for a pooled connection, which
            # statement_timeout does not cover.
            with service_session(statement_timeout_ms=1000,
                                 acquire_timeout_ms=1500) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
            checks["database"] = "ok"
        except Exception:
            checks["database"] = "error"
            healthy = False
            logging.getLogger("a-guard.startup").exception(
                "readiness: database unreachable")

        return (200 if healthy else 503,
                {"status": "ready" if healthy else "not_ready",
                 "checks": checks})

    @application.get("/readyz")
    def readyz() -> JSONResponse:
        """Readiness: can this process actually serve right now?

        Checks what every shipped data path needs — the signing keystore (so
        /jwks and token signing work) and the database (/api, the MCP tools
        and the postgres store backend all read from it). The database check is
        unconditional because there is no configuration in which this server
        serves without it; "alive but no database" is not a serving state.

        Failure returns 503 with a generic per-check status. Details go to the
        log (which is redacted) and never into a response body an
        unauthenticated caller can read.

        Results are reused for settings.readyz_cache_seconds so that polling
        infrastructure cannot turn steady probes into a connection-pool drain.
        """
        ttl = settings.readyz_cache_seconds
        with _readyz_lock:
            if ttl > 0 and time.monotonic() - _readyz_cache["at"] < ttl:
                status, body = _readyz_cache["status"], _readyz_cache["body"]
            else:
                status, body = _probe_readiness()
                if ttl > 0:
                    _readyz_cache.update(at=time.monotonic(),
                                         status=status, body=body)
        return JSONResponse(body, status_code=status,
                            headers={"Cache-Control": "no-store"})

    @application.get("/jwks")
    def jwks() -> dict:
        # Public keys only — ManagedKey.public_jwk() structurally omits `d`.
        return keys.jwks

    # Attach the MCP ASGI app at EXACTLY /mcp. Neither mount target works:
    #   * Mount("/")    swallows every unmatched path, which disables
    #                   Starlette's trailing-slash redirects app-wide
    #                   (GET /login/ stops redirecting to /login)
    #   * Mount("/mcp") only matches "/mcp/" (a Mount appends a path segment),
    #                   so POST /mcp would 307-redirect — fatal for MCP clients
    # A plain Starlette Route matches the exact path and leaves the rest of the
    # router untouched. Note a Route does NOT strip the prefix, so the MCP
    # app's own route stays "/mcp" (see build_mcp). The sub-app keeps its
    # bearer middleware, so /mcp remains authenticated.
    from starlette.routing import Route
    application.router.routes.append(Route("/mcp", endpoint=mcp_app))

    return application


app = create_app()
