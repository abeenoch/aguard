"""FastAPI application factory.

Milestone 1 surface:
  GET /healthz                          liveness
  GET /jwks                             public signing keys (rotation-aware)
  GET /.well-known/openid-configuration OIDC discovery document

Later milestones mount /authorize, /token, /userinfo, /introspect, the
protected resource API, and the MCP Streamable HTTP resource server at /mcp.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router as api_router
from app.mcp.server import build_mcp
from app.oidc.clients import seed_registry
from app.oidc.codes import AuthCodeStore
from app.oidc.keys import KeyManager
from app.oidc.metadata import router as metadata_router
from app.oidc.refresh import RefreshTokenStore
from app.oidc.routes_auth import router as auth_router
from app.oidc.routes_register import router as register_router
from app.oidc.routes_revocable import router as revocable_router
from app.oidc.routes_token import router as token_router
from app.redact.logging import install as install_redaction
from app.settings import settings


def _warn_if_dev_secrets() -> None:
    """Loud startup warning when running with well-known dev secrets.

    Defaults are fine locally (documented in .env.example) but catastrophic
    on a shared host: anyone who has read the source can forge session
    cookies or compute correlation hashes. Fail visible, not silent."""
    import logging
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


def create_app() -> FastAPI:
    keys = KeyManager(settings.key_dir)

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
    application.state.codes = AuthCodeStore()
    application.state.refresh = RefreshTokenStore()

    # PII-redacting choke point: handler-level filters for every record the
    # app emits, PLUS uvicorn's own handlers (access log lines carry URLs).
    install_redaction("", settings.log_pepper)
    from app.redact.logging import wire_uvicorn
    wire_uvicorn(settings.log_pepper)

    _warn_if_dev_secrets()

    application.include_router(auth_router)
    application.include_router(token_router)
    application.include_router(metadata_router)
    application.include_router(register_router)
    application.include_router(revocable_router)
    application.include_router(api_router)

    @application.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

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
