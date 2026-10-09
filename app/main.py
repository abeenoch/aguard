"""FastAPI application factory.

Milestone 1 surface:
  GET /healthz                          liveness
  GET /jwks                             public signing keys (rotation-aware)
  GET /.well-known/openid-configuration OIDC discovery document

Later milestones mount /authorize, /token, /userinfo, /introspect and the
protected resource API.
"""
from __future__ import annotations

from fastapi import FastAPI

from app.api.routes import router as api_router
from app.oidc.clients import seed_registry
from app.oidc.codes import AuthCodeStore
from app.oidc.keys import KeyManager
from app.oidc.refresh import RefreshTokenStore
from app.oidc.routes_auth import router as auth_router
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
    application = FastAPI(title="a-guard", version="0.1.0")

    keys = KeyManager(settings.key_dir)
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
    application.include_router(api_router)

    @application.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @application.get("/jwks")
    def jwks() -> dict:
        # Public keys only — ManagedKey.public_jwk() structurally omits `d`.
        return keys.jwks

    @application.get("/.well-known/openid-configuration")
    def discovery() -> dict:
        issuer = settings.issuer
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "userinfo_endpoint": f"{issuer}/userinfo",
            "jwks_uri": f"{issuer}/jwks",
            "introspection_endpoint": f"{issuer}/introspect",
            "revocation_endpoint": f"{issuer}/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "client_credentials",
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            # "plain" deliberately absent: PKCE downgrade to S256->plain is
            # forbidden by OAuth 2.1; advertise only what we enforce.
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "scopes_supported": [
                "openid",
                "profile",
                "email",
                "orders:read",
                "orders:write",
                "agents:read",
            ],
            "claims_supported": [
                "sub", "iss", "aud", "exp", "iat", "email", "roles", "amr",
            ],
        }

    return application


app = create_app()
