"""Authorization-server metadata: RFC 8414 + OIDC discovery.

One source of truth — the OIDC discovery doc and the RFC 8414 doc are the
same document at two paths because different clients look in different
places (OIDC clients → openid-configuration, MCP clients → RFC 8414 path).

RFC 9728 protected-resource metadata is NOT served here. It belongs to the
resource server by definition (it describes THAT resource and names the ASs
that may issue for it), so it lives with the MCP service — see
aguard/mcp/service.py, where the MCP SDK derives it from resource_server_url.
Keeping it off the AS prevents an AS/RS split from advertising the AS as its
own resource.
"""
from __future__ import annotations

from fastapi import APIRouter

from aguard.settings import settings

router = APIRouter()


def authorization_server_metadata() -> dict:
    """RFC 8414 + OIDC discovery (superset of both)."""
    issuer = settings.issuer
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/jwks",
        "introspection_endpoint": f"{issuer}/introspect",
        "revocation_endpoint": f"{issuer}/revoke",
        "registration_endpoint": f"{issuer}/register",   # RFC 7591 (DCR)
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
        # RFC 8707: we accept and enforce the resource parameter
        "resource_indicators_supported": True,  # informational, not a standard key
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


@router.get("/.well-known/openid-configuration")
def openid_configuration() -> dict:
    return authorization_server_metadata()


@router.get("/.well-known/oauth-authorization-server")
def oauth_authorization_server_metadata() -> dict:
    """RFC 8414 — where MCP clients look per the MCP authorization spec."""
    return authorization_server_metadata()
