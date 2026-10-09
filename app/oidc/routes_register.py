"""RFC 7591 — Dynamic Client Registration (DCR).

This is the MCP-spec SHOULD that real clients REQUIRE: when you add a
remote MCP server to Claude Desktop, the client registers itself here
before starting the OAuth flow.

Open registration is spec-legal and MCP-expected — which makes INPUT
VALIDATION the entire security story. An unvalidated DCR endpoint is an
open-redirect factory: attacker registers evil redirect_uris once, then
harvests codes from any user who consents.

Validation rules (OAuth 2.1 BCP flavored):
- redirect_uris: absolute URIs, NO fragments, https required except
  loopback (RFC 8252 exception — http://localhost is where devs live)
- grant_types: exact allowlist, no surprises
- token_endpoint_auth_method: only what we can actually enforce
- scope: subset of advertised scopes only (can't self-grant more)
"""
from __future__ import annotations

import secrets
import time
from urllib.parse import urlparse

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.oidc.clients import Client, ClientRegistry, hash_secret

router = APIRouter()

_ALLOWED_GRANTS = {"authorization_code", "refresh_token", "client_credentials"}
_ALLOWED_AUTH_METHODS = {"client_secret_basic", "client_secret_post", "none"}
_ALL_SCOPES = {
    "openid", "profile", "email", "orders:read", "orders:write", "agents:read",
}


def _validate_redirect_uri(uri: str) -> str | None:
    """Return an error reason, or None if acceptable. EXACT-uri rules:
    absolute, no fragment, https — or http on loopback only."""
    parsed = urlparse(uri)
    if not parsed.scheme or not parsed.netloc:
        return f"redirect_uri must be absolute: {uri!r}"
    if parsed.fragment:
        return f"redirect_uri must not contain a fragment: {uri!r}"
    if parsed.scheme == "https":
        return None
    if parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1"):
        return None
    return f"redirect_uri must be https (http allowed for loopback only): {uri!r}"


def _error(status: int, code: str, description: str) -> JSONResponse:
    return JSONResponse(
        {"error": code, "error_description": description}, status_code=status
    )


@router.post("/register")
async def register_client(request: Request) -> JSONResponse:
    registry: ClientRegistry = request.app.state.registry

    try:
        body = await request.json()
    except ValueError:
        return _error(400, "invalid_client_metadata", "body must be JSON")

    # --- redirect_uris: the make-or-break validation ---
    redirect_uris = body.get("redirect_uris", [])
    if not isinstance(redirect_uris, list) or len(redirect_uris) > 10:
        return _error(400, "invalid_redirect_uri",
                      "redirect_uris must be a list of at most 10 URIs")
    for uri in redirect_uris:
        if not isinstance(uri, str):
            return _error(400, "invalid_redirect_uri", "each URI must be a string")
        reason = _validate_redirect_uri(uri)
        if reason:
            return _error(400, "invalid_redirect_uri", reason)

    # --- grant_types: allowlist, and they must make sense together ---
    grant_types = body.get("grant_types", ["authorization_code"])
    if not isinstance(grant_types, list) or not grant_types:
        return _error(400, "invalid_client_metadata", "grant_types required")
    if not set(grant_types) <= _ALLOWED_GRANTS:
        return _error(400, "invalid_client_metadata",
                      f"grant_types must be subset of {sorted(_ALLOWED_GRANTS)}")
    if "authorization_code" in grant_types and not redirect_uris:
        return _error(400, "invalid_redirect_uri",
                      "authorization_code grant requires redirect_uris")

    # --- token endpoint auth method ---
    auth_method = body.get("token_endpoint_auth_method", "client_secret_basic")
    if auth_method not in _ALLOWED_AUTH_METHODS:
        return _error(400, "invalid_client_metadata",
                      f"token_endpoint_auth_method must be one of "
                      f"{sorted(_ALLOWED_AUTH_METHODS)}")

    # --- scope: subset of ours, never a superset (no self-granting) ---
    requested_scope = body.get("scope", "openid profile")
    if not isinstance(requested_scope, str):
        return _error(400, "invalid_client_metadata", "scope must be a string")
    scopes = set(requested_scope.split())
    if not scopes <= _ALL_SCOPES:
        return _error(400, "invalid_scope", "requested scope not supported")

    # --- mint the registration ---
    client_id = f"dcr-{secrets.token_urlsafe(12)}"
    secret = secrets.token_urlsafe(32) if auth_method != "none" else None

    # An agent-shaped registration (client_credentials, no browser flow)
    # gets agent capability class — the roles claim follows from this.
    kind = "agent" if "authorization_code" not in grant_types else "human"

    registry.register(Client(
        client_id=client_id,
        client_secret_hash=hash_secret(secret) if secret else None,
        redirect_uris=tuple(redirect_uris),
        allowed_scopes=frozenset(scopes),
        grant_types=frozenset(grant_types),
        auth_method=auth_method,
        kind=kind,
    ))

    response: dict = {
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "client_secret_expires_at": 0,          # 0 = never expires (RFC 7591)
        "client_name": body.get("client_name", ""),
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "token_endpoint_auth_method": auth_method,
        "scope": requested_scope,
    }
    if secret:
        # The ONLY time the plaintext secret exists — hashed before storage.
        response["client_secret"] = secret
    return JSONResponse(response, status_code=201)
