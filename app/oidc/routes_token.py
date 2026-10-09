"""POST /token — the back channel. Every credential exchange happens here.

Three grants (no others — grant_type is an exact allowlist):

  authorization_code  code + PKCE verifier -> access + id_token + refresh
  refresh_token       rotating refresh     -> access (+ id_token, new refresh)
  client_credentials  agent-as-itself      -> access only (no refresh, no id_token)

Cross-cutting rules encoded below:

- Token responses ALWAYS carry `Cache-Control: no-store` (RFC 6749 §5.1):
  proxies and browser caches must never retain bearer credentials.

- This endpoint must never log request bodies (form contains secrets).
  That is a job for the redaction layer (Part A) — belt here, suspenders there.

- Every failure maps to a spec error code with MINIMAL disclosure: no
  "user doesn't exist", no stack traces, no PII in error_description.

- Client authentication method is whatever the client is REGISTERED for.
  Accepting any method "if it works" reintroduces the credential-in-body
  logging problem for clients that demanded Basic.
"""
from __future__ import annotations

import base64
import binascii
import time
import uuid
from urllib.parse import unquote

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, Response

from app.oidc.clients import Client, ClientRegistry
from app.oidc.codes import AuthCodeStore, CodeError, CodeReplayError
from app.oidc.keys import KeyManager
from app.oidc.pkce import verify_challenge
from app.oidc.refresh import RefreshError, RefreshReuseError, RefreshTokenStore
from app.oidc.users import USERS
from app.settings import settings

router = APIRouter()

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _error(status: int, code: str, description: str) -> JSONResponse:
    return JSONResponse(
        {"error": code, "error_description": description},
        status_code=status,
        headers=_NO_STORE,
    )


def _authenticate_client(
    request: Request, registry: ClientRegistry,
    form_client_id: str | None, form_client_secret: str | None,
) -> tuple[Client | None, JSONResponse | None]:
    """Resolve the caller to a registered Client, or return an OAuth error.

    Precedence: Authorization header beats body (and BOTH at once is
    rejected — ambiguity in credential placement is a spec MUST-NOT and a
    classic confused-deputy enabler)."""
    header = request.headers.get("authorization", "")

    if header.lower().startswith("basic "):
        if form_client_secret:
            return None, _error(400, "invalid_request",
                                "client credentials in both header and body")
        try:
            decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None, _error(400, "invalid_request", "malformed Basic header")
        # RFC 6749 §2.3.1: both halves are form-urlencoded inside Basic
        raw_id, sep, raw_secret = decoded.partition(":")
        if not sep:
            return None, _error(400, "invalid_request", "malformed Basic header")
        client_id, secret = unquote(raw_id), unquote(raw_secret)
        client = registry.authenticate(client_id, secret, "client_secret_basic")
        if client is None:
            return None, _error(401, "invalid_client", "client authentication failed")
        return client, None

    if header:
        return None, _error(401, "invalid_client",
                            "unsupported Authorization scheme")

    if form_client_secret is not None:
        client = registry.authenticate(
            form_client_id or "", form_client_secret, "client_secret_post"
        )
        if client is None:
            return None, _error(401, "invalid_client", "client authentication failed")
        return client, None

    # Public client: id only, and it must be REGISTERED as public.
    # A confidential client sneaking through here would skip its secret.
    client = registry.get(form_client_id or "")
    if client is None or client.is_confidential or client.auth_method != "none":
        return None, _error(401, "invalid_client", "client authentication failed")
    return client, None


def _mint_access_token(
    keys: KeyManager, *, sub: str, scope: str, client_id: str, roles: list[str],
) -> str:
    now = int(time.time())
    return keys.sign({
        "iss": settings.issuer,
        "sub": sub,
        "aud": settings.resource_audience,   # audience-restricted
        "iat": now,
        "exp": now + settings.access_token_ttl,
        "jti": uuid.uuid4().hex,             # unique id -> future denylist/replay logs
        "scope": scope,
        "client_id": client_id,              # WHO is calling (RLS audit trail)
        "roles": roles,                      # capability class -> DB role mapping
    })


def _mint_id_token(
    keys: KeyManager, *, sub: str, client_id: str, nonce: str | None,
) -> str:
    user = USERS[sub]
    now = int(time.time())
    claims = {
        "iss": settings.issuer,
        "sub": sub,
        "aud": client_id,                    # ID token audience = the CLIENT
        "iat": now,
        "exp": now + settings.id_token_ttl,
        "email": user.email,                 # identity — the point of OIDC
        "name": user.display_name,
        "amr": list(user.amr),               # how they authenticated (step-up)
    }
    if nonce:
        claims["nonce"] = nonce              # replay binding for the client
    return keys.sign(claims)


def _roles_for(client: Client) -> list[str]:
    """Client kind drives the roles claim: agent clients get ["agent"]
    REGARDLESS of which human flow they rode in on — the capability class
    travels with the client, the identity travels with `sub`."""
    return ["agent"] if client.kind == "agent" else ["human"]


@router.post("/token")
def token_endpoint(
    request: Request,
    grant_type: str = Form(...),
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    code_verifier: str | None = Form(None),
    refresh_token: str | None = Form(None),
    scope: str | None = Form(None),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
) -> Response:
    registry: ClientRegistry = request.app.state.registry
    keys: KeyManager = request.app.state.keys

    client, auth_error = _authenticate_client(
        request, registry, client_id, client_secret
    )
    if auth_error is not None:
        return auth_error
    assert client is not None

    # ---- grant dispatch: exact allowlist, no fuzzy matching -------------
    if grant_type == "authorization_code":
        return _grant_authorization_code(request, client, keys,
                                         code, redirect_uri, code_verifier)
    if grant_type == "refresh_token":
        return _grant_refresh(request, client, keys, refresh_token, scope)
    if grant_type == "client_credentials":
        return _grant_client_credentials(client, keys, scope)
    return _error(400, "unsupported_grant_type",
                  "grant_type must be authorization_code, refresh_token "
                  "or client_credentials")


def _grant_authorization_code(
    request: Request, client: Client, keys: KeyManager,
    code: str | None, redirect_uri: str | None, code_verifier: str | None,
) -> Response:
    if not code or not redirect_uri or not code_verifier:
        return _error(400, "invalid_request",
                      "code, redirect_uri and code_verifier are required")

    codes: AuthCodeStore = request.app.state.codes
    try:
        record = codes.redeem(code)          # single-use enforced inside
    except CodeReplayError:
        # RFC 9700: replay proves interception — refuse, and (once refresh
        # families are linkable to codes) revoke what this code minted.
        return _error(400, "invalid_grant", "authorization code replay detected")
    except CodeError:
        return _error(400, "invalid_grant", "authorization code invalid or expired")

    # code must match THIS client, THIS redirect_uri — a stolen code is
    # useless to an attacker presenting different parameters
    if record.client_id != client.client_id:
        return _error(400, "invalid_grant", "code was issued to another client")
    if record.redirect_uri != redirect_uri:
        return _error(400, "invalid_grant", "redirect_uri does not match")

    # PKCE: the exchange fails without the verifier that never left the
    # client's back channel — an intercepted code cannot be redeemed
    if not verify_challenge(code_verifier, record.code_challenge,
                            record.code_challenge_method):
        return _error(400, "invalid_grant", "PKCE verification failed")

    scope = record.scope
    resp: dict = {
        "access_token": _mint_access_token(
            keys, sub=record.subject, scope=scope,
            client_id=client.client_id, roles=_roles_for(client),
        ),
        "token_type": "Bearer",
        "expires_in": settings.access_token_ttl,
        "scope": scope,
    }

    if "openid" in scope.split():
        resp["id_token"] = _mint_id_token(
            keys, sub=record.subject, client_id=client.client_id,
            nonce=record.nonce,
        )

    if "refresh_token" in client.grant_types:
        refresh_store: RefreshTokenStore = request.app.state.refresh
        raw_refresh, _ = refresh_store.issue(
            client_id=client.client_id, subject=record.subject, scope=scope,
        )
        resp["refresh_token"] = raw_refresh

    return JSONResponse(resp, headers=_NO_STORE)


def _grant_refresh(
    request: Request, client: Client, keys: KeyManager,
    refresh_token: str | None, requested_scope: str | None,
) -> Response:
    if not refresh_token:
        return _error(400, "invalid_request", "refresh_token is required")

    store: RefreshTokenStore = request.app.state.refresh
    try:
        new_raw, record = store.rotate(refresh_token, client_id=client.client_id)
    except RefreshReuseError:
        # family already burned inside rotate(); generic message outward
        return _error(400, "invalid_grant",
                      "refresh token reuse detected; session revoked")
    except RefreshError:
        return _error(400, "invalid_grant", "refresh token invalid or expired")

    # scope NARROWING only: a refresh request may request a subset of the
    # original grant, never an expansion (token-upgrade attack)
    granted_scope = record.scope
    if requested_scope:
        requested = set(requested_scope.split())
        if not requested <= set(granted_scope.split()):
            return _error(400, "invalid_scope",
                          "scope exceeds originally granted scope")
        granted_scope = " ".join(sorted(requested))

    resp: dict = {
        "access_token": _mint_access_token(
            keys, sub=record.subject, scope=granted_scope,
            client_id=client.client_id, roles=_roles_for(client),
        ),
        "token_type": "Bearer",
        "expires_in": settings.access_token_ttl,
        "scope": granted_scope,
        "refresh_token": new_raw,           # rotation: old one is now retired
    }

    if "openid" in granted_scope.split() and record.subject in USERS:
        # OIDC core 12.2: id_token on refresh carries no nonce
        resp["id_token"] = _mint_id_token(
            keys, sub=record.subject, client_id=client.client_id, nonce=None,
        )

    return JSONResponse(resp, headers=_NO_STORE)


def _grant_client_credentials(client: Client, keys: KeyManager,
                              requested_scope: str | None) -> Response:
    if "client_credentials" not in client.grant_types:
        return _error(400, "unauthorized_client",
                      "client may not use client_credentials")

    if requested_scope:
        requested = set(requested_scope.split())
        if not requested <= set(client.allowed_scopes):
            return _error(400, "invalid_scope", "scope not allowed for client")
        granted = " ".join(sorted(requested))
    else:
        granted = " ".join(sorted(client.allowed_scopes))

    # Machine principal: sub is the CLIENT (no human). No refresh token
    # (nothing to keep alive without a user) and no id_token (no identity —
    # OIDC is for humans; pretending otherwise fabricates a login).
    sub = f"svc:{client.client_id}"
    resp = {
        "access_token": _mint_access_token(
            keys, sub=sub, scope=granted,
            client_id=client.client_id, roles=_roles_for(client),
        ),
        "token_type": "Bearer",
        "expires_in": settings.access_token_ttl,
        "scope": granted,
    }
    return JSONResponse(resp, headers=_NO_STORE)


