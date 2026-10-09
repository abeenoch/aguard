"""OIDC userinfo + RFC 7009 revocation + RFC 7662 introspection.

The three endpoints our discovery document has been ADVERTISING since
Milestone 1 without existing — the honesty gap. Now closed.

- /userinfo  (OIDC Core 3.1.3): bearer token -> identity claims. The
  standard way MCP/oidc clients fetch profile data post-token.
- /revoke    (RFC 7009): client-authenticated kill switch for a refresh
  token -> revokes the whole family (same blast radius as reuse detection).
- /introspect(RFC 7662): resource servers ask "is this token alive, and
  what's in it?" — client-authenticated, because the answer is sensitive.
"""
from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse

from aguard.oidc.clients import Client, ClientRegistry
from aguard.oidc.refresh import RefreshTokenStore
from aguard.oidc.users import USERS
from aguard.oidc.validation import TokenValidationError, verify_access_token

router = APIRouter()

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _error(status: int, code: str, description: str) -> JSONResponse:
    return JSONResponse(
        {"error": code, "error_description": description},
        status_code=status, headers=_NO_STORE,
    )


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return None


def _client_auth(request: Request, registry: ClientRegistry,
                  client_id: str | None, client_secret: str | None
                  ) -> tuple[Client | None, JSONResponse | None]:
    """Same rules as the token endpoint: registered method only, or public."""
    from aguard.oidc.routes_token import _authenticate_client
    return _authenticate_client(request, registry, client_id, client_secret)


# ----------------------------------------------------------------- userinfo


def _userinfo(request: Request) -> JSONResponse:
    request.app.state  # touch for type checkers
    token = _bearer_token(request)
    if not token:
        return _error(401, "invalid_token",
                      "bearer token required in Authorization header")
    try:
        claims = verify_access_token(token, keys=request.app.state.keys)
    except TokenValidationError as exc:
        return _error(401, "invalid_token", str(exc))

    # Identity comes from OUR user directory, keyed by the token's sub —
    # never echo arbitrary token claims back (that's a token-smuggling
    # surface). email is returned here BY DESIGN (that's what userinfo is
    # for): this endpoint is authenticated, unlike logs.
    user = USERS.get(claims["sub"])
    body: dict = {"sub": claims["sub"]}
    if user is not None:
        body["email"] = user.email
        body["name"] = user.display_name
        body["amr"] = list(user.amr)
    return JSONResponse(body, headers=_NO_STORE)


router.add_api_route("/userinfo", _userinfo, methods=["GET"])
router.add_api_route("/userinfo", _userinfo, methods=["POST"])


# ------------------------------------------------------------------- revoke


@router.post("/revoke")
def revoke_token(
    request: Request,
    token: str = Form(""),
    token_type_hint: str = Form(""),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
) -> JSONResponse:
    """RFC 7009: MUST return 200 even for unknown tokens (no oracle)."""
    registry: ClientRegistry = request.app.state.registry
    _, auth_error = _client_auth(request, registry, client_id, client_secret)
    if auth_error is not None:
        return auth_error

    store: RefreshTokenStore = request.app.state.refresh
    store.revoke_by_raw(token)   # no-op for unknown tokens; family-wide kill

    # 200 always — telling the caller "that token didn't exist" would be a
    # validity oracle (RFC 7009 §2.2).
    return JSONResponse({}, status_code=200, headers=_NO_STORE)


# --------------------------------------------------------------- introspect


@router.post("/introspect")
def introspect_token(
    request: Request,
    token: str = Form(""),
    token_type_hint: str = Form(""),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
) -> JSONResponse:
    """RFC 7662: authenticated status check. Active access or refresh token."""
    registry: ClientRegistry = request.app.state.registry
    _, auth_error = _client_auth(request, registry, client_id, client_secret)
    if auth_error is not None:
        return auth_error

    # Access token path
    try:
        claims = verify_access_token(token, keys=request.app.state.keys)
        return JSONResponse({
            "active": True,
            "sub": claims["sub"],
            "scope": claims["scope"],
            "client_id": claims.get("client_id", ""),
            "exp": claims["exp"],
            "iat": claims["iat"],
            "iss": claims["iss"],
            "aud": claims["aud"],
            "token_type": "Bearer",
        }, headers=_NO_STORE)
    except TokenValidationError:
        pass

    # Refresh token path
    store: RefreshTokenStore = request.app.state.refresh
    record = store.peek(token)
    if record is not None:
        return JSONResponse({
            "active": True,
            "sub": record.subject,
            "scope": record.scope,
            "client_id": record.client_id,
            "exp": record.expires_at,
            "iat": record.issued_at,
            "token_type": "refresh_token",
        }, headers=_NO_STORE)

    # RFC 7662 §2.2: inactive tokens get {"active": false} — nothing else.
    return JSONResponse({"active": False}, headers=_NO_STORE)
