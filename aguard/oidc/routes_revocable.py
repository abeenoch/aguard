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

import logging

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse

from aguard.oidc.clients import Client, ClientRegistry
from aguard.oidc.refresh import RefreshTokenStore
from aguard.oidc.users import USERS
from aguard.oidc.validation import TokenValidationError, verify_access_token
from aguard.settings import settings

router = APIRouter()

log = logging.getLogger("a-guard.oidc")

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
                 client_id: str | None, client_secret: str | None,
                 *, require_confidential: bool = False
                 ) -> tuple[Client | None, JSONResponse | None]:
    """Same rules as the token endpoint: the registered method, or public.

    require_confidential exists because a PUBLIC client authenticates by NAME
    only — it holds no secret, so naming one proves nothing. An endpoint whose
    answer depends on who is asking (/introspect) cannot accept that: RFC 7662
    §2.1 requires authentication for exactly this reason.
    """
    from aguard.oidc.routes_token import _authenticate_client
    client, error = _authenticate_client(request, registry, client_id,
                                         client_secret)
    if error is not None:
        return None, error
    if require_confidential and (client is None or not client.is_confidential):
        # Deliberately the same wording as every other authentication failure:
        # naming a public client must not be distinguishable from naming a
        # client that does not exist.
        return None, _error(401, "invalid_client", "client authentication failed")
    return client, None


def _may_inspect(client: Client, token_owner: str | None) -> bool:
    """May this authenticated client see that token's claims? (RFC 7662 §2.4)

    Owner-only by default: introspection answers questions about a token, so
    the only caller entitled to the answer is the client the token was issued
    to. INTROSPECTION_CLIENTS is the deliberate exception — a resource server
    or ops tool that must inspect tokens it never received — and it is empty
    unless an operator opts in.
    """
    if client.client_id in settings.introspection_clients:
        return True
    return token_owner is not None and token_owner == client.client_id


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
        # Minimal disclosure: the reason (expired, unknown kid, audience
        # mismatch) describes OUR internal state, so it goes to the log and
        # never into a body an unauthenticated caller can read.
        log.info("userinfo rejected: %s", exc)
        return _error(401, "invalid_token", "the access token is not valid")

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
    """RFC 7009: MUST return 200 even for unknown tokens (no oracle).

    Ownership is enforced — a client may revoke only tokens issued to it — but
    a FOREIGN token is answered exactly like an unknown one (200, nothing
    revoked) rather than with an error. An error would tell the caller that the
    value it holds is a live token belonging to somebody else, which is the
    oracle §2.2 exists to avoid.

    Public clients stay allowed here, unlike at /introspect: revoking requires
    already possessing the token, so naming a public client grants nothing
    extra — and a PKCE public client must be able to kill its own stolen token.
    """
    registry: ClientRegistry = request.app.state.registry
    client, auth_error = _client_auth(request, registry, client_id, client_secret)
    if auth_error is not None:
        return auth_error
    assert client is not None

    store: RefreshTokenStore = request.app.state.refresh
    owner = store.owner_of(token)
    if owner is None or owner == client.client_id:
        store.revoke_by_raw(token)   # no-op for unknown tokens; family-wide kill
    else:
        log.info("revocation refused: token belongs to another client")

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
    """RFC 7662: authenticated status check. Active access or refresh token.

    Authentication is REQUIRED (confidential clients only). §2.1 mandates it
    specifically to prevent token scanning, and a PUBLIC client authenticates
    by NAME alone — accepting one here would let anybody name demo-spa and
    start probing token values. Answers are additionally restricted to tokens
    the caller owns (see _may_inspect).

    Anything not ours answers exactly like anything not found — {"active":
    false} — so this endpoint cannot be used to learn whose token a value is.
    """
    registry: ClientRegistry = request.app.state.registry
    client, auth_error = _client_auth(request, registry, client_id, client_secret,
                                      require_confidential=True)
    if auth_error is not None:
        return auth_error
    assert client is not None

    # Access token path
    try:
        claims = verify_access_token(token, keys=request.app.state.keys)
    except TokenValidationError:
        pass
    else:
        if not _may_inspect(client, claims.get("client_id")):
            return JSONResponse({"active": False}, headers=_NO_STORE)
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

    # Refresh token path
    store: RefreshTokenStore = request.app.state.refresh
    record = store.peek(token)
    if record is not None and _may_inspect(client, record.client_id):
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
