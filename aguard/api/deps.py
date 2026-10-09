"""Auth dependencies: Bearer -> verified Principal, scopes -> 403s.

401 vs 403 is a deliberate contract (and a real interview question):
  401 = unauthenticated (missing/malformed/invalid token)
  403 = authenticated but not authorized (valid token, wrong scope)

The Authorization header is NEVER logged — the dependency reads it, the
redaction layer treats any accidental echo as a secret.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request

from aguard.oidc.keys import KeyManager
from aguard.oidc.validation import TokenValidationError, verify_access_token


@dataclass(frozen=True)
class Principal:
    sub: str
    roles: frozenset[str]
    scopes: frozenset[str]
    client_id: str
    jti: str


def require_principal(request: Request) -> Principal:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        # NOTE: we do not echo the header value in the error — it is a
        # live credential and error bodies end up in logs.
        raise HTTPException(status_code=401, detail="missing bearer token")
    raw = header[7:].strip()
    keys: KeyManager = request.app.state.keys
    try:
        claims = verify_access_token(raw, keys=keys)
    except TokenValidationError as exc:
        raise HTTPException(status_code=401,
                            detail=f"invalid token: {exc}") from None
    roles = claims.get("roles", ["human"])
    return Principal(
        sub=claims["sub"],
        roles=frozenset(roles if isinstance(roles, list) else [roles]),
        scopes=frozenset(str(claims.get("scope", "")).split()),
        client_id=str(claims.get("client_id", "")),
        jti=str(claims.get("jti", "")),
    )


def require_scope(principal: Principal, scope: str) -> None:
    if scope not in principal.scopes:
        raise HTTPException(
            status_code=403,
            detail=f"insufficient scope: need {scope!r}",
        )
