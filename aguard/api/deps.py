"""Auth dependencies: Bearer -> verified Principal, scopes -> 403s.

401 vs 403 is a deliberate contract (and a real interview question):
  401 = unauthenticated (missing/malformed/invalid token)
  403 = authenticated but not authorized (valid token, wrong scope)

The Authorization header is NEVER logged — the dependency reads it, the
redaction layer treats any accidental echo as a secret.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import HTTPException, Request

from aguard.oidc.claims import roles_from_claims
from aguard.oidc.keys import KeyManager
from aguard.oidc.validation import TokenValidationError, verify_access_token

log = logging.getLogger("a-guard.api")


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
        # Minimal disclosure: the reason (expired, unknown kid, audience
        # mismatch, bad signature) describes OUR internals. It goes to the
        # (redacted) log; the caller gets a flat 401. 401 vs 403 stays exact —
        # that distinction is the API contract, not a secret.
        log.info("rejected bearer token: %s", exc)
        raise HTTPException(status_code=401, detail="invalid token") from None
    # Capability class from the claim, failing SAFE when it is absent (see
    # aguard/oidc/claims.py) — a missing `roles` must not mean "human".
    return Principal(
        sub=claims["sub"],
        roles=roles_from_claims(claims),
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
