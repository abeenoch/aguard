"""Access-token validation — the RESOURCE SERVER's checklist (the Part B/§6
list, implemented literally).

This function is the single choke point every protected endpoint will call.
Deliberate properties:

1. Algorithm pinned to RS256 in code. The token's own `alg` header is read
   only to REJECT it if it disagrees — `alg:none` and RS256->HS256
   confusion attacks die here. (HS256 with a public key as HMAC secret was
   the 2015 JWT apocalypse; pinning kills the entire class.)

2. `kid` must index one of OUR keys. Unknown kid → reject (do NOT silently
   fall back to any key — that turns key confusion into auth bypass).

3. iss/aud compared EXACTLY against configuration, never against values
   inside the token itself (that would be the token validating itself).

4. exp/nbf enforced with bounded leeway — 60s max, not the ±24h some
   libraries default to.

5. `require` forces exp/iat/iss/aud/sub presence: a token missing `aud`
   isn't "valid but empty", it's a different (attacker-shaped) object.
"""
from __future__ import annotations

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from jwt import PyJWKError  # noqa: F401  (kept for clarity of failure modes)

from app.oidc.keys import ALGORITHM, KeyManager
from app.settings import settings


class TokenValidationError(Exception):
    """Any validation failure. Message is safe to log (contains no PII —
    token payloads are NOT echoed into it)."""


def verify_access_token(
    raw: str,
    *,
    keys: KeyManager,
    issuer: str | None = None,
    audience: str | None = None,
    leeway: int | None = None,
) -> dict:
    """Return validated claims or raise TokenValidationError.

    Order: header inspection (algorithm/kid) → signature → claim checks.
    Signature before claims: never trust structure until authenticity is
    established — parsing attacker-controlled claims first is how filter
    bypasses happen.
    """
    issuer = settings.issuer if issuer is None else issuer
    audience = settings.resource_audience if audience is None else audience
    leeway = settings.clock_skew_leeway if leeway is None else leeway

    if not raw or not isinstance(raw, str):
        raise TokenValidationError("empty token")

    try:
        header = pyjwt.get_unverified_header(raw)
    except pyjwt.PyJWTError as exc:
        raise TokenValidationError(f"malformed token header: {exc}") from None

    # 1. algorithm pinning
    alg = header.get("alg")
    if alg != ALGORITHM:
        raise TokenValidationError(f"disallowed alg {alg!r} (pinned: {ALGORITHM})")

    # 2. kid lookup against OUR keys only
    kid = header.get("kid")
    if not kid:
        raise TokenValidationError("missing kid header")
    key = next((k for k in keys.all_keys if k.kid == kid), None)
    if key is None:
        raise TokenValidationError("kid not in JWKS")

    public_pem = key.private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    try:
        claims = pyjwt.decode(
            raw,
            public_pem,
            algorithms=[ALGORITHM],
            issuer=issuer,
            audience=audience,
            leeway=leeway,
            options={
                "require": ["exp", "iat", "iss", "aud", "sub", "scope"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except pyjwt.ExpiredSignatureError as exc:
        raise TokenValidationError("token expired") from None
    except pyjwt.ImmatureSignatureError:
        raise TokenValidationError("token not yet valid (nbf/iat)") from None
    except pyjwt.InvalidIssuerError:
        raise TokenValidationError("issuer mismatch") from None
    except pyjwt.InvalidAudienceError:
        raise TokenValidationError("audience mismatch") from None
    except pyjwt.MissingRequiredClaimError as exc:
        raise TokenValidationError(f"missing required claim: {exc}") from None
    except pyjwt.InvalidTokenError as exc:
        raise TokenValidationError(f"token invalid: {exc}") from None

    return claims
