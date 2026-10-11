"""A-guard TokenVerifier: bridges our OIDC tokens to MCP's auth model.

Implements mcp.server.auth.provider.TokenVerifier. On success it returns an
AccessToken with:
  - subject  = our `sub` (identity survives the protocol boundary)
  - scopes   = our space-joined scope claim, split
  - resource = our `aud` — non-negotiable, see below
  - claims["roles"] = our capability class (drives DB sessions in tools)

Why aud is verified HERE and not left to middleware: two layers say no.
Our verifier rejects foreign-audience tokens at verification; the SDK's
`validate_token_resource` check (AuthSettings, enabled in server.py)
compares AccessToken.resource to resource_server_url independently.
A token minted for /api dies twice before touching a tool.
"""
from __future__ import annotations

import logging

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier

from aguard.mcp.principal import Principal
from aguard.oidc.claims import roles_from_claims
from aguard.oidc.validation import (
    KeySet,
    UnknownKeyError,
    verify_access_token,
)
from aguard.settings import settings

logger = logging.getLogger("a-guard.mcp.auth")


class AGuardTokenVerifier(TokenVerifier):
    """Verify a-guard access tokens against a key set.

    The key set is either the AS's own ``KeyManager`` (in-process/tests) or a
    ``RemoteKeyStore`` (the split deployment). This verifier is identical on
    both sides — the resource server simply has no way to SIGN, only to verify
    against public keys it fetched.
    """

    def __init__(self, keys: KeySet | None = None):
        self._keys = keys

    def _verify(self, token: str) -> dict:
        return verify_access_token(token, keys=self._keys,  # type: ignore[arg-type]
                                   audience=settings.mcp_resource_id)

    async def verify_token(self, token: str) -> AccessToken | None:
        keys = self._keys
        if keys is None or not token:
            return None
        try:
            claims = self._verify(token)
        except UnknownKeyError:
            # A key rotation we have not seen yet. Refresh ONCE and retry —
            # only this failure triggers a fetch (see UnknownKeyError), so a
            # forged/expired token cannot make us hammer the JWKS endpoint.
            refresh = getattr(keys, "refresh", None)
            if refresh is None:
                return None
            try:
                refresh()
            except Exception:  # JWKS down: fail closed below
                return None
            try:
                claims = self._verify(token)
            except Exception:  # refresh did not help: fail closed
                return None
        except Exception as exc:
            # Includes TokenValidationError AND a key source that cannot answer
            # (cold RemoteKeyStore with the JWKS unreachable). verify_token must
            # never raise into the SDK: an unverifiable token is simply not
            # authenticated, so fail closed and log the reason (never the token).
            logger.debug("token verification failed: %s", exc)
            return None
        roles = roles_from_claims(claims)
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id", "")),
            scopes=str(claims.get("scope", "")).split(),
            expires_at=int(claims["exp"]),
            resource=str(claims.get("aud", "")),
            subject=claims["sub"],
            # Sorted for determinism; a missing `roles` claim resolved to the
            # LEAST privileged class, never to "human" (aguard/oidc/claims.py).
            claims={"roles": sorted(roles), "iss": claims["iss"]},
        )


def current_principal() -> Principal:
    """Pull the verified principal for this request out of MCP's contextvar.

    Fail-closed: outside authenticated middleware (direct call, skipped
    auth) there is NO principal — tools raise instead of running anonymous.
    """
    token = get_access_token()
    if token is None or token.subject is None:
        raise RuntimeError("no authenticated principal — refusing to run")
    return Principal(
        sub=token.subject,
        roles=roles_from_claims(token.claims),
        scopes=frozenset(token.scopes or []),
        client_id=token.client_id,
    )
