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

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier

from aguard.mcp.principal import Principal
from aguard.oidc.keys import KeyManager
from aguard.oidc.validation import TokenValidationError, verify_access_token
from aguard.settings import settings


class AGuardTokenVerifier(TokenVerifier):
    def __init__(self, keys: KeyManager | None = None):
        self._keys = keys

    async def verify_token(self, token: str) -> AccessToken | None:
        keys = self._keys
        if keys is None or not token:
            return None
        try:
            claims = verify_access_token(token, keys=keys,
                                         audience=settings.mcp_resource_id)
        except TokenValidationError:
            return None
        roles = claims.get("roles", ["human"])
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id", "")),
            scopes=str(claims.get("scope", "")).split(),
            expires_at=int(claims["exp"]),
            resource=str(claims.get("aud", "")),
            subject=claims["sub"],
            claims={"roles": list(roles) if isinstance(roles, list) else [roles],
                    "iss": claims["iss"]},
        )


def current_principal() -> Principal:
    """Pull the verified principal for this request out of MCP's contextvar.

    Fail-closed: outside authenticated middleware (direct call, skipped
    auth) there is NO principal — tools raise instead of running anonymous.
    """
    token = get_access_token()
    if token is None or token.subject is None:
        raise RuntimeError("no authenticated principal — refusing to run")
    roles = (token.claims or {}).get("roles", ["human"])
    return Principal(
        sub=token.subject,
        roles=frozenset(roles if isinstance(roles, list) else [roles]),
        scopes=frozenset(token.scopes or []),
        client_id=token.client_id,
    )
