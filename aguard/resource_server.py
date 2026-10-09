"""Protect YOUR resource server with a-guard-issued tokens.

This is the other half of the product. a-guard issues tokens; this lets any
MCP server (or plain API) accept them **without holding a signing key** — it
fetches the issuer's JWKS, caches it, and re-resolves when it sees an unknown
`kid`, so key rotation just works. PyJWT's PyJWKClient does that, so this adds
no dependency.

Four checks, all enforced here:
  1. signature   — RS256 against a key from the issuer's JWKS
  2. `iss`       — compared against configuration, never against the token
  3. `aud`       — MUST name THIS resource (RFC 8707). This is the check that
                   stops a token minted for another service being replayed here
  4. `exp`/`nbf` — with bounded leeway, not a library default of ±24h

The 401 carries `WWW-Authenticate: Bearer resource_metadata="..."` so an MCP
client can *discover* the authorization server instead of being configured with
it. That is the MCP spec's discovery path, and it costs one header.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import jwt as pyjwt
from fastapi import HTTPException, Request

DEFAULT_LEEWAY = 60
_ALGORITHM = "RS256"


class TokenError(Exception):
    """Verification failed. The message is safe to log (no token echoed)."""


class ResourceServerGuard:
    """Verify a-guard tokens at the edge of a resource server.

    Example (the whole integration):

        guard = ResourceServerGuard(
            issuer="http://localhost:8000",
            audience="http://localhost:9000/mcp",
        )

        @app.post("/mcp")
        def mcp(request: Request, claims: dict = Depends(guard.dependency())):
            return {"sub": claims["sub"]}
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_uri: str | None = None,
        leeway: int = DEFAULT_LEEWAY,
        required_scopes: tuple[str, ...] = (),
        jwk_client: Any | None = None,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.leeway = leeway
        self.required_scopes = required_scopes
        self._jwk_client = jwk_client or pyjwt.PyJWKClient(
            jwks_uri or f"{self.issuer}/jwks")
        # Where an unauthenticated MCP client should look for the AS.
        self.resource_metadata_url = (
            f"{self.issuer}/.well-known/oauth-protected-resource")

    def verify(self, token: str) -> dict:
        """Return validated claims, or raise TokenError."""
        if not token or not isinstance(token, str):
            raise TokenError("empty token")
        try:
            signing_key = self._jwk_client.get_signing_key_from_jwt(token)
            claims: dict = pyjwt.decode(
                token,
                signing_key.key,
                algorithms=[_ALGORITHM],
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except pyjwt.PyJWTError as exc:
            raise TokenError(f"invalid token: {exc}") from None
        except Exception as exc:      # JWKS unreachable, unknown kid, ...
            raise TokenError(f"could not verify token: {exc}") from None

        if self.required_scopes:
            granted = set(str(claims.get("scope", "")).split())
            if not set(self.required_scopes) <= granted:
                raise TokenError("insufficient scope")
        return claims

    @staticmethod
    def bearer_token(request: Request) -> str:
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            # The header value is never echoed — it is a live credential.
            raise TokenError("missing bearer token")
        return header[7:].strip()

    def challenge(self, detail: str) -> HTTPException:
        """A 401 that tells an MCP client where the AS lives (RFC 9728)."""
        return HTTPException(
            status_code=401,
            detail=detail,
            headers={
                "WWW-Authenticate":
                    f'Bearer resource_metadata="{self.resource_metadata_url}"'
            },
        )

    def verify_request(self, request: Request) -> dict:
        """Claims for the request, or raise HTTPException(401)."""
        try:
            return self.verify(self.bearer_token(request))
        except TokenError as exc:
            raise self.challenge(str(exc)) from None

    def dependency(self) -> Callable[[Request], dict]:
        """A FastAPI dependency: `Depends(guard.dependency())`."""
        def _dependency(request: Request) -> dict:
            return self.verify_request(request)
        return _dependency
