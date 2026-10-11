"""Remote JWKS-backed key store for a STANDALONE resource server.

The split design in one sentence: the resource server must be able to verify
tokens without ever holding the signing key. It does that the same way any
third party does — it fetches the issuer's JWKS over HTTP and caches it.

This class presents exactly the small surface ``verify_access_token`` already
consumes from a ``KeyManager`` (``.all_keys`` returning objects with ``.kid``
and ``.public_pem``), so the validation logic — algorithm pinning, kid
allowlist, exact iss/aud, bounded leeway — is reused verbatim rather than
reimplemented. One validator, two key sources; that is the whole point.

Freshness / rotation: keys are cached for ``ttl`` seconds. On an unknown ``kid``
the verifier calls ``refresh()`` once and retries (a rotation just happened
elsewhere), then gives up. Fetch failures serve the last-known-good set rather
than failing closed mid-traffic: a JWKS blip must not 500 every request, and an
unknown kid still fails closed because there is simply no key to match.

The HTTP fetch reuses PyJWT's own ``PyJWKClient.fetch_data`` (urllib under the
hood), so the resource server adds no dependency beyond what it already ships.
"""
from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt.algorithms import RSAAlgorithm


def _jwk_to_pem(jwk: dict) -> bytes:
    """Convert an RSA public JWK to SubjectPublicKeyInfo PEM.

    ``RSAAlgorithm.from_jwk`` is PyJWT's own converter, so we do not hand-roll
    base64url integer decoding here. A non-RSA or malformed JWK raises and is
    skipped by the caller — a bad key in a JWKS must not take down the store.
    """
    public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
    if not isinstance(public_key, RSAPublicKey):
        # from_jwk can hand back a private key object; publishing it is not our
        # job, and serializing one as public would be a bug of the worst kind.
        raise ValueError("JWKS key is not an RSA public key")
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@dataclass(frozen=True)
class RemoteKey:
    """One verification key: opaque kid + public PEM. No private material."""

    kid: str
    public_pem: bytes


class RemoteKeyStore:
    """Cached, refreshable view of an issuer's public JWKS.

    Not a ``KeyManager``: it cannot sign, cannot rotate, and holds no secret.
    That asymmetry is the security property the split buys.
    """

    def __init__(
        self,
        issuer: str,
        *,
        jwks_uri: str | None = None,
        ttl: float = 300.0,
        timeout: float = 5.0,
        fetch: Callable[[], dict] | None = None,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.jwks_uri = jwks_uri or f"{self.issuer}/jwks"
        self.ttl = ttl
        self._lock = threading.RLock()
        self._keys: list[RemoteKey] = []
        self._fetched_at = -1e18
        if fetch is not None:
            self._fetch = fetch
        else:
            # cache_jwk_set=False: freshness is OWNED HERE, not inside PyJWT,
            # so "refresh on unknown kid" is one place and not two half-caches.
            client = pyjwt.PyJWKClient(
                self.jwks_uri, cache_jwk_set=False, timeout=timeout,
                cooldown_duration=1.0,
            )
            self._fetch = client.fetch_data

    def refresh(self) -> None:
        """Fetch the JWKS now and rebuild the key set. Raises on failure."""
        document = self._fetch() or {}
        keys: list[RemoteKey] = []
        for jwk in document.get("keys", []):
            kid = jwk.get("kid")
            if not kid:
                continue
            try:
                keys.append(RemoteKey(kid=str(kid), public_pem=_jwk_to_pem(jwk)))
            except Exception:      # one bad key must not kill the store
                continue
        if not keys:
            raise RuntimeError(f"JWKS at {self.jwks_uri} published no usable keys")
        with self._lock:
            self._keys = keys
            self._fetched_at = time.monotonic()

    def _is_fresh(self) -> bool:
        with self._lock:
            return bool(self._keys) and (
                time.monotonic() - self._fetched_at) < self.ttl

    @property
    def all_keys(self) -> list[RemoteKey]:
        if not self._is_fresh():
            try:
                self.refresh()
            except Exception:
                # Keep serving last-known-good keys; only a cold store (never
                # fetched, nothing cached) surfaces the error.
                with self._lock:
                    if not self._keys:
                        raise
        with self._lock:
            return list(self._keys)


__all__ = ["RemoteKey", "RemoteKeyStore"]
