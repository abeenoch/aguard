"""RSA signing-key management: generation, RFC 7638 thumbprints, rotation, JWKS.

Why hand-rolled: key *lifecycle* — deterministic kids, rotation with a
verification overlap window, atomic persistence, JWKS that never leaks private
material — is exactly the part implementations get wrong (the classic outage:
"we rotated the key and every service started 401ing"). Crypto primitives come
from `cryptography`; everything about lifecycle is ours.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import jwt  # PyJWT: serialization only — all policy lives in this codebase
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ALGORITHM = "RS256"
KEY_SIZE = 2048
_PUBLIC_EXPONENT = 65537


def _b64u(data: bytes) -> str:
    """base64url without padding — the JWS/JWK encoding rule (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_int(value: int) -> str:
    return _b64u(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def jwk_thumbprint(n: int, e: int) -> str:
    """RFC 7638 JWK Thumbprint — used as our `kid`.

    Deterministic: same key material -> same kid, forever, across processes
    and machines. That property is what lets validators cache JWKS, match a
    token's `kid` header to a key after a restart, and survive rotation.

    The canonical JSON MUST have lexicographically sorted required members
    ({"e","kty","n"}) and compact separators — any deviation produces a
    different digest and a kid nothing else in the ecosystem agrees with.
    """
    canonical = json.dumps(
        {"e": _b64u_int(e), "kty": "RSA", "n": _b64u_int(n)},
        separators=(",", ":"),
        sort_keys=True,
    )
    return _b64u(hashlib.sha256(canonical.encode("ascii")).digest())


@dataclass
class ManagedKey:
    kid: str
    pem: str          # PKCS#8 private key — must never leave keystore/process
    created_at: int
    status: str       # "active" (signs) | "retired" (verify-only, rotation overlap)

    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        return serialization.load_pem_private_key(self.pem.encode(), password=None)

    def public_jwk(self) -> dict:
        """Public half as a JWK. Structurally cannot contain private members
        (`d`, `p`, `q`) — they are never read here."""
        pub = self.private_key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": ALGORITHM,
            "kid": self.kid,
            "n": _b64u_int(pub.n),
            "e": _b64u_int(pub.e),
        }


class KeyManager:
    def __init__(self, key_dir: Path):
        self._dir = Path(key_dir)
        self._store = self._dir / "keys.json"
        self._keys: list[ManagedKey] = []
        self._load_or_create()

    # -- lifecycle -------------------------------------------------------

    def _load_or_create(self) -> None:
        """Load existing keystore or mint the first active key.

        kid stability across restarts is a hard requirement: tokens minted
        before a redeploy must still validate after it."""
        if self._store.exists():
            raw = json.loads(self._store.read_text(encoding="utf-8"))
            self._keys = [ManagedKey(**item) for item in raw["keys"]]
            if not any(k.status == "active" for k in self._keys):
                raise RuntimeError("keystore has no active key — corrupt state")
            return
        self._dir.mkdir(parents=True, exist_ok=True)
        self._keys = [self._generate(status="active")]
        self._persist()

    def _generate(self, status: str) -> ManagedKey:
        key = rsa.generate_private_key(
            public_exponent=_PUBLIC_EXPONENT, key_size=KEY_SIZE
        )
        pub = key.public_key().public_numbers()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        return ManagedKey(
            kid=jwk_thumbprint(pub.n, pub.e),
            pem=pem,
            created_at=int(time.time()),
            status=status,
        )

    def rotate(self) -> ManagedKey:
        """Demote current active -> retired, mint a new active key.

        The old key STAYS in the JWKS: every access/id token it signed remains
        verifiable for up to its TTL. Dropping it on rotation = every in-flight
        token 401s instantly — the rotation outage described above."""
        for key in self._keys:
            if key.status == "active":
                key.status = "retired"
        new_key = self._generate(status="active")
        self._keys.append(new_key)
        self._persist()
        return new_key

    def retire_expired(self, max_token_ttl: int) -> list[str]:
        """Remove retired keys older than the longest token TTL.

        Without this, JWKS grows forever; with premature removal, old tokens
        break. The guard is simple: a retired key is only droppable once no
        token signed by it can still be alive."""
        cutoff = int(time.time()) - max_token_ttl
        kept, dropped = [], []
        for key in self._keys:
            if key.status == "retired" and key.created_at < cutoff:
                dropped.append(key.kid)
            else:
                kept.append(key)
        if dropped:
            self._keys = kept
            self._persist()
        return dropped

    def _persist(self) -> None:
        """Atomic write — never leave a half-written keystore on a crash,
        which would brick the server on next boot."""
        payload = {"keys": [asdict(k) for k in self._keys]}
        tmp = self._store.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self._store)

    # -- accessors -------------------------------------------------------

    @property
    def active(self) -> ManagedKey:
        return next(k for k in self._keys if k.status == "active")

    @property
    def all_keys(self) -> list[ManagedKey]:
        return list(self._keys)

    @property
    def jwks(self) -> dict:
        return {"keys": [k.public_jwk() for k in self._keys]}

    def sign(self, claims: dict, *, headers: dict | None = None) -> str:
        """Sign a JWT with the active key, `kid` header injected.

        Callers build the claims; this layer only guarantees algorithm pinning
        (RS256 — never whatever the caller suggests) and key selection."""
        merged = {"kid": self.active.kid, **(headers or {})}
        return jwt.encode(claims, self.active.pem, algorithm=ALGORITHM, headers=merged)

