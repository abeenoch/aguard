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
import threading
import time
from dataclasses import asdict, dataclass
from functools import cached_property
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
    # When this key stopped signing. The grace window for removal is measured
    # from HERE, not from created_at: see retire_expired(). None means
    # "unknown" (a keystore written before this field existed).
    retired_at: int | None = None

    @cached_property
    def private_key(self) -> rsa.RSAPrivateKey:
        """Parse the PEM once and reuse it, narrowed to RSA at RUNTIME.

        Re-parsing PKCS#8 on every access put an RSA parse on the hottest path
        in the server — every token validation and every /jwks render — for a
        value that is a pure function of the immutable ``pem`` field. ``pem`` is
        never reassigned, so the cache cannot go stale. (This is a mutable
        dataclass, but the only mutation is status/retired_at during rotation;
        key MATERIAL is fixed at construction.)

        The keystore is a file on disk, so a non-RSA key (corruption, a stray
        hand-edit, a future key type) must fail loudly here — not later as a
        JWKS that nothing can verify against, or as a signature nobody accepts.
        """
        key = serialization.load_pem_private_key(self.pem.encode(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise RuntimeError(
                f"keystore key {self.kid[:8]}… is not an RSA private key")
        return key

    @cached_property
    def public_pem(self) -> bytes:
        """SubjectPublicKeyInfo PEM, cached — see private_key for the reasoning.

        This is exactly what a remote resource server derives to verify a token,
        so caching it makes verification a dict lookup instead of a key
        reconstruction.
        """
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

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
    def __init__(self, key_dir: Path, *, max_token_ttl: int | None = None):
        self._dir = Path(key_dir)
        self._store = self._dir / "keys.json"
        self._keys: list[ManagedKey] = []
        # Guards every read-modify-write of the keystore. Sync endpoints run in
        # Starlette's threadpool, and /jwks reads concurrently with a rotation
        # in another thread — without this, a rotation can be lost or a reader
        # can observe a half-updated list.
        self._lock = threading.RLock()
        # (mtime_ns, size) of the file as last seen by THIS process. Used to
        # notice when another worker rotated the keystore on disk: with several
        # workers each holds its own copy, and a copy that never refreshes keeps
        # publishing a JWKS the other workers already retired — the multi-worker
        # face of the "every service 401s after rotation" outage.
        self._seen: tuple[int, int] | None = None
        self._load_or_create()
        if max_token_ttl is not None:
            # Startup is the one path that reliably runs, so it is where
            # housekeeping belongs: a retired key that can no longer be signing
            # anything live is pruned here, keeping JWKS from growing forever
            # across rotations. Tests construct without a TTL and therefore
            # never prune implicitly.
            self.retire_expired(max_token_ttl=max_token_ttl)

    # -- lifecycle -------------------------------------------------------

    def _load_or_create(self) -> None:
        """Load existing keystore or mint the first active key.

        kid stability across restarts is a hard requirement: tokens minted
        before a redeploy must still validate after it."""
        if self._store.exists():
            self._keys = self._read_store()
            self._seen = self._stamp()
            if not any(k.status == "active" for k in self._keys):
                raise RuntimeError("keystore has no active key — corrupt state")
            return
        self._dir.mkdir(parents=True, exist_ok=True)
        self._keys = [self._generate(status="active")]
        self._persist()

    def _read_store(self) -> list[ManagedKey]:
        raw = json.loads(self._store.read_text(encoding="utf-8"))
        return [ManagedKey(**item) for item in raw["keys"]]

    def _stamp(self) -> tuple[int, int] | None:
        try:
            st = self._store.stat()
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def _refresh_if_changed(self) -> None:
        """Reload the keystore if another worker changed it on disk.

        Cheap guard: one ``stat()`` per access. Only reloads when the file's
        mtime/size moved, so the steady state is a syscall, not a parse. A
        malformed external edit is ignored (keep serving the last good keys) —
        a bad keystore must not take down a server that is currently signing
        valid tokens; startup is where a corrupt store should fail loudly.
        """
        stamp = self._stamp()
        if stamp is not None and stamp != self._seen:
            try:
                keys = self._read_store()
            except (ValueError, KeyError):
                return
            if any(k.status == "active" for k in keys):
                self._keys = keys
                self._seen = stamp


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
        token 401s instantly — the rotation outage described above.

        retired_at is stamped as the key stops signing, because that — not
        created_at — is what the removal grace window must be measured from.

        Held under the lock for the whole read-modify-write: two concurrent
        rotations would otherwise each read the same active key, demote it
        twice, and the loser's new key would be overwritten — a rotation that
        silently did not happen."""
        with self._lock:
            now = int(time.time())
            for key in self._keys:
                if key.status == "active":
                    key.status = "retired"
                    key.retired_at = now
            new_key = self._generate(status="active")
            self._keys.append(new_key)
            self._persist()
            return new_key

    def retire_expired(self, max_token_ttl: int) -> list[str]:
        """Remove retired keys once nothing they signed can still be valid.

        The guard is on the RETIREMENT time, not the creation time. A signing
        key typically lives for months, so gating on created_at (the
        obvious-looking version of this check) deletes a key the instant it is
        rotated — while tokens signed moments earlier are still valid for their
        full TTL. Reproduced before this was fixed: a 30-day-old key rotated
        once and then pruned with max_token_ttl=900 took a token that still had
        15 minutes of life down with it ("kid not in JWKS"), which is precisely
        the rotation outage this class exists to prevent.

        A key with no retirement timestamp (a keystore written before
        retired_at existed) is never dropped. Unknown age must fail toward
        KEEPING the key: an extra key costs some JWKS bytes, whereas a key
        dropped early 401s live traffic.

        Without this, JWKS grows forever; with it done wrong, old tokens break.
        """
        with self._lock:
            now = int(time.time())
            kept, dropped = [], []
            for key in self._keys:
                if (key.status == "retired"
                        and key.retired_at is not None
                        and key.retired_at + max_token_ttl < now):
                    dropped.append(key.kid)
                else:
                    kept.append(key)
            if dropped:
                self._keys = kept
                self._persist()
            return dropped

    def _persist(self) -> None:
        """Atomic write — never leave a half-written keystore on a crash,
        which would brick the server on next boot. Caller holds self._lock."""
        payload = {"keys": [asdict(k) for k in self._keys]}
        tmp = self._store.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self._store)
        # Record what we just wrote so a sibling worker's copy of the same
        # content isn't mistaken for a change, and so our own next access
        # doesn't reload what we already have.
        self._seen = self._stamp()

    # -- accessors -------------------------------------------------------

    @property
    def active(self) -> ManagedKey:
        with self._lock:
            self._refresh_if_changed()
            return next(k for k in self._keys if k.status == "active")

    @property
    def all_keys(self) -> list[ManagedKey]:
        with self._lock:
            self._refresh_if_changed()
            return list(self._keys)

    @property
    def jwks(self) -> dict:
        with self._lock:
            self._refresh_if_changed()
            return {"keys": [k.public_jwk() for k in self._keys]}

    def sign(self, claims: dict, *, headers: dict | None = None) -> str:
        """Sign a JWT with the active key, `kid` header injected.

        Callers build the claims; this layer only guarantees algorithm pinning
        (RS256 — never whatever the caller suggests) and key selection.

        The active key is read once, under the lock, so the kid header and the
        signature always come from the same key even if another thread rotates
        mid-call."""
        with self._lock:
            self._refresh_if_changed()
            active = next(k for k in self._keys if k.status == "active")
            kid, pem = active.kid, active.pem
        merged = {"kid": kid, **(headers or {})}
        return jwt.encode(claims, pem, algorithm=ALGORITHM, headers=merged)

