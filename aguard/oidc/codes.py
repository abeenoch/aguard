"""Single-use authorization codes with TTL + replay detection.

Lifecycle of a code:
    /authorize issues  → raw code exists for ONE response, hash stored
    /token redeems     → hash popped, record returned, single use enforced
    replay attempt     → detected via tombstones → treated as theft (RFC 9700)

Design decisions worth defending:

1. Store the HASH, not the code. A memory dump, core file, or accidental
   `logger.debug(store)` must not yield redeemable codes.

2. Tombstones for used codes. Naive pop-on-read makes replay *undetectable* —
   attacker steals code, legit client redeems first, attacker's attempt looks
   like a miss. RFC 9700 says replay = proof of interception → the token
   family issued from that code must be revoked. Tombstones give us the
   signal to do that (full family revocation lands with refresh tokens).

3. 60s TTL (settings.auth_code_ttl). Codes are transitionary objects; every
   second of lifetime is an second of interception window. RFC 6749 suggests
   10 minutes max — we're an order of magnitude tighter because nothing
   legitimate needs longer (the user consented *just now*).

4. Two backends (aguard/oidc/stores.py). In-memory is correct for a single
   process; Postgres makes tombstones survive restarts and be visible to every
   worker. That matters for SECURITY, not just uptime: with per-process
   tombstones, a replay handled by a different worker goes undetected.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Protocol

from aguard.settings import settings


class CodeError(Exception):
    """Invalid, expired, or unknown code."""


class CodeReplayError(Exception):
    """A code that was ALREADY redeemed is being presented again."""


@dataclass(frozen=True)
class AuthCodeRecord:
    code_hash: str
    client_id: str
    redirect_uri: str
    subject: str                # the human who consented (sub claim source)
    scope: str
    code_challenge: str         # S256 challenge bound at /authorize
    code_challenge_method: str
    nonce: str | None
    issued_at: int
    expires_at: int
    resource: str | None = None  # RFC 8707: aud binding requested at authorize



def _hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


class AuthCodeStore(Protocol):
    """Storage contract for authorization codes.

    Routes depend on THIS, never on a concrete class. Two implementations
    ship (aguard/oidc/stores.py): InMemoryAuthCodeStore for a single process, and
    PostgresAuthCodeStore for shared, restart-durable state."""

    def issue(self, *, client_id: str, redirect_uri: str, subject: str,
              scope: str, code_challenge: str, code_challenge_method: str,
              nonce: str | None, resource: str | None = None) -> str: ...

    def redeem(self, code: str) -> AuthCodeRecord: ...


class InMemoryAuthCodeStore:
    """Single-process store.

    Correct for exactly one worker. With several workers, a code redeemed by
    worker A is invisible to worker B — so B cannot see the tombstone and a
    replay goes UNDETECTED. That is a security failure, not just an
    availability one, which is why the shared backend exists.
    """

    def __init__(self, ttl_seconds: int | None = None) -> None:
        self._ttl = ttl_seconds if ttl_seconds is not None else settings.auth_code_ttl
        self._live: dict[str, AuthCodeRecord] = {}
        # tombstone -> expiry; long enough to catch late replays, short enough
        # that the table can't be grown by an attacker into a memory DoS
        self._used: dict[str, float] = {}

    def issue(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        subject: str,
        scope: str,
        code_challenge: str,
        code_challenge_method: str,
        nonce: str | None,
        resource: str | None = None,
    ) -> str:
        now = int(time.time())
        raw = secrets.token_urlsafe(48)
        record = AuthCodeRecord(
            code_hash=_hash(raw),
            client_id=client_id,
            redirect_uri=redirect_uri,
            subject=subject,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            issued_at=now,
            expires_at=now + self._ttl,
            resource=resource,
        )
        self._live[record.code_hash] = record
        self._gc()
        return raw  # the ONLY moment the plaintext exists

    def redeem(self, code: str) -> AuthCodeRecord:
        """Consume a code exactly once. Raises CodeReplayError on second use."""
        code_hash = _hash(code)

        if code_hash in self._used:
            raise CodeReplayError("authorization code replay detected")

        record = self._live.pop(code_hash, None)
        if record is None:
            raise CodeError("unknown authorization code")

        if record.expires_at < time.time():
            raise CodeError("authorization code expired")

        self._used[code_hash] = time.time() + 600  # tombstone for 10 min
        return record

    def _gc(self) -> None:
        now = time.time()
        expired = [h for h, r in self._live.items() if r.expires_at < now]
        for h in expired:
            del self._live[h]
        stale = [h for h, t in self._used.items() if t < now]
        for h in stale:
            del self._used[h]


class PostgresAuthCodeStore:
    """Shared store: tombstones survive restarts and every worker sees them.

    Single-use is enforced by the database rather than by process memory:
    SELECT ... FOR UPDATE plus the `redeemed_at IS NULL` guard means two
    workers racing on the same code cannot both win.
    """

    _TOMBSTONE_SECONDS = 600          # matches InMemoryAuthCodeStore

    def __init__(self, ttl_seconds: int | None = None) -> None:
        self._ttl = ttl_seconds if ttl_seconds is not None else settings.auth_code_ttl

    def issue(self, *, client_id: str, redirect_uri: str, subject: str,
              scope: str, code_challenge: str, code_challenge_method: str,
              nonce: str | None, resource: str | None = None) -> str:
        from aguard.db.session import service_session
        now = int(time.time())
        raw = secrets.token_urlsafe(48)
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO auth_codes(code_hash, client_id, redirect_uri,"
                    " subject, scope, code_challenge, code_challenge_method,"
                    " nonce, resource, issued_at, expires_at)"
                    " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (_hash(raw), client_id, redirect_uri, subject, scope,
                     code_challenge, code_challenge_method, nonce, resource,
                     now, now + self._ttl))
                self._gc(cur, now)
        return raw                        # the ONLY moment the plaintext exists

    def redeem(self, code: str) -> AuthCodeRecord:
        from aguard.db.session import service_session
        now = int(time.time())
        code_hash = _hash(code)
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT client_id, redirect_uri, subject, scope,"
                    " code_challenge, code_challenge_method, nonce, resource,"
                    " issued_at, expires_at, redeemed_at"
                    " FROM auth_codes WHERE code_hash = %s FOR UPDATE",
                    (code_hash,))
                row = cur.fetchone()
                if row is None:
                    raise CodeError("unknown authorization code")
                (client_id, redirect_uri, subject, scope, challenge, method,
                 nonce, resource, issued_at, expires_at, redeemed_at) = row
                if redeemed_at is not None:
                    # Tombstone hit: a code already spent is being presented
                    # again. That is the interception signal (RFC 9700).
                    raise CodeReplayError("authorization code replay detected")
                # Compare against a float clock (matching the in-memory store):
                # with an int-truncated "now", a code expiring at exactly this
                # second would stay alive for the rest of it.
                if expires_at < time.time():
                    raise CodeError("authorization code expired")
                cur.execute("UPDATE auth_codes SET redeemed_at = %s"
                            " WHERE code_hash = %s", (now, code_hash))
                return AuthCodeRecord(
                    code_hash=code_hash, client_id=client_id,
                    redirect_uri=redirect_uri, subject=subject, scope=scope,
                    code_challenge=challenge, code_challenge_method=method,
                    nonce=nonce, issued_at=issued_at, expires_at=expires_at,
                    resource=resource)

    def _gc(self, cur, now: int) -> None:
        cur.execute(
            "DELETE FROM auth_codes"
            " WHERE (redeemed_at IS NULL AND expires_at < %s)"
            "    OR (redeemed_at IS NOT NULL AND redeemed_at < %s)",
            (now, now - self._TOMBSTONE_SECONDS))
