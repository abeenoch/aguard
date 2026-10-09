"""Refresh tokens: opaque, hashed at rest, ROTATING, with family invalidation.

The lifecycle (RFC 9700 §4.14):

    issue ──rotate──▶ new token, old marked retired
       │                  │
       │                  └─ present retired token AGAIN
       │                        = proof of interception
       │                        = KILL THE ENTIRE FAMILY
       ▼
    family = {token1(retired), token2(retired), token3(active), ...}

Why rotation instead of one long-lived refresh token: a stolen refresh
token is a 2-week credential with no other signal. With rotation, the thief
and the legitimate client race — whoever presents the retired token first
triggers family revocation, so the max damage window collapses to roughly
one rotation period, and the theft is *detected*.

Why hashed at rest: refresh tokens are bearer credentials. A DB/memory dump
of this store must not yield live tokens — same rule as passwords, codes,
and client secrets elsewhere in this codebase.

Why family, not per-token revocation: when reuse is detected you don't know
which holder is the attacker. Revoking only the presented token lets the
attacker keep using their copy; revoking only "the other one" is guesswork.
The family is the unit of trust — burn it all.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass

from app.settings import settings


class RefreshError(Exception):
    """Invalid/expired/unknown refresh token."""


class RefreshReuseError(RefreshError):
    """Retired token presented again — family compromise."""


@dataclass
class RefreshRecord:
    token_hash: str
    family_id: str
    client_id: str
    subject: str
    scope: str
    issued_at: int
    expires_at: int
    retired: bool = False
    revoked: bool = False


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class RefreshTokenStore:
    def __init__(self, ttl_seconds: int | None = None) -> None:
        self._ttl = ttl_seconds if ttl_seconds is not None else settings.refresh_token_ttl
        self._by_hash: dict[str, RefreshRecord] = {}

    def issue(
        self, *, client_id: str, subject: str, scope: str,
        family_id: str | None = None,
    ) -> tuple[str, RefreshRecord]:
        """Returns (raw_token, record). Raw exists only in this return value."""
        now = int(time.time())
        family = family_id or secrets.token_urlsafe(16)
        raw = secrets.token_urlsafe(48)
        record = RefreshRecord(
            token_hash=_hash(raw),
            family_id=family,
            client_id=client_id,
            subject=subject,
            scope=scope,
            issued_at=now,
            expires_at=now + self._ttl,
        )
        self._by_hash[record.token_hash] = record
        self._gc()
        return raw, record

    def rotate(self, raw: str, *, client_id: str) -> tuple[str, RefreshRecord]:
        """Consume `raw`, issue successor in the same family.

        Raises RefreshReuseError (and revokes the family) if the token was
        already rotated. Caller MUST translate that into invalid_grant and
        must not issue anything."""
        record = self._by_hash.get(_hash(raw))
        if record is None:
            raise RefreshError("unknown refresh token")

        if record.revoked:
            raise RefreshError("refresh token revoked")

        if record.retired:
            # REUSE: burn everything traceable to this family, then refuse.
            self._revoke_family(record.family_id)
            raise RefreshReuseError(
                f"refresh token reuse detected; family {record.family_id} revoked"
            )

        if record.expires_at < time.time():
            raise RefreshError("refresh token expired")

        if record.client_id != client_id:
            # token presented to the wrong client — treat as invalid, not a
            # family kill (client mix-ups shouldn't nuke the user's session)
            raise RefreshError("refresh token not issued to this client")

        record.retired = True
        new_raw, new_record = self.issue(
            client_id=record.client_id,
            subject=record.subject,
            scope=record.scope,
            family_id=record.family_id,
        )
        return new_raw, new_record

    def _revoke_family(self, family_id: str) -> None:
        for record in self._by_hash.values():
            if record.family_id == family_id:
                record.revoked = True

    def _gc(self) -> None:
        now = time.time()
        dead = [
            h for h, r in self._by_hash.items()
            if r.expires_at < now and not r.revoked  # keep revoked 1h for forensics? drop for lab
        ]
        for h in dead:
            del self._by_hash[h]
