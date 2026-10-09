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
from typing import Protocol

from aguard.settings import settings


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


class RefreshTokenStore(Protocol):
    """Storage contract for refresh tokens (see aguard/oidc/stores.py)."""

    def issue(self, *, client_id: str, subject: str, scope: str,
              family_id: str | None = None) -> tuple[str, RefreshRecord]: ...

    def rotate(self, raw: str, *, client_id: str) -> tuple[str, RefreshRecord]: ...

    def revoke_by_raw(self, raw: str) -> bool: ...

    def owner_of(self, raw: str) -> str | None:
        """The client_id this token was issued to, or None if unknown.

        Reads ANY record — live, retired, revoked or expired — because
        revocation must work on a token the client has already rotated away
        from, which is precisely the case after a theft. It answers WHO owns
        the token and never whether it is still usable, so it is not a
        validity oracle. Used to stop one client revoking another's family.
        """
        ...

    def peek(self, raw: str) -> RefreshRecord | None: ...


class InMemoryRefreshTokenStore:
    """Single-process store.

    Same caveat as InMemoryAuthCodeStore, and here it is sharper: reuse
    detection and family revocation live in this process's dict. Run two
    workers and the thief can rotate against the worker that has not yet seen
    the retirement — the family never burns.
    """

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

    def revoke_by_raw(self, raw: str) -> bool:
        """RFC 7009 revocation: kill the family owning this refresh token.

        Returns True if a family was revoked. Unknown tokens are a silent
        no-op — no validity oracle (RFC 7009 §2.2)."""
        record = self._by_hash.get(_hash(raw)) if raw else None
        if record is None:
            return False
        self._revoke_family(record.family_id)
        return True

    def owner_of(self, raw: str) -> str | None:
        """Owning client_id of any record, regardless of state."""
        record = self._by_hash.get(_hash(raw)) if raw else None
        return record.client_id if record is not None else None

    def peek(self, raw: str) -> RefreshRecord | None:
        """RFC 7662 introspection view: valid, unrevoked record or None.

        Read-only — unlike rotate() it never consumes the token."""
        record = self._by_hash.get(_hash(raw)) if raw else None
        if record is None or record.revoked or record.retired:
            return None
        if record.expires_at < time.time():
            return None
        return record

    def _gc(self) -> None:
        now = time.time()
        dead = [
            h for h, r in self._by_hash.items()
            if r.expires_at < now and not r.revoked  # keep revoked 1h for forensics? drop for lab
        ]
        for h in dead:
            del self._by_hash[h]


class PostgresRefreshTokenStore:
    """Shared store: reuse detection and family revocation span workers.

    The subtle part is the reuse path. Revoking the family and then raising
    would ROLL BACK the revocation (service_session rolls back on exception),
    handing the attacker a still-working token — so the revocation is written
    inside the transaction, the transaction is allowed to COMMIT, and only
    then do we raise.
    """

    def __init__(self, ttl_seconds: int | None = None) -> None:
        self._ttl = (ttl_seconds if ttl_seconds is not None
                     else settings.refresh_token_ttl)

    def issue(self, *, client_id: str, subject: str, scope: str,
              family_id: str | None = None) -> tuple[str, RefreshRecord]:
        from aguard.db.session import service_session
        now = int(time.time())
        raw = secrets.token_urlsafe(48)
        record = RefreshRecord(
            token_hash=_hash(raw),
            family_id=family_id or secrets.token_urlsafe(16),
            client_id=client_id, subject=subject, scope=scope,
            issued_at=now, expires_at=now + self._ttl)
        with service_session() as conn:
            with conn.cursor() as cur:
                _insert_record(cur, record)
                self._gc(cur, now)
        return raw, record

    def rotate(self, raw: str, *, client_id: str) -> tuple[str, RefreshRecord]:
        from aguard.db.session import service_session
        now = int(time.time())
        reuse_family: str | None = None
        result: tuple[str, RefreshRecord] | None = None
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT family_id, client_id, subject, scope, issued_at,"
                    " expires_at, retired, revoked FROM refresh_tokens"
                    " WHERE token_hash = %s FOR UPDATE", (_hash(raw),))
                row = cur.fetchone()
                if row is None:
                    raise RefreshError("unknown refresh token")
                (family, cid, subject, scope, issued_at, expires_at,
                 retired, revoked) = row
                if revoked:
                    raise RefreshError("refresh token revoked")
                if retired:
                    cur.execute("UPDATE refresh_tokens SET revoked = true"
                                " WHERE family_id = %s", (family,))
                    reuse_family = family          # commit, THEN raise
                elif expires_at < time.time():
                    # float clock, matching InMemoryRefreshTokenStore
                    raise RefreshError("refresh token expired")
                elif cid != client_id:
                    raise RefreshError(
                        "refresh token not issued to this client")
                else:
                    cur.execute("UPDATE refresh_tokens SET retired = true"
                                " WHERE token_hash = %s", (_hash(raw),))
                    new_raw = secrets.token_urlsafe(48)
                    successor = RefreshRecord(
                        token_hash=_hash(new_raw), family_id=family,
                        client_id=cid, subject=subject, scope=scope,
                        issued_at=now, expires_at=now + self._ttl)
                    _insert_record(cur, successor)
                    result = (new_raw, successor)
        if reuse_family is not None:
            raise RefreshReuseError(
                f"refresh token reuse detected; family {reuse_family} revoked")
        assert result is not None
        return result

    def revoke_by_raw(self, raw: str) -> bool:
        from aguard.db.session import service_session
        if not raw:
            return False
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT family_id FROM refresh_tokens"
                            " WHERE token_hash = %s", (_hash(raw),))
                row = cur.fetchone()
                if row is None:
                    return False                # no validity oracle
                cur.execute("UPDATE refresh_tokens SET revoked = true"
                            " WHERE family_id = %s", (row[0],))
                return True

    def owner_of(self, raw: str) -> str | None:
        """Owning client_id of any record, regardless of state."""
        from aguard.db.session import service_session
        if not raw:
            return None
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT client_id FROM refresh_tokens"
                            " WHERE token_hash = %s", (_hash(raw),))
                row = cur.fetchone()
        return row[0] if row is not None else None

    def peek(self, raw: str) -> RefreshRecord | None:
        from aguard.db.session import service_session
        if not raw:
            return None
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT token_hash, family_id, client_id, subject, scope,"
                    " issued_at, expires_at, retired, revoked FROM refresh_tokens"
                    " WHERE token_hash = %s", (_hash(raw),))
                row = cur.fetchone()
        if row is None:
            return None
        record = RefreshRecord(*row)
        if record.revoked or record.retired or record.expires_at < time.time():
            return None
        return record

    def _gc(self, cur, now: int) -> None:
        cur.execute("DELETE FROM refresh_tokens"
                    " WHERE expires_at < %s AND NOT revoked", (now,))


def _insert_record(cur, record: RefreshRecord) -> None:
    cur.execute(
        "INSERT INTO refresh_tokens(token_hash, family_id, client_id, subject,"
        " scope, issued_at, expires_at, retired, revoked)"
        " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (record.token_hash, record.family_id, record.client_id, record.subject,
         record.scope, record.issued_at, record.expires_at, record.retired,
         record.revoked))
