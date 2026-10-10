"""In-memory user directory for the lab's login/consent step.

Why users exist at all: authorization_code flow requires an *authenticated
resource owner* to consent. In the lab we shortcut real authentication
(usernames/passwords below) — the security-relevant part of this project is
what happens AFTER identity is established: identity→token binding, PII
redaction, and DB role mapping.

Passwords: PBKDF2-HMAC-SHA256, 200k iterations, per-user random salt —
stdlib hashlib, no extra dependency. Compare with hmac.compare_digest.
Note these passwords are the canonical PII/secret fixtures the redaction
layer must never let reach a log file.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class User:
    sub: str            # stable, non-PII identifier — this is what RLS keys on
    email: str          # PII — must be redacted in logs, may appear in id_token
    display_name: str   # PII
    password_hash: str  # hex digest: salt$hash
    amr: tuple[str, ...]  # authentication methods (step-up auth signal)


def _hash_password(password: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex() + "$" + digest.hex()


def verify_password(user: User, password: str) -> bool:
    # A malformed stored hash must FAIL CLOSED (return False), never raise:
    # verify_password sits inside the login handler, where an exception would
    # surface as a 500 and, worse, break the constant-time path below that
    # keeps unknown-email timing indistinguishable from wrong-password timing.
    # Anything we cannot parse is simply "not a match".
    try:
        salt_hex, _ = user.password_hash.split("$", 1)
        candidate = _hash_password(password, bytes.fromhex(salt_hex))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, user.password_hash)


def _user(sub: str, email: str, name: str, password: str, amr: tuple[str, ...]) -> User:
    salt = secrets.token_bytes(16)
    return User(
        sub=sub,
        email=email,
        display_name=name,
        password_hash=_hash_password(password, salt),
        amr=amr,
    )


def _build_users() -> dict[str, User]:
    """Two humans, also the two tenants for the RLS demo (alice's rows must be
    invisible to bob and to any agent acting for bob).

    Called lazily (see ``_LazyUsers``) so that importing this module, which
    happens on every process start and every test session, does not pay two
    200k-iteration PBKDF2 hashes up front. The hashes only need to exist by the
    time someone logs in.
    """
    return {
        "usr_alice": _user(
            "usr_alice", "alice@example.com", "Alice Nguyen",
            os.environ.get("DEMO_ALICE_PASSWORD", "correct-horse-battery"), ("pwd",),
        ),
        "usr_bob": _user(
            "usr_bob", "bob@example.com", "Bob Okafor",
            os.environ.get("DEMO_BOB_PASSWORD", "bob-not-a-real-secret"), ("pwd", "otp"),
        ),
    }


class _LazyUsers(Mapping):
    """A Mapping that builds its contents on first access, then caches them.

    Why: the two demo users are derived by hashing their passwords at import
    time, which is 2 x 200k PBKDF2 iterations paid on every import (every
    process start, and every pytest session). Only a login actually needs the
    hashes, so deferring keeps startup cheap without changing the ``USERS``
    interface (``.get``/``.values()``/iteration all still work).

    Not thread-safe by design: two concurrent first-accesses both build the
    dict and one wins the assignment. That is harmless here because the
    builders are pure and produce equal-by-value users, so the loser's result
    is simply discarded. Real deployments replace this module's directory with
    a database.
    """

    def __init__(self, builder):
        self._builder = builder
        self._cache: dict[str, User] | None = None

    def _loaded(self) -> dict[str, User]:
        if self._cache is None:
            self._cache = self._builder()
        return self._cache

    def __getitem__(self, key: str) -> User:
        return self._loaded()[key]

    def __iter__(self):
        return iter(self._loaded())

    def __len__(self) -> int:
        return len(self._loaded())


USERS: Mapping[str, User] = _LazyUsers(_build_users)


def find_by_email(email: str) -> User | None:
    """Case-insensitive lookup — 'Alice@Example.com' must find alice."""
    normalized = email.strip().lower()
    for user in USERS.values():
        if user.email.lower() == normalized:
            return user
    return None
