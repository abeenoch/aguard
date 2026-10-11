"""User directory: who may sign in.

Two backends, selected by STORE_BACKEND exactly like aguard/oidc/stores.py:

  memory    the seeded demo users only (dev default, zero setup)
  postgres  durable accounts, including self-service sign-up (/signup)

Why users exist at all: the authorization_code flow requires an *authenticated
resource owner* to consent. The security-relevant part of this project is what
happens AFTER identity is established (identity->token binding, PII redaction,
DB role mapping), so the directory stays deliberately small — but it must be
BACKED BY SOMETHING, because "anybody can sign up" is the point of a public
deployment.

Passwords: PBKDF2-HMAC-SHA256, 200k iterations, per-user random salt — stdlib
hashlib, no extra dependency. Compare with hmac.compare_digest, never `==`.

The seeded demo passwords are the canonical PII/secret fixtures the redaction
layer must never let reach a log file. SEED_DEMO_USERS=false drops them.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Protocol

from aguard.settings import settings


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


def hash_password(password: str) -> str:
    """Hash a NEW password with a fresh random salt (used by sign-up)."""
    return _hash_password(password, secrets.token_bytes(16))


def _user(sub: str, email: str, name: str, password: str,
          amr: tuple[str, ...]) -> User:
    return User(
        sub=sub,
        email=email,
        display_name=name,
        password_hash=hash_password(password),
        amr=amr,
    )


#: The demo identities: two humans, also the two tenants for the RLS demo
#: (alice's rows must be invisible to bob and to any agent acting for bob).
#: Suppressed by SEED_DEMO_USERS=false on a real deployment — these passwords
#: are published in the README.
def _demo_users() -> list[User]:
    return [
        _user("usr_alice", "alice@example.com", "Alice Nguyen",
              os.environ.get("DEMO_ALICE_PASSWORD", "correct-horse-battery"),
              ("pwd",)),
        _user("usr_bob", "bob@example.com", "Bob Okafor",
              os.environ.get("DEMO_BOB_PASSWORD", "bob-not-a-real-secret"),
              ("pwd", "otp")),
    ]


_DUMMY_LOCK = threading.Lock()
_DUMMY: User | None = None


def dummy_user() -> User:
    """Stand-in that keeps unknown-email timing equal to wrong-password timing.

    One hash, built once — NOT a walk over the directory, which may legitimately
    be empty on a fresh deployment (and would then raise StopIteration).
    """
    global _DUMMY
    if _DUMMY is None:
        with _DUMMY_LOCK:
            if _DUMMY is None:
                _DUMMY = _user("usr_dummy", "nobody@invalid", "Nobody",
                               secrets.token_urlsafe(32), ("pwd",))
    return _DUMMY


def new_sub() -> str:
    """A fresh, stable, non-PII subject id for a self-service account."""
    return f"usr_{secrets.token_urlsafe(9)}"


class UserStore(Protocol):
    def get(self, sub: str) -> User | None: ...
    def find_by_email(self, email: str) -> User | None: ...
    def add(self, user: User) -> None: ...
    def all(self) -> list[User]: ...


def _normalize(email: str) -> str:
    return email.strip().lower()


class InMemoryUserStore:
    """Single-process directory: the seeded demo users, plus any sign-ups.

    Sign-ups live only as long as the process — which is the dev default, and
    exactly why the postgres backend exists for a real deployment.
    """

    def __init__(self, users: list[User] | None = None) -> None:
        self._by_sub: dict[str, User] = {}
        self._by_email: dict[str, str] = {}
        for user in (self._seeded() if users is None else users):
            self.add(user)

    @staticmethod
    def _seeded() -> list[User]:
        return _demo_users() if settings.seed_demo_users else []

    def add(self, user: User) -> None:
        self._by_sub[user.sub] = user
        self._by_email[_normalize(user.email)] = user.sub

    def get(self, sub: str) -> User | None:
        return self._by_sub.get(sub)

    def find_by_email(self, email: str) -> User | None:
        sub = self._by_email.get(_normalize(email))
        return self._by_sub.get(sub) if sub else None

    def all(self) -> list[User]:
        return list(self._by_sub.values())


class PostgresUserStore:
    """Durable directory: accounts survive a restart or a second worker.

    This is what makes self-service sign-up meaningful — an account created on
    one process must be able to sign in on the next.
    """

    def __init__(self) -> None:
        for user in (_demo_users() if settings.seed_demo_users else []):
            self.add(user)

    def add(self, user: User) -> None:
        from aguard.db.session import service_session
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users(sub, email, display_name, password_hash,"
                    " amr, created_at) VALUES (%s,%s,%s,%s,%s,%s)"
                    " ON CONFLICT (sub) DO NOTHING",
                    (user.sub, user.email, user.display_name,
                     user.password_hash, list(user.amr), int(time.time())))

    @staticmethod
    def _row(row) -> User:
        return User(sub=row[0], email=row[1], display_name=row[2],
                    password_hash=row[3], amr=tuple(row[4]))

    def get(self, sub: str) -> User | None:
        from aguard.db.session import service_session
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT sub, email, display_name, password_hash,"
                            " amr FROM users WHERE sub = %s", (sub,))
                row = cur.fetchone()
        return self._row(row) if row else None

    def find_by_email(self, email: str) -> User | None:
        from aguard.db.session import service_session
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT sub, email, display_name, password_hash,"
                            " amr FROM users WHERE lower(email) = %s",
                            (_normalize(email),))
                row = cur.fetchone()
        return self._row(row) if row else None

    def all(self) -> list[User]:
        from aguard.db.session import service_session
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT sub, email, display_name, password_hash,"
                            " amr FROM users ORDER BY created_at")
                rows = cur.fetchall()
        return [self._row(r) for r in rows]


_STORE_LOCK = threading.Lock()
_STORE: UserStore | None = None


def build_user_store() -> UserStore:
    """The directory matching STORE_BACKEND (see aguard/oidc/stores.py)."""
    from aguard.oidc.stores import POSTGRES
    if settings.store_backend == POSTGRES:
        return PostgresUserStore()
    return InMemoryUserStore()


def user_store() -> UserStore:
    """Process-wide store, built once on first use.

    Lazy rather than at import: the postgres backend opens a connection and
    seeds, and importing this module must not do that on every test session.
    """
    global _STORE
    if _STORE is None:
        with _STORE_LOCK:
            if _STORE is None:
                _STORE = build_user_store()
    return _STORE


def reset_user_store() -> None:
    """Drop the cached store (tests; a deployment never calls this)."""
    global _STORE
    with _STORE_LOCK:
        _STORE = None


class _StoreMapping(Mapping):
    """``USERS``-shaped view over the store, so existing call sites keep working.

    The authorization/token routes look users up by `sub` and need membership
    and iteration — that is exactly a Mapping, so they need not learn the store
    API. Every read goes to the store, which is what keeps sign-ups visible.
    """

    def __getitem__(self, key: str) -> User:
        user = user_store().get(key)
        if user is None:
            raise KeyError(key)
        return user

    def __iter__(self) -> Iterator[str]:
        return (u.sub for u in user_store().all())

    def __len__(self) -> int:
        return len(user_store().all())


USERS: Mapping[str, User] = _StoreMapping()


def find_by_email(email: str) -> User | None:
    """Case-insensitive lookup — 'Alice@Example.com' must find alice."""
    return user_store().find_by_email(email)
