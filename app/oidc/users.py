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
    salt_hex, _ = user.password_hash.split("$", 1)
    candidate = _hash_password(password, bytes.fromhex(salt_hex))
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


# Two humans — also the two tenants for the RLS demo (alice's rows must be
# invisible to bob and to any agent acting for bob).
USERS: dict[str, User] = {
    "usr_alice": _user(
        "usr_alice", "alice@example.com", "Alice Nguyen",
        os.environ.get("DEMO_ALICE_PASSWORD", "correct-horse-battery"), ("pwd",),
    ),
    "usr_bob": _user(
        "usr_bob", "bob@example.com", "Bob Okafor",
        os.environ.get("DEMO_BOB_PASSWORD", "bob-not-a-real-secret"), ("pwd", "otp"),
    ),
}


def find_by_email(email: str) -> User | None:
    """Case-insensitive lookup — 'Alice@Example.com' must find alice."""
    normalized = email.strip().lower()
    for user in USERS.values():
        if user.email.lower() == normalized:
            return user
    return None
