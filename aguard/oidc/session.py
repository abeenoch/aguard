"""Session cookie: HMAC-signed `sub|exp|sig`.

Deliberately NOT a JWT:
- the session is *server-internal* state; asymmetric signing buys nothing
  when exactly one service reads it
- a MAC over `sub.exp` with a server secret is the smallest thing that is
  simultaneously tamper-proof and expiring

Format:  <sub>.<exp_unix>.<hex(hmac_sha256(secret, "sub.exp"))>
Verify:  recompute MAC over the received prefix, compare_digest (no timing
         oracle), then check expiry. Any parse failure → None (no exceptions
         to callers: malformed cookies are attacker input, not errors).
"""
from __future__ import annotations

import hashlib
import hmac
import time

from aguard.settings import settings


def _mac(secret: bytes, payload: str) -> str:
    return hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def create_session_token(
    sub: str, *, ttl: int = 8 * 60 * 60, secret: bytes | None = None
) -> str:
    secret = settings.session_secret if secret is None else secret
    exp = str(int(time.time()) + ttl)
    payload = f"{sub}.{exp}"
    return f"{payload}.{_mac(secret, payload)}"


def parse_session_token(token: str | None, *, secret: bytes | None = None) -> str | None:
    """Return the authenticated `sub`, or None if the token is invalid/expired."""
    if not token:
        return None
    secret = settings.session_secret if secret is None else secret
    parts = token.split(".")
    if len(parts) != 3:
        return None
    sub, exp, signature = parts
    if not sub or not exp.isdigit():
        return None
    payload = f"{sub}.{exp}"
    if not hmac.compare_digest(_mac(secret, payload), signature):
        return None
    if int(exp) < time.time():
        return None
    return sub
