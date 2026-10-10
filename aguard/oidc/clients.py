"""Registered OAuth clients + redirect-URI validation.

The rules here are the boring ones that stop the real attacks:

- redirect_uri: EXACT byte-for-byte match against pre-registered URIs.
  Open redirect is the #1 OAuth vulnerability class. Prefix matching,
  wildcard subdomains, and "normalize then compare" each have published
  bypasses (e.g. https://app.com/https://evil.com, trailing-slash tricks,
  fragment smuggling). Exact match has none.

- Secrets are stored HASHED. A registry dump / accidental log line of the
  client object must not yield live credentials. Secrets are compared with
  hmac.compare_digest — no timing oracle on client authentication.

Demo client secrets below are DEV-ONLY defaults (public in source, like
admin/admin on a router). Shared deployments override via env — see
.env.example.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import threading
from collections import OrderedDict
from dataclasses import dataclass

log = logging.getLogger("a-guard.clients")

#: Ceiling on dynamically-registered clients (those created at runtime via
#: Dynamic Client Registration). Seeded clients are permanent and exempt.
#:
#: /register is rate-limited (10/hour), but rate limiting bounds the RATE, not
#: the total: a process left up for months can still accumulate an unbounded
#: number. This cap is the backstop. It is deliberately generous — a lab will
#: register a handful — and eviction drops the OLDEST dynamic client, so the
#: trade-off (a stale registration eventually disappears) matches how a
#: long-idle credential becoming unusable is acceptable, whereas unbounded
#: growth is not.
MAX_DYNAMIC_CLIENTS = 1000


def hash_secret(secret: str) -> str:
    """SHA-256 for the lab.

    Production note: client secrets are high-entropy (unlike passwords), so
    an un-salted fast hash is defensible — but argon2/bcrypt costs nothing
    and wins if a secret is ever human-chosen. Either way: hash, never store
    plaintext, never log the input."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Client:
    client_id: str
    client_secret_hash: str | None      # None => public client (PKCE is its only shield)
    redirect_uris: tuple[str, ...]      # exact-match allowlist; empty = no browser flows
    allowed_scopes: frozenset[str]
    grant_types: frozenset[str]         # subset of {authorization_code, refresh_token, client_credentials}
    auth_method: str                    # client_secret_basic | client_secret_post | none
    kind: str                           # "human" (acts for users) | "agent" (acts as itself)

    @property
    def is_confidential(self) -> bool:
        return self.client_secret_hash is not None

    def verify_secret(self, secret: str) -> bool:
        if self.client_secret_hash is None:
            return False
        return hmac.compare_digest(hash_secret(secret), self.client_secret_hash)

    def redirect_uri_matches(self, uri: str) -> bool:
        """Exact match only — see module docstring. In particular we do NOT
        strip fragments, query strings, or trailing slashes before comparing."""
        return uri in self.redirect_uris

    def allows_scopes(self, scopes: set[str]) -> bool:
        return scopes <= set(self.allowed_scopes)


class ClientRegistry:
    def __init__(self) -> None:
        self._clients: dict[str, Client] = {}
        # Seeded clients (from seed_registry) are permanent and never evicted.
        # Everything added later via register() is "dynamic" and subject to the
        # MAX_DYNAMIC_CLIENTS ceiling.
        self._seeded: set[str] = set()
        self._dynamic_order: OrderedDict[str, None] = OrderedDict()
        # register() and get() are called from the sync threadpool, so two
        # requests really can interleave. The check-then-insert in register()
        # is a race without this: two concurrent /register calls for the same
        # client_id could both pass the duplicate check and one credential would
        # silently replace another.
        self._lock = threading.Lock()

    def seed(self, client: Client) -> None:
        """Register a permanent client (used only by seed_registry)."""
        with self._lock:
            if client.client_id in self._clients:
                raise ValueError(f"duplicate client_id: {client.client_id}")
            self._clients[client.client_id] = client
            self._seeded.add(client.client_id)

    def register(self, client: Client) -> None:
        """Register a dynamic (runtime-created) client.

        Enforces the duplicate-id check and the dynamic-client ceiling under
        the lock so both hold against concurrent registrations.
        """
        with self._lock:
            if client.client_id in self._clients:
                raise ValueError(f"duplicate client_id: {client.client_id}")
            self._clients[client.client_id] = client
            self._dynamic_order[client.client_id] = None
            while len(self._dynamic_order) > MAX_DYNAMIC_CLIENTS:
                oldest, _ = self._dynamic_order.popitem(last=False)
                del self._clients[oldest]
                log.warning(
                    "dynamic-client ceiling reached; dropped the oldest "
                    "registration %r (seed clients are never evicted)", oldest)

    def get(self, client_id: str) -> Client | None:
        with self._lock:
            return self._clients.get(client_id)

    def authenticate(self, client_id: str, secret: str | None, method: str) -> Client | None:
        """Token-endpoint client authentication (RFC 6749 §2.3.1).

        Returns the client only if: it exists, the caller used the method the
        client is registered for, and the secret matches. Wrong method alone
        fails — a confidential client registered for Basic auth must not be
        authenticable via a body parameter that middleware might log."""
        client = self.get(client_id)
        if client is None:
            return None
        if method not in ("client_secret_basic", "client_secret_post"):
            return None
        if not client.is_confidential or secret is None:
            return None
        if client.auth_method != method:
            return None
        return client if client.verify_secret(secret) else None


def seed_registry() -> ClientRegistry:
    """Lab clients. Secrets are dev-only constants — real deployments mint
    per-client secrets and store only hashes (see hash_secret).

    Three shapes, deliberately:
      demo-spa       public client   → PKCE is its ONLY protection
      demo-conf      confidential    → Basic-auth capable, full scopes
      cli-agent      agent client    → client_credentials, read scopes ONLY
                                         (the read-only story starts here,
                                          long before Postgres is involved)
    """
    registry = ClientRegistry()

    registry.seed(Client(
        client_id="demo-spa",
        client_secret_hash=None,
        redirect_uris=("http://localhost:8000/demo/callback",),
        allowed_scopes=frozenset({
            "openid", "profile", "email", "orders:read", "orders:write",
        }),
        grant_types=frozenset({"authorization_code", "refresh_token"}),
        auth_method="none",
        kind="human",
    ))

    registry.seed(Client(
        client_id="demo-conf",
        client_secret_hash=hash_secret(os.environ.get("DEMO_CONF_SECRET", "demo-conf-secret")),
        redirect_uris=("http://localhost:8000/demo/callback",),
        allowed_scopes=frozenset({
            "openid", "profile", "email", "orders:read", "orders:write",
            "agents:read",
        }),
        grant_types=frozenset({
            "authorization_code", "refresh_token", "client_credentials",
        }),
        auth_method="client_secret_basic",
        kind="human",
    ))

    registry.seed(Client(
        client_id="cli-agent",
        client_secret_hash=hash_secret(os.environ.get("CLI_AGENT_SECRET", "cli-agent-secret")),
        redirect_uris=(),                          # headless: no browser flow
        allowed_scopes=frozenset({"orders:read", "agents:read"}),
        grant_types=frozenset({"client_credentials"}),
        auth_method="client_secret_basic",
        kind="agent",
    ))

    # The Option 6 linchpin: an agent that goes through the *user* flow.
    # Tokens issued here carry sub=<human> AND roles=["agent"] — on-behalf-of.
    # The DB layer will map that to: session role = agent_readonly (cannot
    # write) while app.sub = the human (sees ONLY that human's rows).
    registry.seed(Client(
        client_id="chat-agent",
        client_secret_hash=hash_secret(os.environ.get("CHAT_AGENT_SECRET", "chat-agent-secret")),
        redirect_uris=("http://localhost:8000/demo/callback",),
        allowed_scopes=frozenset({
            "openid", "email", "orders:read",   # deliberately no orders:write
        }),
        grant_types=frozenset({"authorization_code", "refresh_token"}),
        auth_method="client_secret_basic",
        kind="agent",
    ))

    return registry

