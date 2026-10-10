"""Rate limiting for the credential endpoints: /token, /login, /register.

What this defends against — each is a concrete attack, not a hypothetical:

  /login     credential stuffing and password guessing. The per-IP limit stops
             one host; the per-ACCOUNT limit stops a botnet converging on one
             victim, which per-IP limiting structurally cannot see.
  /token     anonymous work and secret guessing. Every request reaching this
             endpoint costs CPU (client auth, code lookup, signing) before any
             credential is verified, so the ceiling here is about capacity as
             much as about guessing a 32-byte client secret.
  /register  unbounded dynamic client registration, which is how an anonymous
             caller grows the client registry without limit.

Two layers, deliberately separated:

  ``RateLimiter`` (Protocol)  WHERE attempts are counted.
      ``InMemoryRateLimiter`` for a single process, ``PostgresRateLimiter`` for
      a shared one; ``build_rate_limiter()`` selects from
      ``RATE_LIMIT_BACKEND``, exactly as ``aguard/oidc/stores.py`` does for
      authorization state. The two differ in one real way — window shape —
      because the medium rewards a fixed window; both honour the Protocol.
  ``enforce_rate_limit()``    WHAT is counted, and what the caller gets back.

Identities are HASHED before they become counters. The counter map would
otherwise be a live list of the email addresses currently being attacked (and
the addresses attacking them) — PII that a memory dump, a core file, or a
stray ``logger.debug(limiter)`` would expose. Same reasoning as ``codes.py``
storing code hashes instead of codes.

Deliberate non-goals: this is a blunt ceiling, not an account-lockout policy
(sustained guessing is still caught by the audit log; lockout is a deployment
decision), and it is not a substitute for a reverse proxy's connection limits.
"""
from __future__ import annotations

import hashlib
import logging
import math
import random
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from aguard.oidc.pages import rate_limited_page
from aguard.settings import settings

log = logging.getLogger("a-guard.ratelimit")

MEMORY = "memory"
POSTGRES = "postgres"

#: Windows are fixed in code; only the counts are deployment-tunable. A window
#: is a property of how the endpoint is used (a human signing in vs a one-off
#: registration), not something an operator should have to reason about.
_WINDOW_SECONDS = {
    "token": 60,
    "login": 60,
    "login_account": 300,     # 5 min: one victim, many source addresses
    "register": 3600,         # DCR is a rare, deliberate operation
}

#: Bucket-key component for an identity we could not determine (no socket
#: peer, empty form field). Such attempts simply share one bucket.
_ANONYMOUS = "anonymous"


@dataclass(frozen=True)
class RateLimit:
    """``limit`` attempts per ``window_seconds``, per identity."""

    limit: int
    window_seconds: int

    def __post_init__(self) -> None:
        if self.limit < 1:
            raise ValueError("rate limit must allow at least one attempt")
        if self.window_seconds < 1:
            raise ValueError("rate limit window must be at least one second")


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    #: Whole seconds until a slot frees. 0 when the attempt is allowed.
    retry_after: int


class RateLimiter(Protocol):
    """Storage contract for attempt counters.

    Callers depend on THIS, never on a concrete class — the same seam that
    aguard/oidc/stores.py provides for authorization state, so a shared
    (multi-worker) backend can replace the in-process one without touching a
    single route.
    """

    def hit(self, policy: str, key: str, *,
            now: float | None = None) -> RateLimitDecision: ...


class InMemoryRateLimiter:
    """Per-process counters, sliding-window.

    Why a sliding window rather than a fixed window: a fixed window lets a
    caller spend the full allowance at the end of one window and again at the
    start of the next — 2x the intended limit back-to-back, precisely when an
    attacker is pushing hardest. A timestamp deque per key has exact boundaries
    and yields an exact ``Retry-After``.

    Correct for exactly ONE process. With N workers the effective ceiling is
    N x limit, which is why build_rate_limiter() refuses to pretend otherwise
    when a shared deployment is requested.
    """

    def __init__(self, policies: Mapping[str, RateLimit], *,
                 max_keys: int = 10_000) -> None:
        if not policies:
            raise ValueError("at least one rate-limit policy is required")
        self._policies = dict(policies)
        self._max_keys = max(1, max_keys)
        # OrderedDict as an LRU: values are the timestamps of recent attempts.
        self._buckets: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()
        # Sync endpoints run in Starlette's threadpool, so two requests really
        # can be inside hit() at the same time. Without this lock the
        # read-then-append below is a race — and a race under load is exactly
        # when the limit matters.
        self._lock = threading.Lock()

    # -- introspection (ops/metrics; also what the tests assert on) ---------
    @property
    def tracked_keys(self) -> int:
        return len(self._buckets)

    def policy(self, name: str) -> RateLimit:
        try:
            return self._policies[name]
        except KeyError:
            raise ValueError(f"unknown rate-limit policy {name!r}") from None

    def hit(self, policy: str, key: str, *,
            now: float | None = None) -> RateLimitDecision:
        rule = self.policy(policy)
        # Monotonic: a wall-clock jump (NTP step, an operator fixing the time)
        # must not hand out a free window.
        stamp = time.monotonic() if now is None else now
        bucket_key = (policy, key)

        with self._lock:
            bucket = self._buckets.get(bucket_key)
            if bucket is None:
                if len(self._buckets) >= self._max_keys:
                    self._make_room()
                bucket = deque()
                self._buckets[bucket_key] = bucket
            else:
                self._buckets.move_to_end(bucket_key)

            cutoff = stamp - rule.window_seconds
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= rule.limit:
                # Accurate to the second, floored at 1: "Retry-After: 0" is an
                # invitation to retry immediately.
                retry = math.ceil(bucket[0] + rule.window_seconds - stamp)
                return RateLimitDecision(False, rule.limit, 0, max(retry, 1))

            bucket.append(stamp)
            return RateLimitDecision(True, rule.limit,
                                     rule.limit - len(bucket), 0)

    def _make_room(self) -> None:
        """Evict the least recently used bucket when the key cap is reached.

        A cap is mandatory: keys derive from request data, so without one a
        caller rotating identities grows this dict until the process dies — the
        limiter would become the outage it exists to prevent.

        Eviction is a documented trade-off: a dropped bucket forgets its count,
        so an attacker who can rotate identities AND saturate the key space
        buys a fresh allowance. Two things keep that honest — the cap is high
        (10k counters is a few MB), and with
        ``RATE_LIMIT_TRUST_FORWARDED_FOR`` off the key is the real socket peer,
        which is not free to rotate. Distributed sources are precisely the case
        the shared backend exists for.
        """
        evicted, _ = self._buckets.popitem(last=False)
        log.warning("rate-limit key cap reached; evicted the oldest bucket for "
                    "policy %r (counters are per-process)", evicted[0])


class PostgresRateLimiter:
    """Shared counters in ``rate_limit_buckets`` — correct for N workers.

    The Protocol guarantees a route change is never needed to move between
    this and the in-process limiter; ``build_rate_limiter()`` picks one from
    ``RATE_LIMIT_BACKEND``. This class is what makes the counter authoritative
    across workers and across a restart: two workers racing the same account
    against the ``login_account`` ceiling see ONE count, not two.

    Fixed windows, deliberately — a different trade than the in-process
    limiter's sliding window, and the reason is the medium, not laziness.
    A shared sliding window means one INSERT per attempt plus a DELETE sweep
    to age entries out; the count can never be a single row. Fixed windows let
    a whole attempt be one ``INSERT ... ON CONFLICT DO UPDATE`` (the counter is
    the row), which keeps the hot path to a single round trip and a single
    source of truth. The cost is the known 2x-at-the-boundary behaviour a fixed
    window has, and that is acceptable here: these are coarse anti-abuse
    ceilings (5 logins per account per 5 min), not billing-grade metering.

    ``now`` defaults to wall-clock seconds. The in-process limiter uses a
    monotonic clock (immune to NTP steps); a shared counter CANNOT, because
    every worker and every row in the table must agree on what "now" is — a
    monotonic clock is per-process and meaningless across them.

    Fail-open on database error: if the counter cannot be read or written the
    decision ALLOWS. Rate limiting is an availability/abuse control layered on
    an already-authenticating endpoint, not the authentication itself; failing
    it closed would let a database blip 429 every legitimate login. The
    security-relevant limit (per-account guessing) is unchanged by the choice.
    """

    def __init__(self, policies: Mapping[str, RateLimit]) -> None:
        if not policies:
            raise ValueError("at least one rate-limit policy is required")
        self._policies = dict(policies)

    # -- introspection (parity with the in-process limiter) ----------------
    @property
    def tracked_keys(self) -> int:
        """Distinct identities still within the widest window.

        Counts rows whose window is open, so an abandoned identity that stops
        hitting drops out once its window expires rather than lingering.
        """
        from aguard.db.session import service_session

        widest = max(rule.window_seconds for rule in self._policies.values())
        cutoff = int(time.time()) - widest
        with service_session() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) FROM ("
                    "  SELECT DISTINCT policy, bucket_key FROM rate_limit_buckets"
                    "  WHERE window_start >= %s"
                    ") AS live", (cutoff,))
                (total,) = cur.fetchone()
        return int(total)

    def policy(self, name: str) -> RateLimit:
        try:
            return self._policies[name]
        except KeyError:
            raise ValueError(f"unknown rate-limit policy {name!r}") from None

    def hit(self, policy: str, key: str, *,
            now: float | None = None) -> RateLimitDecision:
        rule = self.policy(policy)
        stamp = time.time() if now is None else now
        window_start = int(stamp) // rule.window_seconds * rule.window_seconds

        from aguard.db.session import service_session

        try:
            with service_session() as conn:
                with conn.cursor() as cur:
                    # One atomic read-modify-write: the row IS the counter, so
                    # two workers hitting the same (policy, key, window) cannot
                    # both read 4 and both write 5. ON CONFLICT targets the PK.
                    cur.execute(
                        "INSERT INTO rate_limit_buckets"
                        " (policy, bucket_key, window_start, count)"
                        " VALUES (%s, %s, %s, 1)"
                        " ON CONFLICT (policy, bucket_key, window_start)"
                        " DO UPDATE SET count = rate_limit_buckets.count + 1"
                        " RETURNING count",
                        (policy, key, window_start),
                    )
                    (count,) = cur.fetchone()
                    # Opportunistic sweep: prune windows that closed at least
                    # one full period ago. Probabilistic so a busy endpoint does
                    # not pay a DELETE on every single request.
                    if random.random() < 0.01:
                        self._gc(cur, stamp, rule.window_seconds)
        except Exception:
            log.exception("rate-limit counter unavailable; failing open for "
                          "policy %r", policy)
            return RateLimitDecision(True, rule.limit, rule.limit, 0)

        if count > rule.limit:
            # The window rolls at window_start + window_seconds; from there the
            # caller has its allowance back. Floor at 1 for the same reason as
            # the in-process limiter: "Retry-After: 0" invites an instant retry.
            retry = max(window_start + rule.window_seconds - int(stamp), 1)
            return RateLimitDecision(False, rule.limit, 0, retry)

        return RateLimitDecision(True, rule.limit, rule.limit - count, 0)

    def _gc(self, cur, stamp: float, window_seconds: int) -> None:
        """Delete rows from windows that closed at least one period ago.

        Keeping only the current (and just-elapsed) window means the table stays
        proportional to live identities, not to total attempts ever made — the
        same bound the in-process limiter gets from its key cap, here enforced
        by age instead of count.
        """
        cur.execute(
            "DELETE FROM rate_limit_buckets WHERE window_start < %s",
            (int(stamp) // window_seconds * window_seconds - window_seconds,))


def _identity_key(kind: str, value: str) -> str:
    """Stable, bounded, non-reversible bucket key for an identity.

    Hashed for two reasons: a memory dump must not enumerate the accounts being
    attacked, and a caller-supplied value (a client_id, an email) must not be
    able to inject structure into the key space or inflate it with length.
    """
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()
    return f"{kind}:{digest[:32]}"


def _client_ip(request: Request) -> str:
    """Resolve the caller's address, defaulting to the socket peer.

    THE DEFAULT IS A SECURITY DECISION. ``X-Forwarded-For`` is supplied by the
    client: trusting it with no proxy that overwrites it gives an attacker an
    unlimited supply of fresh identities, i.e. a rate limit that does nothing.
    Turn on ``RATE_LIMIT_TRUST_FORWARDED_FOR`` only when a proxy you control
    sets the header, and note the left-most entry is only trustworthy when
    exactly one trusted hop appends to it.
    """
    if settings.rate_limit_trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for", "")
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    client = request.client
    return client.host if client is not None and client.host else _ANONYMOUS


def enforce_rate_limit(
    request: Request,
    policy: str,
    *,
    per_identity: Iterable[tuple[str, str | None]] = (),
    as_html: bool = False,
) -> Response | None:
    """Count one attempt and return a 429 response if any limit is spent.

    Always counts the attempt against the caller's address under ``policy``.
    Each ``(policy, value)`` pair in ``per_identity`` additionally counts it
    against that value's own policy — e.g. ``("login_account", email)`` so that
    guesses spread across many source addresses still meet a ceiling.

    Returns ``None`` when the attempt may proceed. Callers call this FIRST,
    before any credential work: a limit checked after the expensive part has
    already been paid for does not protect capacity.

    A rejected attempt still spends the slots it already passed (limits are
    budgets, not exact double-entry accounting). That is the conventional
    reading of per-address + per-identity limits, and it fails closed.
    """
    limiter: RateLimiter = request.app.state.rate_limiter
    attempts: list[tuple[str, str]] = [
        (policy, _identity_key("ip", _client_ip(request))),
    ]
    for extra_policy, value in per_identity:
        if value:
            attempts.append((extra_policy, _identity_key(extra_policy, value)))

    for attempt_policy, key in attempts:
        decision = limiter.hit(attempt_policy, key)
        if not decision.allowed:
            log.warning("rate limit hit: policy=%s retry_after=%ds",
                        attempt_policy, decision.retry_after)
            return _too_many(decision.retry_after, as_html=as_html)
    return None


def _too_many(retry_after: int, *, as_html: bool) -> Response:
    """429 with Retry-After.

    ``temporarily_unavailable`` is the RFC 6749 §5.2 code for exactly this
    condition ("unable to handle the request due to a temporary overloading"),
    so an OAuth client receives a code it already knows rather than an invented
    one. Nothing about WHICH limit fired or WHICH identity was counted: that
    would turn the limiter into an oracle for probing whether an account
    exists.
    """
    headers = {"Retry-After": str(retry_after)}
    if as_html:
        return Response(
            content=rate_limited_page(retry_after=retry_after),
            status_code=429,
            media_type="text/html",
            headers=headers,
        )
    return JSONResponse(
        {
            "error": "temporarily_unavailable",
            "error_description": "rate limit exceeded; retry later",
        },
        status_code=429,
        headers={**headers, "Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def default_policies() -> dict[str, RateLimit]:
    """The shipped policies. Counts tunable by environment (.env.example)."""
    return {
        "token": RateLimit(settings.rate_limit_token,
                           _WINDOW_SECONDS["token"]),
        "login": RateLimit(settings.rate_limit_login,
                           _WINDOW_SECONDS["login"]),
        "login_account": RateLimit(settings.rate_limit_login_account,
                                   _WINDOW_SECONDS["login_account"]),
        "register": RateLimit(settings.rate_limit_register,
                              _WINDOW_SECONDS["register"]),
    }


def build_rate_limiter() -> RateLimiter:
    """Select where attempts are counted. Mirrors aguard/oidc/stores.py.

    ``memory``  per-process counters (InMemoryRateLimiter). Correct for a
               single worker; with N workers the ceiling is N x the limit.
    ``postgres`` shared counters (PostgresRateLimiter). Correct for N workers
               and durable across a restart — one authoritative count. Requires
               the ``rate_limit_buckets`` table from aguard/db/schema.sql.

    The switch exists so the topology decides the implementation explicitly,
    rather than an operator discovering the gap when a botnet splits its
    guesses across workers.
    """
    backend = settings.rate_limit_backend
    if backend == MEMORY:
        return InMemoryRateLimiter(default_policies(),
                                   max_keys=settings.rate_limit_max_keys)
    if backend == POSTGRES:
        return PostgresRateLimiter(default_policies())
    raise ValueError(
        f"unknown RATE_LIMIT_BACKEND {backend!r} "
        f"(expected {MEMORY!r} or {POSTGRES!r})")


__all__ = [
    "MEMORY",
    "POSTGRES",
    "InMemoryRateLimiter",
    "PostgresRateLimiter",
    "RateLimit",
    "RateLimitDecision",
    "RateLimiter",
    "build_rate_limiter",
    "default_policies",
    "enforce_rate_limit",
]



