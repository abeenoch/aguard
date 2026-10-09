"""Central configuration. Everything env-overridable.

Precedence: real environment variable > .env file > dev default.
Secrets NEVER live in source: .env is gitignored, .env.example is the
template, and dev defaults are documented as dev-only below.

Security note: the redaction layer cannot save you if the config itself
is the secret leak — that is why this file must stay credential-free.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_dotenv() -> None:
    """Zero-dependency .env loader (KEY=VALUE, # comments, optional quotes).

    Real environment always wins — setenv beats file, like every 12-factor
    app. Loaded before Settings reads env so one import covers everything.
    """
    dotenv = PROJECT_ROOT / ".env"
    if not dotenv.is_file():
        return
    for raw in dotenv.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv()


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


# Issuer used to derive resource identifiers (RFC 8707) before Settings exists.
_ISSUER = _env("OIDC_ISSUER", "http://localhost:8000").rstrip("/")
_MCP_RESOURCE_ID = _env("MCP_RESOURCE_ID", f"{_ISSUER}/mcp").rstrip("/")


@dataclass(frozen=True)
class Settings:
    # Public issuer URL — the `iss` claim. Exact string match matters later:
    # validators compare this byte-for-byte, so no trailing-slash drift.
    issuer: str = _ISSUER

    # Where the RSA keystore (keys.json) lives.
    key_dir: Path = Path(_env("KEY_DIR", str(PROJECT_ROOT / "data" / "keys")))

    # Pool DSNs for the two least-privilege login roles (see aguard/db/schema.sql).
    # Each login is a member of EXACTLY ONE data role — that membership, not
    # application code, is what makes agent->human escalation impossible.
    # Dev-only passwords: production injects via secret manager.
    db_dsn_human: str = _env(
        "DB_DSN_HUMAN",
        "postgresql://app_login_human:human-pool-secret-dev@localhost:5432/agent_auth",
    )
    db_dsn_agent: str = _env(
        "DB_DSN_AGENT",
        "postgresql://app_login_agent:agent-pool-secret-dev@localhost:5432/agent_auth",
    )
    # Authorization-server state (auth codes, refresh tokens). A THIRD login,
    # member of auth_service only: the AS must not borrow the tenant roles,
    # and the tenant roles must not reach token tables.
    db_dsn_auth: str = _env(
        "DB_DSN_AUTH",
        "postgresql://app_login_auth:auth-pool-secret-dev@localhost:5432/agent_auth",
    )

    # Superuser password: used ONLY by tests to apply aguard/db/schema.sql.
    # Never referenced by application code — the app only ever holds the two
    # least-privilege pool logins above.
    pg_superuser_password: str = _env("PG_SUPERUSER_PASSWORD", "")


    # Pepper for HMAC log-correlation IDs (Part A3). Well-known dev value —
    # production must inject via secret manager.
    log_pepper: bytes = _env("LOG_HASH_PEPPER", "dev-only-pepper-change-me").encode()

    # Server secret for MAC-signing session cookies (NOT a JWT — see session.py).
    session_secret: bytes = _env(
        "SESSION_SECRET", "dev-session-secret-change-me"
    ).encode()

    # Browser session lifetime. ONE number: the cookie's Max-Age and the
    # token's own exp are derived from it, so they cannot drift apart.
    session_ttl: int = int(_env("SESSION_TTL", str(8 * 3600)))

    # Send the session cookie only over TLS: "auto" (the default) derives it
    # from the issuer scheme — an https issuer means the browser reaches us
    # encrypted, so the cookie must never go out in the clear. A dev issuer is
    # http://localhost, where Secure buys nothing (and would break older
    # browsers), which is why this is derived rather than a blanket True.
    # Force "true"/"false" when TLS terminates in front of an http issuer.
    session_cookie_secure: str = _env(
        "SESSION_COOKIE_SECURE", "auto"
    ).strip().lower()

    @property
    def session_cookie_is_secure(self) -> bool:
        """Resolve session_cookie_secure against the issuer's scheme.

        An unrecognised value degrades to "auto", never to off: a typo in a
        config file must not be able to silently downgrade the cookie to
        plaintext transport.
        """
        if self.session_cookie_secure in ("1", "true", "yes", "on"):
            return True
        if self.session_cookie_secure in ("0", "false", "no", "off"):
            return False
        return self.issuer.startswith("https://")

    # Token lifetimes. Short access tokens are the revocation story for
    # self-contained JWTs: worst-case exposure window == TTL.
    access_token_ttl: int = int(_env("ACCESS_TOKEN_TTL", "900"))        # 15 min
    id_token_ttl: int = int(_env("ID_TOKEN_TTL", "900"))
    refresh_token_ttl: int = int(_env("REFRESH_TOKEN_TTL", str(60 * 60 * 24 * 14)))
    auth_code_ttl: int = int(_env("AUTH_CODE_TTL", "60"))               # single-use, 1 min
    clock_skew_leeway: int = int(_env("CLOCK_SKEW_LEEWAY", "60"))       # ±60s max

    # `aud` for access tokens. Audience restriction means a token minted for
    # this API is rejected by any other service that checks `aud` — kills
    # cross-service token replay even with a valid signature.
    resource_audience: str = _env("RESOURCE_AUDIENCE", "a-guard-api")

    # RFC 8707 (resource indicators) — the MCP-compliance piece.
    # mcp_resource_id is what clients pass as `resource` to get tokens
    # audience-bound to the MCP server; allowed_resources is the EXACT-MATCH
    # allowlist of resource values we accept (no wildcards — an unvalidated
    # resource param is an audience-forgery vector).
    mcp_resource_id: str = _MCP_RESOURCE_ID
    allowed_resources: tuple[str, ...] = tuple(
        r.strip() for r in _env(
            "ALLOWED_RESOURCES",
            f"{_MCP_RESOURCE_ID},{_ISSUER}/api",
        ).split(",") if r.strip()
    )

    # Token/state storage backend.
    #   "memory"   — single process only (default: zero setup, matches dev)
    #   "postgres" — shared + restart-durable; required before running more
    #                than one worker, because single-use code tombstones and
    #                refresh-family revocation are SECURITY state: if worker A
    #                redeems a code and worker B has never seen it, a replay
    #                goes undetected.
    store_backend: str = _env("STORE_BACKEND", "memory").strip().lower()

    # --- Rate limiting (see aguard/ratelimit.py) ---------------------------
    # Attempts allowed per identity per window. Windows are fixed in code
    # (60s for /token and /login, 300s per account, 1h for /register); only the
    # counts are deployment-tunable. These defaults are tuned for one human at
    # a browser: machine clients that legitimately burst need a higher
    # RATE_LIMIT_TOKEN, and a load test WILL trip them.
    rate_limit_token: int = int(_env("RATE_LIMIT_TOKEN", "60"))
    rate_limit_login: int = int(_env("RATE_LIMIT_LOGIN", "10"))
    rate_limit_login_account: int = int(_env("RATE_LIMIT_LOGIN_ACCOUNT", "5"))
    rate_limit_register: int = int(_env("RATE_LIMIT_REGISTER", "10"))

    # Where attempts are counted. "memory" is PER PROCESS: with N workers the
    # effective ceiling is N x limit. A shared backend is not implemented yet,
    # and naming one raises rather than silently behaving like memory — see
    # build_rate_limiter().
    rate_limit_backend: str = _env("RATE_LIMIT_BACKEND", "memory").strip().lower()

    # Trust X-Forwarded-For when deriving the caller's identity.
    # DEFAULT FALSE, and that default is the security-relevant one: the header
    # is client-supplied, so trusting it with no proxy in front hands an
    # attacker unlimited fresh identities and the limit stops meaning anything.
    # Enable only behind a proxy you control that overwrites the header.
    rate_limit_trust_forwarded_for: bool = _env(
        "RATE_LIMIT_TRUST_FORWARDED_FOR", "false"
    ).strip().lower() in ("1", "true", "yes", "on")

    # Cap on counted identities held in memory: bounds a key-rotation flood.
    # The least recently used bucket is evicted when the cap is reached.
    rate_limit_max_keys: int = int(_env("RATE_LIMIT_MAX_KEYS", "10000"))

    # How long a /readyz result may be reused. Infrastructure polls readiness
    # every few seconds and each probe costs a pooled database connection; a
    # short cache stops a probe flood from consuming the pool that /token also
    # draws from. 0 disables the cache (every probe hits the database), which
    # is what the test suite uses so probes cannot leak between tests.
    readyz_cache_seconds: float = float(_env("READYZ_CACHE_SECONDS", "1.0"))

    # Clients allowed to introspect tokens they do NOT own (RFC 7662 §2.4).
    # EMPTY BY DEFAULT, so introspection is owner-only. A resource server or an
    # ops tool that legitimately needs to inspect arbitrary tokens must be
    # named here. Only ever list CONFIDENTIAL clients: a public client
    # authenticates by name alone, so allowlisting one would reopen the hole
    # this restriction exists to close.
    introspection_clients: tuple[str, ...] = tuple(
        c.strip() for c in _env("INTROSPECTION_CLIENTS", "").split(",")
        if c.strip()
    )

    # DCR redirect-URI policy. Default is the strict OAuth 2.1 baseline:
    # https anywhere, http on loopback only (RFC 8252 for native apps).
    # MCP hosts that are editor extensions register a PRIVATE-USE scheme
    # instead of a loopback port — Cline uses
    # `vscode://saoudrizwan.claude-dev/mcp-auth/callback/<hash>`, whose hash
    # is derived from the server URL and therefore cannot be pre-registered.
    # RFC 8252 §7.1 permits private-use schemes; PKCE S256 (which /authorize
    # already requires of every client) is the mitigation against scheme
    # hijack. Opt in per deployment, e.g. DCR_ALLOWED_REDIRECT_SCHEMES=vscode.
    # Empty (the default) keeps registration strict — no behaviour change.
    dcr_allowed_redirect_schemes: tuple[str, ...] = tuple(
        s.strip().lower() for s in _env(
            "DCR_ALLOWED_REDIRECT_SCHEMES", ""
        ).split(",") if s.strip()
    )



settings = Settings()
