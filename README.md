# A-guard

**The security layer for AI agents: OIDC identity with agent principals, PII that never reaches your logs, and database-enforced permissions that survive prompt injection.**

```
   prompt injection says "delete everything"
                    │
                    ▼
┌──────────┐   ┌──────────┐   ┌──────────────────────────────┐
│  Agent    │──▶│  A-guard │──▶│  PostgreSQL                  │
│  (LLM)    │   │  tokens  │   │  role: agent_readonly        │
└──────────┘   │  + logs   │   │  RLS: own tenant rows only   │
               └──────────┘   │                              │
                    │         │  ERROR: permission denied     │
                    ▼         └──────────────────────────────┘
            logs show:
    email[h:5fecc5cd0b92]      ← never the address
```

When an AI agent can touch your database, a prompt injection is a data breach.
A-guard makes the **database** the enforcement point — not application code the
agent might talk its way around.

## What's inside

| Layer | What it does | Where |
|---|---|---|
| 🔐 **OIDC provider** | Hand-rolled OAuth 2.1/OIDC: authorization code + **PKCE S256 only**, short-lived JWTs, **rotating refresh tokens with family revocation**, `client_credentials` for machine principals | `app/oidc/` |
| 🔪 **PII redaction** | Every log record is scrubbed **at creation time** — emails become correlatable `email[h:…]` hashes, cards become `****-****-****-1111`, secrets `[REDACTED]`. Fail-closed: un-scrubable records become `[LOG_DROPPED]`, never raw | `app/redact/` |
| 🗄️ **DB enforcement** | Two login roles → two data roles → Postgres `GRANT`s + **Row-Level Security**. Agents get `SELECT` on their own tenant's rows, **period** — the database refuses writes itself | `app/db/` |

The three layers are independent: use one, two, or all three.

## Quickstart (local)

```bash
git clone https://github.com/abeenoch/a-guard && cd a-guard
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

cp .env.example .env        # fill in PGPASSWORD / secrets (see below)

createdb agent_auth          # or psql -U postgres -c "CREATE DATABASE agent_auth"
psql -U postgres -d agent_auth -f app/db/schema.sql

uvicorn app.main:app --port 8000
```

In another terminal:

```bash
python scripts/smoke.py      # 12 end-to-end checks: OIDC flow, RBAC, redaction
pytest                        # 113 tests
```

### Demo credentials (dev only — override in `.env` for anything shared)

| What | Value |
|---|---|
| Human user | `alice@example.com` / `correct-horse-battery` |
| Second tenant | `bob@example.com` / `bob-not-a-real-secret` |
| Client `demo-spa` | public (PKCE) |
| Client `chat-agent` | `chat-agent-secret` — human-flow tokens with `roles: ["agent"]` |

The app prints `INSECURE DEV SECRETS ACTIVE` at startup until you override
`SESSION_SECRET` and `LOG_HASH_PEPPER` — that warning is intentional.

## The three guarantees, verified by tests

**1. Identity is proven, not asserted.** PKCE S256 only (`plain` rejected),
exact-match redirect URIs, single-use 60-second authorization codes with
replay detection, refresh rotation that revokes the whole token family when a
retired token reappears.

**2. PII never reaches a log sink.** Redaction runs in the `LogRecord` factory
— before serialization, before handlers, before formatters. Structured field
names, content patterns (Luhn-checked cards, percent-encoded emails), and
fail-closed error handling. Verified by fixture corpora *and* a live-server
grep for raw PII:

```json
{"event": "documents.create", "sub": "usr_alice",
 "title": "callback email[h:5fecc5cd0b92] re card ****-****-****-1111"}
```

Same person → same hash → still correlatable, never reversible.

**3. The database refuses, even when the app is tricked.**
```sql
-- agent session, prompt-injected payload:
INSERT INTO documents(...)  →  ERROR: permission denied for table documents
SELECT internal_notes ...    →  ERROR: permission denied for table documents
SELECT * FROM documents      →  0 rows (RLS: only own tenant)
```
Agents connect as `app_login_agent`, which can `SET ROLE` to *only*
`agent_readonly` — escalation fails at the membership level, not in code.

## Architecture

```
Request ──▶ auth middleware (JWT: sig/iss/aud/exp/scope → principal)
              │
              ├─▶ redaction choke point (factory + handler filters)
              │
              └─▶ scoped_session(kind, sub)
                    SET LOCAL ROLE agent_readonly | app_user
                    SET LOCAL app.sub = '<subject>'     ← RLS keys on this
                          │
                          ▼
                    Postgres: GRANTs decide capability, RLS decides visibility
```

- **401** = not authenticated · **403** = authenticated, not authorized
- `roles: ["human"]` → `app_user` (read/write own rows)
- `roles: ["agent"]` → `agent_readonly` (read-only, own tenant rows)

## Status

Alpha. 113 tests green (unit + live-server smoke). Known limitations are
tracked in [SECURITY.md](SECURITY.md) — in-memory token stores (single
process), no rate limiting yet, MCP authorization server compliance in
progress.

## Roadmap

- **MCP Authorization Server** ✅ `RFC 8414`, `RFC 9728`, `RFC 8707`, `RFC 7591` (DCR)
- `/userinfo`, `/revoke` (RFC 7009), `/introspect` (RFC 7662) ✅ — formerly advertised, now real
- `docker compose up` one-command install
- OpenTelemetry/Langfuse export of *redacted* traces

## Contributing

PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Security issues:
[SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
