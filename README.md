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
| 🔐 **OIDC provider** | Hand-rolled OAuth 2.1/OIDC: authorization code + **PKCE S256 only**, short-lived JWTs, **rotating refresh tokens with family revocation**, `client_credentials` for machine principals | `aguard/oidc/` |
| 🔪 **PII redaction** | Every log record is scrubbed **at creation time** — emails become correlatable `email[h:…]` hashes, cards become `****-****-****-1111`, secrets `[REDACTED]`. Fail-closed: un-scrubable records become `[LOG_DROPPED]`, never raw | `aguard/redact/` |
| 🗄️ **DB enforcement** | Two login roles → two data roles → Postgres `GRANT`s + **Row-Level Security**. Agents get `SELECT` on their own tenant's rows, **period** — the database refuses writes itself | `aguard/db/` |

The three layers are independent: use one, two, or all three.

## Quickstart (local)

```bash
git clone https://github.com/abeenoch/aguard && cd aguard
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# One command does the setup — and then proves it worked:
#   .env with freshly generated secrets, database created, schema applied,
#   and a live check that the agent really is refused by Postgres.
#   (Run without --pg-password to just generate .env, then fill it in.)
python scripts/agctl.py init --pg-password <your-postgres-password>

python -m uvicorn aguard.main:app --port 8000
```

Expected tail of `init`:

```
[PASS] human role reads documents — 0 row(s)
[PASS] agent role reads its tenant — 0 row(s)
[PASS] agent DELETE refused by the database — InsufficientPrivilege
[PASS] agent cannot escalate to app_user — membership violation
```

`init` refuses to run if the database already holds audit rows (it re-applies
`schema.sql`, which drops tables) — pass `--force` when that is what you want.

<details>
<summary>Prefer to do it by hand?</summary>

```bash
cp .env.example .env         # then set PG_SUPERUSER_PASSWORD / SESSION_SECRET / LOG_HASH_PEPPER
createdb agent_auth
psql -U postgres -d agent_auth -f aguard/db/schema.sql
```
</details>

### Verify it works

```bash
python scripts/agctl.py verify     # redaction self-check, pass/fail
python scripts/agctl.py audit      # the audit trail (rows=0 ⇒ refused)
python scripts/mcp_smoke.py        # real MCP client against a live server
pytest                             # 193 tests
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

## MCP resource server (Streamable HTTP, OAuth-protected)

`/mcp` is a real MCP server speaking **Streamable HTTP**. It is protected by
the same authorization server as everything else — an MCP client with no token
gets a `401` carrying an RFC 9728 `resource_metadata` pointer, follows it to
discover our AS, registers (RFC 7591 DCR), runs code + PKCE, and asks for a
token audience-bound to this resource (RFC 8707):

```json
POST /token
grant_type=client_credentials&resource=http://localhost:8000/mcp
```

Three tools — and the third is the point:

| Tool | Human | Agent |
|---|---|---|
| `list_documents` | own rows | own tenant rows (RLS) |
| `read_document` | own rows | own tenant rows (RLS) |
| `delete_document` | own rows ✅ | **refused by Postgres** ⛔ |

An agent's `delete_document` call reaches the handler and runs the `DELETE` —
then Postgres raises `InsufficientPrivilege`, because the agent's session is
`agent_readonly`, which has no `DELETE` grant. The tool reports the refusal
(never retries, escalates, or converts it to success) and audits the attempt.
**The LLM cannot talk its way past a `GRANT`.**

A token minted for `/api` is rejected here, and vice versa: audience binding
means one token cannot be replayed against the other surface.

### Point Cline (or any MCP host) at it

Add to `cline_mcp_settings.json` (or use the in-app Remote Servers tab):

```json
{
  "mcpServers": {
    "a-guard-documents": {
      "type": "streamableHttp",
      "url": "http://localhost:8000/mcp",
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

Cline discovers the AS from the `WWW-Authenticate` header, registers itself,
and runs the browser authorization flow. Leave `autoApprove` empty so the
refused tool call is visible in the conversation rather than hidden.

Cline is an editor extension, so it registers a **private-use** redirect
(`vscode://saoudrizwan.claude-dev/mcp-auth/callback/<hash>`) instead of a
loopback port. That is opt-in, because `https`/loopback stays the default:

```bash
DCR_ALLOWED_REDIRECT_SCHEMES=vscode   # in .env, then restart the server
```

Before recording or demoing with a given client, check that its exact request
sequence is satisfiable — this replays discovery, DCR, the `/authorize`
contract and a full `tools/list` over MCP:

```bash
python scripts/cline_preflight.py     # expect 9/9 gates passed
```

Full walkthrough, recording beats and post-run evidence:
[docs/DEMO_CLINE.md](docs/DEMO_CLINE.md).

### Prove it

```bash
uvicorn aguard.main:app --port 8000          # terminal 1
python scripts/mcp_smoke.py               # terminal 2 — real MCP client SDK
pytest tests/test_mcp_resource_server.py  # 10 tests, in-process, no network
```

## See it work from the command line

No dashboard, no browser session, no new attack surface. `scripts/agctl.py`
reads the same tables through the same least-privilege session layer as the
API:

```bash
# what the redactor does to PII — the redaction you can actually watch
python scripts/agctl.py redact "call alice@example.com re card 4111 1111 1111 1111"
#   -> call email[h:5fecc5cd0b92] re card ****-****-****-1111

python scripts/agctl.py verify              # built-in self-check, pass/fail
python scripts/agctl.py redact --file access.log   # redact a whole log file
python scripts/agctl.py redact --json -     # structural walk, from stdin

# the audit trail — rows=0 is where the database said no
python scripts/agctl.py audit --limit 20
python scripts/agctl.py audit --denied      # only refusals / no-ops
python scripts/agctl.py export --format csv --out audit.csv
```

A row where an agent was refused and a human allowed the same operation, from
a real run:

```
   id  ts                    subject       client       rows  statement
    9  2026-10-09 22:04:08   usr_alice     demo-spa        1  MCP delete_document id=7
    8  2026-10-09 22:04:07   usr_alice     chat-agent      0  MCP delete_document id=7
```

## Protect your own MCP server

The other half of the product: your server accepts a-guard-issued tokens
**without holding a signing key**. `ResourceServerGuard` fetches the issuer's
JWKS, caches it, re-resolves on key rotation, and enforces the four checks that
matter — signature, `iss`, **`aud`** (RFC 8707), and expiry:

```python
from fastapi import Depends, FastAPI, Request
from aguard.resource_server import ResourceServerGuard

guard = ResourceServerGuard(
    issuer="http://localhost:8000",        # the AS — ours, or anyone's
    audience="http://localhost:9000/mcp",  # THIS resource, and nothing else
)

app = FastAPI()

@app.post("/mcp")
def mcp(request: Request, claims: dict = Depends(guard.dependency())):
    return {"sub": claims["sub"]}          # identity that survived verification
```

That `audience` argument is the whole point: a token minted for another service
— even a perfectly signed one — is refused here, and vice versa.

Unverified requests get a `401` carrying
`WWW-Authenticate: Bearer resource_metadata="…"`, which is how an MCP client
*discovers* the authorization server rather than being configured with it.

Runnable example: [`examples/protect_mcp_server.py`](examples/protect_mcp_server.py).

```bash
python -m build                 # distribution metadata lives in pyproject.toml
agctl --help                    # console script (see docs/RELEASING.md)
```

## Status

Alpha. 193 tests green (unit + live-server smoke). Known limitations are
tracked in [SECURITY.md](SECURITY.md) — authorization state defaults to
in-memory (set `STORE_BACKEND=postgres` before running more than one worker),
no rate limiting yet, and the MCP resource server runs in-process
with the AS (split into a separate service before any real deployment).

## Roadmap

- **MCP Authorization Server** ✅ `RFC 8414`, `RFC 9728`, `RFC 8707`, `RFC 7591` (DCR)
- `/userinfo`, `/revoke` (RFC 7009), `/introspect` (RFC 7662) ✅ — formerly advertised, now real
- **MCP resource server** at `/mcp` ✅ — Streamable HTTP, audience-bound tokens, DB-enforced tools
- **CLI observability** ✅ — `scripts/agctl.py`: redaction proof, audit trail, CSV/JSONL export
- **Persistent authorization state** ✅ — pluggable stores; `STORE_BACKEND=postgres` makes code tombstones and refresh-family revocation survive restarts and span workers
- Token-endpoint rate limiting; readiness probe that actually checks the database
- Restyle the auth pages (Jinja2 + design tokens) — see [docs/DESIGN.md](docs/DESIGN.md) → E1
- Move users/clients out of Python constants into Postgres → E2
- Index `agent_audit`; add `org_id` → E3
- Split the resource server into its own deployable service (own port, own container)
- `docker compose up` one-command install

A browser dashboard was considered and **cancelled** — it is a new privileged
surface spanning tenants, i.e. the one screen that could undermine the
guarantee. The reasoning is recorded in [docs/DESIGN.md](docs/DESIGN.md) §3.0.

## Contributing

PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Security issues:
[SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
