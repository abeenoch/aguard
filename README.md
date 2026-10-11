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

## Try it in 5 seconds — no account, no keys, no deploy

The redaction engine (the same one that scrubs a-guard's own audit trail) has an
**unauthenticated playground** on the live server:

```bash
curl -s https://aguard.abeenoch.online/redact \
  -H 'Content-Type: application/json' \
  -d '{"text": "my card is 4111 1111 1111 1111, mail alice@example.com, address flat 4, oguntunde estate"}'
```

```json
{
  "redacted": "my card is ****-****-****-1111, mail email[h:5415816037c0], address [ADDRESS_REDACTED]",
  "findings": [
    { "type": "card",    "count": 1 },
    { "type": "email",   "count": 1 },
    { "type": "address", "count": 1 }
  ]
}
```

Emails become keyed-HMAC tags (`email[h:…]`): correlatable across log lines,
never reversible. Findings are counts only — the detected values are returned to
you in the redacted string and then gone: **nothing is stored, nothing is
logged but the counts.** The playground is rate-limited (10 req/min per address)
and capped at 10,000 characters — knobs in `.env.example`
(`RATE_LIMIT_REDACT`, `REDACT_ENDPOINT_MAX_CHARS`).

Prefer it inside an agent? Add the hosted tool to any MCP host — Cline runs the
browser authorization flow on first use, no deployment on your side:

```json
{
  "mcpServers": {
    "a-guard-redact": {
      "type": "streamableHttp",
      "url": "https://aguard.abeenoch.online/mcp",
      "disabled": false,
      "autoApprove": ["redact_text"]
    }
  }
}
```

That is the top of the funnel. Everything below — OAuth 2.1 with agent
principals, DB-enforced tenancy, audit trails that remember the *who* without
the *what* — is what you graduate into when the agent gets database access.
(Self-hosting? [The database is yours](#self-hosting-the-database-is-yours) —
`documents` is demo data, not your new home.)

## What's inside

| Layer | What it does | Where |
|---|---|---|
| 🔐 **OIDC provider** | Hand-rolled OAuth 2.1/OIDC: authorization code + **PKCE S256 only**, short-lived JWTs, **rotating refresh tokens with family revocation**, `client_credentials` for machine principals | `aguard/oidc/` |
| 🔪 **PII redaction** | Every log record is scrubbed **at creation time** — emails become correlatable `email[h:…]` hashes, cards become `****-****-****-1111`, secrets `[REDACTED]`. Fail-closed: un-scrubable records become `[LOG_DROPPED]`, never raw | `aguard/redact/` |
| 🗄️ **DB enforcement** | Two login roles → two data roles → Postgres `GRANT`s + **Row-Level Security**. Agents get `SELECT` on their own tenant's rows, **period** — the database refuses writes itself | `aguard/db/` |

The three layers are independent: use one, two, or all three.

## Protect your own MCP server

a-guard issues the tokens; your server just verifies them. No shared secret, no
signing key, no session table:

```python
from fastapi import Depends, FastAPI, Request
from aguard import ResourceServerGuard

guard = ResourceServerGuard(
    issuer="http://localhost:8080",         # the a-guard AS
    audience="http://localhost:9000/mcp",   # YOUR resource id
)
app = FastAPI()

@app.post("/mcp")
def mcp(claims: dict = Depends(guard.dependency())):
    return {"sub": claims["sub"]}           # verified, not asserted
```

The guard fetches the issuer's JWKS (and re-resolves on key rotation), then
checks the signature, `iss`, and `exp` — and, critically, that **`aud` names
your resource**. A token minted for a different service is refused here even
though its signature is valid: that's RFC 8707 audience binding, and it's what
stops cross-service token replay.

An unauthenticated request gets `401` **plus**
`WWW-Authenticate: Bearer resource_metadata="…"` — which is how an MCP client
*discovers* the authorization server instead of being configured with it.

Runnable version: [`examples/protect_mcp_server.py`](examples/protect_mcp_server.py).

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

# Two services, two ports. The authorization server issues tokens; the MCP
# resource server is a separate deployable that holds NO signing key and
# verifies tokens via the AS's JWKS.
python -m uvicorn aguard.main:app --port 8080            # authorization server
python -m uvicorn aguard.mcp.service:app --port 8081     # MCP resource server
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
python scripts/mcp_smoke.py        # real MCP client against a live resource server
curl -s localhost:8080/readyz      # AS readiness: database + keystore
curl -s localhost:8081/readyz      # resource server readiness: JWKS + database
pytest                             # 278 tests
ruff check . && mypy               # lint + types (also gates CI)
```

### One-command demo

The whole story on one screen — both services, a real MCP client, and the audit
trail where `rows=0` is the agent's refused delete:

```bash
bash scripts/demo.sh                      # run it
DEMO_PAUSE=1.0 bash scripts/demo.sh       # paced, for recording
DEMO_KEEP=1 bash scripts/demo.sh          # leave the services running after
```

It starts the services it needs (and reuses any already running), waits for
readiness, runs the MCP flow, prints the audit rows, shows redaction, then stops
what it started. Recording? The storyboard, narration and export commands are in
[docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md).

### Demo credentials (dev only — override in `.env` for anything shared)

| What | Value |
|---|---|
| Human user | `alice@example.com` / `correct-horse-battery` |
| Second tenant | `bob@example.com` / `bob-not-a-real-secret` |
| Client `demo-spa` | public (PKCE) |
| Client `chat-agent` | `chat-agent-secret` — human-flow tokens with `roles: ["agent"]` |

The app prints `INSECURE DEV SECRETS ACTIVE` at startup until you override
`SESSION_SECRET` and `LOG_HASH_PEPPER` — that warning is intentional.

### Anyone can sign up

Accounts are not hardcoded. `/signup` creates one (name, email, password —
PBKDF2-HMAC-SHA256, 200k iterations), signs the visitor straight in, and — with
`STORE_BACKEND=postgres` — keeps the account across restarts. The sign-in and
consent pages carry a "Create one" link between them.

```bash
ALLOW_SIGNUP=false      # close registration without a code change
SEED_DEMO_USERS=false   # drop alice/bob (their passwords are public above)
```

The two seeded demo users are the RLS fixtures the suite and the demo depend on,
which is why they exist at all — a real deployment turns them off and uses
`/signup`.

## Self-hosting: the database is yours

The `documents` table in this repo is **demo data** — a stand-in so the demo has
something to read and something the agent gets refused deleting. A-guard is not
a storage product and does not want your data. When you self-host, `documents`
goes away and **your real tables** take its place:

| | |
|---|---|
| **You bring** | your Postgres, your schema, your application (it keeps owning the data plane: create/update/delete through your own code) |
| **A-guard brings** | identity (who the agent is, tokens, revocation), the redaction choke point for logs and audit, and the Postgres plumbing that makes "read-only, own tenant only" a property of the *database* |

Adopting it on your own database is three moves:

1. **Point the DSNs** (`DB_DSN_*`) at your Postgres instance.
2. **Port the enforcement pattern** from `aguard/db/schema.sql` onto your
   tables: a tenancy column, `CREATE POLICY` rows scoped to it, `GRANT SELECT`
   to `agent_readonly` — and **no write grants**, so the database itself
   refuses the agent's worst impulses. (Roles are cluster-wide, so the login
   roles schema.sql creates work against your database as-is.)
3. **Adapt the MCP tools** to query your tables — `list_documents` and
   `read_document` are ~20-line functions in `aguard/mcp/server.py`, written
   to be copied, not admired.

Everything else — token machinery, RLS session wiring, the redacted audit
trail, `redact_text` — works unchanged, because none of it cares what your
tables are. A-guard is the guard, not the house: your data stays in your
database under your control, and a-guard supplies the identity layer and the
database-side enforcement that survives prompt injection.

## Deploy (systemd + a TLS reverse proxy)

The files that run a-guard on a server live in this repo:

| File | Role |
|---|---|
| `systemd/aguard-as.service`  | authorization server on `127.0.0.1:8080` |
| `systemd/aguard-mcp.service` | MCP resource server on `127.0.0.1:8081` (holds no signing key) |
| `web/index.html` | the landing page served at `/` (one self-contained file, no build step) |
| `.env.example` | every knob (issuer, DSNs, secrets, signing keys) |

```bash
# 1. configuration — copy the template, then set the issuer, DSNs and secrets
cp .env.example .env

# 2. the two services (survive a crash and a reboot)
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now aguard-as aguard-mcp

# 3. publish the landing page
sudo mkdir -p /var/www/aguard && sudo cp web/index.html /var/www/aguard/
```

Both services bind **loopback only**: a TLS-terminating reverse proxy sits in
front and forwards `/api` → `127.0.0.1:8080` and `/mcp` → `127.0.0.1:8081`, plus
the origin-level `.well-known/` discovery paths (resource metadata → the
resource server; AS metadata → the AS). That per-host proxy config is
environment-specific and deliberately **not** shipped here. See
[`systemd/README.md`](systemd/README.md) for service install/config/ops.

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

`/mcp` is a real MCP server speaking **Streamable HTTP**, running as its **own
service** on its own port (`http://localhost:8081/mcp`). It holds **no signing
key**: it fetches the AS's JWKS and verifies tokens itself, so a resource-server
compromise is not an AS compromise. An MCP client with no token gets a `401`
carrying an RFC 9728 `resource_metadata` pointer, follows it to discover our AS,
registers (RFC 7591 DCR), runs code + PKCE, and asks for a token audience-bound
to this resource (RFC 8707):

```json
POST /token
grant_type=client_credentials&resource=http://localhost:8081/mcp
```

Four tools — the fourth is the one anyone can try without deploying anything:

| Tool | Human | Agent |
|---|---|---|
| `list_documents` | own rows | own tenant rows (RLS) |
| `read_document` | own rows | own tenant rows (RLS) |
| `delete_document` | own rows ✅ | **refused by Postgres** ⛔ |
| `redact_text` | ✅ | ✅ — scrub PII before echoing/forwarding text |

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
      "url": "http://localhost:8081/mcp",
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
DCR_ALLOWED_REDIRECT_SCHEMES=vscode   # in the AS's environment, then restart it
```

Set it in the server's **launch environment**, not in `.env`: the suite reads
`.env` to pin the default-strict posture (`tests/test_dcr_redirect_policy.py`),
so exporting it there turns the tests red. The shipped
[`systemd/aguard-as.service`](systemd/aguard-as.service) already sets it.

Before recording or demoing with a given client, check that its exact request
sequence is satisfiable — this replays discovery, DCR, the `/authorize`
contract and a full `tools/list` over MCP:

```bash
python scripts/cline_preflight.py     # expect 10/10 gates passed
```

Full walkthrough, recording beats and post-run evidence:
[docs/DEMO_CLINE.md](docs/DEMO_CLINE.md).

### Prove it

```bash
uvicorn aguard.main:app --port 8080           # terminal 1 — authorization server
uvicorn aguard.mcp.service:app --port 8081    # terminal 2 — resource server
python scripts/mcp_smoke.py                   # terminal 3 — real MCP client SDK
pytest tests/test_mcp_resource_server.py      # includes the split-boundary tests
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

## Integrate: protect your own MCP server

The other half of the product: your server accepts a-guard-issued tokens
**without holding a signing key**. `ResourceServerGuard` fetches the issuer's
JWKS, caches it, re-resolves on key rotation, and enforces the four checks that
matter — signature, `iss`, **`aud`** (RFC 8707), and expiry:

```python
from fastapi import Depends, FastAPI, Request
from aguard.resource_server import ResourceServerGuard

guard = ResourceServerGuard(
    issuer="http://localhost:8080",        # the AS — ours, or anyone's
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

Alpha. 278 tests green (unit + live-server smoke). Known limitations are
tracked in [SECURITY.md](SECURITY.md) — authorization state defaults to
in-memory (set `STORE_BACKEND=postgres` before running more than one worker),
rate-limit counters default to per-process as well (set
`RATE_LIMIT_BACKEND=postgres` to share them across workers), and the signing key
defaults to a file on disk (`KEY_SOURCE=env`, `aws-kms`, `gcp-kms` or `vault`
for anything shared).

The MCP resource server is its **own service on its own port** and holds **no
signing key** — it verifies tokens against the AS's JWKS. The hand-rolled OIDC
crypto has a review package written for an external reviewer in
[docs/CRYPTO_REVIEW.md](docs/CRYPTO_REVIEW.md), with an internal self-review in
[docs/CRYPTO_REVIEW_FINDINGS.md](docs/CRYPTO_REVIEW_FINDINGS.md).

## Roadmap

- **MCP Authorization Server** ✅ `RFC 8414`, `RFC 9728`, `RFC 8707`, `RFC 7591` (DCR)
- `/userinfo`, `/revoke` (RFC 7009), `/introspect` (RFC 7662) ✅ — formerly advertised, now real
- **MCP resource server** at `/mcp` ✅ — Streamable HTTP, audience-bound tokens, DB-enforced tools
- **CLI observability** ✅ — `scripts/agctl.py`: redaction proof, audit trail, CSV/JSONL export
- **Packaging** ✅ — `agctl` console script; `from aguard import ResourceServerGuard`; wheel verified to contain its data files
- **Downstream guard** ✅ — protect any MCP server in ~10 lines (`examples/protect_mcp_server.py`)
- **Persistent authorization state** ✅ — pluggable stores; `STORE_BACKEND=postgres` makes code tombstones and refresh-family revocation survive restarts and span workers
- **Rate limiting + readiness** ✅ — `/token`, `/login` and `/register` are limited per address (plus per account for login); `GET /readyz` verifies the database and keystore, while `/healthz` stays dependency-free liveness
- **Split resource server** ✅ — the MCP server is its own service (`aguard/mcp/service.py`) on its own port, verifying via the AS's JWKS and holding no signing key
- **Zero-auth playground** ✅ — `POST /redact` runs the redaction engine for any visitor with a curl (rate-limited per address, size-capped, stateless: no DB, no audit row, nothing stored)
- **Signing keys via env / KMS** ✅ — `KEY_SOURCE=file|env|aws-kms|gcp-kms|vault`, one `Signer` interface; the KMS private key never enters the process
- **One-command install** ✅ — `docker compose up` starts the database, the AS and the resource server
- **External crypto review** ⏳ — reviewer package + internal findings ship; the third-party review is the remaining step before 1.0
- Restyle the auth pages (Jinja2 + design tokens) — see [docs/DESIGN.md](docs/DESIGN.md) → E1
- Move users/clients out of Python constants into Postgres → E2
- Index `agent_audit`; add `org_id` → E3

A browser dashboard was considered and **cancelled** — it is a new privileged
surface spanning tenants, i.e. the one screen that could undermine the
guarantee. The reasoning is recorded in [docs/DESIGN.md](docs/DESIGN.md) §3.0.

## Contributing

PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Security issues:
[SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
