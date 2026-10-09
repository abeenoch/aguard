# A-guard — interface & operator-surface design

**Status:** revision 2 — the web operator surface is cancelled (see §3.0)

This document settles three things *before* code is written, because two of
them are security decisions wearing product clothes:

1. **What surfaces exist** — and what is deliberately out of scope.
2. **The operator role** — who may see agent activity, and how the database
   enforces it.
3. **The design language** — the constraints the visuals must live inside.

**Revision 2:** a read-only browser dashboard was designed, then cancelled.
Observability now ships as CLI commands and log export (§3.2), implemented in
`scripts/agctl.py`. §3.0 records the reasoning rather than deleting it.

---

## 1. Why not just build a dashboard

"A dashboard" is two different products wearing one word:

| Reading | Verdict |
|---|---|
| An **operator view of agent activity** — what was attempted, what the database refused | **In scope.** This is the thesis made visible. |
| A **CRUD admin console** — manage clients, users, keys, settings | **Out of scope now.** Undifferentiated, and not yet buildable (§5.2). |

The product's core promise is *invisible*: it constrains what agents can do.
Invisible guarantees get adopted when they are **legible**. A view that shows
"this agent tried to delete a row and Postgres said no" is the product, not a
convenience.

Telling detail: **`agent_audit` is write-only today.** Every request inserts
audit rows; nothing in the codebase ever reads them. The activity view is the
first reader of data we already collect.

---

## 2. Principles

These are constraints, not preferences. Any surface that violates one is
wrong even if it looks good.

- **P1 — The UI never weakens the guarantee.** Every new surface is new attack
  surface. A screen that can leak one tenant's data to another invalidates the
  entire product claim.
- **P2 — Visibility is the feature.** The guarantee is invisible by nature;
  the interface exists to make it observable.
- **P3 — Secure by default, explicit by exception.** Matches the existing
  house style (dev-secret warnings, strict DCR default, opt-in schemes).
- **P4 — Boring stack.** Server-rendered, no JS framework, no build step, no
  third-party CDN assets. This keeps CSP trivial and the supply chain small —
  both are load-bearing for a security library.
- **P5 — One source of truth.** The UI reads the same tables and roles as the
  API. Permission logic lives in Postgres; the UI never re-implements it.

---

## 3. Surfaces

### 3.0 Direction change — no web operator surface

A read-only browser dashboard was the original plan. It is **cancelled**, for
reasons that are exactly what P1 was written to catch:

- **It is a new privileged surface.** The view spans actors, so it cannot be
  governed by the per-tenant RLS policy on `documents`. It needs its own auth
  and an operator role — and getting that wrong creates the single screen that
  leaks across tenants: the product's own failure mode.
- **The need is observability, not a UI.** What people actually want to see is
  that *redaction works* and *what the database refused*. Both are reachable
  from a terminal, with no new attack surface and no new authentication story.
- **It would have been built on data that does not exist yet** (§5) — the audit
  table has no read path, and users/clients are code constants.

So observability ships as **CLI commands + export** (§3.2).

### 3.1 Authentication pages — *restyle, keep*

`login`, `consent`, `error`, `callback` (currently `aguard/oidc/pages.py`).

- **Audience:** every human using any OAuth/OIDC or MCP client. This is the
  highest-traffic user-facing surface the project has.
- **Why it matters:** it is already shipped and unavoidable; polish here
  benefits every user of every client.
- Constraint: no inline scripts; all interpolated values escaped (today
  hand-rolled via `html.escape`, moving to autoescaping templates — §6.1).

### 3.2 Agent activity & redaction proof — *CLI, shipped*

`scripts/agctl.py`:

- `agctl redact …` / `agctl redact --file app.log` — show what the redactor
  does to a string, a JSON object, or a whole log file (stdin-capable).
- `agctl verify` — built-in redaction self-check with pass/fail output.
- `agctl audit [--sub S] [--denied] [--json]` — the audit trail, newest first.
- `agctl export [--format jsonl|csv] [--out F]` — dump it for shipping.

- **Audience:** the operator/developer, on a host that already has database
  credentials. No browser, no session, no new auth surface.
- **Shows:** actor (`sub`), client (`client_id`), request id, the operation,
  rows affected, and the **refusals** (`--denied`).
- **Does not show:** raw tokens, client secrets, un-redacted statements.
  Statements are redacted *at write time* (§5.3), so the CLI renders stored
  text as-is.
- **Read-only.** It never mutates the trail.

### 3.3 Explicitly out of scope

Any browser-based operator UI (cancelled, §3.0), client/user CRUD, key rotation
UI, settings, alerting, real-time streaming, charts, multi-tenant switching.
Rationale: none improve the guarantee, and all of them expand blast radius.

| Surface | Audience | Reads | Writes | Status |
|---|---|---|---|---|
| Auth pages | any end user | — | consent | shipped; restyle pending (E1) |
| Redaction proof (CLI) | operator/dev | — | nothing | **shipped** |
| Agent activity (CLI) | operator | `agent_audit` | nothing | **shipped** |
| Web dashboard | — | — | — | **cancelled** |
| Client/user admin | operator | clients, users | clients, users | not scheduled |

---

## 4. The operator role

This is the decision that matters. An activity view spans actors, so it cannot
be governed by the per-tenant RLS policy that protects `documents`.

### 4.1 Current state (facts, not intentions)

| Fact | Evidence |
|---|---|
| Four Postgres roles exist: `app_login_human`, `app_login_agent` (LOGIN), `app_user`, `agent_readonly` (NOLOGIN) | `aguard/db/schema.sql` `CREATE ROLE` |
| `human_admin` is **not** a Postgres role | same |
| `human_admin` appears only as an `app.role` GUC *value* in the `documents_human` RLS policy and as a type hint | `aguard/db/schema.sql:95,99`; `aguard/db/session.py:47,57` |
| No role can ever satisfy that policy branch: `scoped_session(role_override="human_admin")` emits `SET LOCAL ROLE human_admin`, which **fails** (no such role) — and it runs on the human pool, whose login is a member of `app_user` only | `aguard/db/session.py:56-64` |

**Conclusion: operator support is a stub, not a feature.** The RLS policy
reads as if an admin exists; nothing can reach it. This must be fixed
deliberately, or the activity view will be built on a fiction.

### 4.2 Options

| Option | Isolation | Blast radius | Verdict |
|---|---|---|---|
| **A. Dedicated `operator_readonly` role + `app_login_operator` login**, membership: login → `operator_readonly` only | Strong: separate login, exactly-one-role, exactly like the human/agent split | An operator-session compromise cannot write documents or escalate | **Recommended** |
| B. Implement `human_admin` via the existing `app_user` role | Weak: same role that writes documents | Operator path can mutate data | Rejected |
| C. Run UI reads as superuser | None | Violates **P1** | Rejected |

Option A mirrors the pattern the codebase already celebrates: *two logins, two
data roles, escalation is a membership violation, not a code bug.* It adds a
third of exactly the same shape:

```
app_login_operator ──member of──▶ operator_readonly
                                     │  GRANT SELECT ON agent_audit
                                     │  GRANT SELECT (safe cols) ON documents
                                     └─ no INSERT/UPDATE/DELETE anywhere
```

### 4.3 How the operator authenticates

There is no admin auth today, and inventing a parallel "admin password" would
contradict **P5**. Recommended: reuse the existing mechanism end to end.

- Extend the session/token capability classes with an `operator` role.
- Map it (as today) `roles → DB session kind`. Add `kind="operator"` to
  `scoped_session`, resolving to `app_login_operator`.
- The operator signs in through the *same* `/login` + signed session cookie;
  no second credential system to secure.

### 4.4 The operator is audited too

Reading the audit trail is itself a security-relevant action. Operator views
should append an `agent_audit` row (`client_id="operator-console"`). A log you
can read without leaving a trace is a liability.

### 4.5 Tenant scope — **DECIDED: add `org_id`**

`SECURITY.md` states multi-tenancy is *one deployment per tenant*. If that were
permanent, the operator would be the deployment owner viewing only their own
rows: **no cross-tenant exposure**, and the risk collapses to "operator sees
their own org", which is the point.

But `agent_audit` has **no tenant/org column** — `subject` is the only signal.
Because "one deployment per tenant" is a deployment choice rather than an
enforced invariant, we pre-empt it: **add `org_id` to `agent_audit` in E3**,
while the table is small, and scope the operator query by it. Retrofitting a
tenant key onto a write-only audit table later is painful and error-prone.

### 4.6 Surface threat model

| Threat | Mitigation |
|---|---|
| IDOR — operator reads another deployment's rows | Server-side scoping; no row identifiers that address other tenants; read-only |
| XSS via `statement` text | Autoescaping templates (§6.1); statements are plain text; never `|safe` |
| PII leak through the view | Statements are redacted **at write time** (§5.3); the view renders already-safe strings; document bodies and tokens are never selected |
| Operator impersonation | Same signed-session path as everything else; no shared admin secret; `operator` is a capability, not a shared account |
| Over-collection (view becomes an export tool) | No CSV/export in v1 |



---

## 5. Data prerequisites

These are functional gaps. The activity view is not buildable, or not
*responsible*, until they land.

### 5.1 `agent_audit` needs a read path (and indexes)

- Today the table has **only its primary key** — `schema.sql` defines no
  indexes at all.
- `scoped_session` sets `statement_timeout = 5000ms`. An activity view ordered
  by `ts DESC` over an unindexed table will degrade into sequential scans and
  start timing out precisely when the deployment is busiest.
- **Add:** `CREATE INDEX ON agent_audit (ts DESC)` and
  `(subject, ts DESC)`, plus a bounded default page size and a keyset
  (`ts, id`) cursor — offset pagination on an append-only log is wrong.

### 5.2 Users and clients are Python constants

- `USERS` is a dict literal in `aguard/oidc/users.py`; clients come from
  `seed_registry()` in `aguard/oidc/clients.py`.
- They cannot be listed, edited, or rotated without a redeploy — which makes
  any admin UI impossible, and makes a real operator account awkward.
- **Move to tables** (`app_users`, `oauth_clients`), keeping the current
  fixtures as *seed data*. Good news: clients already store only
  `hash_secret(...)` digests, so the schema shape is already right.

### 5.3 Redaction happens at write time — keep it that way

Every writer (REST API, MCP tools) passes statements through the redactor
before insert. That is what makes an activity view safe to render *by
construction* rather than by careful per-field escaping.

**Rule:** the view renders stored text as-is and must never be the place where
redaction is attempted. If a field is unsafe to store, it is unsafe to store —
not "handle it at render time".

---

## 6. Design language

### 6.1 Stack constraints

- **Jinja2 with autoescaping** replaces the hand-rolled f-string templates.
  Not currently installed (it is **not** a transitive dependency of
  FastAPI/Starlette — verified), so it is a deliberate addition. The explicit
  win is XSS safety: autoescaping is on by default, and interpolation that
  forgets to escape stops being possible.
- **One CSS file** served from `/static`, no build step, no CDN, no inline
  scripts.
- **CSP becomes achievable.** Today's pages use `style="…"` attributes, which
  force `style-src 'unsafe-inline'`. Moving styles into a stylesheet lets us
  ship `default-src 'self'; style-src 'self'; script-src 'none'`.

### 6.2 Tokens (the whole vocabulary)

| Group | Tokens |
|---|---|
| Colour | `--ink`, `--ink-muted`, `--surface`, `--border`, `--accent` (one), `--allow`, `--refuse`, `--warn` |
| Type | system sans for prose; `ui-monospace` for identifiers; scale ≈ 12 / 14 / 16 / 20 / 28 |
| Space | 4 / 8 / 12 / 16 / 24 / 32 |
| Shape | 1px borders, 6px radius, no shadows-as-decoration |

One accent colour. Semantic colour is reserved for meaning: **allowed** vs
**refused** must be distinguishable at a glance, because that distinction *is*
the product.

### 6.3 Components

Page shell (product name + sign-out) · card · form field · button
(primary/secondary) · data table · **status badge** (allow / refuse) · mono
identifier chip (for `sub`, `client_id`, `request_id`) · empty state · banner
(error / info).

### 6.4 Content rules

- Never render a token, secret, or credential. Ever.
- Identifiers (`sub`, `client_id`, `request_id`, `jti`) render in monospace —
  they are compared byte-for-byte and must not be visually ambiguous.
- Timestamps: UTC, ISO-8601, with a relative hint.
- Refusal reasons are quoted from the source, not paraphrased. "refused by
  database policy" is the product speaking.
- No marketing language in the UI.

### 6.5 Accessibility

Labels bound to inputs, visible focus states, semantic `<table>` markup with
headers, contrast ≥ 4.5:1, fully keyboard-operable. A security tool that is
unusable with a keyboard is a security tool people route around.

### 6.6 Naming — **RESOLVED**

The product name is **a-guard**, everywhere: package, README, page titles,
logger names (`a-guard.api`, `a-guard.mcp`, `a-guard.startup`), and the default
JWT `aud` (`a-guard-api`). The historical `agent-auth-lab` strings are gone.

One deliberate exception: the **Postgres database name `agent_auth`** is left
alone (see §9 D6) — it is not a display string, and renaming it mutates a live
database rather than a file.

---

## 7. Explicitly out of scope

Recorded so the boundary is a decision, not an omission:

A browser-based operator dashboard (§3.0) · any JS build step (React/Vue/Vite)
· real-time streaming (SSE/WebSocket) · charting libraries ·
alerting/notifications · client-secret rotation UI · multi-tenant org switching
· theming/dark mode · i18n.

Each is defensible *later*. None improves the guarantee now, and several
conflict with P4.

**Correction:** CLI export (`--format jsonl|csv`) is *in* scope and shipped. An
earlier revision listed "CSV/JSON export" here by mistake — "let people take
their logs" is a legitimate need, not scope creep.

---

## 8. Phasing

| Phase | Work | Depends on | Why here |
|---|---|---|---|
| **E1** | Design foundation: Jinja2 + autoescaping, `/static` CSS with tokens, restyle the 4 auth pages, CSP header | — | Highest-traffic user surface; removes an XSS footgun; zero product risk |
| **E2** | Move `users` + `clients` into Postgres, seed current fixtures | — | Today they are code constants and cannot be listed or rotated without a redeploy |
| **E3** | `agent_audit` read path: indexes + `org_id` (§4.5) | — | The CLI already reads this table; without indexes, paging degrades exactly when the log is largest |
| **E4** | ~~`operator` capability + `operator_readonly` role~~ | — | **Deferred.** With no web surface the CLI runs with deployer credentials. Revisit only if a hosted/remote operator view returns |
| **E5** | CLI observability: `agctl redact\|verify\|audit\|export` | — | **Done** — this is what replaced the dashboard |
| **E6** | Client/user admin UI | E2 | Still unscheduled, and now unlikely to be worth it |

The ordering principle holds, restated for a CLI: **role and data land before
the surface that reads them.** The CLI reads the same tables, through the same
least-privilege session layer, as the API — it does not invent its own path to
the data.

---

## 9. Decisions

| # | Decision | Status | Resolution |
|---|---|---|---|
| D1 | Operator isolation | ⏸ deferred | Would have needed `operator_readonly` + `app_login_operator`. With no web surface, the CLI runs with deployer credentials — revisit only if a hosted operator view returns |
| D2 | Tenant model of the audit trail | ✅ decided | Add `org_id` to `agent_audit` in E3 — the CLI reads across subjects, so this stays the right boundary |
| D3 | Product name | ✅ done | **a-guard** — applied to package, pages, logger names, and default `aud` |
| D4 | Auth-page visual direction | open | minimal / utilitarian (**P4**) |
| D5 | Operator sign-in | ⏸ moot | No web operator surface to sign into (§3.0) |
| D6 | Database name | open | **keep `agent_auth`** (default) · rename to `a_guard` — requires a coordinated `ALTER DATABASE` plus updates to `settings.py`, `schema.sql`, CI, compose, and three test files |
| D7 | Operator surface | ✅ done | **CLI + export** (`scripts/agctl.py`), not a browser dashboard (§3.0) |
| D8 | Authorization state storage | ✅ done | Pluggable: `memory` (default) / `postgres`. Not an ops nicety — per-process tombstones make replay undetectable across workers, so the backend is a security property |

D6 is deliberately *not* bundled with D3: the product rename touched files,
whereas the DB rename mutates a running database — and the local Postgres is a
**shared instance** hosting unrelated databases. That is an operator's call,
not a refactor.

---

## 10. What this document does *not* claim

- It does not claim the audit trail is cheap to read yet — §5.1 (indexes) still
  stands, and the CLI reads that table.
- It does not redesign the API or the OIDC surface.
- It does not commit to a timeline. It commits to an order of operations:
  **role → data → surface.**
- **The CLI is not a privilege boundary.** It runs on a host that already holds
  database credentials and reads `agent_audit`, which carries no RLS (it is the
  cross-actor record). That is appropriate for a deployer-run tool and would not
  be appropriate exposed as a network service — which is precisely why it is a
  CLI and not a dashboard.

