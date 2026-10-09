# A-guard — interface & operator-surface design

**Status:** draft for review · **Supersedes:** nothing · **Blocks:** any UI work

This document exists to settle three things *before* code is written, because
two of them are security decisions wearing product clothes:

1. **What surfaces exist** — and what is deliberately out of scope.
2. **The operator role** — who may see agent activity, and how the database
   enforces it.
3. **The design language** — the constraints the visuals must live inside.

Nothing here is implemented yet. Sections marked **DECISION NEEDED** are open.

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

### 3.1 Authentication pages — *restyle, keep*

`login`, `consent`, `error`, `callback` (currently `app/oidc/pages.py`).

- **Audience:** every human using any OAuth/OIDC or MCP client. This is the
  highest-traffic user-facing surface the project has.
- **Why it matters more than a dashboard:** it is already shipped and
  unavoidable; polish here benefits every user of every client.
- Constraint: no inline scripts; all interpolated values escaped (today
  hand-rolled via `html.escape`, moving to autoescaping templates — §6.1).

### 3.2 Agent Activity — *new, narrow, read-only*

- **Audience:** the operator of this deployment.
- **Shows:** recent agent/human operations across the deployment — actor
  (`sub`), client (`client_id`), request id, the operation, rows returned, and
  **refusals** (the interesting rows).
- **Does not show:** raw tokens, client secrets, un-redacted statements,
  document bodies. (Statements are already redacted *at write time* — see
  §5.3 — so the view is inherently safe to render.)
- **Read-only.** No mutation of anything, ever. Any admin action is a separate
  surface with its own design.

### 3.3 Explicitly out of scope (now)

Client/user CRUD, key rotation UI, settings, alerting, real-time streaming,
charts, multi-tenant switching. Rationale: none of these improve the guarantee,
several are unbuildable today, and all of them expand blast radius.

| Surface | Audience | Reads | Writes | Phase |
|---|---|---|---|---|
| Auth pages | any end user | — | consent | E1 |
| Agent Activity | operator | `agent_audit`, `documents` | nothing | E4 |
| Client/user admin | operator | clients, users | clients, users | **not scheduled** |

---

## 4. The operator role

This is the decision that matters. An activity view spans actors, so it cannot
be governed by the per-tenant RLS policy that protects `documents`.

### 4.1 Current state (facts, not intentions)

| Fact | Evidence |
|---|---|
| Four Postgres roles exist: `app_login_human`, `app_login_agent` (LOGIN), `app_user`, `agent_readonly` (NOLOGIN) | `app/db/schema.sql` `CREATE ROLE` |
| `human_admin` is **not** a Postgres role | same |
| `human_admin` appears only as an `app.role` GUC *value* in the `documents_human` RLS policy and as a type hint | `app/db/schema.sql:95,99`; `app/db/session.py:47,57` |
| No role can ever satisfy that policy branch: `scoped_session(role_override="human_admin")` emits `SET LOCAL ROLE human_admin`, which **fails** (no such role) — and it runs on the human pool, whose login is a member of `app_user` only | `app/db/session.py:56-64` |

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

### 4.5 Tenant scope — **DECISION NEEDED**

`SECURITY.md` states multi-tenancy is *one deployment per tenant*. If that
holds, the operator is the deployment owner viewing only their own rows: **no
cross-tenant exposure**, and the risk collapses to "operator sees their own
org", which is the point.

But `agent_audit` has **no tenant/org column** — `subject` is the only signal.
So:

- **If** one-deployment-per-tenant is permanent → the view is org-scoped by
  construction; document it and move on.
- **If** multi-tenancy is coming → add `org_id` to `agent_audit` *now*, before
  the view exists, and scope the operator query by it. Retrofitting a tenant
  key onto a write-only audit table later is painful and error-prone.

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

- `USERS` is a dict literal in `app/oidc/users.py`; clients come from
  `seed_registry()` in `app/oidc/clients.py`.
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

### 6.6 Naming — **DECISION NEEDED**

The package and README say **a-guard**; the actual pages say
**"Sign in — agent-auth-lab"** and the callback page likewise. The inconsistency
is shown to *every* end user on the login page. Pick one name and apply it.

---

## 7. Explicitly out of scope

Recorded so the boundary is a decision, not an omission:

React/Vue/Vite or any build step · real-time streaming (SSE/WebSocket) ·
charting libraries · alerting/notifications · CSV/JSON export · client secret
rotation UI · multi-tenant org switching · theming/dark mode · i18n.

Each is defensible *later*. None improves the guarantee now, and several
conflict with P4.

---

## 8. Phasing

| Phase | Work | Depends on | Why here |
|---|---|---|---|
| **E1** | Design foundation: Jinja2 + autoescaping, `/static` CSS with tokens, restyle the 4 auth pages, add CSP header | — | Highest-traffic surface; removes an XSS footgun; zero new product risk |
| **E2** | Move `users` + `clients` into Postgres, seed current fixtures | — | Unblocks operator accounts and any admin surface |
| **E3** | `agent_audit` read path: indexes + `org_id` decision (§4.5) + paginated query | E2 (optional) | Makes the log usable and cheap to read |
| **E4** | `operator` capability class → `app_login_operator` / `operator_readonly` (§4.2), operator sign-in | E2 | The security decision lands *before* the screen |
| **E5** | Agent Activity view (read-only) | E3, E4 | The visible payoff |
| **E6** | Client/user admin — only if it earns its place | E2 | Deliberately unscheduled |

Note the ordering principle: **the DB role and the data land before the
screen.** Building the view first would force permissions into application
code, which is the exact failure mode this project exists to demonstrate
against.

---

## 9. Decisions needed

Blocking or shaping the work above:

| # | Decision | Options | Default if silent |
|---|---|---|---|
| D1 | Operator isolation | A: dedicated `operator_readonly` + `app_login_operator` (§4.2) · B: reuse `human_admin` on `app_user` | **A** |
| D2 | Tenant model of the view | one-deployment-per-tenant (org-scoped by construction) · multi-tenant (`org_id` on `agent_audit`) | Add `org_id` in E3 while the table is small |
| D3 | Product name | **a-guard** · **agent-auth-lab** · something else | a-guard (matches package/README) |
| D4 | Auth-page visual direction | minimal/utilitarian · light branded | minimal (P4) |
| D5 | Operator sign-in | reuse `/login` + session with an `operator` capability · separate path | reuse (§4.3) |

---

## 10. What this document does *not* claim

- It does not claim the activity view is safe to build today — it is not,
  until §5 lands.
- It does not redesign the API or the OIDC surface.
- It does not commit to a timeline. It commits to an order of operations:
  **role → data → screen.**

