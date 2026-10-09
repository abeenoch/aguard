# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security vulnerabilities.

Email: **funboy.ea@gmail.com** with:
- what you found, and the affected component (`app/oidc/`, `app/redact/`, `app/db/`, …)
- reproduction steps or a proof of concept
- impact assessment if you have one

You'll get an acknowledgment within 72 hours and a status update within 7
days. Confirmed issues get a coordinated fix + credit (unless you prefer
otherwise).

## Supported versions

Pre-1.0: the latest `main` branch only.

## Known limitations (be honest — these are documented scope, not bugs)

| Limitation | Status | Workaround today |
|---|---|---|
| Auth codes + refresh tokens default to in-memory (`STORE_BACKEND=memory`) | **Mitigated**: a Postgres backend ships (`STORE_BACKEND=postgres`) | Set `STORE_BACKEND=postgres` before running more than one worker — with per-process state, a replay or stolen refresh token served by another worker goes undetected |
| Clients + users are code constants (`seed_registry()`, `USERS`) | Planned: move into Postgres | Override dev secrets via env; changing them requires a redeploy |
| No rate limiting on `/token` + `/login` | Planned (Phase 3) | Front with a rate-limiting proxy |
| Signing key stored unencrypted on disk (`data/keys/`) | Planned: env/KMS-provided keys | Filesystem permissions; keep `data/keys/` out of backups you don't trust |
| Dev-default secrets active unless overridden | **Mitigated**: loud startup warning | Set `SESSION_SECRET`, `LOG_HASH_PEPPER` (see `.env.example`) |
| Hand-rolled OIDC — not independently audited | Planned: external review before 1.0 | Suitable for evaluation/dev; get a review before production |
| Single-tenant config (no org/project isolation server-side) | Hosted multi-tenancy in progress | One deployment per tenant |
| Open Dynamic Client Registration (`/register`) | Rate limiting in progress | Expected by MCP clients; validate-then-register only, redirect URIs strict |
| DCR redirect policy: private-use schemes (`vscode://`, …) only when opted in | Opt-in via `DCR_ALLOWED_REDIRECT_SCHEMES`, off by default | Required by editor-extension MCP hosts (e.g. Cline) whose redirect hash cannot be pre-registered; PKCE S256 stays mandatory and a forbidden-scheme denylist always applies |
| `/authorize` grants the client's registered scopes when `scope` is omitted | RFC 6749 §3.3 default, never a superset of the registration | Non-OIDC MCP clients may omit `scope`; the consent screen shows exactly what is granted |
| MCP resource server runs in-process with the AS (both on one app/port) | Planned: split into a separate deployable service | Fine for evaluation; separate the two before production so a resource-server compromise is not an AS compromise |

## Scope notes

- Demo credentials (`alice@example.com` / `correct-horse-battery`, client
  secrets in `app/oidc/clients.py`) are **development fixtures**, publicly
  visible by design — like `admin/admin` on a router. Overriding them is
  required for shared deployments; the startup warning tells you when you
  haven't.
- The PII redactor is defense-in-depth, not a compliance guarantee. It
  targets common PII shapes (emails, phones, cards, SSNs, JWTs, API keys,
  percent-encoded variants) — it cannot know every encoding your data uses.
