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
| In-memory stores (auth codes, refresh tokens, clients, users) | Planned: pluggable store interface (Redis/Postgres) | Run a single process; sticky sessions won't help because stores don't share |
| No rate limiting on `/token` + `/login` | Planned (Phase 3) | Front with a rate-limiting proxy |
| Signing key stored unencrypted on disk (`data/keys/`) | Planned: env/KMS-provided keys | Filesystem permissions; keep `data/keys/` out of backups you don't trust |
| Dev-default secrets active unless overridden | **Mitigated**: loud startup warning | Set `SESSION_SECRET`, `LOG_HASH_PEPPER` (see `.env.example`) |
| Hand-rolled OIDC — not independently audited | Planned: external review before 1.0 | Suitable for evaluation/dev; get a review before production |
| Single-tenant config (no org/project isolation server-side) | Hosted multi-tenancy in progress | One deployment per tenant |

## Scope notes

- Demo credentials (`alice@example.com` / `correct-horse-battery`, client
  secrets in `app/oidc/clients.py`) are **development fixtures**, publicly
  visible by design — like `admin/admin` on a router. Overriding them is
  required for shared deployments; the startup warning tells you when you
  haven't.
- The PII redactor is defense-in-depth, not a compliance guarantee. It
  targets common PII shapes (emails, phones, cards, SSNs, JWTs, API keys,
  percent-encoded variants) — it cannot know every encoding your data uses.
