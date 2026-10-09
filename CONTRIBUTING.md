# Contributing to A-guard

Thanks for your interest! This project sits at the intersection of OAuth,
logging, and databases — contributions to any of the three are welcome.

## Ground rules

1. **Security first.** This is a security project: every PR is reviewed
   with an adversarial mindset. If your change touches auth, redaction, or
   DB permissions, the PR description must state the threat it addresses
   (or explicitly "none — refactoring").
2. **Tests are the contract.** 113 tests currently pass. Your PR must keep
   them green and add tests for new behavior. For redaction changes, add
   fixture cases to `tests/fixtures/redact_must_catch.json` or
   `redact_must_not_catch.json` — the corpus *is* the spec.
3. **Fail closed.** New error paths must degrade to a safe marker, never to
   raw data or silent success.
4. **No secrets in source.** Anything deployment-specific goes in env vars
   with a documented default or a clear error. See `.env.example`.

## Development setup

```bash
git clone https://github.com/abeenoch/aguard && cd aguard
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env    # fill in PGPASSWORD (tests apply schema.sql)
createdb agent_auth && psql -d agent_auth -f aguard/db/schema.sql
pytest                   # must be green before you start
```

Live server + smoke test:

```bash
uvicorn aguard.main:app --port 8000     # terminal 1
python scripts/smoke.py              # terminal 2
```

## PR checklist

- [ ] `pytest` green locally
- [ ] New behavior covered by tests (redaction: fixture cases added)
- [ ] No secrets, credentials, or personal data in the diff
- [ ] Security-relevant changes explain the threat model in the description
- [ ] Commit messages say *why*, not just *what*

## Architecture notes for newcomers

- **Auth flow**: `aguard/oidc/` — start with `routes_auth.py` (authorize) then
  `routes_token.py` (exchange). Validation checklist: `validation.py`.
- **Redaction**: `aguard/redact/patterns.py` (content) → `redactor.py`
  (structure) → `logging.py` (choke point — read the module docstrings;
  the Phase 1 live-server lesson is documented there).
- **DB enforcement**: `aguard/db/schema.sql` (roles/RLS/grants, idempotent)
  → `session.py` (`SET LOCAL` scoped sessions). The invariant: each login
  role is a member of exactly one data role.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — private disclosure only, please.
