# Demo recording — storyboard & runbook

**Goal:** show the thesis in ~2–3 minutes — *identity is proven, logs are
redacted, and the database refuses the agent*. Terminal-only; no editor, no
browser, no third-party client to configure.

**Driver:** `scripts/demo.sh` (one command). It starts the two services, runs a
real MCP client, prints the audit trail, and shows redaction.

## Pre-roll checklist (30s, do it before you hit record)

```bash
cd /root/aguard
# 1. Services must NOT be pre-running, so the demo starts them on camera with
#    retake-friendly limits. (If they are, they get reused — that works, but the
#    per-account login limit can bite on a second take.)
fuser -k 8080/tcp 8081/tcp 2>/dev/null || true

# 2. Database reachable + schema applied.
.venv/bin/python scripts/agctl.py verify        # redaction self-check

# 3. Dry run once (no pauses) to confirm green.
bash scripts/demo.sh
```

## The beats

Run it with pacing so viewers can read:

```bash
DEMO_PAUSE=1.0 bash scripts/demo.sh
```

| # | On screen | What you say (suggested) |
|---|---|---|
| 0 | Title banner + one-liner | "This is a-guard. An agent is asked to delete a row. The app is tricked. The database says no." |
| 1 | `==> two services` | "Two services: an authorization server, and an MCP resource server that holds **no signing key** — it verifies tokens against the AS's JWKS." |
| 2 | `==> readiness`, "both ready" | "Both report ready: the AS has its keystore and database; the resource server has the issuer's keys and the database." |
| 3 | `==> discovery` | "An MCP client discovers everything. Here are the public signing keys, and the RFC 9728 document naming the AS." |
| 4 | `==> no token -> 401` | "With no token it gets a 401 carrying `resource_metadata` — that header is how the client finds the AS instead of being configured with it." |
| 5 | `==> MCP client flow` (PASS lines) | "Now the real flow: audience-bound token, agent reads **only its own tenant** — and then asks to delete." |
| 6 | `agent delete refused by the database` | "The tool exists. The agent asked. **Postgres** raised InsufficientPrivilege. The LLM cannot talk its way past a GRANT." |
| 7 | `human deletes its own row` | "Same operation, human token: allowed — on its own row only." |
| 8 | `==> audit trail` (rows=0) | "Every attempt is audited. `rows=0` is the refusal — recorded, not hidden." |
| 9 | `==> redaction` | "And the logs never held the raw data: `alice@example.com` lands as a correlatable hash, the card as `****-…-1111`." |
| 10 | Closing banner | "Proven identity, redacted logs, and a database that refuses the agent." |

## Recording

**Terminal (recommended, reproducible):**

```bash
cd /root/aguard
.venv/bin/asciinema rec --overwrite --title "a-guard — the database refuses the agent" \
  -c "DEMO_PAUSE=1.0 DEMO_HOST=0.0.0.0 DEMO_KEEP=1 bash scripts/demo.sh" \
  docs/demo.cast
```

- `DEMO_KEEP=1` leaves the services running after the take (exposed on
  `0.0.0.0`), so a second recording or a live Q&A starts instantly.
- Play it back: `.venv/bin/asciinema play docs/demo.cast`.

**Export the cast** (ffmpeg is installed; `agg` is not):

```bash
# to a plain transcript for docs/PRs:
.venv/bin/asciinema cat docs/demo.cast > docs/demo-transcript.txt

# to SVG/MP4 you need a renderer. Options:
#   ffmpeg path:  record the window with ffmpeg/x11grab, or OBS, while the demo runs
#   agg path:     `cargo install agg` then `agg docs/demo.cast docs/demo.gif`
```

**Screen recorder alternative (macOS/Windows/Linux):** run
`DEMO_PAUSE=1.0 DEMO_KEEP=1 bash scripts/demo.sh` in a large-font terminal and
capture the window; the script's own headings carry the narrative.

## If something goes wrong (recover, don't stop the take)

| Symptom | Cause | Fix |
|---|---|---|
| `429` / "rate-limited" hint | per-account login ceiling on a **reused** server | stop the services, re-run so the script starts them; or `DEMO_KEEP=1` between takes |
| readiness never turns ready | database down / schema missing | `createdb agent_auth && psql -U postgres -d agent_auth -f aguard/db/schema.sql` |
| `Address already in use` | your own app on 8080/8081 | the demo reuses a *running* a-guard; only non-a-guard squatters block — change `AGUARD_BASE`/`MCP_RESOURCE_URL` |
| nothing on screen | running under a pipe without a TTY | colours/pauses are TTY-gated; record with asciinema or a real terminal |

## Length budget

| Section | ~seconds |
|---|---|
| title + services + readiness | 20 |
| discovery + 401 | 20 |
| MCP flow | 45 |
| audit + redaction | 25 |
| close | 5 |
| **total (DEMO_PAUSE=1.0)** | **~2 min** |
