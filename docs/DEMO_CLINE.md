# Recording the Cline demo

Goal: show a real MCP host (Cline) discovering our authorization server,
authorizing a user, calling our tools — and then getting **refused by
Postgres** when the agent tries to write.

Everything below was verified against a running server. The preflight script
replays Cline's exact request sequence so you find breakage *before* you hit
record.

## 0. Why a preflight exists

Cline is an editor extension, so it diverges from the loopback-based native
app model in two ways that fail **before anything visible appears**:

| Divergence | Consequence |
|---|---|
| Registers a private-use redirect: `vscode://saoudrizwan.claude-dev/mcp-auth/callback/<hash>` | Our DCR rejects it by default (`400 invalid_redirect_uri`), and the `<hash>` derives from the server URL so it *cannot* be pre-registered |
| Non-OIDC scope handling | We used to require the `openid` scope, which is an OIDC concept an MCP client need not send |

Both are addressed (see below). Run the preflight to confirm.

## 1. Prerequisites

```bash
cp .env.example .env                 # fill in PG_SUPERUSER_PASSWORD
createdb agent_auth
psql -U postgres -d agent_auth -f aguard/db/schema.sql
```

Seed at least one document for `alice` (the consent flow logs in as her).

## 2. Enable private-use redirect schemes

Cline needs its `vscode://` redirect accepted. This is **opt-in** — the
default stays strict (https + loopback only):

```bash
# .env  (or export in the server's shell)
DCR_ALLOWED_REDIRECT_SCHEMES=vscode
```

RFC 8252 §7.1 permits private-use schemes for native/editor clients; the
mitigation is PKCE S256, which `/authorize` already requires of every client.
A forbidden-scheme denylist (`javascript:`, `data:`, `file:`, …) is applied
even when a scheme is allowlisted.

## 3. Start the two services

```bash
uvicorn aguard.main:app --port 8080            # authorization server
uvicorn aguard.mcp.service:app --port 8081     # MCP resource server
```

## 4. Preflight — do not record until this is 9/9

```bash
python scripts/cline_preflight.py
```

Expected output ends with:

```
9/9 gates passed.
No blockers detected — Cline's OAuth sequence is satisfiable.
```

Each gate is also labelled with what it proves: discovery (RFC 9728 + 8414),
DCR of the `vscode://` redirect, the `/authorize` parameter contract (state and
PKCE S256 are *required* and correctly rejected when absent), and a full
`authorize → consent → token → /mcp tools/list` run.

## 5. Point Cline at the server

`cline_mcp_settings.json` (or the in-app Remote Servers tab):

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

Two non-obvious, load-bearing details:

- **`"type": "streamableHttp"` is required.** Omitting it makes Cline default
  to the legacy SSE transport, which our server does not serve.
- **Keep `autoApprove` empty.** You want the refused tool call to appear in
  the conversation for the viewer to see, not to be auto-approved and hidden.

## 5b. Connecting to the DEPLOYED origin (remote)

The same sequence works against the public deployment; only the URL and the
server's launch environment differ:

- Point Cline at **`https://auth.example.com/mcp`** (`"type":
  "streamableHttp"`), instead of `http://localhost:8081/mcp`.
- The AS must accept Cline's `vscode://` redirect. Strict DCR is the default, so
  enable the opt-in in the AS's **launch environment** — `systemd/aguard-as.service`
  already sets `DCR_ALLOWED_REDIRECT_SCHEMES=vscode`. It is deliberately *not* in
  `.env`, because `tests/test_dcr_redirect_policy.py` reads `.env` to pin the
  default-strict posture; exporting it there would fail the suite.
- `MCP_ALLOWED_HOSTS` must list the **bare** public host: the SDK's `host:*` form
  only matches a Host that explicitly carries a port, and `https://` on 443 sends
  the bare name (otherwise every public request is a 421 Misdirected Request).

Prove it before recording — against the live origin:

```bash
AGUARD_BASE=https://auth.example.com/api \
MCP_CONNECT_URL=https://auth.example.com/mcp \
  python scripts/cline_preflight.py          # expect: 9/9 gates passed
```


## 6. The recording beats

| # | On screen | What to say |
|---|---|---|
| 1 | Cline → MCP Servers → the new server | "It discovers the auth server from a `WWW-Authenticate` header, not from config" |
| 2 | Click *Authorize OAuth* → browser opens our login page | "This is our own authorization server — DCR just registered Cline as a client" |
| 3 | Log in as `alice@example.com` → consent screen | "Note the consent screen lists exactly the scopes being granted" |
| 4 | Back in Cline, ask: *"list my documents"* | Cline calls `list_documents`; only alice's rows come back — row-level security, over MCP |
| 5 | Ask: *"now delete the document titled …"* | **The money beat.** The tool runs, Postgres raises `InsufficientPrivilege`, and the model reports the refusal |
| 6 | (cutaway) `python scripts/cline_preflight.py` | "And a token minted for `/api` is rejected at `/mcp`, and vice versa — audience binding" |

Beat 5 is the whole point: the agent *asked*, the handler *ran*, and the
**database** said no. Nothing in the application code decided the outcome.

## 7. Post-recording evidence

```bash
# the refused write is audited, with a PII-redacted statement
psql -U postgres -d agent_auth -c \
  "SELECT subject, rows_returned, statement FROM agent_audit ORDER BY id DESC LIMIT 5;"
```

The refusal also produces a structured log line
(`"event": "mcp.documents.delete_refused"`).

## 8. Known caveats

- The MCP resource server is its OWN service (`aguard/mcp/service.py`, port
  8081) and holds **no signing key** — it verifies tokens against the issuer's
  JWKS. See `SECURITY.md` and `docs/DESIGN.md`.
- Authorization state (auth codes, refresh families, rate-limit counters) is
  shared via Postgres when `STORE_BACKEND=postgres` (the deployed `.env`), so
  more than one worker is safe; with the default `memory` backend run a single
  process (no `--workers`).
- If a future Cline version changes its redirect URI, re-run the preflight
  and adjust `DCR_ALLOWED_REDIRECT_SCHEMES` if the scheme changed.

