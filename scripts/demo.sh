#!/usr/bin/env bash
#
# scripts/demo.sh — one-command terminal demo of a-guard.
#
# Starts the two services (authorization server + MCP resource server), runs the
# real MCP client flow, and prints the audit trail that proves the database — not
# application code — refused the agent. Built to be recorded: deterministic,
# clear step headings, and it cleans up the services it started.
#
# Usage:
#   scripts/demo.sh                     # start (if needed), run, clean up
#   DEMO_KEEP=1 scripts/demo.sh         # leave the services running afterwards
#   DEMO_PAUSE=1.2 scripts/demo.sh      # pause between beats (nice for recording)
#
# Env overrides (defaults are a plain local checkout; .env is not required):
#   AGUARD_BASE=http://localhost:8080      # AS issuer AND port
#   MCP_RESOURCE_URL=http://localhost:8081 # MCP server origin AND port
#   DEMO_HOST=127.0.0.1                    # bind address for those services
#
# The demo is SELF-CONTAINED: it pins the identity (issuer + resource id) of the
# services it starts to AGUARD_BASE / MCP_RESOURCE_URL and points the smoke client
# at the same endpoints, so a .env aimed at a public deployment (behind nginx/TLS)
# does not break a local run. .env is never modified — a real environment variable
# simply wins over it (see aguard/settings.py), and only the child processes this
# script spawns see these. Point AGUARD_BASE / MCP_RESOURCE_URL at other ports to
# run the demo while a deployment already owns 8080/8081.
#
# Assumes host[:port] URLs. If the database is not initialised, the readiness
# step will tell you to run `scripts/agctl.py init`.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# --- tooling (prefer the project venv) --------------------------------------
PY="$ROOT/.venv/bin/python";     [ -x "$PY" ]      || PY="python3"
UVICORN="$ROOT/.venv/bin/uvicorn"; [ -x "$UVICORN" ] || UVICORN="uvicorn"

AS_BASE="${AGUARD_BASE:-http://localhost:8080}"
MCP_BASE="${MCP_RESOURCE_URL:-http://localhost:8081}"
MCP_ID="${MCP_RESOURCE_ID:-${MCP_BASE}/mcp}"

as_port="${AS_BASE##*:}";  as_port="${as_port%%/*}"
mcp_port="${MCP_BASE##*:}"; mcp_port="${mcp_port%%/*}"
case "$as_port" in (*[!0-9]*|"") as_port=8080;; esac
case "$mcp_port" in (*[!0-9]*|"") mcp_port=8081;; esac

LOG_DIR="$(mktemp -d -t aguard-demo.XXXXXX)"
AS_LOG="$LOG_DIR/as.log"; MCP_LOG="$LOG_DIR/mcp.log"

# --- output -----------------------------------------------------------------
if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; CYAN=$'\033[36m'; RST=$'\033[0m'
else
  BOLD=; DIM=; CYAN=; RST=
fi
step() { printf '\n%s==> %s%s\n' "$CYAN$BOLD" "$1" "$RST"; }
note() { printf '%s    %s%s\n' "$DIM" "$1" "$RST"; }
banner() { printf '\n%s%s%s\n' "$BOLD$CYAN" "$1" "$RST"; }
# DEMO_PAUSE seconds between beats so a viewer (or a recording) can read each
# one; 0 (the default) keeps scripted/CI runs snappy.
DEMO_PAUSE="${DEMO_PAUSE:-0}"
pause() { [ "$DEMO_PAUSE" != "0" ] && sleep "$DEMO_PAUSE" || true; }

STARTED_AS=""; STARTED_MCP=""
cleanup() {
  if [ -z "${DEMO_KEEP:-}" ]; then
    [ -n "$STARTED_MCP" ] && kill "$STARTED_MCP" 2>/dev/null
    [ -n "$STARTED_AS" ] && kill "$STARTED_AS" 2>/dev/null
    [ -n "$STARTED_AS$STARTED_MCP" ] && note "stopped the services this script started"
  else
    note "DEMO_KEEP=1 — services left running ($AS_BASE , $MCP_BASE)"
  fi
  return 0
}
trap cleanup EXIT INT TERM

is_up() { curl -fsS --max-time 2 "$1" >/dev/null 2>&1; }
wait_ready() { # url, label, pid(optional), log(optional)
  local url="$1" label="$2" pid="${3:-}" log="${4:-}" i
  for i in $(seq 1 40); do
    is_up "$url" && return 0
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
      printf '\n%s failed to start — log tail: %s\n' "$label" "$RST"
      tail -n 20 "$log" 2>/dev/null
      return 1
    fi
    sleep 0.5
  done
  printf '\n%s did not become ready at %s — log tail: %s\n' "$label" "$url" "$RST"
  tail -n 20 "$log" 2>/dev/null
  return 1
}

# --- start the services (reuse ones already running) ------------------------
# Demo-friendly limits, applied ONLY to services this script starts (a reused
# server keeps its own config). The production per-account login ceiling is 5
# attempts / 300s — right for one human at a browser, but it trips fast when you
# re-record takes. memory + high ceilings make repeated runs deterministic.
export RATE_LIMIT_BACKEND="${DEMO_RATE_LIMIT_BACKEND:-memory}"
export RATE_LIMIT_TOKEN="${DEMO_RATE_LIMIT_TOKEN:-1000}"
export RATE_LIMIT_LOGIN="${DEMO_RATE_LIMIT_LOGIN:-1000}"
export RATE_LIMIT_LOGIN_ACCOUNT="${DEMO_RATE_LIMIT_LOGIN_ACCOUNT:-1000}"
# Self-contained identity for the services THIS script starts and for the smoke
# client it runs. `.env` may point at a public deployment (e.g. the production
# issuer behind nginx); the loopback smoke client cannot TLS-verify such an
# origin, so the demo pins AGUARD_BASE / MCP_RESOURCE_URL as the identity too.
# Real environment wins over .env (aguard/settings.py), so these reach only the
# child processes below — .env itself is never written.
export OIDC_ISSUER="$AS_BASE"
export MCP_RESOURCE_URL="$MCP_BASE"
export MCP_RESOURCE_ID="$MCP_ID"
export ALLOWED_RESOURCES="${MCP_ID},${AS_BASE}"
export JWKS_URI="${AS_BASE}/jwks"      # the split RS fetches the AS's JWKS here
# CONNECT addresses for the smoke client (IDENTITY still comes from settings).
export AGUARD_BASE="$AS_BASE"
export MCP_CONNECT_URL="$MCP_ID"
# Bind address for services THIS script starts. Loopback is fine for on-host
# recording; use DEMO_HOST=0.0.0.0 to expose them (then set the issuer to this
# host's address and MCP_ALLOWED_HOSTS accordingly — see .env).
DEMO_HOST="${DEMO_HOST:-127.0.0.1}"

banner "a-guard — identity, redacted logs, and a database that refuses the agent"
printf '%sAn agent is asked to delete a row. The app is tricked. The DATABASE says no.%s\n' "$DIM" "$RST"
pause

step "two services, two ports"
note "authorization server : $AS_BASE"
note "MCP resource server  : $MCP_BASE  (no signing key; verifies via the AS's JWKS)"

if is_up "$AS_BASE/healthz"; then
  note "AS already running — reusing it"
else
  "$UVICORN" aguard.main:app --host "$DEMO_HOST" --port "$as_port" >"$AS_LOG" 2>&1 &
  STARTED_AS=$!
fi
if is_up "$MCP_BASE/healthz"; then
  note "resource server already running — reusing it"
else
  "$UVICORN" aguard.mcp.service:app --host "$DEMO_HOST" --port "$mcp_port" >"$MCP_LOG" 2>&1 &
  STARTED_MCP=$!
fi

step "readiness (database + keystore | JWKS + database)"
if ! wait_ready "$AS_BASE/readyz" "authorization server" "$STARTED_AS" "$AS_LOG"; then
  note "is the database up? try:  $PY scripts/agctl.py init"
  exit 1
fi
wait_ready "$MCP_BASE/readyz" "resource server" "$STARTED_MCP" "$MCP_LOG" || exit 1
note "both ready"
pause

# --- the flow ---------------------------------------------------------------
step "discovery — how a client finds the authorization server"
note "JWKS (AS, public keys only) -> $(curl -fsS "$AS_BASE/jwks" | head -c 72)…"
note "RFC 9728 (resource)        -> $(curl -fsS "$MCP_BASE/.well-known/oauth-protected-resource/mcp")"
pause

step "no token -> 401 + the metadata pointer (RFC 9728)"
curl -sS -o /dev/null -D - -X POST \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' "$MCP_BASE/mcp" \
  2>/dev/null | grep -i '^www-authenticate' | sed 's/^/    /'
pause

step "MCP client flow — real SDK, audience-bound tokens, DB-enforced tools"
FLOW_LOG="$LOG_DIR/flow.log"
if ! "$PY" scripts/mcp_smoke.py 2>&1 | tee "$FLOW_LOG"; then
  if grep -qiE '429|rate.?limit|temporarily_unavailable' "$FLOW_LOG"; then
    note "the server rate-limited this run. A REUSED server keeps its own limits"
    note "(default: 5 logins per account / 300s). Stop it and re-run this script"
    note "so it starts the services with demo-friendly limits."
  else
    note "the MCP flow reported a failure above"
  fi
  exit 1
fi
pause

step "audit trail — rows=0 is where the database said NO"
"$PY" scripts/agctl.py audit --limit 8
pause

step "redaction — PII in logs, never in the clear"
"$PY" scripts/agctl.py redact "call alice@example.com re card 4111 1111 1111 1111"
if [ -s "$AS_LOG" ] || [ -s "$MCP_LOG" ]; then
  raw=$( { cat "$AS_LOG" "$MCP_LOG" 2>/dev/null || true; } | grep -c 'alice@example.com' || true)
  note "raw 'alice@example.com' occurrences in this run's service logs: $raw"
else
  note "the same address lands as email[h:…] — correlatable, never reversible"
fi
pause

banner "Proven identity · redacted logs · a database that refuses the agent."
printf '\n%sDemo complete.%s\n' "$BOLD" "$RST"
