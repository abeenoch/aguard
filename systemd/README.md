# Running a-guard as systemd services

Two units, because the topology is two processes on purpose (see
`docs/DESIGN.md`): the authorization server and the MCP resource server. Both
bind **loopback only** — nginx terminates TLS and proxies `/api` and `/mcp`
(see `nginx/auth.example.com.conf`).

| Unit | ASGI app | Port | Holds a signing key |
|---|---|---|---|
| `aguard-as.service`  | `aguard.main:app`        | 8080 | yes |
| `aguard-mcp.service` | `aguard.mcp.service:app` | 8081 | **no** |

## Install

```bash
sudo cp systemd/aguard-as.service systemd/aguard-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now aguard-as aguard-mcp
```

Check:

```bash
systemctl status aguard-as aguard-mcp
journalctl -u aguard-as -f          # PII-redacted request log
curl -s localhost:8080/readyz; echo
curl -s localhost:8081/readyz; echo
```

## Configuration

Identity, DSNs, and secrets come from `.env` in the unit's `WorkingDirectory`
(`/root/aguard`) — `aguard/settings.py` loads it, so no `EnvironmentFile` is
needed. A **real environment variable wins over `.env`** (12-factor), which is
why deployment-only knobs live in the unit's `Environment=`:

- `aguard-as.service` sets `DCR_ALLOWED_REDIRECT_SCHEMES=vscode` so Cline's
  private-use redirect can register (see `docs/DEMO_CLINE.md` §5b). It is kept
  out of `.env` on purpose: `tests/test_dcr_redirect_policy.py` reads `.env` to
  pin the default-strict posture, so exporting it there fails the suite.

Adjust `WorkingDirectory`, `ExecStart`, and `User` if the checkout does not live
at `/root/aguard`.

## Ops notes

- `Restart=always` — the units come back after a crash **and**, because they are
  `enable`d, on reboot.
- To free 8080/8081 for a local demo, stop the **units** and restart them
  afterwards (`systemctl stop aguard-as aguard-mcp`). `fuser -k` alone just makes
  systemd respawn the processes.
- Logs live in the journal (`journalctl -u aguard-as`), already PII-redacted at
  the source (`aguard/redact/`).
