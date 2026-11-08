#!/usr/bin/env python3
"""Experiment AS + MCP pair on 127.0.0.1:8180/8181 wired to database agurd_exp.
Config only: aguard/settings.py reads these env vars; real env beats the repo .env.
usage: python experiments/exp_services.py start|stop|status"""
import os, signal, socket, subprocess, sys, time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "experiments" / "run"
AS_PORT, MCP_PORT = 8180, 8181
ISSUER = f"http://127.0.0.1:{AS_PORT}"
MCP_BASE = f"http://127.0.0.1:{MCP_PORT}"
EXP_DB = "agurd_exp"


def _swap_db(dsn: str) -> str:
    p = urlsplit(dsn)
    return urlunsplit((p.scheme, p.netloc, "/" + EXP_DB, p.query, p.fragment))


def exp_env() -> dict:
    sys.path.insert(0, str(ROOT))
    from aguard.settings import settings as s      # picks up DSNs/secrets from the repo .env
    dsns = {"DB_DSN_HUMAN": _swap_db(s.db_dsn_human),
            "DB_DSN_AGENT": _swap_db(s.db_dsn_agent),
            "DB_DSN_AUTH": _swap_db(s.db_dsn_auth)}
    assert all(urlsplit(v).path == "/" + EXP_DB for v in dsns.values()), "refusing: DSN not on exp DB"
    env = dict(os.environ)
    env.update(dsns)
    env.update({
        "OIDC_ISSUER": ISSUER,
        "MCP_RESOURCE_URL": MCP_BASE,
        "MCP_RESOURCE_ID": f"{MCP_BASE}/mcp",
        "ALLOWED_RESOURCES": f"{MCP_BASE}/mcp,{ISSUER}/api",
        "JWKS_URI": f"{ISSUER}/jwks",
        "MCP_ALLOWED_HOSTS": "", "MCP_ALLOWED_ORIGINS": "",
        "KEY_DIR": str(RUN / "keys"),                  # separate signing key from the demo
        "ACCESS_TOKEN_TTL": "3600",
        # relaxed limits on the EXPERIMENT instance only (record in LIMITATIONS.md)
        "RATE_LIMIT_LOGIN": "100000", "RATE_LIMIT_LOGIN_ACCOUNT": "100000",
        "RATE_LIMIT_TOKEN": "100000", "RATE_LIMIT_REGISTER": "100000",
        "SEED_DEMO_USERS": "true",
    })
    return env


def _up(port: int) -> bool:
    with socket.socket() as sk:
        sk.settimeout(0.5)
        return sk.connect_ex(("127.0.0.1", port)) == 0


def start():
    RUN.mkdir(parents=True, exist_ok=True)
    env = exp_env()
    for name, app, port in (("as", "aguard.main:app", AS_PORT),
                            ("mcp", "aguard.mcp.service:app", MCP_PORT)):
        if _up(port):
            sys.exit(f"port {port} already in use")
        log = open(RUN / f"{name}.log", "ab")
        p = subprocess.Popen(
            [str(ROOT / ".venv/bin/uvicorn"), app, "--host", "127.0.0.1",
             "--port", str(port), "--workers", "1"],
            cwd=ROOT, env=env, stdout=log, stderr=log, start_new_session=True)
        (RUN / f"{name}.pid").write_text(str(p.pid))
    for _ in range(40):
        try:
            if httpx.get(f"{ISSUER}/healthz", timeout=2).status_code == 200 and _up(MCP_PORT):
                print("up:", ISSUER, MCP_BASE)
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    sys.exit("services did not come up; see experiments/run/as.log and mcp.log")


def stop():
    for name in ("as", "mcp"):
        f = RUN / f"{name}.pid"
        if f.exists():
            try:
                os.killpg(os.getpgid(int(f.read_text())), signal.SIGTERM)
            except ProcessLookupError:
                pass
            f.unlink()


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "start": start()
    elif cmd == "stop": stop()
    else: print("as", _up(AS_PORT), "mcp", _up(MCP_PORT))