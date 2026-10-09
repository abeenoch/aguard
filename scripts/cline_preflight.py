"""Cline compatibility preflight: which OAuth gate will block a Cline demo?

Cline is an editor extension, so it diverges from the loopback-based native
app model in ways that fail BEFORE anything appears on screen:

  * it registers a PRIVATE-USE redirect (`vscode://saoudrizwan.claude-dev/
    mcp-auth/callback/<hash>`) via RFC 7591, not a loopback port;
  * it may send a different scope set than a browser OIDC client;
  * the <hash> is derived from the server URL, so it cannot be pre-registered.

This script replays Cline's request sequence against a RUNNING server and
prints PASS/FAIL per gate with the exact server error, so you know what to fix
before recording.

Run the server first:  uvicorn aguard.main:app --port 8000
Then:                  python scripts/cline_preflight.py
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import sys

import httpx

BASE = "http://localhost:8000"
MCP_RESOURCE = f"{BASE}/mcp"
CLINE_REDIRECT = "vscode://saoudrizwan.claude-dev/mcp-auth/callback/3f9a2c"
DEMO_REDIRECT = f"{BASE}/demo/callback"

_results: list[tuple[bool, str, str]] = []


def gate(ok: bool, name: str, detail: str = "") -> bool:
    _results.append((ok, name, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f"\n        {detail}" if detail else ""))
    return ok


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorize(client: httpx.Client, params: dict) -> httpx.Response:
    return client.get(f"{BASE}/authorize", params=params, follow_redirects=False)


def verdict(resp: httpx.Response) -> tuple[bool, str]:
    """Interpret an /authorize response.

    Params are validated BEFORE the session check, so:
      302 -> {BASE}/login            => every parameter was accepted
      302 -> redirect_uri?error=...  => a redirectable gate failed
      400                            => client_id / redirect_uri gate failed
    """
    if resp.status_code == 400:
        return False, "400: client_id or redirect_uri rejected"
    if resp.status_code == 302:
        loc = resp.headers.get("location", "")
        if "error=" in loc:
            return False, f"302 with error -> {loc}"
        if "/login" in loc:
            return True, "302 -> /login (all parameters accepted)"
        return True, f"302 -> {loc}"
    return False, f"unexpected {resp.status_code}"


def run() -> int:
    with httpx.Client(timeout=15) as http:
        # ---- Gate 0: server up ------------------------------------------
        try:
            up = http.get(f"{BASE}/healthz").status_code == 200
        except httpx.HTTPError as exc:
            gate(False, "server reachable", str(exc))
            return 1
        gate(up, "server reachable", f"{BASE}/healthz")

        # ---- Gate 1: discovery ------------------------------------------
        prm = http.get(f"{BASE}/.well-known/oauth-protected-resource/mcp")
        ok = prm.status_code == 200 and prm.json().get("resource") == MCP_RESOURCE
        gate(ok, "RFC 9728 protected-resource metadata", str(prm.json()))
        asm = http.get(f"{BASE}/.well-known/oauth-authorization-server")
        gate(asm.status_code == 200 and "registration_endpoint" in asm.json(),
             "RFC 8414 metadata advertises registration_endpoint",
             f"scopes_supported={asm.json().get('scopes_supported')}")

        # ---- Gate 2: dynamic client registration with Cline's redirect ---
        dcr = http.post(f"{BASE}/register", json={
            "client_name": "Cline",
            "redirect_uris": [CLINE_REDIRECT],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none",
            "scope": "openid email orders:read",
        })
        if dcr.status_code == 201:
            cline_client_id = dcr.json()["client_id"]
            gate(True, "DCR accepts Cline's vscode:// redirect",
                 f"client_id={cline_client_id}")
        else:
            cline_client_id = None
            gate(False, "DCR accepts Cline's vscode:// redirect",
                 f"{dcr.status_code} {dcr.json().get('error_description')}\n"
                 "        FIX: set DCR_ALLOWED_REDIRECT_SCHEMES=vscode and "
                 "restart the server")

        # ---- Gate 3: /authorize parameter contract -----------------------
        # Each variant changes EXACTLY ONE variable. `want_accept` encodes the
        # CORRECT expectation: state + PKCE S256 are required by our security
        # model (and Cline sends both), so their absence SHOULD be rejected.
        # Scope is the one genuine interop question for non-OIDC MCP clients.
        _, challenge = pkce_pair()
        base = {
            "response_type": "code", "client_id": "demo-spa",
            "redirect_uri": DEMO_REDIRECT, "scope": "openid email orders:read",
            "state": "st-preflight", "code_challenge": challenge,
            "code_challenge_method": "S256", "resource": MCP_RESOURCE,
        }

        def check(name: str, params: dict, *, want_accept: bool) -> None:
            accepted, detail = verdict(authorize(http, params))
            ok = accepted == want_accept
            gate(ok, name, detail if not ok else
                 ("accepted" if want_accept else "correctly rejected"))

        check("accepts the documented parameter set", dict(base),
              want_accept=True)
        check("requires state (CSRF binding)", 
              {k: v for k, v in base.items() if k != "state"},
              want_accept=False)
        check("requires PKCE S256 (OAuth 2.1)",
              {k: v for k, v in base.items()
               if k not in ("code_challenge", "code_challenge_method")},
              want_accept=False)
        check("accepts a scope-less request (non-OIDC MCP clients)",
              {k: v for k, v in base.items() if k != "scope"},
              want_accept=True)

        # ---- Gate 4: full browser flow + MCP call -----------------------
        if cline_client_id:
            flow = _full_flow(http, "demo-spa", DEMO_REDIRECT)
            gate(flow, "full authorize->consent->token->/mcp flow",
                 "MCP tools/list answered" if flow else "see error above")

    passed = sum(1 for ok, _, _ in _results if ok)
    total = len(_results)
    print(f"\n{passed}/{total} gates passed.")
    blockers = [name for ok, name, _ in _results if not ok]
    if blockers:
        print("\nBlockers to resolve before recording with Cline:")
        for b in blockers:
            print(f"  - {b}")
        return 1
    print("\nNo blockers detected — Cline's OAuth sequence is satisfiable.")
    return 0



def _full_flow(http: httpx.Client, client_id: str, redirect: str) -> bool:
    http.cookies.clear()
    verifier, challenge = pkce_pair()
    params = {"response_type": "code", "client_id": client_id,
              "redirect_uri": redirect, "scope": "openid email orders:read",
              "state": "st-preflight", "code_challenge": challenge,
              "code_challenge_method": "S256", "resource": MCP_RESOURCE}
    http.post(f"{BASE}/login", data={"email": "alice@example.com",
                                     "password": "correct-horse-battery",
                                     "next": "/"}, follow_redirects=False)
    http.get(f"{BASE}/authorize", params=params, follow_redirects=False)
    consent = http.post(f"{BASE}/consent", data={
        "decision": "approve", "client_id": client_id, "redirect_uri": redirect,
        "scope": params["scope"], "state": params["state"],
        "code_challenge": challenge, "code_challenge_method": "S256",
        "resource": MCP_RESOURCE,
    }, follow_redirects=False)
    if consent.status_code != 302:
        print(f"        consent failed: {consent.status_code}")
        return False
    from urllib.parse import parse_qs, urlparse
    code = parse_qs(urlparse(consent.headers["location"]).query).get("code", [None])[0]
    if not code:
        print(f"        no code in redirect: {consent.headers['location']}")
        return False
    tok = http.post(f"{BASE}/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": redirect, "code_verifier": verifier,
        "client_id": client_id,
    })
    if tok.status_code != 200:
        print(f"        token failed: {tok.status_code} {tok.text[:200]}")
        return False
    token = tok.json()["access_token"]
    rpc = http.post(f"{BASE}/mcp", json={"jsonrpc": "2.0", "id": 1,
                                         "method": "tools/list"},
                    headers={"Accept": "application/json, text/event-stream",
                             "Authorization": f"Bearer {token}"})
    return rpc.status_code == 200


if __name__ == "__main__":
    sys.exit(run())

