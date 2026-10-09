"""Live smoke test: real HTTP against a real uvicorn process.

Probes, in order:
  1. discovery + JWKS over the wire
  2. full browser flow (login -> consent -> code -> token) as alice
  3. API as human: write OK, bob isolated from alice
  4. API as agent: read OK (own tenant), write 403, no/garbage token 401
  5. log probes: PII through an app-logger title AND through a URL query
     (so the server log can be grepped for BOTH log pipelines afterward).
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import sys
from urllib.parse import parse_qs, urlparse

import httpx

BASE = "http://localhost:8000"   # MUST match settings.issuer byte-for-byte

REDIRECT = "http://localhost:8000/demo/callback"
PII_TITLE = "callback alice@example.com re card 4111111111111111"


def say(step: str, ok: bool, detail: str = "") -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {step}" + (f" — {detail}" if detail else ""))
    if not ok:
        sys.exit(1)


def basic(cid: str, secret: str) -> dict:
    cred = base64.b64encode(f"{cid}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {cred}"}


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def get_tokens(client: httpx.Client, *, client_id: str, secret: str | None,
               email: str, password: str, scope: str) -> dict:
    client.cookies.clear()   # each identity starts a FRESH session —
    # a lingering cookie would make authorize silently run as the previous user
    verifier, challenge = pkce_pair()

    params = {"response_type": "code", "client_id": client_id,
              "redirect_uri": REDIRECT, "scope": scope, "state": "st-live",
              "code_challenge": challenge, "code_challenge_method": "S256"}
    r = client.get(f"{BASE}/authorize", params=params, follow_redirects=False)
    if r.status_code == 302 and "/login" in r.headers.get("location", ""):
        # not signed in yet: log in, then retry the authorize URL
        client.post(f"{BASE}/login",
                    data={"email": email, "password": password, "next": "/"},
                    follow_redirects=False)
        r = client.get(f"{BASE}/authorize", params=params, follow_redirects=False)
    assert r.status_code == 200, f"authorize: {r.status_code} {r.text[:300]}"
    data = {"decision": "approve", "client_id": client_id,
            "redirect_uri": REDIRECT, "scope": scope, "state": "st-live",
            "code_challenge": challenge, "code_challenge_method": "S256"}
    r = client.post(f"{BASE}/consent", data=data, follow_redirects=False)
    assert r.status_code == 302, f"consent: {r.status_code} {r.text[:300]}"
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    payload = {"grant_type": "authorization_code", "code": code,
               "redirect_uri": REDIRECT, "code_verifier": verifier}
    headers = {}
    if secret:
        headers = basic(client_id, secret)
    else:
        payload["client_id"] = client_id
    r = client.post(f"{BASE}/token", data=payload, headers=headers)
    assert r.status_code == 200, f"token: {r.status_code} {r.text}"
    return r.json()


def main() -> None:
    c = httpx.Client(timeout=10.0)

    # 1. discovery + JWKS over the wire
    d = c.get(f"{BASE}/.well-known/openid-configuration")
    say("discovery 200 + issuer correct",
        d.status_code == 200 and d.json()["issuer"] == BASE)
    j = c.get(f"{BASE}/jwks")
    say("JWKS public-only",
        j.status_code == 200
        and all("d" not in k for k in j.json()["keys"]))

    # 2. alice: full code flow
    alice = get_tokens(c, client_id="demo-spa", secret=None,
                       email="alice@example.com",
                       password="correct-horse-battery",
                       scope="openid email orders:read orders:write")
    say("alice code->token exchange", "access_token" in alice)
    h_alice = {"Authorization": f"Bearer {alice['access_token']}"}

    # 3. human writes — this triggers the app logger (PII title probe)
    r = c.post(f"{BASE}/api/documents",
               json={"title": PII_TITLE, "body": "live smoke"},
               headers=h_alice)
    say("human (alice) can write", r.status_code == 201, str(r.status_code))

    bob = get_tokens(c, client_id="demo-spa", secret=None,
                     email="bob@example.com", password="bob-not-a-real-secret",
                     scope="openid email orders:read orders:write")
    h_bob = {"Authorization": f"Bearer {bob['access_token']}"}
    r = c.get(f"{BASE}/api/documents", headers=h_bob)
    owners = ({d["owner_sub"] for d in r.json()["documents"]}
              if r.status_code == 200 else set())
    say("bob sees ONLY bob's rows", owners == {"usr_bob"}, str(owners))
    r = c.get(f"{BASE}/api/documents", headers=h_alice)
    owners = ({d["owner_sub"] for d in r.json()["documents"]}
              if r.status_code == 200 else set())
    say("alice sees ONLY alice's rows", owners == {"usr_alice"}, str(owners))

    # 4. agent
    agent = get_tokens(c, client_id="chat-agent", secret="chat-agent-secret",
                       email="alice@example.com",
                       password="correct-horse-battery",
                       scope="openid email orders:read")
    h_agent = {"Authorization": f"Bearer {agent['access_token']}"}
    r = c.get(f"{BASE}/api/documents", headers=h_agent)
    docs = r.json().get("documents", []) if r.status_code == 200 else []
    say("agent reads alice's tenant",
        r.status_code == 200 and {d["owner_sub"] for d in docs} == {"usr_alice"})
    say("agent projection hides internal_notes",
        "internal_notes" not in str(docs))
    r = c.post(f"{BASE}/api/documents",
               json={"title": "injected", "body": "x"}, headers=h_agent)
    say("agent write -> 403", r.status_code == 403, str(r.status_code))
    say("no token -> 401", c.get(f"{BASE}/api/documents").status_code == 401)
    say("garbage token -> 401",
        c.get(f"{BASE}/api/documents",
              headers={"Authorization": "Bearer junk"}).status_code == 401)

    # 5. log probe: PII inside a URL (hits uvicorn's access logger)
    r = c.get(f"{BASE}/login",
              params={"next": "/?exfil=probe.pii@example.com"},
              follow_redirects=False)
    say("login page with PII-in-URL probe 200", r.status_code == 200)

    print("\nAll live checks passed. Now grep server logs for PII.")


if __name__ == "__main__":
    main()

