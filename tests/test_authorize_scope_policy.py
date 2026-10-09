"""Scope policy at /authorize: MCP-friendly, still least-privilege.

`openid` is an OIDC concept, not an MCP one — it only chooses whether /token
also mints an id_token. Requiring it broke non-OIDC clients (Cline omitted
`scope` entirely). The policy now is:

  * omitted scope  -> grant the client's REGISTERED scopes (RFC 6749 §3.3),
                      i.e. the most it could ever be given, never more
  * partial scope  -> grant exactly what was asked (no openid required)
  * anything else  -> invalid_scope
"""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from app.main import app
from app.oidc.pkce import challenge_s256, generate_verifier

client = TestClient(app)
REDIRECT = "http://localhost:8000/demo/callback"
SCOPE_RE = re.compile(r'name="scope" value="([^"]*)"')


def _flow(client_id: str = "demo-spa", scope: str | None = None):
    """Run login -> authorize -> consent -> token. Returns the Response of the
    step that decided the outcome (a 302 from /authorize on a param error, or
    the /token response on success)."""
    client.cookies.clear()
    verifier = generate_verifier()
    params = {"response_type": "code", "client_id": client_id,
              "redirect_uri": REDIRECT, "state": "st-scope",
              "code_challenge": challenge_s256(verifier),
              "code_challenge_method": "S256"}
    if scope is not None:
        params["scope"] = scope
    client.post("/login",
                data={"email": "alice@example.com",
                      "password": "correct-horse-battery", "next": "/"},
                follow_redirects=False)
    resp = client.get("/authorize", params=params, follow_redirects=False)
    if resp.status_code != 200:
        return resp                      # rejected before consent
    granted = SCOPE_RE.search(resp.text).group(1)
    consent = client.post("/consent", data={
        "decision": "approve", "client_id": client_id, "redirect_uri": REDIRECT,
        "scope": granted, "state": "st-scope",
        "code_challenge": params["code_challenge"],
        "code_challenge_method": "S256",
    }, follow_redirects=False)
    code = parse_qs(urlparse(consent.headers["location"]).query)["code"][0]
    return client.post("/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT, "code_verifier": verifier,
        "client_id": client_id,
    })


def test_omitted_scope_grants_client_registered_scopes():
    resp = _flow(scope=None)
    assert resp.status_code == 200, resp.text
    # demo-spa is registered for exactly these; the default is never a superset
    assert resp.json()["scope"].split() == [
        "email", "openid", "orders:read", "orders:write", "profile"]


def test_scope_without_openid_is_accepted():
    resp = _flow(scope="orders:read")
    assert resp.status_code == 200, resp.text
    assert resp.json()["scope"] == "orders:read"
    assert "id_token" not in resp.json()      # no openid -> no id_token


def test_scope_beyond_registration_is_refused():
    resp = _flow(scope="openid admin:everything")
    assert resp.status_code == 302
    assert "error=invalid_scope" in resp.headers["location"]


def test_scope_beyond_client_registration_is_refused():
    # chat-agent is not registered for orders:write
    resp = _flow(client_id="chat-agent", scope="openid orders:write")
    assert resp.status_code == 302
    assert "error=invalid_scope" in resp.headers["location"]
