"""MCP authorization-server compliance (Phase B): RFC 8414, 9728, 7591, 8707
plus the previously-advertised-but-missing /userinfo, /revoke, /introspect."""
from __future__ import annotations

import base64
import dataclasses
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

import aguard.oidc.routes_revocable as routes_revocable
from aguard.main import app
from aguard.oidc.pkce import challenge_s256, generate_verifier
from aguard.oidc.validation import verify_access_token
from aguard.settings import settings

client = TestClient(app)
REDIRECT = "http://localhost:8000/demo/callback"
MCP_RESOURCE = settings.mcp_resource_id


def _basic(cid: str, secret: str) -> dict:
    cred = base64.b64encode(f"{cid}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {cred}"}


def _code(*, client_id="demo-spa", scope="openid orders:read",
          verifier=None, resource=None, email="alice@example.com",
          password="correct-horse-battery") -> tuple[str, str]:
    client.cookies.clear()
    verifier = verifier or generate_verifier()
    r = client.post("/login",
                    data={"email": email, "password": password, "next": "/"},
                    follow_redirects=False)
    assert r.status_code == 303
    params = {"response_type": "code", "client_id": client_id,
              "redirect_uri": REDIRECT, "scope": scope, "state": "st-mcp",
              "code_challenge": challenge_s256(verifier),
              "code_challenge_method": "S256"}
    if resource:
        params["resource"] = resource
    assert client.get("/authorize", params=params).status_code == 200
    data = {"decision": "approve", "client_id": client_id,
            "redirect_uri": REDIRECT, "scope": scope, "state": "st-mcp",
            "code_challenge": params["code_challenge"],
            "code_challenge_method": "S256"}
    if resource:
        data["resource"] = resource
    r = client.post("/consent", data=data, follow_redirects=False)
    assert r.status_code == 302, r.text[:300]
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    return code, verifier


def test_rfc8414_metadata_served():
    doc = client.get("/.well-known/oauth-authorization-server").json()
    assert doc["issuer"] == settings.issuer
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert doc["registration_endpoint"].endswith("/register")
    assert doc["revocation_endpoint"].endswith("/revoke")
    assert doc["introspection_endpoint"].endswith("/introspect")
    assert "plain" not in doc["code_challenge_methods_supported"]


def test_oidc_and_rfc8414_same_document():
    a = client.get("/.well-known/openid-configuration").json()
    b = client.get("/.well-known/oauth-authorization-server").json()
    assert a == b


def test_rfc9728_protected_resource_served():
    doc = client.get("/.well-known/oauth-protected-resource").json()
    assert doc["authorization_servers"] == [settings.issuer]
    assert doc["resource"] == MCP_RESOURCE
    assert MCP_RESOURCE in settings.allowed_resources
    assert "header" in doc["bearer_methods_supported"]


def test_dcr_happy_path_and_full_flow():
    r = client.post("/register", json={
        "client_name": "claude-desktop-test",
        "redirect_uris": [REDIRECT],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "none",
        "scope": "openid email orders:read",
    })
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["client_id"].startswith("dcr-")
    assert "client_secret" not in body          # public: nothing to leak
    assert body["client_secret_expires_at"] == 0

    code, verifier = _code(client_id=body["client_id"],
                           scope="openid email orders:read")
    r = client.post("/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT, "code_verifier": verifier,
        "client_id": body["client_id"],
    })
    assert r.status_code == 200, r.text
    claims = verify_access_token(r.json()["access_token"],
                                 keys=app.state.keys)
    assert claims["sub"] == "usr_alice"


def test_dcr_confidential_returns_secret_once():
    r = client.post("/register", json={
        "client_name": "backend-svc", "redirect_uris": [],
        "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "orders:read",
    })
    assert r.status_code == 201
    body = r.json()
    assert body["client_secret"]                   # plaintext only HERE
    r2 = client.post("/token", data={"grant_type": "client_credentials"},
                     headers=_basic(body["client_id"], body["client_secret"]))
    assert r2.status_code == 200, r2.text


def test_dcr_rejects_http_redirect():
    r = client.post("/register", json={
        "redirect_uris": ["http://evil.example/cb"],
        "grant_types": ["authorization_code"]})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_redirect_uri"


def test_dcr_rejects_fragment_redirect():
    r = client.post("/register", json={
        "redirect_uris": ["https://app.example/cb#leak"],
        "grant_types": ["authorization_code"]})
    assert r.status_code == 400


def test_dcr_rejects_unknown_grant_and_method():
    r = client.post("/register", json={
        "redirect_uris": [], "grant_types": ["password"]})
    assert r.status_code == 400
    r = client.post("/register", json={
        "redirect_uris": [], "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "private_key_jwt"})
    assert r.status_code == 400


def test_dcr_rejects_scope_expansion():
    r = client.post("/register", json={
        "redirect_uris": [], "grant_types": ["client_credentials"],
        "scope": "openid admin:everything"})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_scope"


# -------------------------------- RFC 8707 ---------------------------------


def test_resource_param_binds_audience():
    code, verifier = _code(scope="openid email orders:read",
                           resource=MCP_RESOURCE)
    r = client.post("/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT, "code_verifier": verifier,
        "client_id": "demo-spa", "resource": MCP_RESOURCE,
    })
    assert r.status_code == 200, r.text
    claims = verify_access_token(r.json()["access_token"],
                                 keys=app.state.keys, audience=MCP_RESOURCE)
    assert claims["aud"] == MCP_RESOURCE
    # and the API's own audience check correctly REJECTS an MCP-bound token:
    # cross-API replay protection is the whole point of aud binding
    from aguard.oidc.validation import TokenValidationError
    try:
        verify_access_token(r.json()["access_token"], keys=app.state.keys)
        raise AssertionError("MCP-aud token accepted by API audience")
    except TokenValidationError:
        pass


def test_resource_mismatch_rejected():
    code, verifier = _code(scope="openid email orders:read",
                           resource=MCP_RESOURCE)
    r = client.post("/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT, "code_verifier": verifier,
        "client_id": "demo-spa", "resource": MCP_RESOURCE + "-other",
    })
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_target"


def test_resource_not_allowed_at_authorize():
    resp = client.get("/authorize", params={
        "response_type": "code", "client_id": "demo-spa",
        "redirect_uri": REDIRECT, "scope": "openid orders:read",
        "state": "st", "code_challenge": challenge_s256("x" * 43),
        "code_challenge_method": "S256",
        "resource": "https://api.evil.example",
    }, follow_redirects=False)
    assert resp.status_code == 302
    assert "error=invalid_target" in resp.headers["location"]


def test_resource_not_allowed_at_token():
    code, verifier = _code()
    r = client.post("/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT, "code_verifier": verifier,
        "client_id": "demo-spa", "resource": "https://api.evil.example",
    })
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_target"


# --------------------- userinfo / revoke / introspect ----------------------


def _human_tokens(scope="openid email orders:read") -> dict:
    code, verifier = _code(scope=scope)
    r = client.post("/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT, "code_verifier": verifier,
        "client_id": "demo-spa",
    })
    assert r.status_code == 200
    return r.json()


CONF_CLIENT = "demo-conf"
CONF_SECRET = "demo-conf-secret"        # dev fixture, seeded in clients.py


def _conf_tokens(scope="openid email orders:read") -> dict:
    """Tokens issued to demo-conf — the confidential client that, unlike a
    public one, can actually prove WHO it is at /introspect."""
    code, verifier = _code(client_id=CONF_CLIENT, scope=scope)
    r = client.post("/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT, "code_verifier": verifier,
    }, headers=_basic(CONF_CLIENT, CONF_SECRET))
    assert r.status_code == 200, r.text[:300]
    return r.json()


def test_userinfo_returns_identity():
    tokens = _human_tokens()
    r = client.get("/userinfo",
                   headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 200
    body = r.json()
    assert body["sub"] == "usr_alice"
    assert body["email"] == "alice@example.com"
    assert body["name"] == "Alice Nguyen"


def test_userinfo_rejects_garbage():
    r = client.get("/userinfo",
                   headers={"Authorization": "Bearer garbage-token"})
    assert r.status_code == 401
    assert client.get("/userinfo").status_code == 401


def test_error_bodies_do_not_leak_internals():
    """M8: every one of these endpoints knows the exact failure reason (bad
    kid, expired, malformed segment, audience mismatch). That is internal
    state: the caller gets a flat answer and the (redacted) log gets the
    detail. Pinned as a list of words that must never reach a response body."""
    leaked = ("kid", "signature", "malformed", "segment", "decode", "jwks",
              "audience", "issuer", "expired")

    r = client.get("/userinfo", headers={"Authorization": "Bearer garbage-token"})
    assert r.status_code == 401
    body = r.text.lower()
    assert not any(word in body for word in leaked), body

    # The API answers the same way for a malformed token as for a forged one:
    # one flat detail, so the body cannot be used to probe why it failed.
    r2 = client.get("/api/documents", headers={"Authorization": "Bearer garbage"})
    assert r2.status_code == 401
    assert r2.json() == {"detail": "invalid token"}


def test_revoke_refresh_kills_family():
    tokens = _human_tokens()
    rt = tokens["refresh_token"]
    r = client.post("/revoke", data={
        "client_id": "demo-spa", "token": rt,
        "token_type_hint": "refresh_token",
    })
    assert r.status_code == 200
    r2 = client.post("/revoke", data={"client_id": "demo-spa",
                                      "refresh_token": rt})
    assert r2.status_code == 200   # revoke is idempotent — still 200
    r3 = client.post("/token", data={
        "grant_type": "refresh_token", "refresh_token": rt,
        "client_id": "demo-spa",
    })
    assert r3.status_code == 400
    assert r3.json()["error"] == "invalid_grant"


def test_revoke_unknown_token_still_200():
    r = client.post("/revoke", data={"client_id": "demo-spa",
                                     "token": "not-a-real-token"})
    assert r.status_code == 200      # no validity oracle (RFC 7009 §2.2)


def test_introspect_active_token():
    tokens = _conf_tokens()
    r = client.post("/introspect", data={"token": tokens["access_token"]},
                    headers=_basic(CONF_CLIENT, CONF_SECRET))
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is True
    assert body["sub"] == "usr_alice"
    assert "openid" in body["scope"]
    assert body["client_id"] == CONF_CLIENT


def test_introspect_garbage_is_inactive():
    r = client.post("/introspect", data={"token": "garbage"},
                    headers=_basic(CONF_CLIENT, CONF_SECRET))
    assert r.status_code == 200
    assert r.json() == {"active": False}


def test_introspect_sees_refresh_token():
    tokens = _conf_tokens()
    r = client.post("/introspect", data={
        "token": tokens["refresh_token"],
        "token_type_hint": "refresh_token",
    }, headers=_basic(CONF_CLIENT, CONF_SECRET))
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is True
    assert body["token_type"] == "refresh_token"


def test_introspect_requires_client_authentication():
    """RFC 7662 §2.1 requires authentication here to prevent token SCANNING.
    A public client authenticates by name alone, so accepting one would let
    anybody name demo-spa and start probing token values."""
    tokens = _human_tokens()                    # issued to demo-spa (public)
    r = client.post("/introspect", data={"client_id": "demo-spa",
                                         "token": tokens["access_token"]})
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_client"
    # and it must not be distinguishable from a client that does not exist
    r2 = client.post("/introspect", data={"client_id": "no-such-client",
                                          "token": tokens["access_token"]})
    assert r2.status_code == r.status_code == 401
    assert r2.json() == r.json()


def test_introspect_refuses_another_clients_token():
    """cli-agent holds valid credentials, but the token is not its business."""
    tokens = _conf_tokens()
    r = client.post("/introspect", data={"token": tokens["access_token"]},
                    headers=_basic("cli-agent", "cli-agent-secret"))
    assert r.status_code == 200
    # identical to the unknown-token answer: nothing reveals whose token it is
    assert r.json() == {"active": False}


def test_introspection_can_be_delegated_explicitly(monkeypatch):
    """A resource server or ops tool must be NAMED in INTROSPECTION_CLIENTS;
    token visibility is never granted implicitly."""
    tokens = _conf_tokens()
    monkeypatch.setattr(routes_revocable, "settings", dataclasses.replace(
        routes_revocable.settings, introspection_clients=("cli-agent",)))
    r = client.post("/introspect", data={"token": tokens["access_token"]},
                    headers=_basic("cli-agent", "cli-agent-secret"))
    assert r.status_code == 200
    assert r.json()["active"] is True


def test_revoke_refuses_another_clients_token():
    tokens = _conf_tokens()
    rt = tokens["refresh_token"]
    r = client.post("/revoke", data={"token": rt},
                    headers=_basic("cli-agent", "cli-agent-secret"))
    assert r.status_code == 200              # never an oracle

    # ...and the family is untouched: its owner can still rotate it
    r2 = client.post("/token", data={"grant_type": "refresh_token",
                                     "refresh_token": rt},
                     headers=_basic(CONF_CLIENT, CONF_SECRET))
    assert r2.status_code == 200, r2.text[:300]
