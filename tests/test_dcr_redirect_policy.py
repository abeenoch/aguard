"""DCR redirect-URI policy: strict by default, private-use schemes opt-in.

Cline (and other editor-extension MCP hosts) register a `vscode://` redirect
rather than a loopback port, and its hash cannot be pre-registered. RFC 8252
§7.1 permits private-use schemes; these tests pin both that the DEFAULT stays
strict and that opting in actually works — and that opting in never admits a
scheme that executes in the user agent.
"""
from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.main import app
from app.oidc import routes_register
from app.oidc.routes_register import _validate_redirect_uri

client = TestClient(app)

CLINE = "vscode://saoudrizwan.claude-dev/mcp-auth/callback/abc123hash"


def _register(uri: str):
    return client.post("/register", json={
        "client_name": "policy-test",
        "redirect_uris": [uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "none",
        "scope": "openid email orders:read",
    })


# ------------------------------ the validator ------------------------------


def test_baseline_https_allowed():
    assert _validate_redirect_uri("https://app.example.com/cb") is None


def test_baseline_loopback_http_allowed():
    for uri in ("http://localhost:1234/cb", "http://127.0.0.1:8080/cb",
                "http://[::1]:9000/cb"):
        assert _validate_redirect_uri(uri) is None, uri


def test_http_non_loopback_rejected():
    assert _validate_redirect_uri("http://evil.example/cb") is not None


def test_fragment_rejected():
    assert _validate_redirect_uri("https://app.example/cb#tok") is not None


def test_relative_rejected():
    assert _validate_redirect_uri("/callback") is not None


def test_private_use_scheme_rejected_by_default():
    assert _validate_redirect_uri(CLINE) is not None


def test_private_use_scheme_allowed_when_opted_in():
    assert _validate_redirect_uri(
        CLINE, allowed_schemes=frozenset({"vscode"})) is None


def test_unlisted_private_use_scheme_still_rejected():
    assert _validate_redirect_uri(
        "myapp://cb", allowed_schemes=frozenset({"vscode"})) is not None


def test_forbidden_scheme_rejected_even_if_allowlisted():
    # these carry an authority, so only the denylist stops them
    assert _validate_redirect_uri(
        "javascript://host/x", allowed_schemes=frozenset({"javascript"})) is not None


# -------------------------------- the route --------------------------------


def test_route_rejects_vscode_by_default():
    """Proves the default posture is unchanged: no env var, no vscode."""
    resp = _register(CLINE)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"


def test_route_accepts_vscode_when_configured(monkeypatch):
    monkeypatch.setattr(
        routes_register, "settings",
        SimpleNamespace(dcr_allowed_redirect_schemes=("vscode",)),
    )
    resp = _register(CLINE)
    assert resp.status_code == 201, resp.text
    assert resp.json()["redirect_uris"] == [CLINE]


def test_route_still_rejects_fragment_when_opted_in(monkeypatch):
    monkeypatch.setattr(
        routes_register, "settings",
        SimpleNamespace(dcr_allowed_redirect_schemes=("vscode",)),
    )
    resp = _register(CLINE + "#frag")
    assert resp.status_code == 400
