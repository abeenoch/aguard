"""Authorization flow tests — the security rules, not just the happy path.

Each test corresponds to a specific attack or spec requirement:
- open redirect via forged client_id / redirect_uri  → must render, not redirect
- missing PKCE / plain method / missing state        → must fail
- authorization code single-use + replay detection   → must fail loudly
- account enumeration via login                      → identical error message
"""
from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from app.main import app
from app.oidc.codes import CodeReplayError
from app.oidc.pkce import challenge_s256, generate_verifier

client = TestClient(app)

REGISTERED_REDIRECT = "http://localhost:8000/demo/callback"


def _login(email: str = "alice@example.com", password: str = "correct-horse-battery") -> None:
    resp = client.post(
        "/login",
        data={"email": email, "password": password, "next": "/"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


def _valid_params(**overrides) -> dict:
    params = {
        "response_type": "code",
        "client_id": "demo-spa",
        "redirect_uri": REGISTERED_REDIRECT,
        "scope": "openid orders:read",
        "state": "st-abc123",
        "code_challenge": challenge_s256("x" * 43),
        "code_challenge_method": "S256",
    }
    params.update(overrides)
    return params


# -- non-redirectable errors: must render 400, never redirect -------------


def test_unknown_client_renders_error_no_redirect():
    resp = client.get("/authorize", params={
        "client_id": "not-registered",
        "redirect_uri": REGISTERED_REDIRECT,
        "response_type": "code",
    })
    assert resp.status_code == 400
    assert "location" not in resp.headers


def test_redirect_uri_must_match_exactly():
    # bypass attempts that naive startswith()/prefix checks accept:
    for evil in (
        "http://evil.example/steal",
        REGISTERED_REDIRECT + "/../evil",
        REGISTERED_REDIRECT + "x",
        "https://localhost:8000/demo/callback",   # scheme differs
        REGISTERED_REDIRECT + "/",                 # trailing slash differs
        "//evil.example/steal",                    # protocol-relative
    ):
        resp = client.get("/authorize", params={
            "client_id": "demo-spa", "redirect_uri": evil,
            "response_type": "code",
        })
        assert resp.status_code == 400, f"accepted: {evil}"
        assert "location" not in resp.headers, f"redirected to: {evil}"


# -- redirectable errors: 302 back to the registered URI with error -------


def test_missing_state_rejected():
    params = _valid_params()
    del params["state"]
    resp = client.get("/authorize", params=params, follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith(REGISTERED_REDIRECT)
    assert "error=invalid_request" in location


def test_missing_pkce_rejected():
    params = _valid_params()
    del params["code_challenge"]
    resp = client.get("/authorize", params=params, follow_redirects=False)
    assert resp.status_code == 302
    assert "error=invalid_request" in resp.headers["location"]
    desc = parse_qs(urlparse(resp.headers["location"]).query)["error_description"][0]
    assert "PKCE" in desc


def test_plain_pkce_method_rejected():
    params = _valid_params(code_challenge_method="plain")
    resp = client.get("/authorize", params=params, follow_redirects=False)
    assert resp.status_code == 302
    assert "error=invalid_request" in resp.headers["location"]


def test_disallowed_scope_rejected():
    resp = client.get(
        "/authorize", params=_valid_params(scope="openid admin:everything"),
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "error=invalid_scope" in resp.headers["location"]


def test_state_echoed_back_on_error():
    resp = client.get(
        "/authorize",
        params=_valid_params(response_type="token", state="st-xyz"),
        follow_redirects=False,
    )
    assert resp.status_code == 302
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["error"] == ["unsupported_response_type"]
    assert query["state"] == ["st-xyz"]  # CSRF binding preserved


# -- login -----------------------------------------------------------------


def test_login_bad_password_rejected():
    resp = client.post("/login", data={
        "email": "alice@example.com", "password": "wrong", "next": "/",
    })
    assert resp.status_code == 401
    assert "lab_session" not in resp.cookies


def test_login_unknown_email_same_error_as_bad_password():
    resp = client.post("/login", data={
        "email": "nobody@example.com", "password": "wrong", "next": "/",
    })
    assert resp.status_code == 401
    # identical message => no account enumeration through the response body
    assert "Invalid email or password." in resp.text


def test_login_next_open_redirect_guard():
    for evil_next in ("//evil.example", "http://evil.example", "/\\evil.example"):
        resp = client.get("/login", params={"next": evil_next})
        assert resp.status_code == 200
        assert f'value="{evil_next}"' not in resp.text
        assert 'value="/"' in resp.text


# -- full happy path -------------------------------------------------------


def test_full_authorize_consent_code_issue_and_single_use():
    client.cookies.clear()
    _login()

    # 1. GET /authorize now shows consent (session cookie present)
    verifier = generate_verifier()
    params = _valid_params(code_challenge=challenge_s256(verifier))
    resp = client.get("/authorize", params=params)
    assert resp.status_code == 200
    assert "orders:read" in resp.text              # scopes rendered
    assert 'name="code_challenge"' in resp.text    # echoed for re-validation

    # 2. approve -> 302 to registered URI with code + original state
    resp = client.post("/consent", data={
        "decision": "approve",
        "client_id": params["client_id"],
        "redirect_uri": params["redirect_uri"],
        "scope": params["scope"],
        "state": params["state"],
        "code_challenge": params["code_challenge"],
        "code_challenge_method": "S256",
    }, follow_redirects=False)
    assert resp.status_code == 302
    location = urlparse(resp.headers["location"])
    query = parse_qs(location.query)
    assert location.hostname == "localhost"
    assert query["state"] == ["st-abc123"]
    code = query["code"][0]

    # 3. redeem: bound to alice + the PKCE challenge presented at authorize
    store = app.state.codes
    record = store.redeem(code)
    assert record.subject == "usr_alice"
    assert record.code_challenge == challenge_s256(verifier)
    assert record.scope == "openid orders:read"

    # 4. replay must be detected (RFC 9700: replay => token family theft)
    try:
        store.redeem(code)
        raise AssertionError("replay accepted")
    except CodeReplayError:
        pass


def test_consent_deny_returns_access_denied():
    client.cookies.clear()
    _login()
    params = _valid_params()
    client.get("/authorize", params=params)
    resp = client.post("/consent", data={
        "decision": "deny",
        "client_id": params["client_id"],
        "redirect_uri": params["redirect_uri"],
        "scope": params["scope"],
        "state": params["state"],
        "code_challenge": params["code_challenge"],
        "code_challenge_method": "S256",
    }, follow_redirects=False)
    assert resp.status_code == 302
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["st-abc123"]


def test_consent_without_session_is_403():
    client.cookies.clear()
    params = _valid_params()
    resp = client.post("/consent", data={
        "decision": "approve",
        "client_id": params["client_id"],
        "redirect_uri": params["redirect_uri"],
        "scope": params["scope"],
        "state": params["state"],
        "code_challenge": params["code_challenge"],
        "code_challenge_method": "S256",
    })
    assert resp.status_code == 403


def test_unauthenticated_authorize_redirects_to_login():
    client.cookies.clear()
    resp = client.get("/authorize", params=_valid_params(), follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"].startswith("/login?next=")

