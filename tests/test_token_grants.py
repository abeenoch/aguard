"""POST /token tests — one test per attack the endpoint must survive.

The code-grant section models a real attacker: steals the code (intercepts
the redirect), tries every parameter twist to turn it into a token.
"""
from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from aguard.main import app
from aguard.oidc.pkce import challenge_s256, generate_verifier
from aguard.oidc.validation import verify_access_token

client = TestClient(app)

REGISTERED_REDIRECT = "http://localhost:8000/demo/callback"


def _basic(client_id: str, secret: str) -> dict:
    cred = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {cred}"}


def _login(email="alice@example.com", password="correct-horse-battery") -> None:
    resp = client.post("/login",
                       data={"email": email, "password": password, "next": "/"},
                       follow_redirects=False)
    assert resp.status_code == 303


def _obtain_code(*, client_id="demo-spa", scope="openid orders:read",
                 verifier: str | None = None, nonce: str | None = None) -> tuple[str, str]:
    """Run authorize+consent to get (code, verifier). Fresh cookies each call."""
    client.cookies.clear()
    _login()
    verifier = verifier or generate_verifier()
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REGISTERED_REDIRECT,
        "scope": scope,
        "state": "st-test",
        "code_challenge": challenge_s256(verifier),
        "code_challenge_method": "S256",
    }
    if nonce:
        params["nonce"] = nonce
    resp = client.get("/authorize", params=params)
    assert resp.status_code == 200, resp.text
    data = {
        "decision": "approve",
        "client_id": client_id,
        "redirect_uri": REGISTERED_REDIRECT,
        "scope": scope,
        "state": "st-test",
        "code_challenge": params["code_challenge"],
        "code_challenge_method": "S256",
    }
    if nonce:
        data["nonce"] = nonce
    resp = client.post("/consent", data=data, follow_redirects=False)
    assert resp.status_code == 302, resp.text
    query = parse_qs(urlparse(resp.headers["location"]).query)
    return query["code"][0], verifier


def _exchange(payload: dict, headers: dict | None = None):
    return client.post("/token", data=payload, headers=headers or {})


# -- authorization_code -----------------------------------------------------


def test_code_exchange_happy_path():
    code, verifier = _obtain_code(nonce="n-42")
    resp = _exchange({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REGISTERED_REDIRECT,
        "code_verifier": verifier,
        "client_id": "demo-spa",
    })
    assert resp.status_code == 200, resp.text
    assert resp.headers["Cache-Control"] == "no-store"   # RFC 6749 §5.1

    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 900
    assert "refresh_token" in body
    assert "id_token" in body

    claims = verify_access_token(body["access_token"], keys=app.state.keys)
    from aguard.settings import settings
    assert claims["sub"] == "usr_alice"
    assert claims["iss"] == settings.issuer          # exact issuer match
    assert claims["aud"] == settings.resource_audience  # audience-restricted
    assert claims["client_id"] == "demo-spa"
    assert claims["roles"] == ["human"]
    assert set(claims["scope"].split()) == {"openid", "orders:read"}

    # id_token: audience = CLIENT (not the API), nonce replay-bound
    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization
    pem = app.state.keys.active.private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    id_claims = pyjwt.decode(body["id_token"], pem, algorithms=["RS256"],
                             audience="demo-spa")
    assert id_claims["nonce"] == "n-42"
    assert id_claims["email"] == "alice@example.com"   # OIDC identity = the point


def test_code_wrong_verifier_rejected():
    code, _ = _obtain_code()
    resp = _exchange({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REGISTERED_REDIRECT,
        "code_verifier": generate_verifier(),   # attacker's own verifier
        "client_id": "demo-spa",
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_code_missing_verifier_rejected():
    code, _ = _obtain_code()
    resp = _exchange({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REGISTERED_REDIRECT,
        "client_id": "demo-spa",
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_code_becomes_single_use_at_token_endpoint():
    code, verifier = _obtain_code()
    first = _exchange({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REGISTERED_REDIRECT,
        "code_verifier": verifier,
        "client_id": "demo-spa",
    })
    assert first.status_code == 200
    second = _exchange({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REGISTERED_REDIRECT,
        "code_verifier": verifier,
        "client_id": "demo-spa",
    })
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


def test_code_with_mismatched_redirect_uri_rejected():
    code, verifier = _obtain_code()
    resp = _exchange({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://localhost:8000/demo/callback-evil",
        "code_verifier": verifier,
        "client_id": "demo-spa",
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_code_stolen_to_another_client_rejected():
    code, verifier = _obtain_code(client_id="demo-spa")   # alice's code for spa
    # attacker presents it as demo-conf (which has its own secret)
    resp = _exchange({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REGISTERED_REDIRECT,
        "code_verifier": verifier,
    }, headers=_basic("demo-conf", "demo-conf-secret"))
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_bad_client_secret_is_401_not_400():
    code, verifier = _obtain_code(client_id="demo-conf", scope="openid agents:read")
    # demo-conf is registered for client_secret_basic — body auth is refused
    body_style = _exchange({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REGISTERED_REDIRECT,
        "code_verifier": verifier,
        "client_id": "demo-conf",
        "client_secret": "demo-conf-secret",
    })
    assert body_style.status_code == 401
    assert body_style.json()["error"] == "invalid_client"

    # wrong secret over Basic is also invalid_client (never reveal why)
    resp = _exchange({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REGISTERED_REDIRECT,
        "code_verifier": verifier,
    }, headers=_basic("demo-conf", "wrong-secret"))
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


def test_credentials_in_both_header_and_body_rejected():
    code, verifier = _obtain_code(client_id="demo-conf", scope="openid agents:read")
    resp = _exchange({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REGISTERED_REDIRECT,
        "code_verifier": verifier,
        "client_secret": "demo-conf-secret",
    }, headers=_basic("demo-conf", "demo-conf-secret"))
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_unsupported_grant_type():
    resp = _exchange({"grant_type": "password",
                      "username": "x", "password": "y", "client_id": "demo-spa"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_grant_type"

