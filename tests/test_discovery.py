"""Discovery + JWKS endpoint tests (Milestone 1 surface)."""
from __future__ import annotations

from fastapi.testclient import TestClient

from aguard.main import app
from aguard.settings import settings

client = TestClient(app)


def test_healthz():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_discovery_document():
    resp = client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    doc = resp.json()

    assert doc["issuer"] == settings.issuer
    # every endpoint must hang off the issuer — no mixed-host confusion
    for endpoint_field in (
        "authorization_endpoint", "token_endpoint", "userinfo_endpoint",
        "jwks_uri", "introspection_endpoint", "revocation_endpoint",
    ):
        assert doc[endpoint_field].startswith(settings.issuer + "/")

    # OAuth 2.1 posture: code flow only, S256 only, no implicit
    assert doc["response_types_supported"] == ["code"]
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert "plain" not in doc["code_challenge_methods_supported"]
    assert "token" not in doc["response_types_supported"]   # no implicit flow

    assert "RS256" in doc["id_token_signing_alg_values_supported"]
    assert "client_credentials" in doc["grant_types_supported"]  # for agents


def test_jwks_endpoint():
    resp = client.get("/jwks")
    assert resp.status_code == 200
    keys = resp.json()["keys"]
    assert len(keys) >= 1
    for key in keys:
        assert key["kty"] == "RSA"
        assert "d" not in key
