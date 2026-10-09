"""ResourceServerGuard: what a downstream server must check before trusting a
token. Also drives the examples/ integration end-to-end.

Key resolution is injected so the guard's real PyJWT path (header parse, kid
lookup, signature verify) runs without a network fetch.
"""
from __future__ import annotations

import importlib.util
import time
from pathlib import Path

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from fastapi import HTTPException
from fastapi.testclient import TestClient

from aguard.main import app
from aguard.resource_server import ResourceServerGuard, TokenError
from aguard.settings import settings

ISSUER = settings.issuer
MY_RESOURCE = "http://localhost:9000/mcp"
EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "protect_mcp_server.py"


class _LocalJWKS:
    """Stands in for PyJWKClient, resolving from the app's own keystore."""

    def __init__(self, keys):
        self._keys = keys

    def get_signing_key_from_jwt(self, token: str):
        kid = pyjwt.get_unverified_header(token)["kid"]
        key = next(k for k in self._keys.all_keys if k.kid == kid)
        pem = key.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        return type("SigningKey", (), {"key": pem})()


class _StubRequest:
    def __init__(self, headers: dict):
        self.headers = headers


@pytest.fixture(scope="module")
def guard():
    return ResourceServerGuard(issuer=ISSUER, audience=MY_RESOURCE,
                               jwk_client=_LocalJWKS(app.state.keys))


def _token(**overrides) -> str:
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "usr_alice", "aud": MY_RESOURCE,
              "iat": now, "exp": now + 300, "scope": "orders:read",
              "client_id": "demo-spa"}
    claims.update(overrides)
    return app.state.keys.sign(claims)


# ------------------------------- claim checks ------------------------------


def test_valid_token_yields_claims(guard):
    claims = guard.verify(_token())
    assert claims["sub"] == "usr_alice"
    assert claims["client_id"] == "demo-spa"


def test_token_for_another_audience_is_refused(guard):
    """The RFC 8707 payoff: a token minted for a DIFFERENT service must not be
    replayable here, even though its signature is perfectly valid."""
    other = _token(aud=settings.resource_audience)      # minted for /api
    with pytest.raises(TokenError, match="invalid token"):
        guard.verify(other)


def test_wrong_issuer_is_refused(guard):
    with pytest.raises(TokenError):
        guard.verify(_token(iss="http://evil.example"))


def test_expired_is_refused(guard):
    with pytest.raises(TokenError):
        guard.verify(_token(exp=int(time.time()) - 3600))


def test_missing_audience_is_refused(guard):
    token = app.state.keys.sign({"iss": ISSUER, "sub": "usr_alice",
                                 "iat": int(time.time()),
                                 "exp": int(time.time()) + 300})
    with pytest.raises(TokenError):
        guard.verify(token)


def test_garbage_is_refused(guard):
    with pytest.raises(TokenError):
        guard.verify("not-a-jwt")
    with pytest.raises(TokenError):
        guard.verify("")


def test_required_scopes_enforced():
    strict = ResourceServerGuard(issuer=ISSUER, audience=MY_RESOURCE,
                                 required_scopes=("orders:write",),
                                 jwk_client=_LocalJWKS(app.state.keys))
    with pytest.raises(TokenError, match="insufficient scope"):
        strict.verify(_token(scope="orders:read"))
    assert strict.verify(_token(scope="orders:read orders:write"))["sub"]


# ------------------------------- HTTP surface ------------------------------


def test_missing_bearer_is_401_with_discovery(guard):
    with pytest.raises(HTTPException) as excinfo:
        guard.verify_request(_StubRequest({}))
    err = excinfo.value
    assert err.status_code == 401
    assert "resource_metadata=" in err.headers["WWW-Authenticate"]
    assert "/.well-known/oauth-protected-resource" in err.headers["WWW-Authenticate"]


def test_bad_token_is_401(guard):
    with pytest.raises(HTTPException) as excinfo:
        guard.verify_request(_StubRequest({"authorization": "Bearer nope"}))
    assert excinfo.value.status_code == 401


# ---------------------- the examples/ integration, end to end --------------


def _load_example():
    spec = importlib.util.spec_from_file_location("example_mcp", EXAMPLE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)          # type: ignore[union-attr]
    return module


def test_example_protects_its_mcp_endpoint():
    module = _load_example()
    module.guard._jwk_client = _LocalJWKS(app.state.keys)   # no network
    client = TestClient(module.app)

    # unauthenticated: 401 + the header an MCP client follows
    resp = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1,
                                     "method": "tools/list"})
    assert resp.status_code == 401
    assert "resource_metadata=" in resp.headers["www-authenticate"]

    # authenticated: tools/list, then a call that echoes VERIFIED identity
    headers = {"Authorization": f"Bearer {_token()}"}
    listed = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1,
                                       "method": "tools/list"}, headers=headers)
    assert listed.status_code == 200
    assert listed.json()["result"]["tools"][0]["name"] == "whoami"

    called = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2,
                                       "method": "tools/call"}, headers=headers)
    assert "sub=usr_alice" in called.json()["result"]["content"][0]["text"]
