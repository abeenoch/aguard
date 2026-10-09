"""verify_access_token unit tests: algorithm confusion, kid, iss, aud, exp.

Each test is one named attack from the JWT hall of shame — this is the file
that documents WHY the validator checklist exists.
"""
from __future__ import annotations

import base64
import time

import pytest

from aguard.main import app
from aguard.oidc.validation import TokenValidationError, verify_access_token
from aguard.settings import settings

keys = app.state.keys


def _valid_claims(**overrides) -> dict:
    now = int(time.time())
    claims = {
        "iss": settings.issuer,
        "sub": "usr_alice",
        "aud": settings.resource_audience,
        "iat": now,
        "exp": now + 900,
        "scope": "openid orders:read",
    }
    claims.update(overrides)
    return claims


def test_valid_token_round_trips():
    raw = keys.sign(_valid_claims())
    assert verify_access_token(raw, keys=keys)["sub"] == "usr_alice"


def test_unknown_kid_rejected():
    raw = keys.sign(_valid_claims(), headers={"kid": "attacker-kid-123"})
    with pytest.raises(TokenValidationError, match="kid"):
        verify_access_token(raw, keys=keys)


def test_alg_none_rejected():
    def b64u(obj: dict) -> str:
        import json
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    forged = (
        b64u({"alg": "none", "typ": "JWT"})
        + "." + b64u(_valid_claims()) + "."
    )
    with pytest.raises(TokenValidationError, match="disallowed alg"):
        verify_access_token(forged, keys=keys)


def test_rs256_token_from_another_key_rejected():
    # a validly-signed token with a kid we don't know: signature could be
    # perfect, we still reject — we only trust OUR published keys
    raw = keys.sign(_valid_claims(), headers={"kid": "rotated-away-2024"})
    with pytest.raises(TokenValidationError, match="kid"):
        verify_access_token(raw, keys=keys)


def test_wrong_audience_rejected():
    raw = keys.sign(_valid_claims(aud="some-other-api"))
    with pytest.raises(TokenValidationError, match="audience"):
        verify_access_token(raw, keys=keys)


def test_wrong_issuer_rejected():
    raw = keys.sign(_valid_claims())
    with pytest.raises(TokenValidationError, match="issuer"):
        verify_access_token(raw, keys=keys, issuer="https://evil.example")


def test_expired_token_rejected():
    raw = keys.sign(_valid_claims(exp=int(time.time()) - 120))
    with pytest.raises(TokenValidationError, match="expired"):
        verify_access_token(raw, keys=keys)


def test_missing_scope_claim_rejected():
    claims = _valid_claims()
    del claims["scope"]
    raw = keys.sign(claims)
    with pytest.raises(TokenValidationError):
        verify_access_token(raw, keys=keys)


def test_garbage_token_rejected():
    with pytest.raises(TokenValidationError):
        verify_access_token("not.a.token", keys=keys)
    with pytest.raises(TokenValidationError):
        verify_access_token("", keys=keys)
