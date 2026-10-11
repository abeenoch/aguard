"""RemoteKeyStore: the split resource server's key source.

The whole point of the split is that the resource server verifies tokens WITHOUT
holding a signing key. These tests prove that key source is honest:
  * a JWKS becomes verifying keys, and the published material is PUBLIC only
  * a rotation is picked up (the unknown-kid refresh path), so the split does
    not reintroduce the classic "we rotated and everything 401ed" outage
  * a JWKS blip serves last-known-good keys instead of failing mid-traffic,
    while a cold store still fails closed
  * one malformed key in a JWKS does not take down the store
"""
from __future__ import annotations

import asyncio
import time

import pytest

from aguard.mcp.auth import AGuardTokenVerifier
from aguard.oidc.keys import KeyManager
from aguard.oidc.remote_keys import RemoteKeyStore
from aguard.settings import settings


def _claims(**overrides) -> dict:
    now = int(time.time())
    claims = {
        "iss": settings.issuer, "sub": "usr_alice",
        "aud": settings.mcp_resource_id, "iat": now, "exp": now + 300,
        "scope": "orders:read", "roles": ["agent"], "client_id": "cli-agent",
    }
    claims.update(overrides)
    return claims


def test_jwks_becomes_public_verification_keys(tmp_path):
    km = KeyManager(tmp_path / "keys")
    store = RemoteKeyStore(settings.issuer, fetch=lambda: km.jwks)

    assert {k.kid for k in store.all_keys} == {k.kid for k in km.all_keys}
    # Public only: PEM material carries no private key.
    for key in store.all_keys:
        assert b"PRIVATE" not in key.public_pem
        assert key.public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")


def test_remote_store_verifies_a_split_resource_server_token(tmp_path):
    """The end-to-end shape: AS signs, resource server verifies from JWKS."""
    km = KeyManager(tmp_path / "keys")
    store = RemoteKeyStore(settings.issuer, fetch=lambda: km.jwks)
    token = km.sign(_claims())

    access = asyncio.run(AGuardTokenVerifier(store).verify_token(token))
    assert access is not None
    assert access.subject == "usr_alice"
    assert access.resource == settings.mcp_resource_id


def test_rotation_is_picked_up_via_unknown_kid_refresh(tmp_path):
    """A token signed by a key newer than our cache must still verify: the
    unknown-kid path refreshes the JWKS once and retries."""
    km = KeyManager(tmp_path / "keys")
    fetches = {"n": 0}

    def fetch() -> dict:
        fetches["n"] += 1
        return km.jwks

    store = RemoteKeyStore(settings.issuer, fetch=fetch)
    store.refresh()                      # warm the cache on the OLD key
    assert fetches["n"] == 1

    km.rotate()                          # another worker rotated
    token = km.sign(_claims())           # signed by the NEW active key

    access = asyncio.run(AGuardTokenVerifier(store).verify_token(token))
    assert access is not None, "rotation broke verification — the outage class"
    assert fetches["n"] >= 2, "unknown kid did not trigger a JWKS refresh"


def test_fetch_failure_serves_last_known_good_keys(tmp_path):
    km = KeyManager(tmp_path / "keys")
    state = {"ok": True}

    def fetch() -> dict:
        if not state["ok"]:
            raise OSError("jwks unreachable")
        return km.jwks

    store = RemoteKeyStore(settings.issuer, ttl=0.0, fetch=fetch)
    store.refresh()                      # cache good keys...
    state["ok"] = False                  # ...then the endpoint blips
    # ttl=0 forces a refresh attempt, which fails; cached keys still serve.
    assert {k.kid for k in store.all_keys} == {k.kid for k in km.all_keys}


def test_cold_store_with_unreachable_jwks_fails_closed(tmp_path):
    def fetch() -> dict:
        raise OSError("jwks unreachable")

    store = RemoteKeyStore(settings.issuer, fetch=fetch)
    with pytest.raises(OSError):
        _ = store.all_keys

    # And the verifier turns that into "not authenticated", never an exception.
    assert asyncio.run(AGuardTokenVerifier(store).verify_token("x.y.z")) is None


def test_one_malformed_jwk_does_not_break_the_store(tmp_path):
    km = KeyManager(tmp_path / "keys")
    document = dict(km.jwks)
    document["keys"] = [*km.jwks["keys"], {"kty": "RSA", "kid": "broken"}]

    store = RemoteKeyStore(settings.issuer, fetch=lambda: document)
    assert {k.kid for k in store.all_keys} == {k.kid for k in km.all_keys}
