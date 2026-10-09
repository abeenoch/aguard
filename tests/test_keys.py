"""Key lifecycle tests: JWKS hygiene, kid determinism, rotation overlap."""
from __future__ import annotations

import base64
import json
import time

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from aguard.oidc.keys import KeyManager, jwk_thumbprint
from aguard.oidc.validation import verify_access_token


def _b64u_dec(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_jwks_contains_no_private_material(tmp_path):
    km = KeyManager(tmp_path / "keys")
    jwks = km.jwks
    assert len(jwks["keys"]) == 1
    key = jwks["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"          # matches what discovery advertises
    assert key["use"] == "sig"
    assert set(key) == {"kty", "use", "alg", "kid", "n", "e"}  # exact: no extras
    # defense in depth: no private members anywhere in the published document
    serialized = json.dumps(jwks)
    for forbidden in ('"d"', '"p"', '"q"', '"dp"', '"dq"', '"qi"', "PRIVATE"):
        assert forbidden not in serialized


def test_kid_is_deterministic_across_restarts(tmp_path):
    key_dir = tmp_path / "keys"
    km1 = KeyManager(key_dir)
    kids1 = [k.kid for k in km1.all_keys]

    km2 = KeyManager(key_dir)  # simulate process restart
    kids2 = [k.kid for k in km2.all_keys]
    assert kids1 == kids2

    # and the thumbprint is a pure function of key material
    pub = km1.active.private_key.public_key().public_numbers()
    assert km1.active.kid == jwk_thumbprint(pub.n, pub.e)


def test_rotation_preserves_old_key_for_verification(tmp_path):
    km = KeyManager(tmp_path / "keys")
    old_kid = km.active.kid

    # token signed BEFORE rotation, with the old active key
    token = km.sign({"sub": "usr_1", "iat": 0, "exp": 4_000_000_000})
    assert pyjwt.get_unverified_header(token)["kid"] == old_kid

    km.rotate()
    new_kid = km.active.kid
    assert new_kid != old_kid

    # both keys must be published: new one signs, old one still verifies
    kids_in_jwks = {k["kid"] for k in km.jwks["keys"]}
    assert kids_in_jwks == {old_kid, new_kid}

    # verify the pre-rotation token against ONLY the public JWKS data,
    # reconstructing the public key exactly as a remote resource server would
    jwk = next(k for k in km.jwks["keys"] if k["kid"] == old_kid)
    numbers = rsa.RSAPublicNumbers(
        e=int.from_bytes(_b64u_dec(jwk["e"]), "big"),
        n=int.from_bytes(_b64u_dec(jwk["n"]), "big"),
    )
    public_pem = numbers.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    claims = pyjwt.decode(
        token,
        public_pem,
        algorithms=["RS256"],          # algorithm pinned — never from the token
        options={"require_exp": True},
    )
    assert claims["sub"] == "usr_1"


def test_sign_pins_algorithm_header(tmp_path):
    km = KeyManager(tmp_path / "keys")
    token = km.sign({"sub": "x", "exp": 4_000_000_000})
    header = pyjwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
    assert header["kid"] == km.active.kid


def _retired(km: KeyManager):
    return [k for k in km.all_keys if k.status == "retired"][0]


def test_retire_expired_keeps_a_freshly_retired_key(tmp_path):
    km = KeyManager(tmp_path / "keys")
    km.rotate()
    old_kid = _retired(km).kid

    # tokens signed moments ago may still be alive: the key must stay
    assert km.retire_expired(max_token_ttl=900) == []
    assert old_kid in {k.kid for k in km.all_keys}


def test_retire_expired_measures_the_window_from_retirement(tmp_path):
    """Regression: measure the grace window from retired_at, not created_at.

    Gating on created_at deleted a long-lived key the instant it was rotated,
    taking every in-flight token with it ("kid not in JWKS") — the exact outage
    this class's docstring promises does not happen. Reproduced before the fix.
    """
    km = KeyManager(tmp_path / "keys")
    # a real signing key lives for months, so created_at is ancient...
    km.active.created_at = int(time.time()) - 30 * 24 * 3600
    km._persist()

    token = km.sign({
        "iss": "http://localhost:8000", "sub": "usr_alice",
        "aud": "a-guard-api", "scope": "orders:read", "roles": ["human"],
        "iat": int(time.time()), "exp": int(time.time()) + 900,
    })
    km.rotate()                        # ...and it is retired just now

    assert km.retire_expired(max_token_ttl=900) == []

    # the in-flight token still verifies: its key is still published
    assert verify_access_token(token, keys=km)["sub"] == "usr_alice"

    # once the grace window has genuinely elapsed, the key goes
    key = _retired(km)
    key.retired_at = int(time.time()) - 901
    km._persist()
    assert km.retire_expired(max_token_ttl=900) == [key.kid]


def test_retired_key_without_a_timestamp_is_never_dropped(tmp_path):
    """A keystore written before retired_at existed must fail toward KEEPING:
    an extra key costs JWKS bytes, a key dropped early 401s live traffic."""
    km = KeyManager(tmp_path / "keys")
    km.rotate()
    key = _retired(km)
    key.retired_at = None
    key.created_at = int(time.time()) - 10_000     # ancient by creation only
    km._persist()

    assert km.retire_expired(max_token_ttl=900) == []
    assert key.kid in {k.kid for k in km.all_keys}


def test_startup_prunes_keys_that_can_no_longer_verify_anything(tmp_path):
    key_dir = tmp_path / "keys"
    km = KeyManager(key_dir)
    km.rotate()
    key = _retired(km)
    key.retired_at = int(time.time()) - 10_000
    km._persist()

    reloaded = KeyManager(key_dir, max_token_ttl=900)   # startup housekeeping
    assert key.kid not in {k.kid for k in reloaded.all_keys}
    assert len(reloaded.all_keys) == 1
    assert reloaded.active.status == "active"


def test_startup_keeps_keys_that_may_still_be_verifying(tmp_path):
    key_dir = tmp_path / "keys"
    km = KeyManager(key_dir)
    km.rotate()
    retired_kid = _retired(km).kid

    reloaded = KeyManager(key_dir, max_token_ttl=900)
    assert retired_kid in {k.kid for k in reloaded.all_keys}
