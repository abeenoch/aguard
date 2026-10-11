"""Signing-key sources: env PEMs, and KMS backends behind one Signer interface.

The security claim being tested: a KMS-signed token is byte-for-byte the same
RS256 object as a locally signed one, minted by the SAME code path — and the
process never holds private key material for a KMS source. Provider SDKs are
replaced with fakes, so these run with no cloud credentials.
"""
from __future__ import annotations

import base64
import dataclasses
import json
import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

import aguard.oidc.signers as signers
from aguard.oidc import keys as keys_mod
from aguard.oidc.keys import StaticKeyManager
from aguard.oidc.signers import build_key_manager, build_kms_signer
from aguard.oidc.validation import verify_access_token
from aguard.settings import settings


def _new_rsa() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _private_pem(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()


def _public_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def _kid(key: rsa.RSAPrivateKey) -> str:
    numbers = key.public_key().public_numbers()
    return keys_mod.jwk_thumbprint(numbers.n, numbers.e)


def _claims() -> dict:
    now = int(time.time())
    return {"iss": settings.issuer, "sub": "usr_alice",
            "aud": settings.resource_audience, "iat": now, "exp": now + 900,
            "scope": "orders:read"}


def _settings(**overrides):
    return dataclasses.replace(settings, **overrides)


# ------------------------------- env source --------------------------------


def test_env_source_signs_and_verifies_without_touching_disk(monkeypatch, tmp_path):
    key = _new_rsa()
    monkeypatch.setattr(signers, "settings", _settings(
        key_source="env", signing_key_pem=_private_pem(key)))

    km = build_key_manager(tmp_path)
    assert isinstance(km, StaticKeyManager)
    token = km.sign(_claims())
    assert verify_access_token(token, keys=km)["sub"] == "usr_alice"

    # Public-only JWKS, and no keystore was written anywhere.
    doc = json.dumps(km.jwks)
    for forbidden in ('"d"', '"p"', '"q"', "PRIVATE"):
        assert forbidden not in doc
    assert list(tmp_path.iterdir()) == []


def test_env_source_still_verifies_a_retired_keys_tokens(monkeypatch):
    """The rotation overlap: a token signed by the previous key must keep
    verifying after the active key changes."""
    active, retired = _new_rsa(), _new_rsa()
    monkeypatch.setattr(signers, "settings", _settings(
        key_source="env", signing_key_pem=_private_pem(active),
        signing_key_retired_pems=(_private_pem(retired),)))

    km = build_key_manager()
    assert {k.kid for k in km.all_keys} == {_kid(active), _kid(retired)}

    # A token the retired key signed (e.g. minted just before a rotation).
    token = pyjwt.encode(_claims(), _private_pem(retired), algorithm="RS256",
                         headers={"kid": _kid(retired)})
    assert verify_access_token(token, keys=km)["sub"] == "usr_alice"


def test_env_source_requires_a_pem(monkeypatch):
    monkeypatch.setattr(signers, "settings", _settings(
        key_source="env", signing_key_pem=""))
    with pytest.raises(RuntimeError, match="SIGNING_KEY_PEM"):
        build_key_manager()


# ------------------------------- KMS source --------------------------------


class _LocalStandInBackend:
    """A KMS backend whose 'remote' sign is a local RSA op — enough to prove the
    Signer interface and the JWS assembly, without a cloud."""

    def __init__(self, key: rsa.RSAPrivateKey) -> None:
        self._key = key
        self.sign_calls = 0

    def public_key_pem(self) -> bytes:
        return _public_pem(self._key)

    def sign(self, signing_input: bytes) -> bytes:
        self.sign_calls += 1
        return self._key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def test_kms_signer_signs_and_verifies_and_exposes_only_public_material():
    backend = _LocalStandInBackend(_new_rsa())
    signer = build_kms_signer(backend)
    km = StaticKeyManager([signer])

    token = km.sign(_claims())
    assert backend.sign_calls == 1
    assert verify_access_token(token, keys=km)["sub"] == "usr_alice"
    assert pyjwt.get_unverified_header(token)["kid"] == signer.kid
    # The published key carries no private members.
    assert set(km.jwks["keys"][0]) == {"kty", "use", "alg", "kid", "n", "e"}


def test_unknown_key_source_is_rejected_loudly(monkeypatch):
    monkeypatch.setattr(signers, "settings", _settings(key_source="magic"))
    with pytest.raises(ValueError, match="unknown KEY_SOURCE"):
        build_key_manager()


def test_kms_source_without_key_id_fails_at_startup(monkeypatch):
    monkeypatch.setattr(signers, "settings", _settings(
        key_source="aws-kms", kms_key_id=""))
    with pytest.raises(RuntimeError, match="KMS_KEY_ID"):
        build_key_manager()


# --------------------------- provider contracts ----------------------------


class _FakeAwsKms:
    """Stands in for boto3's kms client. Returns a DER SPKI on get_public_key and
    a real signature on sign, recording the call it was asked to make."""

    def __init__(self, key: rsa.RSAPrivateKey) -> None:
        self._key = key
        self.sign_kwargs: dict | None = None

    def get_public_key(self, KeyId: str) -> dict:  # AWS API casing on purpose
        return {"PublicKey": self._key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)}

    def sign(self, **kwargs) -> dict:
        self.sign_kwargs = kwargs
        return {"Signature": self._key.sign(
            kwargs["Message"], padding.PKCS1v15(), hashes.SHA256())}


def test_aws_kms_backend_uses_the_rs256_contract():
    key = _new_rsa()
    client = _FakeAwsKms(key)
    signer = build_kms_signer(signers.AwsKmsBackend("key-1", client=client))
    token = StaticKeyManager([signer]).sign(_claims())

    assert verify_access_token(token, keys=StaticKeyManager([signer]))["sub"] \
        == "usr_alice"
    assert client.sign_kwargs is not None
    assert client.sign_kwargs["MessageType"] == "RAW"
    assert client.sign_kwargs["SigningAlgorithm"] == "RSASSA_PKCS1_V1_5_SHA_256"


class _FakeGcpKms:
    """Stands in for google-cloud-kms. AsymmetricSign receives the SHA-256
    DIGEST (GCP's contract), and returns a real RS256 signature."""

    def __init__(self, key: rsa.RSAPrivateKey) -> None:
        self._key = key
        self.digest: bytes | None = None

    def get_public_key(self, request: dict):
        return type("Resp", (), {"pem": _public_pem(self._key).decode()})()

    def asymmetric_sign(self, request: dict):
        assert request["name"]
        digest = request["digest"]["sha256"]
        self.digest = digest
        signature = self._key.sign(
            digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        return type("Resp", (), {"signature": signature})()


def test_gcp_kms_backend_signs_the_sha256_digest():
    key = _new_rsa()
    client = _FakeGcpKms(key)
    signer = build_kms_signer(
        signers.GcpKmsBackend("projects/p/locations/l/keyRings/r/"
                              "cryptoKeys/k/cryptoKeyVersions/1", client=client))
    km = StaticKeyManager([signer])
    token = km.sign(_claims())
    assert verify_access_token(token, keys=km)["sub"] == "usr_alice"
    assert client.digest is not None and len(client.digest) == 32


def test_vault_transit_backend_signs_pkcs1v15_sha256():
    key = _new_rsa()
    seen: dict = {}

    def fetch(method: str, path: str, payload: dict | None) -> dict:
        if method == "GET":
            assert path == "transit/keys/agent-key"
            return {"data": {"keys": {"3": {"public_key":
                                            _public_pem(key).decode()}}}}
        assert path == "transit/sign/agent-key"
        seen["payload"] = payload
        raw = base64.b64decode(payload["input"])
        signature = key.sign(raw, padding.PKCS1v15(), hashes.SHA256())
        return {"data": {"signature":
                         "vault:v3:" + base64.b64encode(signature).decode()}}

    backend = signers.VaultTransitBackend("agent-key", fetch=fetch)
    signer = build_kms_signer(backend)
    km = StaticKeyManager([signer])
    token = km.sign(_claims())

    assert verify_access_token(token, keys=km)["sub"] == "usr_alice"
    assert seen["payload"]["signature_algorithm"] == "pkcs1v15"
    assert seen["payload"]["hash_algorithm"] == "sha2-256"
    assert seen["payload"]["prehashed"] is False
