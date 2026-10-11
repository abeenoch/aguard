"""Pluggable signing-key sources: env-provided PEMs and KMS/HSM backends.

Why this exists (SECURITY.md): a signing key sitting unencrypted on disk is the
weakest link in a token issuer. ``KEY_SOURCE`` selects where the key lives:

    file      generate/persist data/keys/keys.json (default; dev/eval)
    env       read the PEM from the environment; never written to disk
    aws-kms   AWS KMS asymmetric key (private key never leaves the service)
    gcp-kms   Google Cloud KMS
    vault     HashiCorp Vault Transit (stdlib HTTP, no SDK)

Every source ends at the same place: ``Signer`` objects (aguard/oidc/keys.py)
wrapped in a ``StaticKeyManager``. The token-minting, JWKS-publishing and
validation paths are therefore IDENTICAL for a local key and a KMS key — the one
difference is who performs ``sign(bytes)``.

Notes for a security reviewer:
  * Provider SDKs are imported LAZILY, inside the backend that needs them, so
    the base install stays small and an unused provider cannot break startup.
  * For a KMS source the private key is never materialised here: we fetch only
    the PUBLIC key (for `kid`, JWKS and verification) and ask the provider to
    sign. There is no code path that reads or writes private key bytes.
  * Misconfiguration fails LOUDLY at startup. It never falls back to a freshly
    generated key — a deployment that believed it was using KMS while signing
    with an ephemeral key would invalidate every token on restart.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from aguard.oidc.keys import (
    KeyManager,
    ManagedKey,
    Signer,
    StaticKeyManager,
    jwk_thumbprint,
    public_jwk_from_numbers,
    public_key_from_pem,
)
from aguard.settings import settings

FILE = "file"
ENV = "env"
AWS_KMS = "aws-kms"
GCP_KMS = "gcp-kms"
VAULT = "vault"
_KMS_SOURCES = (AWS_KMS, GCP_KMS, VAULT)


def _public_pem_bytes(pub: rsa.RSAPublicKey) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@dataclass(frozen=True)
class PublicKey:
    """A verification-only key (a retired PEM supplied without its private half).

    Satisfies ``Signer`` structurally; ``sign`` refuses. A component that can
    only verify must never be talked into signing."""

    kid: str
    public_pem: bytes
    _jwk: dict

    def public_jwk(self) -> dict:
        return self._jwk

    def sign(self, signing_input: bytes) -> bytes:
        raise RuntimeError("this key is public-only; it cannot sign")


@dataclass(frozen=True)
class KmsSigner:
    """A signer whose private key lives in a KMS/HSM.

    Holds only public material plus a callable that asks the provider to sign
    the JWS signing input. The private key is never present in this process."""

    kid: str
    public_pem: bytes
    _jwk: dict
    _sign: Callable[[bytes], bytes] = field(repr=False)

    def public_jwk(self) -> dict:
        return self._jwk

    def sign(self, signing_input: bytes) -> bytes:
        return self._sign(signing_input)


class KmsBackend(Protocol):
    """What a provider adapter must provide: a public key and a signing call."""

    def public_key_pem(self) -> bytes: ...
    def sign(self, signing_input: bytes) -> bytes: ...


# ------------------------------- env source --------------------------------


def _managed_key_from_pem(pem: str, *, status: str) -> ManagedKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise RuntimeError("SIGNING_KEY_PEM must be an RSA PKCS#8 private key")
    pub = key.public_key().public_numbers()
    return ManagedKey(kid=jwk_thumbprint(pub.n, pub.e), pem=pem,
                      created_at=int(time.time()), status=status)


def _verification_key_from_pem(pem: str) -> Signer:
    """A retired key may arrive as a private OR a public PEM."""
    try:
        return _managed_key_from_pem(pem, status="retired")
    except Exception:
        pub = public_key_from_pem(pem)
        numbers = pub.public_numbers()
        return PublicKey(kid=jwk_thumbprint(numbers.n, numbers.e),
                         public_pem=_public_pem_bytes(pub),
                         _jwk=public_jwk_from_numbers(numbers.n, numbers.e))


def _env_key_manager() -> StaticKeyManager:
    pem = settings.signing_key_pem.strip()
    if not pem:
        raise RuntimeError(
            "KEY_SOURCE=env requires SIGNING_KEY_PEM "
            "(a PKCS#8 RSA private key PEM)")
    active = _managed_key_from_pem(pem, status="active")
    retired = [_verification_key_from_pem(p)
               for p in settings.signing_key_retired_pems]
    return StaticKeyManager([active, *retired], active_index=0)


# ------------------------------ KMS backends -------------------------------


class AwsKmsBackend:
    """AWS KMS asymmetric key (RSASSA_PKCS1_V1_5_SHA_256 == RS256).

    ``MessageType="RAW"`` hands KMS the signing input and lets it hash — that is
    exactly a JWS RS256 signature, so no digest juggling is needed. ``client``
    is an injectable boto3 client, which is how the tests exercise this without
    credentials.
    """

    def __init__(self, key_id: str, *, region: str | None = None,
                 client: Any | None = None) -> None:
        self._key_id = key_id
        if client is None:
            import boto3  # lazy: only required for KEY_SOURCE=aws-kms
            client = boto3.client("kms", region_name=region)
        self._client = client

    def public_key_pem(self) -> bytes:
        resp = self._client.get_public_key(KeyId=self._key_id)
        pub = serialization.load_der_public_key(resp["PublicKey"])
        if not isinstance(pub, rsa.RSAPublicKey):
            raise RuntimeError("AWS KMS key is not an RSA key")
        return _public_pem_bytes(pub)

    def sign(self, signing_input: bytes) -> bytes:
        resp = self._client.sign(
            KeyId=self._key_id, Message=signing_input, MessageType="RAW",
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256")
        return resp["Signature"]


class GcpKmsBackend:
    """Google Cloud KMS. ``key_name`` is the full resource name, e.g.
    projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*."""

    def __init__(self, key_name: str, *, client: Any | None = None) -> None:
        self._key_name = key_name
        if client is None:
            from google.cloud import kms  # lazy: optional dependency
            client = kms.KeyManagementServiceClient()
        self._client = client

    def public_key_pem(self) -> bytes:
        resp = self._client.get_public_key(request={"name": self._key_name})
        return resp.pem.encode()

    def sign(self, signing_input: bytes) -> bytes:
        digest = {"sha256": hashlib.sha256(signing_input).digest()}
        resp = self._client.asymmetric_sign(
            request={"name": self._key_name, "digest": digest})
        return resp.signature


class VaultTransitBackend:
    """HashiCorp Vault Transit over stdlib HTTP (no SDK dependency).

    The transit key must be an RSA key (type ``rsa-2048``). Vault is asked to
    hash the signing input (prehashed=false, sha2-256) and sign with PKCS#1
    v1.5 — i.e. RS256. ``fetch`` is injectable for tests.
    """

    def __init__(self, key_name: str, *, addr: str | None = None,
                 token: str | None = None, namespace: str | None = None,
                 fetch: Callable[[str, str, dict | None], dict] | None = None,
                 timeout: float = 5.0) -> None:
        self._key_name = key_name
        self._addr = (addr or "").rstrip("/")
        self._token = token or ""
        self._namespace = namespace or ""
        self._timeout = timeout
        if fetch is None and not self._addr:
            raise RuntimeError("KEY_SOURCE=vault requires VAULT_ADDR")
        self._fetch = fetch or self._http

    def _http(self, method: str, path: str, payload: dict | None) -> dict:
        import urllib.request
        url = f"{self._addr}/v1/{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("X-Vault-Token", self._token)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self._namespace:
            req.add_header("X-Vault-Namespace", self._namespace)
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def public_key_pem(self) -> bytes:
        doc = self._fetch("GET", f"transit/keys/{self._key_name}", None)
        versions = doc["data"]["keys"]
        newest = str(max(int(v) for v in versions))
        pem = (versions[newest] or {}).get("public_key")
        if not pem:
            raise RuntimeError(
                "Vault transit key exposes no public_key; it must be an "
                "asymmetric 'rsa-2048' key")
        return pem.encode()

    def sign(self, signing_input: bytes) -> bytes:
        doc = self._fetch("POST", f"transit/sign/{self._key_name}", {
            "input": base64.b64encode(signing_input).decode("ascii"),
            "signature_algorithm": "pkcs1v15",
            "hash_algorithm": "sha2-256",
            "prehashed": False,
        })
        signature = doc["data"]["signature"]
        # Vault prefixes signatures ("vault:v1:<base64>"); JWS needs raw bytes.
        return base64.b64decode(signature.rsplit(":", 1)[-1])


# -------------------------------- factory ----------------------------------


def _build_backend() -> KmsBackend:
    src = settings.key_source
    if src == AWS_KMS:
        if not settings.kms_key_id:
            raise RuntimeError("KEY_SOURCE=aws-kms requires KMS_KEY_ID")
        return AwsKmsBackend(settings.kms_key_id,
                             region=settings.kms_region or None)
    if src == GCP_KMS:
        if not settings.kms_key_id:
            raise RuntimeError(
                "KEY_SOURCE=gcp-kms requires KMS_KEY_ID (the key resource name)")
        return GcpKmsBackend(settings.kms_key_id)
    if src == VAULT:
        if not settings.kms_key_id:
            raise RuntimeError(
                "KEY_SOURCE=vault requires KMS_KEY_ID (the transit key name)")
        return VaultTransitBackend(settings.kms_key_id,
                                   addr=settings.vault_addr or None,
                                   token=settings.vault_token or None,
                                   namespace=settings.vault_namespace or None)
    raise ValueError(f"unknown KEY_SOURCE {src!r}")


def build_kms_signer(backend: KmsBackend | None = None) -> Signer:
    """Wrap a KMS backend as a Signer: fetch the public key, derive kid/JWK."""
    backend = backend or _build_backend()
    pem = backend.public_key_pem()
    numbers = public_key_from_pem(pem).public_numbers()
    return KmsSigner(kid=jwk_thumbprint(numbers.n, numbers.e),
                     public_pem=pem,
                     _jwk=public_jwk_from_numbers(numbers.n, numbers.e),
                     _sign=backend.sign)


def build_key_manager(key_dir: Path | None = None, *,
                      max_token_ttl: int | None = None
                      ) -> KeyManager | StaticKeyManager:
    """Select the signing-key source from settings.

    Returns a ``KeyManager`` (file) or a ``StaticKeyManager`` (env/KMS). Every
    misconfiguration raises HERE, at startup: a bad source must never degrade to
    a silently generated key.
    """
    src = settings.key_source
    if src == FILE:
        if key_dir is None:
            raise ValueError("KEY_SOURCE=file requires a key_dir")
        return KeyManager(key_dir, max_token_ttl=max_token_ttl)
    if src == ENV:
        return _env_key_manager()
    if src in _KMS_SOURCES:
        return StaticKeyManager([build_kms_signer()])
    raise ValueError(
        f"unknown KEY_SOURCE {src!r} "
        f"(expected {FILE}, {ENV}, {AWS_KMS}, {GCP_KMS}, or {VAULT})")
