# a-guard — cryptographic review package

**Status:** prepared for an external reviewer. This document is the brief; it is
written so a reviewer can start attacking the interesting parts in minutes
rather than reading the whole repository first. The companion
[`CRYPTO_REVIEW_FINDINGS.md`](CRYPTO_REVIEW_FINDINGS.md) records the internal
self-review already performed (and its resolutions).

## 1. Why this review exists

a-guard implements OAuth 2.1 / OIDC by hand — no `authlib`, no `python-oidc`.
The decisions that matter (algorithm pinning, key lifecycle, audience binding,
PKCE, refresh rotation, cookie MAC) are therefore *ours to get wrong*, and the
project says so publicly in [SECURITY.md](../SECURITY.md). The goal of this
review is to falsify the claims in §3, not to style-check the code.

## 2. What is in scope

| Area | Path | What to attack |
|---|---|---|
| JWT signing / key lifecycle | `aguard/oidc/keys.py`, `aguard/oidc/signers.py` | JWS assembly, `kid` derivation, rotation overlap, KMS trust boundary |
| Token validation | `aguard/oidc/validation.py`, `aguard/resource_server.py`, `aguard/oidc/remote_keys.py` | alg/kid/iss/aud/exp checks, JWKS fetching, refresh-on-unknown-kid |
| Authorization endpoint | `aguard/oidc/routes_auth.py`, `aguard/oidc/pkce.py` | redirect-URI matching, PKCE S256, state/nonce, scope policy |
| Token endpoint | `aguard/oidc/routes_token.py`, `aguard/oidc/codes.py`, `aguard/oidc/refresh.py` | grants, code single-use/tombstones, refresh rotation + family revocation |
| Session cookie | `aguard/oidc/session.py` | MAC construction, comparison, TTL binding |
| Client registry / DCR | `aguard/oidc/clients.py`, `aguard/oidc/routes_register.py` | secret hashing, redirect policy |
| MCP resource server | `aguard/mcp/auth.py`, `aguard/mcp/service.py`, `aguard/mcp/server.py` | audience binding, the AS/RS split boundary |

## 3. Claims to falsify

1. **Signature authenticity.** A token is accepted only if signed by a key this
   deployment publishes, with `alg` fixed to RS256 (never read from the token as
   authority, so `alg:none` and RS256→HS256 confusion fail).
2. **Key lifecycle.** Rotation never invalidates an in-flight token: the retired
   key stays in the JWKS until `retired_at + max_token_ttl` elapses, then it is
   pruned. A `kid` is a pure function of key material (RFC 7638).
3. **Audience binding.** A token minted for one resource is rejected by another
   even when perfectly signed (`aud` is compared against configuration, not the
   token).
4. **The split.** The resource server holds no signing key and cannot mint a
   token; it can only verify against the AS's JWKS.
5. **PKCE.** `plain` is unusable; only `S256` is accepted; the challenge is
   bound to the code and the client.
6. **Authorization codes** are single-use, redirect-URI-bound, and replay is
   *detected* (tombstone), not silently treated as unknown.
7. **Refresh tokens** rotate; replaying a retired one revokes the whole family.
8. **PII redaction** is fail-closed and runs before serialization (adjacent to
   crypto: it is the "no secrets in logs" control).

## 4. Cryptographic inventory

| Purpose | Primitive | Parameters | Source |
|---|---|---|---|
| Token/ID-token signature | RSASSA-PKCS1-v1_5 + SHA-256 (JWS `RS256`) | RSA-2048, e=65537 | `cryptography`; JWS assembled in `keys.encode_jwt` |
| `kid` | SHA-256 over RFC 7638 thumbprint | base64url | `keys.jwk_thumbprint` |
| JWKS | RFC 7517 public JWK (`kty,use,alg,kid,n,e`) | — | `keys.public_jwk_from_numbers` |
| PKCE | SHA-256 of the verifier | S256 only | `pkce.challenge_s256` |
| Client secret at rest | SHA-256 (see note) | — | `clients.hash_secret` |
| Session cookie | HMAC MAC over `sub|exp` (not a JWT) | ≥256-bit secret | `session.py` |
| Log correlation ID | HMAC-SHA-256 with a pepper | truncated, base16 | `redact/` |
| Randomness | `secrets` / `os.urandom` via `cryptography` | — | stdlib |

**Libraries:** `pyjwt` (verify + JWK parsing), `cryptography` (RSA, SHA-256,
PEM/JWK/DER), `mcp` SDK (MCP transport + RFC 9728 metadata), FastAPI/Starlette.
No home-grown block cipher, AEAD, or KDF — the project composes vetted
primitives and owns only *policy*.

## 5. Threat model (assumed attacker)

- Controls the network path to the AS and the resource server (can replay,
  reorder, and forge requests) but cannot break TLS.
- Can register a client via open DCR and can craft arbitrary `/authorize`,
  `/token`, `/mcp` requests.
- May obtain a valid token for resource A and try to use it on resource B.
- May read the application logs.
- May read the `file` keystore *only* if the deployment left `KEY_SOURCE=file`
  (the KMS sources are designed so that reading the process yields no key).

Out of scope for this review: the Postgres RLS model (reviewed separately by
`tests/test_db_rbac.py` and `agctl init`'s live enforcement check), the DCR
policy semantics, and UI/CSS.

## 6. How to reproduce and attack

Everything runs against a local database; no cloud account is required.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env         # set PG_SUPERUSER_PASSWORD
createdb agent_auth && psql -U postgres -d agent_auth -f aguard/db/schema.sql
pytest -q                    # the full suite (crypto-relevant files below)
```

Crypto-relevant suites (each maps to a §3 claim):

```bash
pytest -q tests/test_validation.py        # alg pinning, kid, iss, aud, exp
pytest -q tests/test_keys.py              # rotation overlap, JWKS hygiene, kid
pytest -q tests/test_signers.py           # env + KMS backends, one JWS path
pytest -q tests/test_remote_keys.py       # split RS: JWKS fetch, refresh, fail-closed
pytest -q tests/test_authorize_flow.py tests/test_token_grants.py
pytest -q tests/test_token_refresh_cc.py  # refresh rotation + family revocation
pytest -q tests/test_resource_server_guard.py
```

Two live services, if you prefer black-box probing:

```bash
uvicorn aguard.main:app --port 8080            # authorization server
uvicorn aguard.mcp.service:app --port 8081     # resource server (no signing key)
curl -s localhost:8080/jwks                    # public keys only
curl -s localhost:8081/.well-known/oauth-protected-resource/mcp
python scripts/mcp_smoke.py                     # end-to-end incl. audience binding
```

The internal review used a **mutation mindset**: for each claim, break the
invariant in the smallest way and confirm a test goes red. Good starting
mutations (each should be caught):

- replace `algorithms=[ALGORITHM]` with the token's header `alg`;
- make `verify_access_token` fall back to "any key" on an unknown `kid`;
- drop `aud` from the `require` set in `validation.py`;
- make `retire_expired` prune on `created_at` instead of `retired_at`;
- make `encode_jwt` honour a caller-supplied `alg`;
- have `RemoteKeyStore` return an empty key set instead of failing closed.

## 7. Specific questions for the reviewer

1. **JWS assembly** (`keys.encode_jwt`): is the hand-built compact JWS correct
   and free of canonicalisation pitfalls (header/payload encoding, `kid`/`alg`
   pinning, no duplicate JSON keys)?
2. **Validation ordering** (`validation.py`): are all checks applied before any
   claim is trusted, and can any of `alg`, `kid`, `crit`, `jku`, `x5u`, or a
   duplicate header member influence key selection?
3. **Rotation** (`ManagedKey`, `KeyManager.retire_expired`): is there any window
   in which a live token's key is absent from JWKS? Any way to resurrect/abuse a
   retired key?
4. **KMS trust boundary** (`signers.py`): is the AWS/`RAW`+algorithm and the
   GCP digest construction provably RS256? Can a provider response make us
   publish a private key or a non-RSA key?
5. **Split resource server** (`remote_keys.py`, `mcp/auth.py`): can a forged or
   expired token cause unbounded JWKS fetches (DoS)? Does a JWKS outage fail
   *closed* while still serving cached keys?
6. **PKCE & code binding** (`pkce.py`, `routes_auth.py`, `routes_token.py`): any
   S256 bypass, verifier-confusion, or code/client/redirect mix-up?
7. **Session cookie** (`session.py`): is the MAC comparison constant-time, is the
   MAC bound to everything it must be, and can a truncated/absent MAC verify?

## 8. Deliverable expected from the reviewer

A findings list with, per finding: severity (Critical/High/Medium/Low/Info),
the exact claim from §3 it breaks (or "out of scope"), a minimal reproduction
(command or test), and a suggested fix. Findings should be recorded in a copy
of this file or as issues referencing it. **Clean sign-off with no high/critical
findings is the gate for the 1.0 release** (see [RELEASING.md](RELEASING.md)).
