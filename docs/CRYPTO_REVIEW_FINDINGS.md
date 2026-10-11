# a-guard — internal crypto self-review findings

**Reviewer:** maintainer (adversarial pass) · **Scope:** see
[`CRYPTO_REVIEW.md`](CRYPTO_REVIEW.md) §2–§4 · **Status of this document:**
living. Each entry names the claim it bears on, the evidence, and the
resolution. This is *not* a substitute for the external review — it is the
material that review starts from.

| # | Severity | Claim | Finding | Resolution |
|---|---|---|---|---|
| F1 | **Medium** | §3.2 key selection | `KeyManager.sign` delegated to `jwt.encode`, which merged caller-supplied `headers` *over* the computed `kid`. A caller could mislabel a token's key. (The dangerous knob, `alg`, was still pinned by the encode call, so this was a correctness/abuse-of-API issue, not signature forgery.) | **Fixed.** JWS is now assembled in `keys.encode_jwt`, which pins `alg` **and** `kid` above any caller headers. Tests `tests/test_validation.py::test_unknown_kid_rejected` and `::test_rs256_token_from_another_key_rejected` now forge the header explicitly, proving the pin. |
| F2 | **High (design)** | §3.4 the split | The MCP resource server shared the AS process and its `KeyManager`, so a resource-server compromise could sign tokens at will. | **Fixed.** The resource server is a separate service (`aguard/mcp/service.py`) that takes a `KeySet`, never a signing key. Its default source is `RemoteKeyStore` (JWKS over HTTP). `tests/test_mcp_resource_server.py::test_as_no_longer_serves_the_resource_or_its_metadata` pins the boundary. |
| F3 | **Medium** | §3.1/§3.5 DoS | A remote key source that refreshes the JWKS on *any* validation failure would let an attacker drive unbounded fetches. | **Fixed (by construction).** `validation.py` raises a distinct `UnknownKeyError` for a missing `kid`; only that triggers a single refresh-and-retry in `mcp/auth.py`. A cold store with the JWKS unreachable fails closed (`tests/test_remote_keys.py`). |
| F4 | Low | §3.3 audience binding | `RemoteKeyStore` served a stale key set indefinitely if a refresh raised, with no bound on staleness. | **Accepted-by-design.** Serving last-known-good keys is deliberate (a JWKS blip must not 500 live traffic) and the key set is public data; freshness is bounded by `ttl` on the next successful fetch. Documented in `remote_keys.py`. |
| F5 | Info | §3.3 metadata | The MCP SDK serializes the AS issuer in RFC 9728 `authorization_servers` via `AnyHttpUrl`, which appends a trailing slash (`http://host:8080/`). | **Accepted/noted.** The token's `iss` is the authority for validation; clients must normalize. Asserted explicitly in the MCP tests so a future SDK change is visible. Raised to the vendor if it causes interop friction. |
| F6 | Info | §4 secrets at rest | Client secrets are stored as unsalted SHA-256. | **Accepted.** Client secrets are high-entropy machine credentials, not human passwords; a slow KDF is unnecessary and adds latency to every `/token`. Revisit if human-chosen client secrets are ever allowed. |
| F7 | Low | §4 key storage | Default `KEY_SOURCE=file` writes an unencrypted PKCS#8 PEM to `data/keys/`. | **Mitigated.** `KEY_SOURCE=env` (PEM from a secret manager, never written to disk) and `aws-kms`/`gcp-kms`/`vault` (private key never in-process) now ship. Startup warns on the dev-safe-but-not-production defaults. |
| F8 | Info | §3.1 KMS boundary | Provider responses could, in principle, hand back a non-RSA or private key object. | **Checked.** AWS path asserts `isinstance(..., RSAPublicKey)`; GCP/Vault paths pass through `keys.public_key_from_pem`, which raises unless the PEM is an RSA public key. `tests/test_signers.py` exercises all three with fakes. |

## What this pass did *not* cover

- No independent cryptographer has reviewed the JWS assembly or the validation
  ordering — that is exactly what §7 of the review brief asks for.
- No fuzzing of the JWKS/KMS parsers or the `/authorize` parameter surface.
- No review of the Postgres RLS model (tracked separately).

## Residual risk statement

With F1–F3 and F7 addressed, the remaining known exposure is (a) the absence of
an external review and (b) the intentional `file`-key default for developer
convenience. Neither is exploitable by a network attacker alone; both are
called out in [SECURITY.md](../SECURITY.md).
