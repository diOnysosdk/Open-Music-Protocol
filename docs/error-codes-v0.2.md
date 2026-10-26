# OMP v0.2 verification and playback error codes

These codes describe machine decisions without conflating cryptographic
authenticity, current trust, legal ownership, or playback entitlement.

| Code | Meaning |
|---|---|
| `OMP_SCHEMA_INVALID` | JSON, versioned schema, or semantic invariant failed |
| `OMP_SIGNATURE_INVALID` | Ed25519 authentication failed |
| `OMP_SIGNING_DOMAIN_MISMATCH` | Object type/version was evaluated under the wrong domain |
| `OMP_IDENTITY_UNKNOWN` | No local identity chain or accepted TOFU pin exists |
| `OMP_IDENTITY_UNVERIFIED` | TOFU identity is pinned but has no verified introduction |
| `OMP_KEY_UNKNOWN` | Identity is known but the referenced key is unavailable |
| `OMP_KEY_UNAUTHORIZED` | Key lacks the required role or validity interval |
| `OMP_KEY_REVOKED` | Signature is authentic but current trust marks its key revoked |
| `OMP_TRUST_CONFLICT` | Valid competing identity or lifecycle histories are known |
| `OMP_TRUST_STALE` | Available trust evidence is older than applicable policy permits |
| `OMP_TRUST_ROLLBACK` | State regressed below a previously observed sequence or hash |
| `OMP_ASSET_BINDING_INVALID` | Path, selection, hash, size, or containment check failed |
| `OMP_LICENSE_INVALID` | License linkage, audience, or policy is invalid |
| `OMP_LICENSE_NOT_YET_VALID` | Evaluation precedes `valid_from` |
| `OMP_LICENSE_EXPIRED` | Evaluation is at or after exclusive `expires_at` |
| `OMP_TRUSTED_TIME_UNAVAILABLE` | A time-limited decision lacks acceptable time evidence |
| `OMP_TRUSTED_TIME_ROLLBACK` | Time evidence regressed beyond permitted local policy |
| `OMP_UNSUPPORTED_VERSION` | Exact schema version is unsupported |

An authentic historical signature may return cryptographic result `VALID`
while current trust returns `REVOKED` or `CONFLICT`. APIs MUST expose both and
must not collapse `OMP_IDENTITY_UNVERIFIED` into verified trust. Legal rights
and ownership are separate application claims and have no success code here.

The frozen v0.2 schemas are closed. Any undeclared extension member is rejected
as `OMP_SCHEMA_INVALID`; v0.2 defines no extension-specific error code.

