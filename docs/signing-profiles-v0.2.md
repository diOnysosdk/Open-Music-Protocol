# OMP v0.2 signing profiles

**Status:** normative draft approved for cryptographic-vector review.

All inputs are duplicate-key-free I-JSON. Canonicalization is RFC 8785 JCS.
Every domain below is the listed ASCII text followed by exactly one NUL byte
(`00`). Concatenation has no length prefix or newline.

| Object | Domain text | Excluded top-level member |
|---|---|---|
| Manifest | `OMP-MANIFEST-v0.2` | `signature` |
| Identity document | `OMP-IDENTITY-DOCUMENT-v0.2` | `proofs` |
| Key lifecycle event | `OMP-KEY-LIFECYCLE-EVENT-v0.2` | `proofs` |
| License | `OMP-LICENSE-v0.2` | `signature` |
| Trust bundle | `OMP-TRUST-BUNDLE-v0.2` | `signatures` |
| Time anchor | `OMP-TIME-ANCHOR-v0.2` | `signature` |

The signing input is:

```text
ASCII(domain text) || 0x00 || JCS(object with only the listed top-level member removed)
```

The member is removed only at top level. A nested member with the same name
remains signed. The excluded member MUST exist in the transported object.
Objects MUST NOT be normalized, timestamp-rewritten, trimmed, or otherwise
mutated before verification. Signature values and Ed25519 public keys use
unpadded base64url. Ed25519 is the only v0.2 signature algorithm.

The self-certifying identity commitment is not a signature and uses:

```text
SHA-256(ASCII("OMP-IDENTITY-GENESIS-v0.2") || 0x00 || JCS(genesis_body))
```

expressed as `omp:party:sha256-` followed by lowercase hexadecimal.

v0.1 remains exactly:

```text
ASCII("OMP-SIGNED-OBJECT-v0.1") || 0x00 || JCS(v0.1 object without top-level signature)
```

No verifier may retry an object with a different domain or version after
failure. Unknown versions and object/domain mismatches fail with
`OMP_SIGNING_DOMAIN_MISMATCH`.

