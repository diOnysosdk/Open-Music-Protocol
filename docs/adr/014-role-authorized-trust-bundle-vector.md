# ADR-014: role-authorized trust-bundle vector

Status: Accepted (post-freeze amendment)  
Date: 2026-10-26  
Baseline: `OMP-v0.2-w0-freeze.1`

## Decision

The frozen trust-bundle vector signed by recovery key `root-01` remains
byte-identical. It is cryptographically valid under the W3 trust-bundle
profile, but role-unauthorized for end-to-end W4 acceptance because `root-01`
has no authenticated `trust-bundle` operational role.

The separately versioned positive vector
`OMP-v0.2-trust-bundle-vector-amendment-1` is signed by operational key
`media-01`, whose authenticated identity document grants that role. The
positive vector represents the key's active state and therefore does not carry
the later frozen compromise-revocation event.

Recovery authority does not imply publishing authority. Implementations MUST
verify the exact W3 profile, resolve the signer to one unambiguous authenticated
operational key, enforce the `trust-bundle` role, validate embedded identity and
lifecycle chains, and reject a revoked or conflicted publisher.

Declared conflicts unrelated to the publisher remain representable under
ADR-007. Undeclared forks and any fork affecting publisher authorization fail
closed.

## Compatibility

This amendment changes no frozen schema, signing domain, canonical bytes,
identity commitment, key-role semantic, or v0.1 behavior.

