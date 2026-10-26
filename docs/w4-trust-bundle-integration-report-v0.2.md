# OMP v0.2 W4 portable trust-bundle integration report

Date: 2026-10-26  
Baseline: `OMP-v0.2-w0-freeze.1` plus ADR-013 and ADR-014  
Recommendation: **GO for controlled W4 integration; NO-GO for production release**.

## Disposition

ADR-014 preserves the frozen `root-01` vector as cryptographically valid but
role-unauthorized. The separately versioned positive fixture is signed by
active operational key `media-01`, which has the authenticated `trust-bundle`
role. Recovery authority does not imply publishing authority.

## Integration matrix

| Input | W3 | W4 | Result |
|---|---|---|---|
| Frozen `root-01` vector | Valid | Missing operational role | Reject |
| Amendment `media-01` vector | Valid | Active, role-authorized | Accept |
| Altered signed field | Invalid | Not evaluated | Reject |
| Authenticated role removal | Valid signatures | Role absent | Reject |
| Unknown signer | Not resolvable | Unknown key | Reject |
| `media-01` plus authenticated compromise revocation | Valid | Revoked | Reject |
| Undeclared identity fork | Valid branch proofs | Conflict | Reject |
| Publisher identity fork, even if declared | Valid branch proofs | Ambiguous publisher | Reject |
| Declared unrelated conflict | Valid | Preserved as ADR-007 evidence | Accept as conflict evidence |

Bundle merging is deterministic and independent of arrival order.

## Production boundary

`ProductionFactProvider` is the only implementation of the sealed
`ValidatedFactProvider`. Validated fact fields are crate-private and the types
do not implement deserialization. Public consumers can inspect authenticated
facts through read-only accessors but cannot construct or deserialize values
that state-machine APIs would mistake for W2/W3-validated facts.

## Remaining assurance

- Independent cryptographic and schema-parity review.
- Production secure-storage and anti-rollback implementations per platform.
- Platform crash-consistency and filesystem/symlink assurance.
- External review of identity-fork and historical-authorization policy.

