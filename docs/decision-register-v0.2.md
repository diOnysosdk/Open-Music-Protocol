# OMP v0.2 decision register

Frozen revision: `OMP-v0.2-w0-freeze.1`  
Decision date: 2026-10-26

| Decision | Disposition | Normative result |
|---|---|---|
| ADR-007 identity forks | Approved | Exact previously authenticated, pinned unrestricted artifacts may return `VALID_CONFLICTED_PINNED`; new artifacts and non-public entitlements fail closed. |
| ADR-008 stale trust | Approved | Previously verified and pinned permanent subject licenses may return `VALID_STALE`; the state is never presented as fresh. |
| ADR-009 subscriptions | Approved | Every subscription is subject-bound, explicitly time-limited, and has an exclusive expiry. |
| ADR-010 trusted time | Approved | Conservative evidence-interval evaluation and durable rollback protection apply; time-limited access fails closed without acceptable evidence. |
| ADR-011 metadata localization | Approved | v0.2 carries one canonical NFC metadata presentation; localized alternatives and implicit locale fallback are deferred. |
| ADR-012 extensions | Deferred | v0.2 schemas remain strictly closed. Every undeclared extension member is `OMP_SCHEMA_INVALID`; no critical/noncritical extension envelope exists in v0.2. |

These decisions do not alter v0.1 signed bytes or validation. They do not make
cryptographic authenticity evidence of legal identity or ownership.

## Remaining protocol-owner decision

The older accepted identity/trust ADRs do not map each signed object type to
the timestamp used for historical signing-key validity. Because a signer-
controlled timestamp may be backdated, this security-sensitive rule cannot be
inferred from field names. W4 identity/trust implementation is blocked until
the owner approves that mapping. This does not change the frozen schemas,
signing domains, canonical bytes, or W1/W2/W3 readiness.
