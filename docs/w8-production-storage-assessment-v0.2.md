# W8 production storage capability assessment

`TrustStateStore`, `DurablePinStore`, and `TrustedTimeStore` define the required
atomic/integrity/rollback boundaries. No generic file, encrypted file, SQLite,
or hash-chain implementation is labeled production-capable.

Windows candidates require a device/user-bound protected integrity key plus a
TPM-backed monotonic/version assertion or equivalent enterprise capability,
atomic replacement, ACLs, and restore/clone detection. Linux candidates
require an equivalent TPM/secure-element or administered monotonic service;
ordinary keyrings alone do not prove rollback resistance.

When capability is absent, `DurablePinStore::rollback_protection_available`
is false and pin playback fails closed; time-limited grants likewise fail when
the trusted-time store cannot authenticate current high-water state. Public
unrestricted ordinary playback remains offline-capable under its approved
policy. Platform adapters are intentionally deferred pending platform review.

