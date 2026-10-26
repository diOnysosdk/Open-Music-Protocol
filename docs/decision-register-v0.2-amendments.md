# OMP v0.2 post-freeze amendment decision register

Baseline: `OMP-v0.2-w0-freeze.1`  
The frozen `docs/decision-register-v0.2.md` is intentionally unchanged.

| Amendment | Date | Disposition | Result |
|---|---|---|---|
| ADR-013 historical key authorization | 2026-10-26 | Provisionally approved | Ordering/threshold authorization and independent durable observations define historical evidence; `AUTHORIZATION_UNKNOWN` is distinct; exact previously verified pinned unrestricted content may return `PLAYBACK_ALLOWED_PINNED_AUTH_UNKNOWN` under the mandatory exclusions. |
| ADR-014 role-authorized trust-bundle vector | 2026-10-26 | Approved | Preserve the frozen `root-01` vector as W3-valid/W4-role-unauthorized; publish a separately versioned positive vector signed by active `media-01`. Recovery authority does not imply `trust-bundle` publishing authority. |

ADR-013 changes no schema, signing payload, canonical bytes, cryptographic
vector, or v0.1 behavior. Controlled W4 implementation is authorized; release
remains subject to independent assurance.

ADR-014 adds only post-freeze documentation, fixtures, and tests. It changes no
frozen artifact or normative wire behavior.
