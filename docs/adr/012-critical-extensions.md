# ADR 012: Critical and noncritical extensions

- Status: Deferred — protocol owner decision 2026-10-26
- Scope: v0.2 extensibility

## Deferred design (non-normative for v0.2)

Only object schemas that explicitly opt in may contain these top-level signed
members:

```json
{
  "extensions": {
    "urn:example:feature:v1": { "...": "..." }
  },
  "critical_extensions": ["urn:example:feature:v1"]
}
```

Rules:

1. Extension identifiers are absolute URI strings, compared byte-for-byte.
   They MUST be NFC, contain no fragment, user information, control character,
   or percent-encoded unreserved character, and MUST NOT require dereferencing.
2. `extensions` is an object with at most 32 members; each value is I-JSON and
   the encoded extension object is at most 64 KiB. Duplicate JSON keys remain
   invalid.
3. `critical_extensions` contains unique identifiers and every entry MUST name
   a present `extensions` member.
4. Every extension remains inside the ordinary signed payload. Verifiers MUST
   preserve its exact parsed value for JCS verification.
5. An unknown critical extension fails with
   `OMP_CRITICAL_EXTENSION_UNSUPPORTED` before the object is used.
6. An unknown noncritical extension may be ignored semantically only after the
   core object and signature validate. It MUST NOT alter, relax, or override a
   core invariant, trust result, asset binding, or license decision.
7. A known extension defines its own version in its URI and validator. Changing
   meaning requires a new URI.
8. Core v0.1 has no extension point and is never widened.

Schemas remain closed. Until each v0.2 schema is amended to declare these two
members, an object containing them is invalid; documentation alone does not
create an extension point.

## Security consequences

Criticality prevents unsafe partial interpretation. Signed noncritical data
supports experimentation but can increase parser and display attack surface;
bounded size/count and core-invariant precedence reduce that risk.

## Required tests

- Known/unknown critical, known/unknown noncritical, missing critical member,
  duplicate identifier, noncanonical URI, oversize/count, tampering, and an
  extension attempting to override a core denial.

## Protocol-owner disposition

Deferred 2026-10-26. The extension envelope is not part of OMP v0.2. Every
v0.2 schema remains strictly closed and every undeclared extension field is
rejected as `OMP_SCHEMA_INVALID`. The design above is retained only as input
to a future protocol version and MUST NOT be implemented as v0.2 behavior.
