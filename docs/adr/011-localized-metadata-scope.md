# ADR 011: Localized metadata scope

- Status: Normative proposal — owner approval required
- Scope: v0.2 descriptive metadata
- Depends on: ADR-003

## Proposed normative decision

OMP v0.2 carries one canonical metadata presentation per manifest. The
existing optional BCP 47 `language` applies to human-language recording title,
subtitle, and version label in that metadata object. Artist/contributor names,
label names, catalog identifiers, and join phrases remain exact signed display
strings and are not automatically translated.

Localized alternate titles, credit names, transliterations, and sort names are
deferred to a future closed schema or noncritical extension. Implementations
MUST NOT infer localization from the user's locale, rewrite signed strings, or
select one of multiple undeclared language variants.

Every applicable signed string MUST already be Unicode NFC. Validation rejects
non-NFC; it never normalizes before signature verification. User interfaces
MUST escape text and SHOULD distinguish identity verification from display
names because authenticated metadata is not legal ownership evidence.

## Rationale

A full localization model needs fallback, transliteration, duplicate-language,
and field-addressing rules. Adding a partial map now would create incompatible
selection behavior. One explicit presentation is deterministic and matches the
current approved schema.

## Required tests

- BCP 47 acceptance/rejection, NFC/non-NFC pairs, confusable display strings,
  and proof that UI locale does not change canonical or signing bytes.

## Owner approval required

Approve deferral of localized alternatives beyond the single canonical v0.2
presentation. Safest default: no implicit language fallback in core v0.2.

