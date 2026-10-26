# OMP v0.2 external security and compliance review checklist

Status: required before production release. Reviewer identity, scope, version,
date, evidence links, severity, disposition, and owner sign-off must be
recorded for every applicable item.

## Cryptography and canonicalization

- [ ] Verify every domain byte, trailing NUL, excluded top-level member, and
      no-fallback rule against independent implementations.
- [ ] Review RFC 8785 conformance, I-JSON rejection, UTF-16 key ordering,
      IEEE-754 formatting, negative zero, escapes, and invalid Unicode.
- [ ] Review Ed25519 verification, encoding strictness, key generation,
      zeroization, threshold-proof uniqueness, and duplicate signer handling.
- [ ] Confirm identity commitments and complete-event hashes cannot be
      confused across types or versions.
- [ ] Confirm deterministic TEST-ONLY seeds cannot enter production builds.

## Parser and schema boundary

- [ ] Compare Rust semantic validation with every Draft 2020-12 schema.
- [ ] Review recursive duplicate-key rejection and resource/size limits.
- [ ] Test version/object/domain confusion and undeclared extension fields.
- [ ] Review stable error mapping for information leakage and ambiguity.
- [ ] Fuzz all untrusted JSON and base64url entry points.

## Identity, lifecycle, and trust

- [ ] Threat-model bootstrap, explicit TOFU, promotion, impersonation, and
      fingerprint substitution.
- [ ] Review rotation, threshold recovery, root loss/compromise, signer
      uniqueness, fork/equivocation, rollback, and atomic persistence.
- [ ] Confirm historical authenticity remains distinct from current trust.
- [ ] Review bundle merge determinism, provenance semantics, freeze attacks,
      staleness, and publisher capture.
- [ ] Confirm no mandatory resolver, publisher, registry, or network path.

## Trusted time and licensing

- [ ] Review interval boundaries, timezone normalization, signed original
      timestamp preservation, anchor sequence, max age, and authority policy.
- [ ] Test wall-clock/monotonic rollback, suspend/resume, restore/snapshot,
      state loss, leap behavior, and compromised-device limitations.
- [ ] Confirm unavailable acceptable time fails closed only where required.
- [ ] Confirm public unrestricted content remains playable without network,
      login, subject key, freshness refresh, or trusted clock.
- [ ] Confirm user override cannot emit a protocol-valid entitlement result.

## Unicode and filesystem

- [ ] Review NFC detection without pre-verification normalization.
- [ ] Test confusables, bidi controls, noncharacters, controls, separators,
      percent/double encoding, reserved device names, trailing dots/spaces,
      long paths, and case-fold collisions.
- [ ] Review package-root containment on Windows and Linux.
- [ ] Test symlinks, junctions, reparse points, bind mounts where applicable,
      race replacement, hard links, and verify/reopen TOCTOU.
- [ ] Confirm decoder consumes the verified open handle.

## Media and sandboxing

- [ ] Confirm WAV/FLAC fixtures are original/generated and legally documented.
- [ ] Review media type/container sniffing and unsupported-codec behavior.
- [ ] Fuzz decoders separately from signed-object parsers.
- [ ] Review buffer, CPU, memory, duration, nesting, and decompression limits.
- [ ] Review decoder process isolation and platform sandbox profiles.

## Privacy, legal, and accessibility

- [ ] Perform data-protection review of stable identities, subject licenses,
      trust bundles, local library state, and potential listening telemetry.
- [ ] Document data minimization, retention, export, deletion, and backup.
- [ ] Confirm metadata/identity authenticity is never presented as legal
      ownership, copyright, consent, payment, or royalty evidence.
- [ ] Review fixture and dependency copyright/licenses and attribution.
- [ ] Review export/sanctions/cryptography distribution obligations for target
      jurisdictions without embedding a proprietary service requirement.
- [ ] Review user-visible trust/error states for accessibility and safe
      localization, including confusable identity labels.

## Supply chain and operations

- [ ] Produce and review SBOM, dependency licenses, advisories, maintainers,
      source integrity, feature flags, and minimum supported Rust version.
- [ ] Reproduce builds and fixture hashes in clean independent environments.
- [ ] Run secret scanning and prove test keys are excluded from release output.
- [ ] Define vulnerability disclosure, security contacts, update signing,
      incident response, and compromised-release procedures.
- [ ] Verify optional update/network adapters cannot block offline playback.

## Release sign-off

- [ ] Protocol owner confirms the exact schema/vector revision.
- [ ] Independent cryptography reviewer approves signing and identity profiles.
- [ ] Filesystem/Unicode review is complete on Windows and Linux.
- [ ] Privacy/legal review findings are resolved or formally accepted.
- [ ] All critical/high security findings are closed.
- [ ] v0.1 compatibility snapshots and full v0.2 gates pass from a clean tree.
- [ ] Final recommendation and residual-risk statement are published.
