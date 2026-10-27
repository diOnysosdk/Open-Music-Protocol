//! Stable, non-normative diagnostic categories for developer tooling.
//!
//! These labels do not replace or reinterpret frozen protocol error codes.

/// Broad failure class suitable for logs and automation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticCategory {
    /// Command syntax or a required local input is invalid.
    Usage,
    /// JSON, schema, path, or media structure is malformed.
    MalformedContent,
    /// Cryptographic authentication failed.
    InvalidSignature,
    /// A key is unknown, revoked, conflicted, or lacks the required role.
    UnauthorizedKey,
    /// A license is invalid or does not grant the requested operation.
    InvalidLicense,
    /// Required trusted time is missing, stale, or rolled back.
    UntrustedTime,
    /// Local I/O, decoding, or another operational dependency failed.
    Operational,
}

impl DiagnosticCategory {
    /// Stable ASCII identifier. Identifiers are additive and not wire errors.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Usage => "OMP-DIAG-USAGE",
            Self::MalformedContent => "OMP-DIAG-MALFORMED-CONTENT",
            Self::InvalidSignature => "OMP-DIAG-INVALID-SIGNATURE",
            Self::UnauthorizedKey => "OMP-DIAG-UNAUTHORIZED-KEY",
            Self::InvalidLicense => "OMP-DIAG-INVALID-LICENSE",
            Self::UntrustedTime => "OMP-DIAG-UNTRUSTED-TIME",
            Self::Operational => "OMP-DIAG-OPERATIONAL",
        }
    }

    /// Short recovery guidance that does not weaken validation.
    pub const fn action(self) -> &'static str {
        match self {
            Self::Usage => "check command usage and required file paths",
            Self::MalformedContent => "validate the unchanged input against the matching OMP schema",
            Self::InvalidSignature => "obtain authentic bytes and the expected public key; do not re-sign received content",
            Self::UnauthorizedKey => "check the trusted identity history, key role, status, and local trust policy",
            Self::InvalidLicense => "check license binding, audience, offline policy, and validity interval",
            Self::UntrustedTime => "provide fresh authenticated time and rollback-resistant persisted state",
            Self::Operational => "check local files, platform support, resource limits, and decoder diagnostics",
        }
    }
}

/// Conservatively classify an existing error message without changing it.
pub fn classify_message(message: &str) -> DiagnosticCategory {
    let value = message.to_ascii_lowercase();
    if value.contains("trusted_time")
        || value.contains("trusted time")
        || value.contains("rollback")
    {
        DiagnosticCategory::UntrustedTime
    } else if value.contains("signature") || value.contains("ed25519") {
        DiagnosticCategory::InvalidSignature
    } else if value.contains("unauthorized")
        || value.contains("key_unknown")
        || value.contains("key_revoked")
        || value.contains("trust_conflict")
        || value.contains("key_id")
    {
        DiagnosticCategory::UnauthorizedKey
    } else if value.contains("invalid json")
        || value.contains("schema")
        || value.contains("validation failed")
        || value.contains("path_invalid")
        || value.contains("media_type_invalid")
        || value.contains("asset does not match")
    {
        DiagnosticCategory::MalformedContent
    } else if value.contains("license")
        || value.contains("offline_not_allowed")
        || value.contains("subject_mismatch")
        || value.contains("not_yet_valid")
        || value.contains("expired")
    {
        DiagnosticCategory::InvalidLicense
    } else if value.contains("unknown command")
        || value.contains("unknown option")
        || value.contains("requires")
        || value.contains("takes no positional")
        || value.contains("unsupported short option")
    {
        DiagnosticCategory::Usage
    } else {
        DiagnosticCategory::Operational
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_distinctions_are_stable() {
        assert_eq!(
            classify_message("invalid JSON"),
            DiagnosticCategory::MalformedContent
        );
        assert_eq!(
            classify_message("Ed25519 signature verification failed"),
            DiagnosticCategory::InvalidSignature
        );
        assert_eq!(
            classify_message("OMP_KEY_UNAUTHORIZED"),
            DiagnosticCategory::UnauthorizedKey
        );
        assert_eq!(
            classify_message("OMP_LICENSE_EXPIRED"),
            DiagnosticCategory::InvalidLicense
        );
        assert_eq!(
            classify_message("OMP_TRUSTED_TIME_UNAVAILABLE"),
            DiagnosticCategory::UntrustedTime
        );
    }
}
