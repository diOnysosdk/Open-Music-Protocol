//! Offline identity/trust state machines for OMP v0.2.
//!
//! This W4 crate intentionally does not parse v0.2 wire objects or implement
//! signing domains, canonicalization, signatures, or key generation. It
//! consumes opaque [`ValidatedIdentityDocument`], [`ValidatedLifecycleEvent`],
//! and [`ValidatedTrustBundle`] facts produced by the W2/W3 adapter.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// W4 state-machine or persistence error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Validated facts violate a frozen semantic invariant.
    #[error("OMP_SCHEMA_INVALID: {0}")]
    InvalidFact(String),
    /// Required identity input is missing.
    #[error("OMP_IDENTITY_UNKNOWN")]
    IdentityUnknown,
    /// Required key input is missing.
    #[error("OMP_KEY_UNKNOWN")]
    KeyUnknown,
    /// Threshold or role authorization failed.
    #[error("OMP_KEY_UNAUTHORIZED")]
    KeyUnauthorized,
    /// W3 rejected a signature or commitment.
    #[error("OMP_SIGNATURE_INVALID")]
    SignatureInvalid,
    /// A key is currently revoked.
    #[error("OMP_KEY_REVOKED")]
    KeyRevoked,
    /// Competing valid histories exist.
    #[error("OMP_TRUST_CONFLICT")]
    TrustConflict,
    /// Durable state regressed.
    #[error("OMP_TRUST_ROLLBACK")]
    TrustRollback,
    /// Storage atomicity or integrity is unavailable.
    #[error("trust-state integrity failure: {0}")]
    Integrity(String),
    /// Local state serialization failed.
    #[error("local state serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Operational key facts already authenticated by W2/W3.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct OperationalKeyFact {
    /// Identity-scoped key identifier.
    pub(crate) key_id: String,
    /// Frozen v0.2 roles authenticated in the identity document.
    pub(crate) roles: BTreeSet<String>,
    /// Authenticated Ed25519 public key for W3 adapter use.
    pub(crate) public_key_base64url: String,
}

impl OperationalKeyFact {
    /// Authenticated identity-scoped key identifier.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Whether the authenticated identity document grants `role`.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }

    /// Authenticated unpadded base64url Ed25519 public key.
    pub fn public_key_base64url(&self) -> &str {
        &self.public_key_base64url
    }
}

/// Recovery policy facts already authenticated by W2/W3.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RecoveryPolicyFact {
    /// Required number of distinct valid proofs.
    pub(crate) threshold: usize,
    /// Eligible recovery key IDs.
    pub(crate) key_ids: BTreeSet<String>,
    /// Authenticated public keys by recovery key ID, for W3 adapters.
    pub(crate) public_keys_base64url: BTreeMap<String, String>,
}

/// Complete identity-document facts after W2 schema and W3 crypto validation.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ValidatedIdentityDocument {
    /// SHA-256 of the complete transported object from W3.
    pub(crate) complete_hash: String,
    /// Self-certifying ID already recomputed and checked by W3.
    pub(crate) identity_id: String,
    /// Strict document sequence.
    pub(crate) sequence: u64,
    /// Previous complete-document hash.
    pub(crate) previous_document_hash: Option<String>,
    /// Stable genesis commitment hash.
    pub(crate) genesis_hash: String,
    /// Recovery policy effective for authorizing the successor document.
    pub(crate) recovery: RecoveryPolicyFact,
    /// Operational keys in this state.
    pub(crate) operational_keys: BTreeMap<String, OperationalKeyFact>,
    /// Distinct proof key IDs whose signatures W3 validated over exact bytes.
    pub(crate) valid_proof_keys: BTreeSet<String>,
}

impl ValidatedIdentityDocument {
    /// Authenticated self-certifying identity identifier.
    pub fn identity_id(&self) -> &str {
        &self.identity_id
    }

    /// Authenticated document sequence.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Recovery facts required when validating lifecycle objects.
    pub fn recovery(&self) -> &RecoveryPolicyFact {
        &self.recovery
    }

    /// Look up an authenticated operational key by identity-scoped ID.
    pub fn operational_key(&self, key_id: &str) -> Option<&OperationalKeyFact> {
        self.operational_keys.get(key_id)
    }
}

/// Lifecycle event kind.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleKind {
    /// Activate a key.
    Activate,
    /// Rotate from one key to a successor.
    Rotate,
    /// Revoke a key.
    Revoke,
}

/// Revocation reason.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationReason {
    /// Ordinary supersession.
    Superseded,
    /// Known or suspected compromise.
    Compromised,
    /// Lost key material.
    Lost,
    /// Intentional retirement.
    Retired,
}

/// Complete lifecycle-event facts after W2/W3 validation.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ValidatedLifecycleEvent {
    /// SHA-256 of the complete transported event from W3.
    pub(crate) complete_hash: String,
    /// Controlled identity.
    pub(crate) identity_id: String,
    /// Strict event sequence.
    pub(crate) sequence: u64,
    /// Previous complete-event hash.
    pub(crate) previous_event_hash: Option<String>,
    /// Event kind.
    pub(crate) kind: LifecycleKind,
    /// Affected key.
    pub(crate) key_id: Option<String>,
    /// Rotation successor.
    pub(crate) successor_key_id: Option<String>,
    /// Revocation reason.
    pub(crate) reason: Option<RevocationReason>,
    /// Distinct recovery proof IDs validated by W3.
    pub(crate) valid_proof_keys: BTreeSet<String>,
}

/// Trust bootstrap state.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentityTrust {
    /// Explicitly verified trust.
    Verified,
    /// Explicit TOFU pin, never automatically promoted.
    UnverifiedTofu,
    /// No accepted trust basis.
    Unknown,
}

/// Signature authenticity supplied by W3.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Authenticity {
    /// W3 verified exact signed bytes.
    Valid,
    /// W3 rejected the signature.
    Invalid,
}

/// ADR-013 authorization axis.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Authorization {
    /// Currently role-authorized.
    AuthorizedCurrent,
    /// Independently proven historical authorization.
    AuthorizedHistorical,
    /// Authorization cannot be established.
    AuthorizationUnknown,
    /// Evidence proves lack of authorization.
    Unauthorized,
}

/// Current lifecycle status.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CurrentStatus {
    /// Active on the accepted branch.
    Active,
    /// Revoked by validated lifecycle evidence.
    Revoked,
    /// Competing validated histories exist.
    Conflict,
    /// Current state is unavailable.
    Unknown,
}

/// Trust freshness axis.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Freshness {
    /// Evidence is within its authenticated deadline.
    #[default]
    Fresh,
    /// Evidence is beyond its deadline.
    Stale,
    /// Freshness cannot be established.
    Unknown,
}

/// Playback decision, separate from authorization.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlaybackDecision {
    /// Ordinary allowed playback.
    PlaybackAllowed,
    /// ADR-013 exact pinned-public availability exception.
    PlaybackAllowedPinnedAuthUnknown,
    /// ADR-007 conflicted pinned result.
    ValidConflictedPinned,
    /// ADR-008 stale permanent-subject result.
    ValidStale,
    /// Denied playback.
    PlaybackDenied,
}

/// Separate W4 result axes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationResult {
    /// W3 authenticity result.
    pub authenticity: Authenticity,
    /// W4 role authorization result.
    pub authorization: Authorization,
    /// Local bootstrap trust.
    pub identity_trust: IdentityTrust,
    /// Current lifecycle state.
    pub current_status: CurrentStatus,
    /// Evidence freshness.
    pub freshness: Freshness,
    /// Optional playback decision.
    pub playback: Option<PlaybackDecision>,
}

/// Adapter boundary that W2/W3 must implement before integrated W4 use.
pub trait ValidatedFactProvider: private::Sealed {
    /// W2/W3 parse, validate, canonicalize, authenticate, and convert an
    /// identity document to W4 facts.
    fn identity_document(&self, bytes: &[u8]) -> Result<ValidatedIdentityDocument, Error>;
    /// W2/W3 parse, validate, canonicalize, authenticate, and convert a
    /// lifecycle event to W4 facts.
    fn lifecycle_event(
        &self,
        bytes: &[u8],
        recovery: &RecoveryPolicyFact,
    ) -> Result<ValidatedLifecycleEvent, Error>;
    /// W2/W3 authenticate a portable trust bundle and return validated facts.
    fn trust_bundle(&self, bytes: &[u8]) -> Result<ValidatedTrustBundle, Error>;
}

/// A bundle containing only W2/W3-authenticated W4 inputs.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ValidatedTrustBundle {
    /// Complete bundle hash from W3.
    pub(crate) complete_hash: String,
    /// Authenticated bundle ID.
    pub(crate) bundle_id: String,
    /// Authenticated identity documents.
    pub(crate) identity_documents: Vec<ValidatedIdentityDocument>,
    /// Authenticated lifecycle events.
    pub(crate) lifecycle_events: Vec<ValidatedLifecycleEvent>,
    /// Authenticated declared conflicts.
    pub(crate) conflicts: BTreeSet<(String, u64, Vec<String>)>,
    /// Freshness already evaluated using acceptable time evidence.
    pub(crate) freshness: Freshness,
}

impl ValidatedTrustBundle {
    /// Authenticated bundle identifier.
    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    /// Number of authenticated identity documents carried by the bundle.
    pub fn identity_document_count(&self) -> usize {
        self.identity_documents.len()
    }

    /// Number of authenticated lifecycle events carried by the bundle.
    pub fn lifecycle_event_count(&self) -> usize {
        self.lifecycle_events.len()
    }
}

mod private {
    pub trait Sealed {}
}

fn local_state_hash<T: Serialize>(value: &T) -> Result<String, Error> {
    let bytes = serde_json::to_vec(value)?;
    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

mod chain;
mod integration;
mod store;
mod trust;

pub use chain::{
    detect_identity_forks, detect_lifecycle_forks, validate_identity_chain,
    validate_lifecycle_chain,
};
pub use integration::ProductionFactProvider;
pub use store::{
    update_trust_state, verify_state_progression, DurablePin, MemoryTrustStore, PinOrigin,
    TrustState, TrustStateStore,
};
pub use trust::{
    current_key_status, evaluate_authorization, evaluate_playback, merge_trust_facts,
    AuthorizationInput, HistoricalEvidence, PlaybackInput, TrustFacts,
};

#[cfg(test)]
mod tests;
