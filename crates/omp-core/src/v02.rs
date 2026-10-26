//! Strict frozen OMP v0.2 wire models.

use super::{parse_value, Error, Validate};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use unicode_normalization::UnicodeNormalization;

/// Supported exact wire version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireVersion {
    /// Frozen v0.1 semantics.
    V01,
    /// Frozen v0.2 semantics.
    V02,
}

/// Detect the exact version after duplicate-safe JSON parsing.
pub fn detect_version(input: &[u8]) -> Result<WireVersion, Error> {
    let value = parse_value(input)?;
    match value.get("schema_version").and_then(|item| item.as_str()) {
        Some("0.1") => Ok(WireVersion::V01),
        Some("0.2") => Ok(WireVersion::V02),
        _ => Err(Error::Validation(
            "unsupported or missing schema_version".into(),
        )),
    }
}

/// Parse one explicitly selected v0.2 object type.
///
/// Callers must select the type from context; this function never tries other
/// models after failure.
pub fn parse<T: DeserializeOwned + Validate>(input: &[u8]) -> Result<T, Error> {
    if detect_version(input)? != WireVersion::V02 {
        return Err(Error::Validation("object is not v0.2".into()));
    }
    let model = serde_json::from_value::<T>(parse_value(input)?)?;
    model.validate()?;
    Ok(model)
}

/// Strict Ed25519 envelope used by single-signature objects.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Must be `Ed25519`.
    pub algorithm: String,
    /// Identity-scoped key ID.
    pub key_id: String,
    /// Unpadded base64url signature.
    pub value: String,
}

/// Strict Ed25519 proof used by threshold objects.
pub type Proof = Signature;

/// Embedded public key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    /// Key ID.
    pub key_id: String,
    /// Must be `Ed25519`.
    pub algorithm: String,
    /// Unpadded 32-byte public key.
    pub public_key_base64url: String,
}

/// Recovery threshold definition.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicy {
    /// Required proof count.
    pub threshold: u64,
    /// Eligible distinct key IDs.
    pub key_ids: Vec<String>,
}

/// Immutable genesis commitment body.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenesisBody {
    /// Frozen profile name.
    pub profile: String,
    /// RFC 3339 assertion.
    pub created_at: String,
    /// Root keys.
    pub root_keys: Vec<PublicKey>,
    /// Recovery policy.
    pub recovery: RecoveryPolicy,
}

/// Operational identity key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationalKey {
    /// Key ID.
    pub key_id: String,
    /// Must be `Ed25519`.
    pub algorithm: String,
    /// Unpadded public key.
    pub public_key_base64url: String,
    /// Closed role list.
    pub roles: Vec<String>,
    /// Inclusive validity assertion.
    pub valid_from: String,
    /// Optional exclusive end assertion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

/// Frozen v0.2 identity document.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityDocument {
    /// Exact version.
    pub schema_version: String,
    /// Self-certifying ID.
    pub identity_id: String,
    /// Genesis body.
    pub genesis_body: GenesisBody,
    /// Strict sequence.
    pub sequence: u64,
    /// Previous complete object hash.
    pub previous_document_hash: Option<String>,
    /// RFC 3339 assertion.
    pub issued_at: String,
    /// Operational keys.
    pub operational_keys: Vec<OperationalKey>,
    /// Threshold proofs.
    pub proofs: Vec<Proof>,
}

impl Validate for IdentityDocument {
    fn validate(&self) -> Result<(), Error> {
        v02(&self.schema_version)?;
        party_hash_id(&self.identity_id)?;
        if self.genesis_body.profile != "omp-self-certifying-identity-v0.2" {
            return invalid("invalid genesis profile");
        }
        timestamp(&self.genesis_body.created_at)?;
        timestamp(&self.issued_at)?;
        nonempty(&self.genesis_body.root_keys, "root_keys")?;
        unique_by(&self.genesis_body.root_keys, |key| &key.key_id, "root key")?;
        for key in &self.genesis_body.root_keys {
            public_key(key)?;
        }
        let recovery = &self.genesis_body.recovery;
        if recovery.threshold == 0
            || recovery.threshold as usize > recovery.key_ids.len()
            || !unique(&recovery.key_ids)
            || recovery.key_ids.iter().any(|id| {
                !self
                    .genesis_body
                    .root_keys
                    .iter()
                    .any(|key| &key.key_id == id)
            })
        {
            return invalid("invalid recovery threshold or key_ids");
        }
        if (self.sequence == 0) != self.previous_document_hash.is_none() {
            return invalid("invalid identity sequence linkage");
        }
        if let Some(hash) = &self.previous_document_hash {
            sha256(hash)?;
        }
        nonempty(&self.operational_keys, "operational_keys")?;
        unique_by(&self.operational_keys, |key| &key.key_id, "operational key")?;
        for key in &self.operational_keys {
            operational_key(key)?;
        }
        nonempty(&self.proofs, "proofs")?;
        for proof in &self.proofs {
            proof_value(proof)?;
        }
        Ok(())
    }
}

/// Lifecycle event kind.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LifecycleEventType {
    /// Activation.
    Activate,
    /// Rotation.
    Rotate,
    /// Revocation.
    Revoke,
}

/// Revocation reason.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RevocationReason {
    /// Superseded.
    Superseded,
    /// Compromised.
    Compromised,
    /// Lost.
    Lost,
    /// Retired.
    Retired,
}

/// Frozen v0.2 lifecycle event.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyLifecycleEvent {
    /// Exact version.
    pub schema_version: String,
    /// Event ID.
    pub event_id: String,
    /// Identity ID.
    pub identity_id: String,
    /// Sequence.
    pub sequence: u64,
    /// Previous event hash.
    pub previous_event_hash: Option<String>,
    /// Event kind.
    pub event_type: LifecycleEventType,
    /// Affected key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Successor key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub successor_key_id: Option<String>,
    /// Revocation reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<RevocationReason>,
    /// Retrospective compromise boundary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compromise_from: Option<String>,
    /// Effect assertion.
    pub effective_at: String,
    /// Issuance assertion.
    pub issued_at: String,
    /// Threshold proofs.
    pub proofs: Vec<Proof>,
}

impl Validate for KeyLifecycleEvent {
    fn validate(&self) -> Result<(), Error> {
        v02(&self.schema_version)?;
        prefixed_id(&self.event_id, "omp:key-event:")?;
        party_hash_id(&self.identity_id)?;
        if (self.sequence == 0) != self.previous_event_hash.is_none() {
            return invalid("invalid lifecycle sequence linkage");
        }
        if let Some(hash) = &self.previous_event_hash {
            sha256(hash)?;
        }
        match self.event_type {
            LifecycleEventType::Rotate
                if self.key_id.is_none() || self.successor_key_id.is_none() =>
            {
                return invalid("rotate requires key_id and successor_key_id")
            }
            LifecycleEventType::Revoke if self.key_id.is_none() || self.reason.is_none() => {
                return invalid("revoke requires key_id and reason")
            }
            _ => {}
        }
        if self.compromise_from.is_some()
            && (self.event_type != LifecycleEventType::Revoke
                || self.reason != Some(RevocationReason::Compromised))
        {
            return invalid("compromise_from requires compromised revoke");
        }
        timestamp(&self.effective_at)?;
        timestamp(&self.issued_at)?;
        if let Some(value) = &self.compromise_from {
            timestamp(value)?;
        }
        nonempty(&self.proofs, "proofs")?;
        for proof in &self.proofs {
            proof_value(proof)?;
        }
        Ok(())
    }
}

/// Artist display credit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtistCredit {
    /// Signed display name.
    pub display_name: String,
    /// Optional identity reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// Optional join phrase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_phrase: Option<String>,
}

/// Contributor credit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Contributor {
    /// Credit-local ID.
    pub credit_id: String,
    /// Signed display name.
    pub display_name: String,
    /// Optional identity reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// Closed role tokens.
    pub roles: Vec<String>,
    /// Optional instrument display text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instrument: Option<String>,
}

/// Release metadata.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseMetadata {
    /// Optional release reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    /// Release title.
    pub title: String,
    /// Release type.
    pub release_type: String,
    /// Partial ISO date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_date: Option<String>,
    /// Optional label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_name: Option<String>,
    /// Optional catalog number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_number: Option<String>,
    /// Track number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_number: Option<u64>,
    /// Track total.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_total: Option<u64>,
    /// Disc number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disc_number: Option<u64>,
    /// Disc total.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disc_total: Option<u64>,
}

/// Structured v0.2 descriptive metadata.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    /// Canonical title.
    pub title: String,
    /// Optional subtitle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    /// Optional version label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_label: Option<String>,
    /// Optional BCP 47 language.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Closed role vocabulary identifier.
    pub role_vocabulary: String,
    /// Ordered artist credits.
    pub artist_credits: Vec<ArtistCredit>,
    /// Ordered contributors.
    pub contributors: Vec<Contributor>,
    /// Optional release data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseMetadata>,
}

/// Deterministic manifest asset.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    /// Local asset ID.
    pub asset_id: String,
    /// Portable package-relative path.
    pub relative_path: String,
    /// Primary, alternate, or preview.
    pub role: String,
    /// Globally unique selection rank.
    pub selection_rank: u64,
    /// Allowlisted media type.
    pub media_type: String,
    /// Exact SHA-256.
    pub sha256: String,
    /// Exact size.
    pub size_bytes: u64,
}

/// Frozen v0.2 manifest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Exact version.
    pub schema_version: String,
    /// Manifest ID.
    pub manifest_id: String,
    /// Recording ID.
    pub recording_id: String,
    /// Work ID.
    pub work_id: String,
    /// Optional release ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    /// Issuer reference.
    pub issuer_id: String,
    /// Signed metadata.
    pub metadata: Metadata,
    /// Bound assets.
    pub assets: Vec<Asset>,
    /// Agreement ID.
    pub agreement_id: String,
    /// License ID.
    pub license_id: String,
    /// Creation assertion.
    pub created_at: String,
    /// Signature.
    pub signature: Signature,
}

impl Validate for Manifest {
    fn validate(&self) -> Result<(), Error> {
        v02(&self.schema_version)?;
        typed_id(&self.manifest_id, "manifest")?;
        typed_id(&self.recording_id, "recording")?;
        typed_id(&self.work_id, "work")?;
        if let Some(value) = &self.release_id {
            typed_id(value, "release")?;
        }
        identity_reference(&self.issuer_id)?;
        typed_id(&self.agreement_id, "agreement")?;
        typed_id(&self.license_id, "license")?;
        timestamp(&self.created_at)?;
        metadata(&self.metadata)?;
        if self.assets.is_empty() || self.assets.len() > 256 {
            return invalid("asset count");
        }
        let mut ids = HashSet::new();
        let mut paths = HashSet::new();
        let mut ranks = HashSet::new();
        let mut primary = 0;
        for asset in &self.assets {
            token(&asset.asset_id, 128)?;
            portable_path(&asset.relative_path)?;
            if !ids.insert(&asset.asset_id)
                || !paths.insert(&asset.relative_path)
                || !ranks.insert(asset.selection_rank)
            {
                return invalid("duplicate asset id, path, or rank");
            }
            if asset.role == "primary" {
                primary += 1;
            }
            if !matches!(asset.role.as_str(), "primary" | "alternate" | "preview") {
                return invalid("invalid asset role");
            }
            if !matches!(
                asset.media_type.as_str(),
                "audio/flac" | "audio/mpeg" | "audio/ogg" | "audio/wav" | "audio/mp4"
            ) {
                return invalid("invalid media type");
            }
            sha256(&asset.sha256)?;
            if asset.size_bytes == 0 {
                return invalid("zero asset size");
            }
        }
        if primary != 1 {
            return invalid("exactly one primary asset required");
        }
        signature(&self.signature, false)
    }
}

/// Offline policy kind.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OfflinePolicy {
    /// Permanent offline grant.
    Permanent,
    /// Time-limited grant requiring trusted time.
    TimeLimited {
        /// Must be `trusted_time`.
        clock_requirement: String,
    },
}

/// Frozen v0.2 license.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct License {
    /// Exact version.
    pub schema_version: String,
    /// License ID.
    pub license_id: String,
    /// Recording ID.
    pub recording_id: String,
    /// Optional subject ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    /// Public or subject audience.
    pub audience: String,
    /// Free, purchase, or subscription.
    pub mode: String,
    /// Offline flag.
    pub offline: bool,
    /// Explicit offline policy.
    pub offline_policy: OfflinePolicy,
    /// Inclusive start.
    pub valid_from: String,
    /// Optional exclusive expiry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Issuer identity.
    pub issuer_id: String,
    /// Signature.
    pub signature: Signature,
}

impl Validate for License {
    fn validate(&self) -> Result<(), Error> {
        v02(&self.schema_version)?;
        typed_id(&self.license_id, "license")?;
        typed_id(&self.recording_id, "recording")?;
        typed_id(&self.issuer_id, "party")?;
        if let Some(subject) = &self.subject_id {
            party_hash_id(subject)?;
        }
        let from = timestamp(&self.valid_from)?;
        let expiry = self.expires_at.as_deref().map(timestamp).transpose()?;
        if expiry.is_some_and(|value| value <= from) {
            return invalid("license interval");
        }
        match &self.offline_policy {
            OfflinePolicy::Permanent if expiry.is_some() => {
                return invalid("permanent license has expiry")
            }
            OfflinePolicy::TimeLimited { clock_requirement }
                if clock_requirement != "trusted_time" || expiry.is_none() =>
            {
                return invalid("invalid time-limited policy")
            }
            _ => {}
        }
        if self.audience == "public" {
            if self.subject_id.is_some()
                || self.mode != "free"
                || !self.offline
                || !matches!(self.offline_policy, OfflinePolicy::Permanent)
            {
                return invalid("invalid public license");
            }
        } else if self.audience == "subject" {
            if self.subject_id.is_none() {
                return invalid("subject license missing subject");
            }
        } else {
            return invalid("invalid audience");
        }
        if !matches!(self.mode.as_str(), "free" | "purchase" | "subscription") {
            return invalid("invalid mode");
        }
        if self.mode == "subscription"
            && !matches!(self.offline_policy, OfflinePolicy::TimeLimited { .. })
        {
            return invalid("subscription must expire");
        }
        signature_unbounded(&self.signature)
    }
}

/// Frozen v0.2 time anchor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TimeAnchor {
    /// Exact version.
    pub schema_version: String,
    /// Anchor ID.
    pub anchor_id: String,
    /// Authority identity.
    pub authority_id: String,
    /// Sequence.
    pub sequence: u64,
    /// Observed time assertion.
    pub observed_at: String,
    /// Issued time assertion.
    pub issued_at: String,
    /// Maximum age.
    pub max_age_seconds: u64,
    /// Optional predecessor hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_anchor_hash: Option<String>,
    /// Signature.
    pub signature: Signature,
}

impl Validate for TimeAnchor {
    fn validate(&self) -> Result<(), Error> {
        v02(&self.schema_version)?;
        prefixed_id(&self.anchor_id, "omp:time-anchor:")?;
        party_hash_id(&self.authority_id)?;
        timestamp(&self.observed_at)?;
        timestamp(&self.issued_at)?;
        if !(1..=31_536_000).contains(&self.max_age_seconds) {
            return invalid("max_age_seconds");
        }
        if let Some(v) = &self.previous_anchor_hash {
            sha256(v)?;
        }
        signature(&self.signature, true)
    }
}

/// Legacy trust binding.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyBinding {
    /// Issuer ID.
    pub issuer_id: String,
    /// Key ID.
    pub key_id: String,
    /// Algorithm.
    pub algorithm: String,
    /// Public key.
    pub public_key_base64url: String,
    /// Roles.
    pub roles: Vec<String>,
    /// Optional start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    /// Optional end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    /// Provenance label.
    pub provenance: String,
}

/// Explicit conflict record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Conflict {
    /// Identity ID.
    pub identity_id: String,
    /// Sequence.
    pub sequence: u64,
    /// Competing hashes.
    pub document_hashes: Vec<String>,
}

/// Bundle provenance entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// Publisher ID.
    pub publisher_id: String,
    /// Creation assertion.
    pub created_at: String,
    /// Content hash.
    pub content_hash: String,
    /// Signature.
    pub signature: Proof,
}

/// Frozen v0.2 portable trust bundle.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustBundle {
    /// Version.
    pub schema_version: String,
    /// Profile.
    pub profile: String,
    /// Bundle ID.
    pub bundle_id: String,
    /// Creation assertion.
    pub created_at: String,
    /// Optional deadline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update_at: Option<String>,
    /// Identities.
    pub identity_documents: Vec<IdentityDocument>,
    /// Lifecycle events.
    pub lifecycle_events: Vec<KeyLifecycleEvent>,
    /// Legacy bindings.
    pub legacy_bindings: Vec<LegacyBinding>,
    /// Conflicts.
    pub conflicts: Vec<Conflict>,
    /// Provenance.
    pub provenance: Vec<Provenance>,
    /// Publisher signatures.
    pub signatures: Vec<Proof>,
}

impl Validate for TrustBundle {
    fn validate(&self) -> Result<(), Error> {
        v02(&self.schema_version)?;
        if self.profile != "omp-offline-trust-bundle-v0.2" {
            return invalid("bundle profile");
        }
        prefixed_id(&self.bundle_id, "omp:trust-bundle:")?;
        timestamp(&self.created_at)?;
        if let Some(v) = &self.next_update_at {
            timestamp(v)?;
        }
        for v in &self.identity_documents {
            v.validate()?;
        }
        for v in &self.lifecycle_events {
            v.validate()?;
        }
        for v in &self.legacy_bindings {
            typed_id(&v.issuer_id, "party")?;
            key_id(&v.key_id)?;
            if v.algorithm != "Ed25519" || !base64url(&v.public_key_base64url, Some(43)) {
                return invalid("legacy key");
            }
            let legacy_roles = [
                "manifest",
                "license",
                "rights",
                "settlement",
                "receipt",
                "trust-bundle",
                "time-anchor",
            ];
            if v.roles.is_empty()
                || !unique(&v.roles)
                || v.roles
                    .iter()
                    .any(|role| !legacy_roles.contains(&role.as_str()))
            {
                return invalid("legacy roles");
            }
            if !matches!(
                v.provenance.as_str(),
                "user-pinned" | "publisher-signed" | "local-policy"
            ) {
                return invalid("legacy provenance");
            }
            if let Some(t) = &v.valid_from {
                timestamp(t)?;
            }
            if let Some(t) = &v.valid_until {
                timestamp(t)?;
            }
        }
        for v in &self.conflicts {
            party_hash_id(&v.identity_id)?;
            if v.document_hashes.len() < 2 || !unique(&v.document_hashes) {
                return invalid("conflict hashes");
            }
            for h in &v.document_hashes {
                sha256(h)?;
            }
        }
        for v in &self.provenance {
            typed_id(&v.publisher_id, "party")?;
            timestamp(&v.created_at)?;
            sha256(&v.content_hash)?;
            proof_value(&v.signature)?;
        }
        nonempty(&self.signatures, "signatures")?;
        for v in &self.signatures {
            proof_value(v)?;
        }
        Ok(())
    }
}

fn metadata(v: &Metadata) -> Result<(), Error> {
    display(&v.title)?;
    for x in [&v.subtitle, &v.version_label].into_iter().flatten() {
        display(x)?;
    }
    if let Some(l) = &v.language {
        let mut parts = l.split('-');
        let first = parts.next().unwrap_or_default();
        if l.len() < 2
            || l.len() > 63
            || first.len() < 2
            || first.len() > 8
            || !first.bytes().all(|byte| byte.is_ascii_alphabetic())
            || !parts.all(|p| {
                !p.is_empty() && p.len() <= 8 && p.bytes().all(|b| b.is_ascii_alphanumeric())
            })
        {
            return invalid("language");
        }
    }
    if v.role_vocabulary != "omp-contributor-roles-v0.2"
        || v.artist_credits.is_empty()
        || v.artist_credits.len() > 128
        || v.contributors.len() > 1024
    {
        return invalid("metadata cardinality");
    }
    for a in &v.artist_credits {
        display(&a.display_name)?;
        if let Some(i) = &a.identity {
            identity_reference(i)?;
        }
        if let Some(j) = &a.join_phrase {
            nfc(j)?;
            if j.chars().count() > 64 {
                return invalid("join phrase");
            }
        }
    }
    let roles = [
        "primary_artist",
        "featured_artist",
        "performer",
        "vocalist",
        "instrumentalist",
        "composer",
        "lyricist",
        "producer",
        "engineer",
        "mixer",
        "mastering_engineer",
    ];
    let mut ids = HashSet::new();
    for c in &v.contributors {
        token(&c.credit_id, 128)?;
        if !ids.insert(&c.credit_id) {
            return invalid("duplicate credit_id");
        }
        display(&c.display_name)?;
        if let Some(i) = &c.identity {
            identity_reference(i)?;
        }
        if c.roles.is_empty()
            || c.roles.len() > 32
            || !unique(&c.roles)
            || c.roles.iter().any(|r| !roles.contains(&r.as_str()))
        {
            return invalid("contributor roles");
        }
        if let Some(i) = &c.instrument {
            display(i)?;
        }
    }
    if let Some(r) = &v.release {
        display(&r.title)?;
        if !matches!(
            r.release_type.as_str(),
            "single" | "ep" | "album" | "compilation" | "mixtape" | "soundtrack" | "other"
        ) {
            return invalid("release type");
        }
        if let Some(x) = &r.release_id {
            identity_reference(x)?;
        }
        if let Some(x) = &r.label_name {
            display(x)?;
        }
        if let Some(x) = &r.catalog_number {
            nfc(x)?;
            if x.is_empty() || x.len() > 128 {
                return invalid("catalog number");
            }
        }
        if let Some(date) = &r.release_date {
            let bytes = date.as_bytes();
            let valid = matches!(bytes.len(), 4 | 7 | 10)
                && bytes.iter().enumerate().all(|(index, byte)| {
                    if index == 4 || index == 7 {
                        *byte == b'-'
                    } else {
                        byte.is_ascii_digit()
                    }
                });
            if !valid {
                return invalid("release date");
            }
        }
        for (n, t) in [
            (r.track_number, r.track_total),
            (r.disc_number, r.disc_total),
        ] {
            if n.is_some_and(|x| x == 0)
                || t.is_some_and(|x| x == 0)
                || matches!((n,t),(Some(a),Some(b)) if a>b)
            {
                return invalid("release numbering");
            }
        }
    }
    Ok(())
}
fn operational_key(v: &OperationalKey) -> Result<(), Error> {
    key_id(&v.key_id)?;
    if v.algorithm != "Ed25519" || !base64url(&v.public_key_base64url, Some(43)) {
        return invalid("operational key");
    }
    let roles = [
        "manifest",
        "license",
        "rights",
        "trust-bundle",
        "time-anchor",
        "identity-update",
    ];
    if v.roles.is_empty()
        || !unique(&v.roles)
        || v.roles.iter().any(|r| !roles.contains(&r.as_str()))
    {
        return invalid("operational roles");
    }
    let from = timestamp(&v.valid_from)?;
    if let Some(until) = &v.valid_until {
        if from >= timestamp(until)? {
            return invalid("key interval");
        }
    }
    Ok(())
}
fn public_key(v: &PublicKey) -> Result<(), Error> {
    key_id(&v.key_id)?;
    if v.algorithm != "Ed25519" || !base64url(&v.public_key_base64url, Some(43)) {
        return invalid("public key");
    }
    Ok(())
}
fn signature(v: &Signature, exact: bool) -> Result<(), Error> {
    if v.algorithm != "Ed25519"
        || v.key_id.is_empty()
        || v.key_id.len() > 512
        || !base64url(&v.value, if exact { Some(86) } else { None })
    {
        return invalid("signature");
    }
    Ok(())
}
fn signature_unbounded(v: &Signature) -> Result<(), Error> {
    if v.algorithm != "Ed25519" || v.key_id.is_empty() || !base64url(&v.value, None) {
        return invalid("signature");
    }
    Ok(())
}
fn proof_value(v: &Proof) -> Result<(), Error> {
    key_id(&v.key_id)?;
    signature(v, true)
}
fn portable_path(v: &str) -> Result<(), Error> {
    nfc(v)?;
    if v.is_empty()
        || v.chars().count() > 1024
        || v.starts_with('/')
        || v.contains(['\\', ':', '%'])
        || v.chars().any(|c| c < ' ' || c == '\u{7f}')
        || v.split('/')
            .any(|s| s.is_empty() || s == "." || s == ".." || s.ends_with([' ', '.']))
    {
        return invalid("portable path");
    }
    Ok(())
}
fn display(v: &str) -> Result<(), Error> {
    nfc(v)?;
    if v.is_empty() || v.chars().count() > 1024 || !v.chars().any(|c| !c.is_whitespace()) {
        return invalid("display text");
    }
    Ok(())
}
fn nfc(v: &str) -> Result<(), Error> {
    if v.nfc().ne(v.chars()) {
        return invalid("non-NFC string");
    }
    Ok(())
}
fn timestamp(v: &str) -> Result<OffsetDateTime, Error> {
    OffsetDateTime::parse(v, &Rfc3339)
        .map_err(|_| Error::Validation("invalid RFC3339 timestamp".into()))
}
fn v02(v: &str) -> Result<(), Error> {
    if v != "0.2" {
        return invalid("schema_version");
    }
    Ok(())
}
fn typed_id(v: &str, kind: &str) -> Result<(), Error> {
    prefixed_id(v, &format!("omp:{kind}:"))
}
fn party_hash_id(v: &str) -> Result<(), Error> {
    if !v.starts_with("omp:party:sha256-") || !is_lower_hex(&v[17..], 64) {
        return invalid("identity id");
    }
    Ok(())
}
fn identity_reference(v: &str) -> Result<(), Error> {
    nfc(v)?;
    if v.is_empty() || v.chars().count() > 512 {
        return invalid("identity reference");
    }
    Ok(())
}
fn prefixed_id(v: &str, prefix: &str) -> Result<(), Error> {
    let Some(rest) = v.strip_prefix(prefix) else {
        return invalid("identifier prefix");
    };
    token_min(rest, 3, 128)
}
fn token_min(v: &str, min: usize, max: usize) -> Result<(), Error> {
    token(v, max)?;
    if v.len() < min {
        return invalid("token too short");
    }
    Ok(())
}
fn token(v: &str, max: usize) -> Result<(), Error> {
    if v.is_empty()
        || v.len() > max
        || !v.as_bytes()[0].is_ascii_lowercase() && !v.as_bytes()[0].is_ascii_digit()
        || !v.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
    {
        return invalid("token");
    }
    Ok(())
}
fn key_id(v: &str) -> Result<(), Error> {
    token(v, 128)
}
fn sha256(v: &str) -> Result<(), Error> {
    if !is_lower_hex(v, 64) {
        return invalid("sha256");
    }
    Ok(())
}
fn is_lower_hex(v: &str, n: usize) -> bool {
    v.len() == n
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn base64url(v: &str, len: Option<usize>) -> bool {
    len.map_or(true, |n| v.len() == n)
        && !v.is_empty()
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
fn unique<T: std::hash::Hash + Eq>(v: &[T]) -> bool {
    let mut s = HashSet::new();
    v.iter().all(|x| s.insert(x))
}
fn unique_by<'a, T, K: std::hash::Hash + Eq + ?Sized + 'a>(
    v: &'a [T],
    f: impl Fn(&'a T) -> &'a K,
    name: &str,
) -> Result<(), Error> {
    let mut s = HashSet::new();
    if v.iter().all(|x| s.insert(f(x))) {
        Ok(())
    } else {
        invalid(&format!("duplicate {name}"))
    }
}
fn nonempty<T>(v: &[T], name: &str) -> Result<(), Error> {
    if v.is_empty() {
        invalid(&format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}
fn invalid<T>(message: &str) -> Result<T, Error> {
    Err(Error::Validation(message.into()))
}
