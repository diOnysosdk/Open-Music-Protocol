//! Pure offline license and trusted-time decisions for OMP v0.2.
//!
//! Signature authenticity, W4 authorization/trust, entitlement, and legal
//! ownership remain separate concepts. No API consults a network or ordinary
//! wall clock.

#![deny(missing_docs)]

use ed25519_dalek::VerifyingKey;
use omp_core::v02::{self, License, OfflinePolicy, TimeAnchor};
use omp_crypto::{canonical_object_sha256, verify_v02, V02Profile};
use omp_identity::{
    Authorization, CurrentStatus, Freshness, IdentityTrust, PlaybackDecision, VerificationResult,
};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

/// Deterministic W6 denial or validation reason.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// W2 rejected the object.
    #[error("OMP_SCHEMA_INVALID: {0}")]
    Schema(String),
    /// W3 rejected the exact signing profile.
    #[error("OMP_SIGNATURE_INVALID")]
    SignatureInvalid,
    /// The signer is not authorized for the required role.
    #[error("OMP_KEY_UNAUTHORIZED")]
    Unauthorized,
    /// The known signer is revoked.
    #[error("OMP_KEY_REVOKED")]
    Revoked,
    /// Identity history is conflicted.
    #[error("OMP_TRUST_CONFLICT")]
    Conflict,
    /// Required trust evidence is stale.
    #[error("OMP_TRUST_STALE")]
    TrustStale,
    /// Trust identity is unknown or TOFU-only.
    #[error("OMP_IDENTITY_UNKNOWN")]
    TrustUnknown,
    /// The license does not bind the requested recording or manifest license.
    #[error("OMP_LICENSE_BINDING_INVALID")]
    BindingMismatch,
    /// The configured subject does not match.
    #[error("OMP_LICENSE_SUBJECT_MISMATCH")]
    SubjectMismatch,
    /// Offline playback is not granted.
    #[error("OMP_OFFLINE_NOT_ALLOWED")]
    OfflineDenied,
    /// Acceptable trusted-time evidence is absent or too old.
    #[error("OMP_TRUSTED_TIME_UNAVAILABLE")]
    TrustedTimeUnavailable,
    /// Trusted-time state regressed.
    #[error("OMP_TRUSTED_TIME_ROLLBACK")]
    TrustedTimeRollback,
    /// Evaluation is wholly before the inclusive start.
    #[error("OMP_LICENSE_NOT_YET_VALID")]
    NotYetValid,
    /// Evaluation touches or crosses the exclusive expiry.
    #[error("OMP_LICENSE_EXPIRED")]
    Expired,
}

/// Opaque W2-valid, W3-authenticated license.
pub struct AuthenticatedLicense {
    license: License,
}

impl AuthenticatedLicense {
    /// Parse and verify the exact v0.2 license profile. Authorization is a
    /// separate W4 input to [`evaluate`].
    pub fn parse_and_verify(bytes: &[u8], key: &VerifyingKey) -> Result<Self, Error> {
        let license = v02::parse::<License>(bytes).map_err(|e| Error::Schema(e.to_string()))?;
        let value = serde_json::to_value(&license).map_err(|e| Error::Schema(e.to_string()))?;
        verify_v02(V02Profile::License, &value, &license.signature.value, key)
            .map_err(|_| Error::SignatureInvalid)?;
        Ok(Self { license })
    }
}

/// Opaque W2-valid, W3-authenticated time anchor.
pub struct AuthenticatedTimeAnchor {
    anchor: TimeAnchor,
    complete_hash: String,
}

impl AuthenticatedTimeAnchor {
    /// Parse and verify the exact time-anchor profile. The caller must still
    /// supply W4 authority trust when accepting the anchor.
    pub fn parse_and_verify(bytes: &[u8], key: &VerifyingKey) -> Result<Self, Error> {
        let anchor = v02::parse::<TimeAnchor>(bytes).map_err(|e| Error::Schema(e.to_string()))?;
        let value = serde_json::to_value(&anchor).map_err(|e| Error::Schema(e.to_string()))?;
        verify_v02(V02Profile::TimeAnchor, &value, &anchor.signature.value, key)
            .map_err(|_| Error::SignatureInvalid)?;
        let complete_hash =
            canonical_object_sha256(&anchor).map_err(|e| Error::Schema(e.to_string()))?;
        Ok(Self {
            anchor,
            complete_hash,
        })
    }
}

/// Explicit W4 result axes supplied to W6.
#[derive(Clone, Copy, Debug)]
pub struct TrustAssessment {
    /// Role authorization result.
    authorization: Authorization,
    /// Current key/identity status.
    current_status: CurrentStatus,
    /// Identity bootstrap trust.
    identity_trust: IdentityTrust,
    /// Available trust freshness.
    freshness: Freshness,
    /// Narrow W4 playback exception, if independently established.
    playback: Option<PlaybackDecision>,
}

impl TrustAssessment {
    /// Import the separate W4 result axes without reinterpreting authenticity
    /// as authorization.
    pub fn from_w4(result: &VerificationResult) -> Self {
        Self {
            authorization: result.authorization(),
            current_status: result.current_status(),
            identity_trust: result.identity_trust(),
            freshness: result.freshness(),
            playback: result.playback(),
        }
    }

    /// Import an opaque W4 durable-pin assessment. This is intentionally the
    /// same representation and never upgrades unknown authorization.
    pub fn from_pinned_w4(result: &VerificationResult) -> Self {
        Self::from_w4(result)
    }
}

/// Persistable high-water trusted-time state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedTimeState {
    sequence: u64,
    anchor_hash: String,
    lower_unix_seconds: i64,
    monotonic_origin: u64,
    max_age_seconds: u64,
    uncertainty_seconds: u64,
}

/// Platform-persisted checkpoint. A store implementation must authenticate it
/// and provide genuine rollback resistance; a hash chain alone is insufficient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedTimeCheckpoint {
    /// Highest accepted anchor sequence.
    pub sequence: u64,
    /// Complete hash of that anchor.
    pub anchor_hash: String,
    /// Durable high-water lower bound in Unix seconds.
    pub lower_unix_seconds: i64,
    /// Monotonic reading paired with the anchor observation.
    pub monotonic_origin: u64,
    /// Signed maximum age.
    pub max_age_seconds: u64,
    /// Conservative configured uncertainty.
    pub uncertainty_seconds: u64,
}

/// Rollback-resistant persistence boundary supplied by each platform.
pub trait TrustedTimeStore {
    /// Load and authenticate the latest durable checkpoint.
    fn load(&self) -> Result<Option<TrustedTimeCheckpoint>, Error>;
    /// Atomically commit a strictly advancing checkpoint.
    fn commit(&self, checkpoint: &TrustedTimeCheckpoint) -> Result<(), Error>;
}

/// Conservative trusted-time interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedInterval {
    lower: OffsetDateTime,
    upper: OffsetDateTime,
}

/// Accept an authenticated anchor only from a currently/historically
/// authorized, verified, non-revoked, nonconflicted time authority.
pub fn accept_time_anchor(
    anchor: &AuthenticatedTimeAnchor,
    trust: TrustAssessment,
    monotonic_now: u64,
    uncertainty_seconds: u64,
    previous: Option<&TrustedTimeState>,
) -> Result<TrustedTimeState, Error> {
    require_authority(trust, true)?;
    let observed = parse_time(&anchor.anchor.observed_at)?;
    if let Some(previous) = previous {
        if anchor.anchor.sequence <= previous.sequence
            || anchor.anchor.previous_anchor_hash.as_deref() != Some(&previous.anchor_hash)
            || observed.unix_timestamp() < previous.lower_unix_seconds
        {
            return Err(Error::TrustedTimeRollback);
        }
    } else if anchor.anchor.sequence != 0 || anchor.anchor.previous_anchor_hash.is_some() {
        return Err(Error::TrustedTimeUnavailable);
    }
    Ok(TrustedTimeState {
        sequence: anchor.anchor.sequence,
        anchor_hash: anchor.complete_hash.clone(),
        lower_unix_seconds: observed.unix_timestamp(),
        monotonic_origin: monotonic_now,
        max_age_seconds: anchor.anchor.max_age_seconds,
        uncertainty_seconds,
    })
}

/// Load durable high-water state, accept a new anchor, and atomically commit
/// the successor. Store integrity failures must be returned by the adapter.
pub fn accept_and_commit_time_anchor<S: TrustedTimeStore>(
    store: &S,
    anchor: &AuthenticatedTimeAnchor,
    trust: TrustAssessment,
    monotonic_now: u64,
    uncertainty_seconds: u64,
) -> Result<TrustedTimeState, Error> {
    let previous = store
        .load()?
        .map(TrustedTimeState::from_checkpoint)
        .transpose()?;
    let next = accept_time_anchor(
        anchor,
        trust,
        monotonic_now,
        uncertainty_seconds,
        previous.as_ref(),
    )?;
    store.commit(&next.checkpoint())?;
    Ok(next)
}

impl TrustedTimeState {
    fn from_checkpoint(value: TrustedTimeCheckpoint) -> Result<Self, Error> {
        if value.anchor_hash.len() != 64
            || !value
                .anchor_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || value.max_age_seconds == 0
            || value.max_age_seconds > 31_536_000
        {
            return Err(Error::TrustedTimeRollback);
        }
        Ok(Self {
            sequence: value.sequence,
            anchor_hash: value.anchor_hash,
            lower_unix_seconds: value.lower_unix_seconds,
            monotonic_origin: value.monotonic_origin,
            max_age_seconds: value.max_age_seconds,
            uncertainty_seconds: value.uncertainty_seconds,
        })
    }

    /// Export state for an authenticated rollback-resistant platform store.
    pub fn checkpoint(&self) -> TrustedTimeCheckpoint {
        TrustedTimeCheckpoint {
            sequence: self.sequence,
            anchor_hash: self.anchor_hash.clone(),
            lower_unix_seconds: self.lower_unix_seconds,
            monotonic_origin: self.monotonic_origin,
            max_age_seconds: self.max_age_seconds,
            uncertainty_seconds: self.uncertainty_seconds,
        }
    }
}

/// Evaluate an accepted anchor using only continuous monotonic elapsed time.
pub fn trusted_interval(
    state: &TrustedTimeState,
    monotonic_now: u64,
) -> Result<TrustedInterval, Error> {
    let elapsed = monotonic_now
        .checked_sub(state.monotonic_origin)
        .ok_or(Error::TrustedTimeRollback)?;
    if elapsed > state.max_age_seconds {
        return Err(Error::TrustedTimeUnavailable);
    }
    let lower = OffsetDateTime::from_unix_timestamp(state.lower_unix_seconds)
        .map_err(|_| Error::TrustedTimeUnavailable)?
        + Duration::seconds(i64::try_from(elapsed).map_err(|_| Error::TrustedTimeUnavailable)?);
    let upper = lower
        + Duration::seconds(
            i64::try_from(state.uncertainty_seconds).map_err(|_| Error::TrustedTimeUnavailable)?,
        );
    Ok(TrustedInterval { lower, upper })
}

/// Inputs binding a license evaluation to requested content and local subject.
pub struct EvaluationInput<'a> {
    /// Recording selected by the manifest/media pipeline.
    pub recording_id: &'a str,
    /// License ID authenticated by the manifest.
    pub license_id: &'a str,
    /// Configured local subject, if any.
    pub subject_id: Option<&'a str>,
    /// W4 result axes for the license issuer key.
    pub trust: TrustAssessment,
    /// Trusted interval for time-limited grants.
    pub time: Option<TrustedInterval>,
}

/// Successful permit classification exposed to W7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermitKind {
    /// Ordinary authorized entitlement.
    Authorized,
    /// ADR-008 pinned permanent-subject stale result.
    ValidStale,
    /// ADR-013 exact pinned public availability exception.
    PinnedAuthorizationUnknown,
}

/// Non-deserializable, non-constructible playback permit for future W7.
#[derive(Debug, PartialEq, Eq)]
pub struct PlaybackPermit {
    kind: PermitKind,
    recording_id: String,
    license_id: String,
}

impl PlaybackPermit {
    /// Permit classification; exceptions remain explicit.
    pub fn kind(&self) -> PermitKind {
        self.kind
    }

    /// Recording this permit authorizes.
    pub fn recording_id(&self) -> &str {
        &self.recording_id
    }

    /// License used for this decision.
    pub fn license_id(&self) -> &str {
        &self.license_id
    }
}

/// Evaluate offline entitlement deterministically and fail closed.
pub fn evaluate(
    license: &AuthenticatedLicense,
    input: &EvaluationInput<'_>,
) -> Result<PlaybackPermit, Error> {
    let value = &license.license;
    if value.recording_id != input.recording_id || value.license_id != input.license_id {
        return Err(Error::BindingMismatch);
    }
    if !value.offline {
        return Err(Error::OfflineDenied);
    }
    if value.audience == "subject" && value.subject_id.as_deref() != input.subject_id {
        return Err(Error::SubjectMismatch);
    }
    let public = value.audience == "public";
    let exception = public
        && input.trust.authorization == Authorization::AuthorizationUnknown
        && input.trust.current_status == CurrentStatus::Unknown
        && input.trust.playback == Some(PlaybackDecision::PlaybackAllowedPinnedAuthUnknown);
    let stale_subject = !public
        && matches!(value.offline_policy, OfflinePolicy::Permanent)
        && input.trust.freshness == Freshness::Stale
        && input.trust.playback == Some(PlaybackDecision::ValidStale);
    if !exception {
        require_authority(
            input.trust,
            (!public || matches!(value.offline_policy, OfflinePolicy::TimeLimited { .. }))
                && !stale_subject,
        )?;
    }
    let kind = match value.offline_policy {
        OfflinePolicy::Permanent if exception => PermitKind::PinnedAuthorizationUnknown,
        OfflinePolicy::Permanent if stale_subject => PermitKind::ValidStale,
        OfflinePolicy::Permanent => PermitKind::Authorized,
        OfflinePolicy::TimeLimited { .. } => {
            if input.trust.freshness != Freshness::Fresh {
                return Err(Error::TrustStale);
            }
            let interval = input.time.ok_or(Error::TrustedTimeUnavailable)?;
            let start = parse_time(&value.valid_from)?;
            let expiry = parse_time(
                value
                    .expires_at
                    .as_deref()
                    .ok_or(Error::TrustedTimeUnavailable)?,
            )?;
            if interval.lower < start {
                return Err(Error::NotYetValid);
            }
            if interval.upper >= expiry {
                return Err(Error::Expired);
            }
            PermitKind::Authorized
        }
    };
    Ok(PlaybackPermit {
        kind,
        recording_id: value.recording_id.clone(),
        license_id: value.license_id.clone(),
    })
}

fn require_authority(trust: TrustAssessment, require_fresh: bool) -> Result<(), Error> {
    match trust.current_status {
        CurrentStatus::Revoked => return Err(Error::Revoked),
        CurrentStatus::Conflict => return Err(Error::Conflict),
        CurrentStatus::Unknown => return Err(Error::TrustUnknown),
        CurrentStatus::Active => {}
    }
    if trust.identity_trust != IdentityTrust::Verified {
        return Err(Error::TrustUnknown);
    }
    if !matches!(
        trust.authorization,
        Authorization::AuthorizedCurrent | Authorization::AuthorizedHistorical
    ) {
        return Err(Error::Unauthorized);
    }
    if require_fresh && trust.freshness != Freshness::Fresh {
        return Err(Error::TrustStale);
    }
    Ok(())
}

fn parse_time(value: &str) -> Result<OffsetDateTime, Error> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|e| Error::Schema(e.to_string()))
}
