//! Headless secure offline playback orchestration for OMP v0.2.

#![deny(missing_docs)]

use ed25519_dalek::VerifyingKey;
use omp_crypto::public_key_from_base64url;
use omp_identity::{
    assess_signer, Freshness, HistoricalEvidence, IdentityTrust, PlaybackDecision,
    ValidatedIdentityDocument, ValidatedLifecycleEvent, VerificationResult,
};
use omp_license::{
    evaluate, AuthenticatedLicense, EvaluationInput, PermitKind, PlaybackPermit, TrustAssessment,
    TrustedInterval,
};
use omp_media::{
    select_and_verify, AuthenticatedManifest, MediaPolicy, PackageRoot, VerifiedMedia,
};
use std::{fs::File, io::Seek};
use symphonia::core::{
    codecs::DecoderOptions, errors::Error as SymphoniaError, formats::FormatOptions,
    io::MediaSourceStream, meta::MetadataOptions, probe::Hint,
};

/// W7 pipeline or decoder failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Manifest/media verification failed.
    #[error("media verification failed: {0}")]
    Media(#[from] omp_media::Error),
    /// License validation or entitlement failed.
    #[error("license denied: {0}")]
    License(#[from] omp_license::Error),
    /// Supplied key is not the authenticated identity key.
    #[error("OMP_KEY_UNAUTHORIZED")]
    KeyUnauthorized,
    /// Decoder rejected or exceeded limits.
    #[error("OMP_DECODER_INVALID: {0}")]
    Decoder(String),
}

/// Resource limits applied before/during decoding.
#[derive(Clone, Copy, Debug)]
pub struct DecodeLimits {
    /// Maximum decoded frames.
    pub max_frames: u64,
    /// Maximum packets processed.
    pub max_packets: u64,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_frames: 48_000 * 60 * 60 * 4,
            max_packets: 2_000_000,
        }
    }
}

/// Status returned by a completed headless decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaybackReport {
    /// Permit classification, including explicit exceptions.
    pub classification: PermitKind,
    /// Bound recording ID.
    pub recording_id: String,
    /// Selected asset ID.
    pub asset_id: String,
    /// Decoder media type.
    pub media_type: String,
    /// Total decoded frames.
    pub decoded_frames: u64,
    /// Total decoder packets.
    pub decoded_packets: u64,
}

/// Opaque object produced only after W3/W4/W5/W6 checks succeed.
pub struct PreparedPlayback {
    permit: PlaybackPermit,
    media: VerifiedMedia,
}

/// Narrow local audio-output backend.
pub trait AudioSink {
    /// Consume the exact verified handle and block until playback completes.
    fn play(&self, file: File) -> Result<(), Error>;
}

/// Default local device backend powered by Rodio/CPAL.
pub struct LocalAudioSink;

impl AudioSink for LocalAudioSink {
    fn play(&self, file: File) -> Result<(), Error> {
        let (_stream, handle) = rodio::OutputStream::try_default()
            .map_err(|e| Error::Decoder(format!("audio device unavailable: {e}")))?;
        let sink = rodio::Sink::try_new(&handle)
            .map_err(|e| Error::Decoder(format!("audio sink unavailable: {e}")))?;
        let source =
            rodio::Decoder::new(file).map_err(|e| Error::Decoder(format!("audio decoder: {e}")))?;
        sink.append(source);
        sink.sleep_until_end();
        Ok(())
    }
}

/// Play through a caller-selected sink only after preparation succeeded.
pub fn play_with_sink<S: AudioSink>(
    prepared: PreparedPlayback,
    sink: &S,
) -> Result<PlaybackReport, Error> {
    let report = PlaybackReport {
        classification: prepared.permit.kind(),
        recording_id: prepared.permit.recording_id().to_owned(),
        asset_id: prepared.media.asset_id().to_owned(),
        media_type: prepared.media.media_type().to_owned(),
        decoded_frames: 0,
        decoded_packets: 0,
    };
    sink.play(prepared.media.into_file())?;
    Ok(report)
}

/// Inputs that are local trust policy rather than signed wire fields.
pub struct TrustPolicy<'a> {
    /// Opaque authenticated identity fact.
    pub identity: &'a ValidatedIdentityDocument,
    /// Opaque authenticated lifecycle facts.
    pub lifecycle: &'a [ValidatedLifecycleEvent],
    /// Signer key ID used by manifest and license.
    pub key_id: &'a str,
    /// Explicit local bootstrap trust.
    pub identity_trust: IdentityTrust,
    /// Available trust freshness.
    pub freshness: Freshness,
    /// Independently established historical evidence.
    pub historical_evidence: HistoricalEvidence,
    /// Narrow W4 playback result, if applicable.
    pub playback: Option<PlaybackDecision>,
    /// Opaque ADR-013 durable-pin assessment, when applicable.
    pub pinned_assessment: Option<&'a VerificationResult>,
}

/// Verify and authorize a complete local package without network access.
#[allow(clippy::too_many_arguments)]
pub fn prepare(
    manifest_json: &[u8],
    license_json: &[u8],
    signing_key: &VerifyingKey,
    package_root: &PackageRoot,
    policy: &TrustPolicy<'_>,
    subject_id: Option<&str>,
    trusted_time: Option<TrustedInterval>,
    media_policy: MediaPolicy,
) -> Result<PreparedPlayback, Error> {
    let authenticated_key = policy
        .identity
        .operational_key(policy.key_id)
        .ok_or(Error::KeyUnauthorized)?;
    let expected = public_key_from_base64url(authenticated_key.public_key_base64url())
        .map_err(|_| Error::KeyUnauthorized)?;
    if expected.as_bytes() != signing_key.as_bytes() {
        return Err(Error::KeyUnauthorized);
    }
    let manifest = AuthenticatedManifest::parse_and_verify(manifest_json, signing_key)?;
    let manifest_trust = policy
        .pinned_assessment
        .cloned()
        .unwrap_or_else(|| assess(policy, "manifest"));
    let license = AuthenticatedLicense::parse_and_verify(license_json, signing_key)?;
    let license_trust = policy
        .pinned_assessment
        .cloned()
        .unwrap_or_else(|| assess(policy, "license"));
    let permit = evaluate(
        &license,
        &EvaluationInput {
            recording_id: manifest.recording_id(),
            license_id: manifest.license_id(),
            subject_id,
            trust: TrustAssessment::from_w4(&license_trust),
            time: trusted_time,
        },
    )?;
    if permit.kind() == PermitKind::PinnedAuthorizationUnknown {
        if manifest_trust.playback() != Some(PlaybackDecision::PlaybackAllowedPinnedAuthUnknown) {
            return Err(Error::KeyUnauthorized);
        }
    } else {
        require_authorized(&manifest_trust)?;
    }
    let media = select_and_verify(&manifest, package_root, media_policy)?;
    Ok(PreparedPlayback { permit, media })
}

fn assess(policy: &TrustPolicy<'_>, role: &str) -> VerificationResult {
    assess_signer(
        policy.identity,
        policy.key_id,
        role,
        policy.lifecycle,
        policy.identity_trust,
        policy.freshness,
        policy.historical_evidence,
        policy.playback,
    )
}

fn require_authorized(result: &VerificationResult) -> Result<(), Error> {
    use omp_identity::{Authorization, CurrentStatus};
    if result.current_status() != CurrentStatus::Active
        || !matches!(
            result.authorization(),
            Authorization::AuthorizedCurrent | Authorization::AuthorizedHistorical
        )
    {
        return Err(Error::KeyUnauthorized);
    }
    Ok(())
}

/// Decode WAV or FLAC from the exact W5 verified handle into a headless sink.
/// No pathname is reopened and no audio device or network is required.
pub fn decode_headless(
    prepared: PreparedPlayback,
    limits: DecodeLimits,
) -> Result<PlaybackReport, Error> {
    let asset_id = prepared.media.asset_id().to_owned();
    let media_type = prepared.media.media_type().to_owned();
    if !matches!(media_type.as_str(), "audio/wav" | "audio/flac") {
        return Err(Error::Decoder("unsupported codec".into()));
    }
    let mut file: File = prepared.media.into_file();
    file.rewind()?;
    let mss = MediaSourceStream::new(Box::new(file), Default::default());
    let mut hint = Hint::new();
    hint.with_extension(if media_type == "audio/flac" {
        "flac"
    } else {
        "wav"
    });
    let probed = symphonia::default::get_probe()
        .format(
            &hint,
            mss,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .map_err(decoder)?;
    let mut format = probed.format;
    let track = format
        .default_track()
        .ok_or_else(|| Error::Decoder("no default track".into()))?;
    let track_id = track.id;
    let mut decoder_impl = symphonia::default::get_codecs()
        .make(&track.codec_params, &DecoderOptions::default())
        .map_err(decoder)?;
    let mut frames = 0_u64;
    let mut packets = 0_u64;
    loop {
        let packet = match format.next_packet() {
            Ok(v) => v,
            Err(SymphoniaError::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break
            }
            Err(e) => return Err(decoder(e)),
        };
        if packet.track_id() != track_id {
            continue;
        }
        packets += 1;
        if packets > limits.max_packets {
            return Err(Error::Decoder("packet limit".into()));
        }
        let decoded = decoder_impl.decode(&packet).map_err(decoder)?;
        frames = frames
            .checked_add(decoded.frames() as u64)
            .ok_or_else(|| Error::Decoder("frame overflow".into()))?;
        if frames > limits.max_frames {
            return Err(Error::Decoder("frame limit".into()));
        }
    }
    Ok(PlaybackReport {
        classification: prepared.permit.kind(),
        recording_id: prepared.permit.recording_id().to_owned(),
        asset_id,
        media_type,
        decoded_frames: frames,
        decoded_packets: packets,
    })
}

fn decoder(error: SymphoniaError) -> Error {
    Error::Decoder(error.to_string())
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Decoder(value.to_string())
    }
}
