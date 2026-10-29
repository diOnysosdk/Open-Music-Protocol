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
use rodio::Source;
use std::time::Duration;
use std::{fs::File, io::Seek};
use symphonia::core::{
    codecs::{CodecParameters, Decoder, DecoderOptions},
    errors::Error as SymphoniaError,
    formats::{FormatOptions, FormatReader},
    io::MediaSourceStream,
    meta::MetadataOptions,
    probe::Hint,
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

#[derive(Debug)]
struct PacketBudget {
    processed: u64,
    limit: u64,
}

// FLAC blocks are limited to 65,535 samples. Symphonia's WAV reader uses much
// smaller packets (normally 1,152 frames), so this bounds one decode allocation
// without rejecting valid packets for either supported codec.
const MAX_FRAMES_PER_PACKET: u64 = 65_536;
// Symphonia's FLAC parser uses the format's 16 MiB maximum frame size. WAV
// packets are smaller under the frame ceiling above, so this is a common
// encoded-packet limit for every supported track.
const MAX_ENCODED_PACKET_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RESET_EVENTS: u64 = 64;

#[derive(Debug)]
struct FrameBudget {
    decoded: u64,
    limit: u64,
}

impl FrameBudget {
    fn new(limit: u64) -> Self {
        Self { decoded: 0, limit }
    }

    fn validate_codec_ceiling(&self, declared_max: Option<u64>) -> Result<(), Error> {
        if declared_max.is_some_and(|frames| frames > MAX_FRAMES_PER_PACKET) {
            return Err(Error::Decoder("frame limit".into()));
        }
        Ok(())
    }

    fn before_decode(&self, declared_frames: u64) -> Result<(), Error> {
        let remaining = self
            .limit
            .checked_sub(self.decoded)
            .ok_or_else(|| Error::Decoder("frame limit".into()))?;
        if remaining == 0 || declared_frames > remaining || declared_frames > MAX_FRAMES_PER_PACKET
        {
            return Err(Error::Decoder("frame limit".into()));
        }
        Ok(())
    }

    fn record_decoded(&mut self, actual_frames: u64) -> Result<(), Error> {
        self.decoded = self
            .decoded
            .checked_add(actual_frames)
            .ok_or_else(|| Error::Decoder("frame overflow".into()))?;
        if self.decoded > self.limit || actual_frames > MAX_FRAMES_PER_PACKET {
            return Err(Error::Decoder("frame limit".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct RecoveryState {
    reset_events: u64,
    damaged: bool,
}

impl RecoveryState {
    fn record_reset(&mut self) -> Result<(), Error> {
        self.reset_events = self
            .reset_events
            .checked_add(1)
            .ok_or_else(|| Error::Decoder("reset limit".into()))?;
        if self.reset_events > MAX_RESET_EVENTS {
            return Err(Error::Decoder("reset limit".into()));
        }
        Ok(())
    }

    fn record_damaged_packet(&mut self) {
        self.damaged = true;
    }

    fn record_verification(&mut self, verify_ok: Option<bool>) {
        if verify_ok == Some(false) {
            self.damaged = true;
        }
    }

    fn ensure_complete(&self) -> Result<(), Error> {
        if self.damaged {
            return Err(Error::Decoder("incomplete stream".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecodeRecovery {
    DiscardPacket,
    RecreateDecoder,
}

fn decode_recovery(error: SymphoniaError) -> Result<DecodeRecovery, Error> {
    match error {
        SymphoniaError::DecodeError(_) | SymphoniaError::IoError(_) => {
            Ok(DecodeRecovery::DiscardPacket)
        }
        SymphoniaError::ResetRequired => Ok(DecodeRecovery::RecreateDecoder),
        error => Err(decoder(error)),
    }
}

fn validate_encoded_packet_size(encoded_bytes: usize) -> Result<(), Error> {
    let encoded_bytes =
        u64::try_from(encoded_bytes).map_err(|_| Error::Decoder("packet size limit".into()))?;
    if encoded_bytes > MAX_ENCODED_PACKET_BYTES {
        return Err(Error::Decoder("packet size limit".into()));
    }
    Ok(())
}

fn make_decoder(
    params: &CodecParameters,
    frame_budget: &FrameBudget,
) -> Result<Box<dyn Decoder>, Error> {
    frame_budget.validate_codec_ceiling(params.max_frames_per_packet)?;
    symphonia::default::get_codecs()
        .make(params, &DecoderOptions::default())
        .map_err(decoder)
}

fn select_decoder(
    format: &dyn FormatReader,
    frame_budget: &FrameBudget,
) -> Result<(u32, Box<dyn Decoder>), Error> {
    let track = format
        .default_track()
        .ok_or_else(|| Error::Decoder("no default track".into()))?;
    Ok((track.id, make_decoder(&track.codec_params, frame_budget)?))
}

impl PacketBudget {
    fn new(limit: u64) -> Self {
        Self {
            processed: 0,
            limit,
        }
    }

    fn consume(&mut self) -> Result<(), Error> {
        self.processed = self
            .processed
            .checked_add(1)
            .ok_or_else(|| Error::Decoder("packet limit".into()))?;
        if self.processed > self.limit {
            return Err(Error::Decoder("packet limit".into()));
        }
        Ok(())
    }
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
        // Match the default four-hour decoded-frame ceiling. Rodio streams
        // into CPAL; it does not buffer the complete asset.
        sink.append(source.take_duration(Duration::from_secs(4 * 60 * 60)));
        sink.sleep_until_end();
        Ok(())
    }
}

/// Controllable local playback created only from an authorized prepared handle.
pub struct LocalPlayback {
    _stream: rodio::OutputStream,
    sink: rodio::Sink,
    report: PlaybackReport,
}

impl LocalPlayback {
    /// Start local playback from an already authorized and verified handle.
    pub fn start(prepared: PreparedPlayback) -> Result<Self, Error> {
        let report = PlaybackReport {
            classification: prepared.permit.kind(),
            recording_id: prepared.permit.recording_id().to_owned(),
            asset_id: prepared.media.asset_id().to_owned(),
            media_type: prepared.media.media_type().to_owned(),
            decoded_frames: 0,
            decoded_packets: 0,
        };
        let (stream, handle) = rodio::OutputStream::try_default()
            .map_err(|error| Error::Decoder(format!("audio output unavailable: {error}")))?;
        let sink = rodio::Sink::try_new(&handle)
            .map_err(|error| Error::Decoder(format!("audio sink unavailable: {error}")))?;
        let source = rodio::Decoder::new(prepared.media.into_file())
            .map_err(|error| Error::Decoder(format!("audio decoder: {error}")))?;
        sink.append(source.take_duration(Duration::from_secs(4 * 60 * 60)));
        Ok(Self {
            _stream: stream,
            sink,
            report,
        })
    }

    /// Pause without discarding the authorized playback session.
    pub fn pause(&self) {
        self.sink.pause();
    }

    /// Resume a paused authorized playback session.
    pub fn resume(&self) {
        self.sink.play();
    }

    /// Stop and discard queued audio.
    pub fn stop(&self) {
        self.sink.stop();
    }

    /// Set linear output volume, clamped to the UI's supported range.
    pub fn set_volume(&self, volume: f32) {
        self.sink.set_volume(volume.clamp(0.0, 1.0));
    }

    /// Seek when the underlying verified source supports it.
    pub fn seek(&self, position: Duration) -> Result<(), Error> {
        self.sink
            .try_seek(position)
            .map_err(|error| Error::Decoder(format!("seek unavailable: {error}")))
    }

    /// Current playback position reported by the audio sink.
    pub fn position(&self) -> Duration {
        self.sink.get_pos()
    }

    /// Whether playback has completed or was stopped.
    pub fn is_finished(&self) -> bool {
        self.sink.empty()
    }

    /// Security classification and authenticated identifiers for this session.
    pub fn report(&self) -> &PlaybackReport {
        &self.report
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
    let mut frame_budget = FrameBudget::new(limits.max_frames);
    let (mut track_id, mut decoder_impl) = select_decoder(format.as_ref(), &frame_budget)?;
    let mut packet_budget = PacketBudget::new(limits.max_packets);
    let mut recovery = RecoveryState::default();
    'decode: loop {
        let packet = match format.next_packet() {
            Ok(v) => v,
            Err(SymphoniaError::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break 'decode;
            }
            Err(SymphoniaError::ResetRequired) => {
                recovery.record_reset()?;
                (track_id, decoder_impl) = select_decoder(format.as_ref(), &frame_budget)?;
                continue 'decode;
            }
            Err(e) => return Err(decoder(e)),
        };
        packet_budget.consume()?;
        validate_encoded_packet_size(packet.buf().len())?;
        if packet.track_id() != track_id {
            continue;
        }
        frame_budget.before_decode(packet.dur())?;
        loop {
            match decoder_impl.decode(&packet) {
                Ok(decoded) => {
                    frame_budget.record_decoded(decoded.frames() as u64)?;
                    break;
                }
                Err(error) => match decode_recovery(error)? {
                    DecodeRecovery::DiscardPacket => {
                        recovery.record_damaged_packet();
                        break;
                    }
                    DecodeRecovery::RecreateDecoder => {
                        recovery.record_reset()?;
                        let updated = decoder_impl.codec_params().clone();
                        decoder_impl = make_decoder(&updated, &frame_budget)?;
                    }
                },
            }
        }
    }
    recovery.record_verification(decoder_impl.finalize().verify_ok);
    recovery.ensure_complete()?;
    Ok(PlaybackReport {
        classification: prepared.permit.kind(),
        recording_id: prepared.permit.recording_id().to_owned(),
        asset_id,
        media_type,
        decoded_frames: frame_budget.decoded,
        decoded_packets: packet_budget.processed,
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

#[cfg(test)]
mod tests {
    use super::{
        decode_recovery, validate_encoded_packet_size, DecodeRecovery, Error, FrameBudget,
        PacketBudget, RecoveryState, MAX_ENCODED_PACKET_BYTES, MAX_FRAMES_PER_PACKET,
        MAX_RESET_EVENTS,
    };
    use std::io;
    use symphonia::core::errors::Error as SymphoniaError;

    fn process_tracks(track_ids: &[u32], selected_track: u32, limit: u64) -> Result<u64, Error> {
        let mut budget = PacketBudget::new(limit);
        for &track_id in track_ids {
            budget.consume()?;
            if track_id != selected_track {
                continue;
            }
        }
        Ok(budget.processed)
    }

    #[test]
    fn packet_budget_counts_packets_from_every_track() {
        let error = process_tracks(&[2, 2, 1], 1, 2).unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message == "packet limit"));
    }

    #[test]
    fn packet_budget_rejects_first_packet_when_zero() {
        let error = process_tracks(&[1], 1, 0).unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message == "packet limit"));
    }

    #[test]
    fn packet_budget_accepts_exact_limit() {
        assert_eq!(process_tracks(&[2, 1, 2], 1, 3).unwrap(), 3);
    }

    #[test]
    fn packet_budget_rejects_packet_after_exact_limit() {
        let error = process_tracks(&[2, 1, 2, 1], 1, 3).unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message == "packet limit"));
    }

    #[test]
    fn packet_budget_rejects_counter_overflow() {
        let mut budget = PacketBudget {
            processed: u64::MAX,
            limit: u64::MAX,
        };
        let error = budget.consume().unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message == "packet limit"));
    }

    #[test]
    fn encoded_packet_size_accepts_empty_and_exact_limit() {
        validate_encoded_packet_size(0).unwrap();
        validate_encoded_packet_size(usize::try_from(MAX_ENCODED_PACKET_BYTES).unwrap()).unwrap();
    }

    #[test]
    fn encoded_packet_size_rejects_first_byte_over_limit() {
        let oversized = MAX_ENCODED_PACKET_BYTES.checked_add(1).unwrap();
        let error = validate_encoded_packet_size(usize::try_from(oversized).unwrap()).unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message == "packet size limit"));
    }

    #[test]
    fn oversized_nonselected_packet_still_consumes_packet_budget() {
        let mut packets = PacketBudget::new(1);
        packets.consume().unwrap();
        let oversized = MAX_ENCODED_PACKET_BYTES.checked_add(1).unwrap();
        let error = validate_encoded_packet_size(usize::try_from(oversized).unwrap()).unwrap_err();

        assert_eq!(packets.processed, 1);
        assert!(matches!(error, Error::Decoder(message) if message == "packet size limit"));
    }

    #[test]
    fn zero_frame_budget_rejects_before_decode() {
        let budget = FrameBudget::new(0);
        let error = budget.before_decode(1).unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message == "frame limit"));
    }

    #[test]
    fn frame_budget_accepts_exact_boundary() {
        let mut budget = FrameBudget::new(4_096);
        budget.before_decode(4_096).unwrap();
        budget.record_decoded(4_096).unwrap();
        assert_eq!(budget.decoded, 4_096);
    }

    #[test]
    fn frame_budget_rejects_oversized_packet_declarations() {
        let budget = FrameBudget::new(MAX_FRAMES_PER_PACKET + 1);
        let error = budget.before_decode(MAX_FRAMES_PER_PACKET + 1).unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message == "frame limit"));

        let error = budget
            .validate_codec_ceiling(Some(MAX_FRAMES_PER_PACKET + 1))
            .unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message == "frame limit"));
    }

    #[test]
    fn frame_budget_enforces_cumulative_actual_frames() {
        let mut budget = FrameBudget::new(4_096);
        budget.before_decode(2_048).unwrap();
        budget.record_decoded(2_048).unwrap();
        let error = budget.before_decode(2_049).unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message == "frame limit"));

        budget.before_decode(2_048).unwrap();
        budget.record_decoded(2_048).unwrap();
        assert_eq!(budget.decoded, 4_096);
    }

    #[test]
    fn frame_budget_post_decode_check_rejects_underdeclared_packet() {
        let mut budget = FrameBudget::new(4_096);
        budget.before_decode(1_024).unwrap();
        let error = budget.record_decoded(4_097).unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message == "frame limit"));
    }

    #[test]
    fn frame_budget_rejects_counter_overflow() {
        let mut budget = FrameBudget {
            decoded: u64::MAX,
            limit: u64::MAX,
        };
        let error = budget.record_decoded(1).unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message == "frame overflow"));
    }

    #[test]
    fn recoverable_packet_errors_are_discarded() {
        assert_eq!(
            decode_recovery(SymphoniaError::DecodeError("damaged packet")).unwrap(),
            DecodeRecovery::DiscardPacket
        );
        assert_eq!(
            decode_recovery(SymphoniaError::IoError(io::Error::new(
                io::ErrorKind::InvalidData,
                "damaged packet",
            )))
            .unwrap(),
            DecodeRecovery::DiscardPacket
        );
    }

    #[test]
    fn terminal_decoder_errors_remain_terminal() {
        let error = decode_recovery(SymphoniaError::LimitError("codec limit")).unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message.contains("codec limit")));
    }

    #[test]
    fn decoder_reset_requests_recreation() {
        assert_eq!(
            decode_recovery(SymphoniaError::ResetRequired).unwrap(),
            DecodeRecovery::RecreateDecoder
        );
    }

    #[test]
    fn repeated_resets_are_bounded() {
        let mut recovery = RecoveryState::default();
        for _ in 0..MAX_RESET_EVENTS {
            recovery.record_reset().unwrap();
        }
        let error = recovery.record_reset().unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message == "reset limit"));
    }

    #[test]
    fn budgets_remain_monotonic_across_errors_and_resets() {
        let mut packets = PacketBudget::new(2);
        let mut frames = FrameBudget::new(1_024);
        let mut recovery = RecoveryState::default();

        packets.consume().unwrap();
        recovery.record_damaged_packet();
        recovery.record_reset().unwrap();
        packets.consume().unwrap();
        frames.before_decode(1_024).unwrap();
        frames.record_decoded(1_024).unwrap();

        assert_eq!(packets.processed, 2);
        assert_eq!(frames.decoded, 1_024);
        assert_eq!(recovery.reset_events, 1);
    }

    #[test]
    fn damaged_media_cannot_report_successful_completion() {
        let mut recovery = RecoveryState::default();
        recovery.record_damaged_packet();
        let error = recovery.ensure_complete().unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message == "incomplete stream"));
    }

    #[test]
    fn failed_decoder_verification_cannot_report_successful_completion() {
        let mut recovery = RecoveryState::default();
        recovery.record_verification(Some(false));
        let error = recovery.ensure_complete().unwrap_err();
        assert!(matches!(error, Error::Decoder(message) if message == "incomplete stream"));

        let mut unavailable = RecoveryState::default();
        unavailable.record_verification(None);
        unavailable.ensure_complete().unwrap();
    }
}
