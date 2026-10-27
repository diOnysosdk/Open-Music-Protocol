use omp_crypto::public_key_from_base64url;
use omp_identity::{
    Freshness, HistoricalEvidence, IdentityTrust, ProductionFactProvider, ValidatedFactProvider,
};
use omp_media::{MediaPolicy, PackageRoot};
use omp_player::{
    decode_headless, play_with_sink, prepare, DecodeLimits, LocalAudioSink, TrustPolicy,
};

fn main() {
    if let Err(error) = run() {
        let category = omp_core::diagnostics::classify_message(&error.to_string());
        eprintln!("{}: {error}", category.code());
        eprintln!("action: {}", category.action());
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 7 || !matches!(args[1].as_str(), "verify" | "play-headless" | "play") {
        eprintln!("usage: omp-player <verify|play-headless|play> <package-root> <manifest.json> <license.json> <identity.json> <public-key-base64url>");
        std::process::exit(2);
    }
    let identity_bytes = std::fs::read(&args[5])?;
    let identity = ProductionFactProvider.identity_document(&identity_bytes)?;
    let key = public_key_from_base64url(&args[6])?;
    let root = PackageRoot::open(&args[2])?;
    let policy = TrustPolicy {
        identity: &identity,
        lifecycle: &[],
        key_id: "media-01",
        identity_trust: IdentityTrust::Verified,
        freshness: Freshness::Unknown,
        historical_evidence: HistoricalEvidence::None,
        playback: None,
        pinned_assessment: None,
    };
    let prepared = prepare(
        &std::fs::read(&args[3])?,
        &std::fs::read(&args[4])?,
        &key,
        &root,
        &policy,
        None,
        None,
        MediaPolicy::default(),
    )?;
    let report = if args[1] == "play" {
        play_with_sink(prepared, &LocalAudioSink)?
    } else {
        decode_headless(prepared, DecodeLimits::default())?
    };
    println!(
        "recording={} asset={} media={} classification={:?} frames={} packets={}",
        report.recording_id,
        report.asset_id,
        report.media_type,
        report.classification,
        report.decoded_frames,
        report.decoded_packets
    );
    Ok(())
}
