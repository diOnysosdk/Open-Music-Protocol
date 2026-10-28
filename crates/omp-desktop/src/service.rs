//! Application service that maps local package files to existing OMP APIs.

use crate::library::{SecurityStatus, Track};
use omp_core::{diagnostics::classify_message, v02};
use omp_crypto::public_key_from_base64url;
use omp_identity::{
    assess_signer, Freshness, HistoricalEvidence, IdentityTrust, ProductionFactProvider,
    ValidatedFactProvider,
};
use omp_license::{evaluate, AuthenticatedLicense, EvaluationInput, TrustAssessment};
use omp_media::{select_and_verify, AuthenticatedManifest, MediaPolicy, PackageRoot};
use omp_player::{prepare, LocalPlayback, PreparedPlayback, TrustPolicy};
use std::{fs, path::Path};

/// Package import or playback preparation failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A required package file could not be read.
    #[error("package I/O: {0}")]
    Io(#[from] std::io::Error),
    /// A protocol, trust, license, or playback check rejected the package.
    #[error("{0}")]
    Rejected(String),
}

struct Documents {
    manifest: Vec<u8>,
    license: Vec<u8>,
    identity: Vec<u8>,
}

fn documents(root: &Path) -> Result<Documents, Error> {
    Ok(Documents {
        manifest: fs::read(root.join("manifest.json"))?,
        license: fs::read(root.join("license.json"))?,
        identity: fs::read(root.join("identity.json"))?,
    })
}

fn reject(error: impl std::fmt::Display) -> Error {
    Error::Rejected(error.to_string())
}

/// Verify every package layer and return only authenticated display metadata.
pub fn inspect_package(path: &Path, identity_trust: IdentityTrust) -> Result<Track, Error> {
    if identity_trust != IdentityTrust::Verified {
        return Err(reject(
            "OMP_IDENTITY_UNKNOWN: establish identity trust out of band",
        ));
    }
    let canonical = fs::canonicalize(path)?;
    let docs = documents(&canonical)?;
    let manifest_model = v02::parse::<v02::Manifest>(&docs.manifest).map_err(reject)?;
    let identity = ProductionFactProvider
        .identity_document(&docs.identity)
        .map_err(reject)?;
    let key_fact = identity
        .operational_key(&manifest_model.signature.key_id)
        .ok_or_else(|| reject("OMP_KEY_UNAUTHORIZED"))?;
    let key = public_key_from_base64url(key_fact.public_key_base64url()).map_err(reject)?;
    let manifest = AuthenticatedManifest::parse_and_verify(&docs.manifest, &key).map_err(reject)?;
    let manifest_trust = assess_signer(
        &identity,
        &manifest_model.signature.key_id,
        "manifest",
        &[],
        identity_trust,
        Freshness::Unknown,
        HistoricalEvidence::None,
        None,
    );
    let license_model = v02::parse::<v02::License>(&docs.license).map_err(reject)?;
    if license_model.signature.key_id != manifest_model.signature.key_id {
        return Err(reject(
            "OMP_KEY_UNAUTHORIZED: manifest/license signer mismatch",
        ));
    }
    let license = AuthenticatedLicense::parse_and_verify(&docs.license, &key).map_err(reject)?;
    let license_trust = assess_signer(
        &identity,
        &license_model.signature.key_id,
        "license",
        &[],
        identity_trust,
        Freshness::Unknown,
        HistoricalEvidence::None,
        None,
    );
    let permit = evaluate(
        &license,
        &EvaluationInput {
            recording_id: manifest.recording_id(),
            license_id: manifest.license_id(),
            subject_id: None,
            trust: TrustAssessment::from_w4(&license_trust),
            time: None,
        },
    )
    .map_err(reject)?;
    let root = PackageRoot::open(&canonical).map_err(reject)?;
    let media = select_and_verify(&manifest, &root, MediaPolicy::default()).map_err(reject)?;
    let prepared = prepare_package(&canonical, identity_trust)?;
    drop(prepared);

    let metadata = manifest.metadata();
    let artist = metadata
        .artist_credits
        .iter()
        .map(|credit| credit.display_name.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    Ok(Track {
        recording_id: manifest.recording_id().to_owned(),
        package_path: canonical.display().to_string(),
        title: metadata.title.clone(),
        artist,
        album: metadata
            .release
            .as_ref()
            .map(|release| release.title.clone())
            .unwrap_or_else(|| "Singles".into()),
        duration: "Not declared by OMP v0.2".into(),
        artwork: None,
        security: SecurityStatus {
            authenticity: "Valid signature".into(),
            key_authorization: format!("{:?}", manifest_trust.authorization()),
            trust: format!(
                "{:?} / {:?}",
                manifest_trust.identity_trust(),
                manifest_trust.freshness()
            ),
            package_integrity: format!("Verified {} ({})", media.asset_id(), media.sha256()),
            license: format!("Authorized ({:?})", permit.kind()),
            playback: "Authorized; prepared through omp-player".into(),
            diagnostic: None,
        },
        present: true,
    })
}

/// Run the complete W7 pipeline and return its opaque authorized handle.
pub fn prepare_package(
    path: &Path,
    identity_trust: IdentityTrust,
) -> Result<PreparedPlayback, Error> {
    if identity_trust != IdentityTrust::Verified {
        return Err(reject(
            "OMP_IDENTITY_UNKNOWN: establish identity trust out of band",
        ));
    }
    let docs = documents(path)?;
    let manifest_model = v02::parse::<v02::Manifest>(&docs.manifest).map_err(reject)?;
    let identity = ProductionFactProvider
        .identity_document(&docs.identity)
        .map_err(reject)?;
    let key_fact = identity
        .operational_key(&manifest_model.signature.key_id)
        .ok_or_else(|| reject("OMP_KEY_UNAUTHORIZED"))?;
    let key = public_key_from_base64url(key_fact.public_key_base64url()).map_err(reject)?;
    let root = PackageRoot::open(path).map_err(reject)?;
    let policy = TrustPolicy {
        identity: &identity,
        lifecycle: &[],
        key_id: &manifest_model.signature.key_id,
        identity_trust,
        freshness: Freshness::Unknown,
        historical_evidence: HistoricalEvidence::None,
        playback: None,
        pinned_assessment: None,
    };
    prepare(
        &docs.manifest,
        &docs.license,
        &key,
        &root,
        &policy,
        None,
        None,
        MediaPolicy::default(),
    )
    .map_err(reject)
}

/// Start a controllable session after complete authorization.
pub fn start_playback(path: &Path, identity_trust: IdentityTrust) -> Result<LocalPlayback, Error> {
    LocalPlayback::start(prepare_package(path, identity_trust)?).map_err(reject)
}

/// Convert a rejected package error into the stable UI diagnostic label.
pub fn diagnostic(error: &Error) -> String {
    let category = classify_message(&error.to_string());
    format!("{} — {}", category.code(), category.action())
}
