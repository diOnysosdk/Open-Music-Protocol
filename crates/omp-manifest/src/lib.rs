//! Creation and strict offline verification of OMP v0.1 sidecar manifests.

#![deny(missing_docs)]

use ed25519_dalek::{SigningKey, VerifyingKey};
use omp_core::{parse_and_validate, parse_value, Asset, Manifest, Signature, Validate};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::path::Path;

/// A public-key record supplied by a trusted external source.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyDocument {
    /// External key-registry identifier.
    pub key_id: String,
    /// Signature algorithm, fixed to `Ed25519`.
    pub algorithm: String,
    /// Unpadded base64url Ed25519 public key.
    pub public_key_base64url: String,
}

impl PublicKeyDocument {
    /// Strictly decode this record as an Ed25519 verification key.
    pub fn verifying_key(&self) -> Result<VerifyingKey, Error> {
        if self.algorithm != "Ed25519" {
            return Err(Error::Key("only Ed25519 is allowed".into()));
        }
        if self.key_id.is_empty() {
            return Err(Error::Key("key_id must not be empty".into()));
        }
        omp_crypto::public_key_from_base64url(&self.public_key_base64url).map_err(Error::Crypto)
    }
}

/// Inputs needed to construct one single-asset manifest.
#[derive(Clone, Debug)]
pub struct CreateManifest<'a> {
    /// Registry-assigned manifest identifier.
    pub manifest_id: &'a str,
    /// Encoding-independent recording identifier.
    pub recording_id: &'a str,
    /// Musical-work identifier.
    pub work_id: &'a str,
    /// Optional release identifier.
    pub release_id: Option<&'a str>,
    /// Issuing party identifier.
    pub issuer_id: &'a str,
    /// Rights-agreement identifier.
    pub agreement_id: &'a str,
    /// License identifier.
    pub license_id: &'a str,
    /// Manifest-local asset identifier.
    pub asset_id: &'a str,
    /// Allowlisted audio media type.
    pub media_type: &'a str,
    /// RFC 3339 manifest creation timestamp.
    pub created_at: &'a str,
    /// External signing-key identifier.
    pub key_id: &'a str,
}

/// Manifest creation or verification failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Core parsing or validation failed.
    #[error(transparent)]
    Core(#[from] omp_core::Error),
    /// Cryptographic processing failed.
    #[error(transparent)]
    Crypto(#[from] omp_crypto::Error),
    /// The external key document is invalid.
    #[error("invalid key document: {0}")]
    Key(String),
    /// Manifest and trusted-key identifiers differ.
    #[error("signature key_id does not match supplied trusted key")]
    KeyIdMismatch,
    /// Local audio hash or size differs from the signed asset.
    #[error("asset does not match manifest (expected sha256 {expected_hash}, size {expected_size}; got sha256 {actual_hash}, size {actual_size})")]
    AssetMismatch {
        /// Hash authenticated by the manifest.
        expected_hash: String,
        /// Size authenticated by the manifest.
        expected_size: u64,
        /// Hash calculated from the local file.
        actual_hash: String,
        /// Size calculated from the local file.
        actual_size: u64,
    },
    /// No asset has the requested allowlisted media type.
    #[error("manifest does not contain an asset matching media type `{0}`")]
    NoMatchingAsset(String),
    /// Audio or manifest file I/O failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization failed.
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Create and sign a manifest for the exact bytes at `audio_path`.
pub fn create_signed(
    audio_path: &Path,
    input: &CreateManifest<'_>,
    signing_key: &SigningKey,
) -> Result<Manifest, Error> {
    let (hash, size) = omp_crypto::sha256_reader(File::open(audio_path)?)?;
    let mut manifest = Manifest {
        schema_version: "0.1".into(),
        manifest_id: input.manifest_id.into(),
        recording_id: input.recording_id.into(),
        work_id: input.work_id.into(),
        release_id: input.release_id.map(str::to_owned),
        issuer_id: input.issuer_id.into(),
        assets: vec![Asset {
            asset_id: input.asset_id.into(),
            media_type: input.media_type.into(),
            sha256: hash,
            size_bytes: size,
        }],
        agreement_id: input.agreement_id.into(),
        license_id: input.license_id.into(),
        created_at: input.created_at.into(),
        signature: Signature {
            algorithm: "Ed25519".into(),
            key_id: input.key_id.into(),
            value: "placeholder".into(),
        },
    };
    manifest.validate()?;
    let unsigned = unsigned_value(serde_json::to_value(&manifest)?)?;
    manifest.signature.value = omp_crypto::sign_object(&unsigned, signing_key)?;
    manifest.validate()?;
    Ok(manifest)
}

/// Serialize a manifest as readable JSON. Signature validity is independent
/// of whitespace and property order because verification applies JCS.
pub fn to_pretty_json(manifest: &Manifest) -> Result<Vec<u8>, Error> {
    manifest.validate()?;
    let mut bytes = serde_json::to_vec_pretty(manifest)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Parse, validate, and authenticate a manifest from raw JSON bytes.
pub fn verify_signature(input: &[u8], trusted_key: &PublicKeyDocument) -> Result<Manifest, Error> {
    let manifest: Manifest = parse_and_validate(input)?;
    if manifest.signature.algorithm != trusted_key.algorithm {
        return Err(Error::Key(
            "manifest and trusted-key algorithms differ".into(),
        ));
    }
    if manifest.signature.key_id != trusted_key.key_id {
        return Err(Error::KeyIdMismatch);
    }
    let key = trusted_key.verifying_key()?;
    let unsigned = unsigned_value(parse_value(input)?)?;
    omp_crypto::verify_object(&unsigned, &manifest.signature.value, &key)?;
    Ok(manifest)
}

/// Verify that an audio file exactly matches an asset entry in the manifest.
/// Matching is selected by the allowlisted media type inferred by the caller.
pub fn verify_asset(manifest: &Manifest, audio_path: &Path, media_type: &str) -> Result<(), Error> {
    let (actual_hash, actual_size) = omp_crypto::sha256_reader(File::open(audio_path)?)?;
    let mut candidates = manifest
        .assets
        .iter()
        .filter(|asset| asset.media_type == media_type);
    let first = candidates
        .next()
        .ok_or_else(|| Error::NoMatchingAsset(media_type.into()))?;
    if first.sha256 == actual_hash && first.size_bytes == actual_size {
        return Ok(());
    }
    if candidates.any(|asset| asset.sha256 == actual_hash && asset.size_bytes == actual_size) {
        return Ok(());
    }
    Err(Error::AssetMismatch {
        expected_hash: first.sha256.clone(),
        expected_size: first.size_bytes,
        actual_hash,
        actual_size,
    })
}

fn unsigned_value(mut value: Value) -> Result<Value, Error> {
    let object = value.as_object_mut().ok_or_else(|| {
        omp_core::Error::Validation("signed value must be a top-level object".into())
    })?;
    if object.remove("signature").is_none() {
        return Err(omp_core::Error::Validation(
            "signed object is missing top-level signature".into(),
        )
        .into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture(path: &str) -> Vec<u8> {
        std::fs::read(format!("../../omp-spec-v0.1/examples/{path}")).unwrap()
    }

    #[test]
    fn supplied_manifest_vector_verifies() {
        let key: PublicKeyDocument =
            serde_json::from_slice(&fixture("test-public-key.json")).unwrap();
        verify_signature(&fixture("manifest.json"), &key).unwrap();
    }

    #[test]
    fn whitespace_and_property_order_do_not_affect_signature() {
        let key: PublicKeyDocument =
            serde_json::from_slice(&fixture("test-public-key.json")).unwrap();
        let value: Value = serde_json::from_slice(&fixture("manifest.json")).unwrap();
        let compact = serde_json::to_vec(&value).unwrap();
        verify_signature(&compact, &key).unwrap();
    }

    #[test]
    fn tampering_truncation_wrong_key_and_duplicates_fail() {
        let key: PublicKeyDocument =
            serde_json::from_slice(&fixture("test-public-key.json")).unwrap();
        let mut value: Value = serde_json::from_slice(&fixture("manifest.json")).unwrap();
        value["issuer_id"] = Value::String("omp:party:attacker-001".into());
        assert!(verify_signature(&serde_json::to_vec(&value).unwrap(), &key).is_err());
        value = serde_json::from_slice(&fixture("manifest.json")).unwrap();
        value["signature"]["value"] = Value::String("AAAA".into());
        assert!(verify_signature(&serde_json::to_vec(&value).unwrap(), &key).is_err());
        let wrong = PublicKeyDocument {
            key_id: key.key_id.clone(),
            algorithm: key.algorithm.clone(),
            public_key_base64url: omp_crypto::encode_base64url(&[7; 32]),
        };
        assert!(verify_signature(&fixture("manifest.json"), &wrong).is_err());
        let duplicate = br#"{"schema_version":"0.1","schema_version":"0.1"}"#;
        assert!(verify_signature(duplicate, &key).is_err());
    }

    #[test]
    fn signed_manifest_checks_original_bytes() {
        let directory = std::env::temp_dir();
        let path = directory.join(format!("omp-test-{}.flac", std::process::id()));
        let mut file = File::create(&path).unwrap();
        file.write_all(b"not really flac").unwrap();
        drop(file);
        let key = omp_crypto::generate_signing_key();
        let input = CreateManifest {
            manifest_id: "omp:manifest:test-001",
            recording_id: "omp:recording:test-001",
            work_id: "omp:work:test-001",
            release_id: None,
            issuer_id: "omp:party:test-001",
            agreement_id: "omp:agreement:test-001",
            license_id: "omp:license:test-001",
            asset_id: "asset-001",
            media_type: "audio/flac",
            created_at: "2026-10-26T10:00:00Z",
            key_id: "key-001",
        };
        let manifest = create_signed(&path, &input, &key).unwrap();
        verify_asset(&manifest, &path, "audio/flac").unwrap();
        std::fs::write(&path, b"changed").unwrap();
        assert!(verify_asset(&manifest, &path, "audio/flac").is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn asset_verification_checks_every_candidate_of_the_media_type() {
        let path =
            std::env::temp_dir().join(format!("omp-multi-asset-test-{}.flac", std::process::id()));
        std::fs::write(&path, b"matching second asset").unwrap();
        let (hash, size) = omp_crypto::sha256_reader(File::open(&path).unwrap()).unwrap();
        let mut manifest: Manifest = serde_json::from_slice(&fixture("manifest.json")).unwrap();
        manifest.assets.push(Asset {
            asset_id: "asset-flac-02".into(),
            media_type: "audio/flac".into(),
            sha256: hash,
            size_bytes: size,
        });
        verify_asset(&manifest, &path, "audio/flac").unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
