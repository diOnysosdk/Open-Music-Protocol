use omp_crypto::{sign_v02, signing_key_from_base64url, V02Profile};
use omp_desktop::service::{inspect_package, prepare_package};
use omp_identity::IdentityTrust;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_slice(
        &std::fs::read("../../omp-spec-v0.2-draft/test-vectors/cryptographic-vectors.json")
            .unwrap(),
    )
    .unwrap()
}

fn object(vectors: &Value, kind: &str) -> Value {
    vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["object_type"] == kind)
        .unwrap()["signed_object"]
        .clone()
}

fn package() -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "omp-desktop-package-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(root.join("fixtures/audio")).unwrap();
    let vectors = vectors();
    let manifest = object(&vectors, "manifest");
    let identity = object(&vectors, "identity_document");
    let mut license = object(&vectors, "license");
    license["license_id"] = manifest["license_id"].clone();
    let fixture_key = vectors["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["key_id"] == "media-01")
        .unwrap();
    let signing =
        signing_key_from_base64url(fixture_key["private_seed_base64url"].as_str().unwrap())
            .unwrap();
    license["signature"]["value"] = sign_v02(V02Profile::License, &license, &signing)
        .unwrap()
        .into();
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("license.json"),
        serde_json::to_vec(&license).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join("identity.json"),
        serde_json::to_vec(&identity).unwrap(),
    )
    .unwrap();
    for name in ["omp-triangle-250ms.flac", "omp-triangle-250ms.wav"] {
        std::fs::copy(
            format!("../../omp-spec-v0.2-draft/fixtures/audio/{name}"),
            root.join("fixtures/audio").join(name),
        )
        .unwrap();
    }
    root
}

#[test]
fn deterministic_package_is_verified_indexed_and_prepared() {
    let root = package();
    let track = inspect_package(&root, IdentityTrust::Verified).unwrap();
    assert_eq!(track.title, "Northern Lights");
    assert!(track.security.authenticity.contains("Valid"));
    assert!(prepare_package(&root, IdentityTrust::Verified).is_ok());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn invalid_license_cannot_reach_prepared_playback() {
    let root = package();
    let path = root.join("license.json");
    let mut license: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    license["recording_id"] = "omp:recording:tampered".into();
    std::fs::write(path, serde_json::to_vec(&license).unwrap()).unwrap();
    assert!(inspect_package(&root, IdentityTrust::Verified).is_err());
    assert!(prepare_package(&root, IdentityTrust::Verified).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unknown_identity_never_reaches_index_or_playback() {
    let root = package();
    assert!(inspect_package(&root, IdentityTrust::Unknown).is_err());
    assert!(prepare_package(&root, IdentityTrust::Unknown).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
