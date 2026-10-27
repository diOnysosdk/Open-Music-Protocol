use omp_crypto::{public_key_from_base64url, sign_v02, signing_key_from_base64url, V02Profile};
use omp_media::{select_and_verify, AuthenticatedManifest, Error, MediaPolicy, PackageRoot};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::PathBuf};

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn vectors() -> Value {
    serde_json::from_slice(
        &fs::read(repository().join("omp-spec-v0.2-draft/test-vectors/cryptographic-vectors.json"))
            .unwrap(),
    )
    .unwrap()
}

fn manifest() -> Value {
    vectors()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["object_type"] == "manifest")
        .unwrap()["signed_object"]
        .clone()
}

fn media_key() -> Value {
    vectors()["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["key_id"] == "media-01")
        .unwrap()
        .clone()
}

fn resign(manifest: &mut Value) {
    let key = media_key();
    let signing =
        signing_key_from_base64url(key["private_seed_base64url"].as_str().unwrap()).unwrap();
    manifest["signature"]["value"] = sign_v02(V02Profile::Manifest, manifest, &signing)
        .unwrap()
        .into();
}

fn authenticate(value: &Value) -> Result<AuthenticatedManifest, Error> {
    let key = media_key();
    let public = public_key_from_base64url(key["public_key_base64url"].as_str().unwrap()).unwrap();
    AuthenticatedManifest::parse_and_verify(&serde_json::to_vec(value).unwrap(), &public)
}

fn frozen_root() -> PackageRoot {
    PackageRoot::open(repository().join("omp-spec-v0.2-draft")).unwrap()
}

fn single_primary() -> Value {
    let mut value = manifest();
    value["assets"].as_array_mut().unwrap().truncate(1);
    resign(&mut value);
    value
}

fn package_copy() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let audio = directory.path().join("fixtures/audio");
    fs::create_dir_all(&audio).unwrap();
    for name in ["omp-triangle-250ms.flac", "omp-triangle-250ms.wav"] {
        fs::copy(
            repository()
                .join("omp-spec-v0.2-draft/fixtures/audio")
                .join(name),
            audio.join(name),
        )
        .unwrap();
    }
    directory
}

#[test]
fn wav_flac_selection_is_deterministic_and_handle_is_rewound() {
    let original = manifest();
    let authenticated = authenticate(&original).unwrap();
    let verified =
        select_and_verify(&authenticated, &frozen_root(), MediaPolicy::default()).unwrap();
    assert_eq!(verified.asset_id(), "primary-flac");
    assert_eq!(verified.media_type(), "audio/flac");
    let mut magic = [0; 4];
    verified.into_file().read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"fLaC");

    let mut reversed = original;
    reversed["assets"].as_array_mut().unwrap().reverse();
    resign(&mut reversed);
    let selected = select_and_verify(
        &authenticate(&reversed).unwrap(),
        &frozen_root(),
        MediaPolicy::default(),
    )
    .unwrap();
    assert_eq!(selected.asset_id(), "primary-flac");
}

#[test]
fn altered_bytes_size_hash_and_media_type_fail_closed() {
    let directory = package_copy();
    let path = directory
        .path()
        .join("fixtures/audio/omp-triangle-250ms.flac");
    let mut bytes = fs::read(&path).unwrap();
    bytes[100] ^= 1;
    fs::write(&path, bytes).unwrap();
    assert!(matches!(
        select_and_verify(
            &authenticate(&single_primary()).unwrap(),
            &PackageRoot::open(directory.path()).unwrap(),
            MediaPolicy::default()
        ),
        Err(Error::BindingInvalid(_))
    ));

    let mut wrong_size = single_primary();
    wrong_size["assets"][0]["size_bytes"] = 2221.into();
    resign(&mut wrong_size);
    assert!(matches!(
        select_and_verify(
            &authenticate(&wrong_size).unwrap(),
            &frozen_root(),
            MediaPolicy::default()
        ),
        Err(Error::BindingInvalid(_))
    ));

    let mut wrong_hash = single_primary();
    wrong_hash["assets"][0]["sha256"] = "0".repeat(64).into();
    resign(&mut wrong_hash);
    assert!(matches!(
        select_and_verify(
            &authenticate(&wrong_hash).unwrap(),
            &frozen_root(),
            MediaPolicy::default()
        ),
        Err(Error::BindingInvalid(_))
    ));

    let mut wrong_type = single_primary();
    wrong_type["assets"][0]["media_type"] = "audio/wav".into();
    resign(&mut wrong_type);
    assert!(matches!(
        select_and_verify(
            &authenticate(&wrong_type).unwrap(),
            &frozen_root(),
            MediaPolicy::default()
        ),
        Err(Error::MediaTypeInvalid)
    ));
}

#[test]
fn metadata_paths_collisions_and_unsupported_codecs_are_rejected() {
    let mut metadata_tamper = manifest();
    metadata_tamper["metadata"]["title"] = "Changed".into();
    assert!(matches!(
        authenticate(&metadata_tamper),
        Err(Error::SignatureInvalid)
    ));

    let mut non_nfc = manifest();
    non_nfc["metadata"]["title"] = "Cafe\u{301}".into();
    resign(&mut non_nfc);
    assert!(matches!(authenticate(&non_nfc), Err(Error::Schema(_))));

    let mut collision = manifest();
    collision["assets"][1]["relative_path"] = "FIXTURES/AUDIO/OMP-TRIANGLE-250MS.FLAC".into();
    resign(&mut collision);
    assert!(matches!(authenticate(&collision), Err(Error::PathConflict)));

    let mut reserved = single_primary();
    reserved["assets"][0]["relative_path"] = "fixtures/CON.flac".into();
    resign(&mut reserved);
    assert!(matches!(
        authenticate(&reserved),
        Err(Error::PathInvalid(_))
    ));

    for invalid in ["../outside.flac", "/absolute.flac", "audio\\song.flac"] {
        let mut value = single_primary();
        value["assets"][0]["relative_path"] = invalid.into();
        resign(&mut value);
        assert!(matches!(authenticate(&value), Err(Error::Schema(_))));
    }

    let mut unsupported = single_primary();
    unsupported["assets"][0]["media_type"] = "audio/mpeg".into();
    resign(&mut unsupported);
    assert!(matches!(
        select_and_verify(
            &authenticate(&unsupported).unwrap(),
            &frozen_root(),
            MediaPolicy::default()
        ),
        Err(Error::AssetUnavailable)
    ));
}

#[test]
fn verified_snapshot_survives_path_replacement() {
    let directory = package_copy();
    let authenticated = authenticate(&single_primary()).unwrap();
    let verified = select_and_verify(
        &authenticated,
        &PackageRoot::open(directory.path()).unwrap(),
        MediaPolicy::default(),
    )
    .unwrap();
    let original_hash = verified.sha256().to_owned();
    fs::write(
        directory
            .path()
            .join("fixtures/audio/omp-triangle-250ms.flac"),
        b"substitution",
    )
    .unwrap();
    let mut bytes = Vec::new();
    verified.into_file().read_to_end(&mut bytes).unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(bytes)), original_hash);
}

#[test]
fn symlink_or_reparse_asset_is_rejected_when_platform_allows_creation() {
    let directory = package_copy();
    let target = directory
        .path()
        .join("fixtures/audio/omp-triangle-250ms.flac");
    let link = directory.path().join("fixtures/audio/link.flac");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).unwrap();
    #[cfg(windows)]
    if let Err(error) = std::os::windows::fs::symlink_file(&target, &link) {
        eprintln!("SKIP: Windows symlink privilege unavailable: {error}");
        return;
    }
    let mut value = single_primary();
    value["assets"][0]["relative_path"] = "fixtures/audio/link.flac".into();
    resign(&mut value);
    assert!(matches!(
        select_and_verify(
            &authenticate(&value).unwrap(),
            &PackageRoot::open(directory.path()).unwrap(),
            MediaPolicy::default()
        ),
        Err(Error::PathInvalid(_))
    ));
}

#[test]
fn oversized_flac_metadata_declaration_is_rejected_before_decode() {
    let mut malicious = b"fLaC".to_vec();
    malicious.extend_from_slice(&[0x00, 0xff, 0xff, 0xff]);
    malicious.resize(70, 0);
    assert!(matches!(
        omp_media::validate_container_structure(
            &mut std::io::Cursor::new(&malicious),
            "audio/flac",
            malicious.len() as u64,
        ),
        Err(Error::ResourceLimit)
    ));
}

#[test]
fn flac_bytes_cannot_enter_the_wav_decoder_profile() {
    let bytes = b"fLaC/\0\0\0\x04\0\x09]\0\0\0\0\0ID\x09]\0L\xff";
    assert!(matches!(
        omp_media::validate_container_structure(
            &mut std::io::Cursor::new(bytes),
            "audio/wav",
            bytes.len() as u64,
        ),
        Err(Error::MediaTypeInvalid)
    ));
}

#[test]
fn impossible_flac_streaminfo_frame_sizes_are_rejected_before_decode() {
    let bytes = b"fLaC\0\0\0\x22\0\x2d\0\x60\x21\xfe\x0a\0\0\0\0\x43fLa\xf3\xa5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x32\x06\0\0\x22\0\x2d\0\x60\0\0\0\0\xf9\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf9\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    assert!(matches!(
        omp_media::validate_container_structure(
            &mut std::io::Cursor::new(bytes),
            "audio/flac",
            bytes.len() as u64,
        ),
        Err(Error::ResourceLimit)
    ));
}
