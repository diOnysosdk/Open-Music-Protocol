use omp_core::v02::{self, WireVersion};
use omp_core::Validate;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_slice(
        &std::fs::read("../../omp-spec-v0.2-draft/test-vectors/cryptographic-vectors.json")
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn every_frozen_crypto_object_matches_the_typed_model() {
    for vector in fixture()["vectors"].as_array().unwrap() {
        let bytes = serde_json::to_vec(&vector["signed_object"]).unwrap();
        assert_eq!(v02::detect_version(&bytes).unwrap(), WireVersion::V02);
        match vector["object_type"].as_str().unwrap() {
            "manifest" => v02::parse::<v02::Manifest>(&bytes)
                .unwrap()
                .validate()
                .unwrap(),
            "identity_document" => v02::parse::<v02::IdentityDocument>(&bytes)
                .unwrap()
                .validate()
                .unwrap(),
            "key_lifecycle_event" => v02::parse::<v02::KeyLifecycleEvent>(&bytes)
                .unwrap()
                .validate()
                .unwrap(),
            "license" => v02::parse::<v02::License>(&bytes)
                .unwrap()
                .validate()
                .unwrap(),
            "trust_bundle" => v02::parse::<v02::TrustBundle>(&bytes)
                .unwrap()
                .validate()
                .unwrap(),
            "time_anchor" => v02::parse::<v02::TimeAnchor>(&bytes)
                .unwrap()
                .validate()
                .unwrap(),
            other => panic!("unexpected vector type {other}"),
        }
    }
}

#[test]
fn duplicate_unknown_version_and_unknown_fields_fail_closed() {
    assert!(v02::detect_version(br#"{"schema_version":"0.2","schema_version":"0.2"}"#).is_err());
    assert!(v02::detect_version(br#"{"schema_version":"9.9"}"#).is_err());
    let identity = fixture()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["object_type"] == "identity_document")
        .unwrap()["signed_object"]
        .clone();
    let mut unknown = identity;
    unknown["undeclared"] = Value::Bool(true);
    assert!(v02::parse::<v02::IdentityDocument>(&serde_json::to_vec(&unknown).unwrap()).is_err());
}

#[test]
fn non_nfc_and_cross_field_failures_are_rejected() {
    let manifest = serde_json::from_slice::<Value>(
        &std::fs::read(
            "../../omp-spec-v0.2-draft/test-vectors/manifest-metadata-multiasset.valid.json",
        )
        .unwrap(),
    )
    .unwrap();
    let mut non_nfc = manifest.clone();
    non_nfc["metadata"]["title"] = Value::String("Cafe\u{301}".into());
    assert!(v02::parse::<v02::Manifest>(&serde_json::to_vec(&non_nfc).unwrap()).is_err());
    let mut traversal = manifest.clone();
    traversal["assets"][0]["relative_path"] = Value::String("../escape.wav".into());
    assert!(v02::parse::<v02::Manifest>(&serde_json::to_vec(&traversal).unwrap()).is_err());
    let mut duplicate_rank = manifest;
    duplicate_rank["assets"][1]["selection_rank"] =
        duplicate_rank["assets"][0]["selection_rank"].clone();
    assert!(v02::parse::<v02::Manifest>(&serde_json::to_vec(&duplicate_rank).unwrap()).is_err());
}

#[test]
fn v01_dispatch_remains_exact() {
    let bytes = std::fs::read("../../omp-spec-v0.1/examples/manifest.json").unwrap();
    assert_eq!(v02::detect_version(&bytes).unwrap(), WireVersion::V01);
    assert!(v02::parse::<v02::Manifest>(&bytes).is_err());
    omp_core::parse_and_validate::<omp_core::Manifest>(&bytes).unwrap();
}
