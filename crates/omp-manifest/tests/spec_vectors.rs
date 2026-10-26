use omp_core::{
    parse_and_validate, parse_value, ApiError, License, PlaybackReceipt, RightsAgreement,
    Settlement,
};
use omp_manifest::PublicKeyDocument;
use serde_json::Value;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("../../omp-spec-v0.1/examples/{name}.json")).unwrap()
}

fn verify_signed_fixture(name: &str) {
    let key: PublicKeyDocument = serde_json::from_slice(&fixture("test-public-key")).unwrap();
    let verifying_key = key.verifying_key().unwrap();
    let mut value = parse_value(&fixture(name)).unwrap();
    let signature = value["signature"]["value"].as_str().unwrap().to_owned();
    value.as_object_mut().unwrap().remove("signature");
    omp_crypto::verify_object(&value, &signature, &verifying_key).unwrap();
    let mut tampered = value;
    tampered["schema_version"] = Value::String("tampered".into());
    assert!(omp_crypto::verify_object(&tampered, &signature, &verifying_key).is_err());
}

#[test]
fn every_supplied_object_matches_models_semantics_and_signatures() {
    let _: RightsAgreement = parse_and_validate(&fixture("rights-agreement")).unwrap();
    verify_signed_fixture("rights-agreement");
    let _: License = parse_and_validate(&fixture("license")).unwrap();
    verify_signed_fixture("license");
    let _: PlaybackReceipt = parse_and_validate(&fixture("playback-receipt")).unwrap();
    verify_signed_fixture("playback-receipt");
    let _: Settlement = parse_and_validate(&fixture("settlement")).unwrap();
    verify_signed_fixture("settlement");
    let _: ApiError = parse_and_validate(&fixture("api-error")).unwrap();
}

#[test]
fn malformed_semantics_are_rejected() {
    let mut agreement: Value = serde_json::from_slice(&fixture("rights-agreement")).unwrap();
    agreement["splits"][0]["basis_points"] = Value::from(7999);
    assert!(
        parse_and_validate::<RightsAgreement>(&serde_json::to_vec(&agreement).unwrap()).is_err()
    );

    let mut receipt: Value = serde_json::from_slice(&fixture("playback-receipt")).unwrap();
    receipt["sequence"] = Value::from(1);
    assert!(parse_and_validate::<PlaybackReceipt>(&serde_json::to_vec(&receipt).unwrap()).is_err());

    let mut settlement: Value = serde_json::from_slice(&fixture("settlement")).unwrap();
    settlement["deductions_minor"] = Value::String("1".into());
    assert!(parse_and_validate::<Settlement>(&serde_json::to_vec(&settlement).unwrap()).is_err());

    let mut api_error: Value = serde_json::from_slice(&fixture("api-error")).unwrap();
    api_error["error"]["details"] = serde_json::json!(["must", "be", "an", "object"]);
    assert!(parse_and_validate::<ApiError>(&serde_json::to_vec(&api_error).unwrap()).is_err());
}
