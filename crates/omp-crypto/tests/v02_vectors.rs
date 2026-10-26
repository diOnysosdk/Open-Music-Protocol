use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

fn decode(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value).expect("valid base64url")
}

#[test]
fn python_generated_v02_vectors_match_rust_jcs_and_ed25519() {
    let bytes =
        std::fs::read("../../omp-spec-v0.2-draft/test-vectors/cryptographic-vectors.json").unwrap();
    let fixture: Value = serde_json::from_slice(&bytes).unwrap();
    let keys: HashMap<&str, &Value> = fixture["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| (key["key_id"].as_str().unwrap(), key))
        .collect();

    for vector in fixture["vectors"].as_array().unwrap() {
        let mut unsigned = vector["signed_object"].clone();
        let excluded = vector["excluded_top_level_member"].as_str().unwrap();
        let envelope = if unsigned[excluded].is_array() {
            unsigned[excluded][0].clone()
        } else {
            unsigned[excluded].clone()
        };
        unsigned.as_object_mut().unwrap().remove(excluded);
        let canonical = serde_jcs::to_vec(&unsigned).unwrap();
        assert_eq!(
            canonical,
            decode(vector["unsigned_jcs_utf8_base64url"].as_str().unwrap())
        );
        let mut payload = vector["domain_ascii"].as_str().unwrap().as_bytes().to_vec();
        payload.push(0);
        payload.extend_from_slice(&canonical);
        assert_eq!(
            payload,
            decode(vector["signing_payload_base64url"].as_str().unwrap())
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&payload)),
            vector["signing_payload_sha256"].as_str().unwrap()
        );

        let key_id = envelope["key_id"].as_str().unwrap();
        let public: [u8; 32] = decode(keys[key_id]["public_key_base64url"].as_str().unwrap())
            .try_into()
            .unwrap();
        let signature =
            Signature::from_slice(&decode(envelope["value"].as_str().unwrap())).unwrap();
        VerifyingKey::from_bytes(&public)
            .unwrap()
            .verify(&payload, &signature)
            .unwrap();
    }

    let identity = &fixture["vectors"][0]["signed_object"];
    let genesis = serde_jcs::to_vec(&identity["genesis_body"]).unwrap();
    let mut commitment_input = b"OMP-IDENTITY-GENESIS-v0.2\0".to_vec();
    commitment_input.extend_from_slice(&genesis);
    assert_eq!(
        format!("omp:party:sha256-{:x}", Sha256::digest(commitment_input)),
        fixture["identity_id"].as_str().unwrap()
    );
}
