use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::VerifyingKey;
use omp_crypto::{v02_identity_id, v02_signing_bytes, verify_v02, V02Profile};
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
        let signed = vector["signed_object"].clone();
        let excluded = vector["excluded_top_level_member"].as_str().unwrap();
        let envelope = if signed[excluded].is_array() {
            signed[excluded][0].clone()
        } else {
            signed[excluded].clone()
        };
        let profile = match vector["object_type"].as_str().unwrap() {
            "manifest" => V02Profile::Manifest,
            "identity_document" => V02Profile::IdentityDocument,
            "key_lifecycle_event" => V02Profile::KeyLifecycleEvent,
            "license" => V02Profile::License,
            "trust_bundle" => V02Profile::TrustBundle,
            "time_anchor" => V02Profile::TimeAnchor,
            other => panic!("unknown vector type {other}"),
        };
        let payload = v02_signing_bytes(profile, &signed).unwrap();
        let canonical = &payload[vector["domain_ascii"].as_str().unwrap().len() + 1..];
        assert_eq!(
            canonical,
            decode(vector["unsigned_jcs_utf8_base64url"].as_str().unwrap())
        );
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
        let public = VerifyingKey::from_bytes(&public).unwrap();
        verify_v02(
            profile,
            &signed,
            envelope["value"].as_str().unwrap(),
            &public,
        )
        .unwrap();
        if profile != V02Profile::Manifest {
            assert!(verify_v02(
                V02Profile::Manifest,
                &signed,
                envelope["value"].as_str().unwrap(),
                &public,
            )
            .is_err());
        }
    }

    let identity = &fixture["vectors"][0]["signed_object"];
    assert_eq!(
        v02_identity_id(&identity["genesis_body"]).unwrap(),
        fixture["identity_id"].as_str().unwrap()
    );
}

#[test]
fn v02_profiles_fail_closed_on_envelope_and_encoding_errors() {
    let fixture: Value = serde_json::from_slice(
        &std::fs::read("../../omp-spec-v0.2-draft/test-vectors/cryptographic-vectors.json")
            .unwrap(),
    )
    .unwrap();
    let vector = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["object_type"] == "manifest")
        .unwrap();
    let signed = &vector["signed_object"];
    let envelope = &signed["signature"];
    let key = fixture["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["key_id"] == envelope["key_id"])
        .unwrap();
    let public: [u8; 32] = decode(key["public_key_base64url"].as_str().unwrap())
        .try_into()
        .unwrap();
    let public = VerifyingKey::from_bytes(&public).unwrap();

    let mut missing = signed.clone();
    missing.as_object_mut().unwrap().remove("signature");
    assert!(v02_signing_bytes(V02Profile::Manifest, &missing).is_err());
    assert!(verify_v02(
        V02Profile::Manifest,
        signed,
        &format!("{}=", envelope["value"].as_str().unwrap()),
        &public,
    )
    .is_err());
    let mut tampered = signed.clone();
    tampered["created_at"] = "2026-10-27T00:00:00Z".into();
    assert!(verify_v02(
        V02Profile::Manifest,
        &tampered,
        envelope["value"].as_str().unwrap(),
        &public,
    )
    .is_err());
}
