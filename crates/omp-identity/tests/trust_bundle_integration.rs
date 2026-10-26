use ed25519_dalek::VerifyingKey;
use omp_crypto::{
    public_key_from_base64url, sign_v02, signing_key_from_base64url, verify_v02, V02Profile,
};
use omp_identity::{merge_trust_facts, Error, ProductionFactProvider, ValidatedFactProvider};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn json(path: &str) -> Value {
    serde_json::from_slice(&std::fs::read(root().join(path)).unwrap()).unwrap()
}

fn frozen() -> Value {
    json("omp-spec-v0.2-draft/test-vectors/cryptographic-vectors.json")
}

fn frozen_vector(kind: &str) -> Value {
    frozen()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["object_type"] == kind)
        .unwrap()["signed_object"]
        .clone()
}

fn authorized_bundle() -> Value {
    json("omp-spec-v0.2-amendments/trust-bundle-vector/media-01-authorized.json")["signed_object"]
        .clone()
}

fn key_material(key_id: &str) -> Value {
    frozen()["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["key_id"] == key_id)
        .unwrap()
        .clone()
}

fn public_key(key_id: &str) -> VerifyingKey {
    public_key_from_base64url(
        key_material(key_id)["public_key_base64url"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
}

fn resign(value: &mut Value, profile: V02Profile, envelope: &str, key_id: &str) {
    let key = key_material(key_id);
    let signing_key =
        signing_key_from_base64url(key["private_seed_base64url"].as_str().unwrap()).unwrap();
    value[envelope][0]["key_id"] = key_id.into();
    value[envelope][0]["value"] = sign_v02(profile, value, &signing_key).unwrap().into();
}

#[test]
fn frozen_root_is_crypto_valid_but_w4_role_unauthorized() {
    let bundle = frozen_vector("trust_bundle");
    verify_v02(
        V02Profile::TrustBundle,
        &bundle,
        bundle["signatures"][0]["value"].as_str().unwrap(),
        &public_key("root-01"),
    )
    .unwrap();
    assert!(matches!(
        ProductionFactProvider.trust_bundle(&serde_json::to_vec(&bundle).unwrap()),
        Err(Error::KeyUnknown | Error::KeyUnauthorized)
    ));
}

#[test]
fn amendment_media_vector_passes_w3_and_w4() {
    let bundle = authorized_bundle();
    verify_v02(
        V02Profile::TrustBundle,
        &bundle,
        bundle["signatures"][0]["value"].as_str().unwrap(),
        &public_key("media-01"),
    )
    .unwrap();
    let validated = ProductionFactProvider
        .trust_bundle(&serde_json::to_vec(&bundle).unwrap())
        .unwrap();
    assert_eq!(
        validated.bundle_id(),
        "omp:trust-bundle:media-authorized-amendment-1"
    );
    assert_eq!(validated.identity_document_count(), 1);
    assert_eq!(validated.lifecycle_event_count(), 0);
}

#[test]
fn tampering_role_substitution_and_unknown_signers_fail_closed() {
    let mut tampered = authorized_bundle();
    tampered["created_at"] = "2026-10-26T13:00:01Z".into();
    assert!(matches!(
        ProductionFactProvider.trust_bundle(&serde_json::to_vec(&tampered).unwrap()),
        Err(Error::SignatureInvalid)
    ));

    let mut substituted = authorized_bundle();
    substituted["identity_documents"][0]["operational_keys"][0]["roles"] =
        serde_json::json!(["manifest", "license", "time-anchor"]);
    let identity = &mut substituted["identity_documents"][0];
    resign(identity, V02Profile::IdentityDocument, "proofs", "root-01");
    resign(
        &mut substituted,
        V02Profile::TrustBundle,
        "signatures",
        "media-01",
    );
    assert!(matches!(
        ProductionFactProvider.trust_bundle(&serde_json::to_vec(&substituted).unwrap()),
        Err(Error::KeyUnknown | Error::KeyUnauthorized)
    ));

    let mut unknown = authorized_bundle();
    unknown["signatures"][0]["key_id"] = "unknown-01".into();
    assert!(matches!(
        ProductionFactProvider.trust_bundle(&serde_json::to_vec(&unknown).unwrap()),
        Err(Error::KeyUnknown)
    ));
}

#[test]
fn revoked_publishers_and_undeclared_identity_forks_are_rejected() {
    let mut revoked = authorized_bundle();
    revoked["lifecycle_events"] = serde_json::json!([frozen_vector("key_lifecycle_event")]);
    resign(
        &mut revoked,
        V02Profile::TrustBundle,
        "signatures",
        "media-01",
    );
    assert!(matches!(
        ProductionFactProvider.trust_bundle(&serde_json::to_vec(&revoked).unwrap()),
        Err(Error::KeyRevoked)
    ));

    let mut forked = authorized_bundle();
    let mut competing = forked["identity_documents"][0].clone();
    competing["issued_at"] = "2026-10-26T12:00:01Z".into();
    resign(
        &mut competing,
        V02Profile::IdentityDocument,
        "proofs",
        "root-01",
    );
    forked["identity_documents"]
        .as_array_mut()
        .unwrap()
        .push(competing);
    resign(
        &mut forked,
        V02Profile::TrustBundle,
        "signatures",
        "media-01",
    );
    assert!(matches!(
        ProductionFactProvider.trust_bundle(&serde_json::to_vec(&forked).unwrap()),
        Err(Error::TrustConflict)
    ));
}

#[test]
fn authenticated_bundle_merge_is_arrival_order_independent() {
    let first = authorized_bundle();
    let mut second = first.clone();
    second["bundle_id"] = "omp:trust-bundle:media-authorized-amendment-2".into();
    resign(
        &mut second,
        V02Profile::TrustBundle,
        "signatures",
        "media-01",
    );
    let first = ProductionFactProvider
        .trust_bundle(&serde_json::to_vec(&first).unwrap())
        .unwrap();
    let second = ProductionFactProvider
        .trust_bundle(&serde_json::to_vec(&second).unwrap())
        .unwrap();
    assert_eq!(
        merge_trust_facts(&[first.clone(), second.clone()]).unwrap(),
        merge_trust_facts(&[second, first]).unwrap()
    );
}
