//! Reproduce the post-freeze role-authorized trust-bundle vector.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use omp_crypto::{
    canonical_object_sha256, sign_v02, signing_key_from_base64url, v02_signing_bytes, V02Profile,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let frozen_path = root.join("omp-spec-v0.2-draft/test-vectors/cryptographic-vectors.json");
    let frozen: Value = serde_json::from_slice(&fs::read(frozen_path).expect("read frozen vector"))
        .expect("parse frozen vector");
    let mut bundle = frozen["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .find(|item| item["object_type"] == "trust_bundle")
        .expect("trust bundle")["signed_object"]
        .clone();

    bundle["bundle_id"] = "omp:trust-bundle:media-authorized-amendment-1".into();
    // The frozen lifecycle event revokes media-01. The positive amendment
    // deliberately represents the preceding active state.
    bundle["created_at"] = "2026-10-26T13:00:00Z".into();
    bundle["next_update_at"] = "2026-11-02T13:00:00Z".into();
    bundle["lifecycle_events"] = json!([]);
    bundle["signatures"] = json!([{
        "algorithm": "Ed25519",
        "key_id": "media-01",
        "value": ""
    }]);

    let key = frozen["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .find(|key| key["key_id"] == "media-01")
        .expect("media key");
    let signing_key = signing_key_from_base64url(
        key["private_seed_base64url"]
            .as_str()
            .expect("private test seed"),
    )
    .expect("decode test key");
    let signature = sign_v02(V02Profile::TrustBundle, &bundle, &signing_key).expect("sign");
    bundle["signatures"][0]["value"] = signature.into();

    let payload = v02_signing_bytes(V02Profile::TrustBundle, &bundle).expect("payload");
    let fixture = json!({
        "profile": "OMP-v0.2-trust-bundle-vector-amendment-1",
        "baseline": "OMP-v0.2-w0-freeze.1",
        "classification": "role-authorized-positive",
        "signed_object": bundle,
        "signing_payload_base64url": URL_SAFE_NO_PAD.encode(&payload),
        "signing_payload_sha256": format!("{:x}", Sha256::digest(&payload)),
        "complete_object_sha256": canonical_object_sha256(&bundle).expect("complete hash"),
        "expected": {
            "w3_signature": "VALID",
            "w4_authorization": "AUTHORIZED_CURRENT"
        }
    });
    let output = root.join("omp-spec-v0.2-amendments/trust-bundle-vector/media-01-authorized.json");
    fs::create_dir_all(output.parent().expect("output parent")).expect("create output directory");
    let mut bytes = serde_json::to_vec_pretty(&fixture).expect("serialize fixture");
    bytes.push(b'\n');
    fs::write(&output, bytes).expect("write fixture");
    println!("{}", output.display());
}
