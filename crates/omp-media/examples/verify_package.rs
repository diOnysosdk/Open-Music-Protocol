//! Verify the frozen CC0 package without any network access.

use omp_crypto::public_key_from_base64url;
use omp_media::{select_and_verify, AuthenticatedManifest, MediaPolicy, PackageRoot};
use serde_json::Value;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new("omp-spec-v0.2-draft");
    let vectors: Value = serde_json::from_slice(&std::fs::read(
        root.join("test-vectors/cryptographic-vectors.json"),
    )?)?;
    let public = vectors["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|key| key["key_id"] == "media-01"))
        .and_then(|key| key["public_key_base64url"].as_str())
        .ok_or("missing public fixture key")?;
    let manifest = vectors["vectors"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["object_type"] == "manifest"))
        .map(|item| &item["signed_object"])
        .ok_or("missing manifest vector")?;
    let key = public_key_from_base64url(public)?;

    // Authentication verifies bytes and signature. Authorization is separate.
    let authenticated =
        AuthenticatedManifest::parse_and_verify(&serde_json::to_vec(manifest)?, &key)?;
    let package = PackageRoot::open(root)?;
    let media = select_and_verify(&authenticated, &package, MediaPolicy::default())?;
    println!("verified {} {}", media.asset_id(), media.sha256());
    Ok(())
}
