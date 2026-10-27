//! Evaluate the frozen public/offline license with explicit trust facts.

use omp_crypto::public_key_from_base64url;
use omp_identity::{
    assess_signer, Freshness, HistoricalEvidence, IdentityTrust, ProductionFactProvider,
    ValidatedFactProvider,
};
use omp_license::{evaluate, AuthenticatedLicense, EvaluationInput, TrustAssessment};
use serde_json::Value;

fn vector<'a>(document: &'a Value, kind: &str) -> Result<&'a Value, &'static str> {
    document["vectors"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["object_type"] == kind))
        .map(|item| &item["signed_object"])
        .ok_or("missing fixture vector")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vectors: Value = serde_json::from_slice(&std::fs::read(
        "omp-spec-v0.2-draft/test-vectors/cryptographic-vectors.json",
    )?)?;
    let public = vectors["keys"]
        .as_array()
        .and_then(|keys| keys.iter().find(|key| key["key_id"] == "media-01"))
        .and_then(|key| key["public_key_base64url"].as_str())
        .ok_or("missing public fixture key")?;
    let key = public_key_from_base64url(public)?;
    let identity = ProductionFactProvider
        .identity_document(&serde_json::to_vec(vector(&vectors, "identity_document")?)?)?;

    // Authenticity, role authorization, and entitlement are independent steps.
    let license = AuthenticatedLicense::parse_and_verify(
        &serde_json::to_vec(vector(&vectors, "license")?)?,
        &key,
    )?;
    let signer = assess_signer(
        &identity,
        "media-01",
        "license",
        &[],
        IdentityTrust::Verified,
        Freshness::Fresh,
        HistoricalEvidence::None,
        None,
    );
    let permit = evaluate(
        &license,
        &EvaluationInput {
            recording_id: "omp:recording:track-v02-0001",
            license_id: "omp:license:public-free-001",
            subject_id: None,
            trust: TrustAssessment::from_w4(&signer),
            time: None,
        },
    )?;
    println!("license permit: {:?}", permit.kind());
    Ok(())
}
