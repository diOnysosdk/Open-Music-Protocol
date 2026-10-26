use omp_crypto::{public_key_from_base64url, sign_v02, signing_key_from_base64url, V02Profile};
use omp_identity::{
    assess_signer, Authorization, CurrentStatus, Freshness, HistoricalEvidence, IdentityTrust,
    PlaybackDecision, ProductionFactProvider, ValidatedFactProvider,
};
use omp_license::*;
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_slice(
        &std::fs::read("../../omp-spec-v0.2-draft/test-vectors/cryptographic-vectors.json")
            .unwrap(),
    )
    .unwrap()
}
fn object(kind: &str) -> Value {
    fixture()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["object_type"] == kind)
        .unwrap()["signed_object"]
        .clone()
}
fn key() -> Value {
    fixture()["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key_id"] == "media-01")
        .unwrap()
        .clone()
}
fn resign(v: &mut Value, profile: V02Profile, member: &str) {
    let k = key();
    let sk = signing_key_from_base64url(k["private_seed_base64url"].as_str().unwrap()).unwrap();
    v[member]["value"] = sign_v02(profile, v, &sk).unwrap().into();
}
fn public() -> ed25519_dalek::VerifyingKey {
    public_key_from_base64url(key()["public_key_base64url"].as_str().unwrap()).unwrap()
}
fn assessment(
    authorization: Authorization,
    current_status: CurrentStatus,
    identity_trust: IdentityTrust,
    freshness: Freshness,
    playback: Option<PlaybackDecision>,
) -> TrustAssessment {
    let identity = ProductionFactProvider
        .identity_document(&serde_json::to_vec(&object("identity_document")).unwrap())
        .unwrap();
    let events = if current_status == CurrentStatus::Revoked {
        vec![ProductionFactProvider
            .lifecycle_event(
                &serde_json::to_vec(&object("key_lifecycle_event")).unwrap(),
                identity.recovery(),
            )
            .unwrap()]
    } else {
        vec![]
    };
    let key_id = if authorization == Authorization::AuthorizationUnknown {
        "unknown-key"
    } else {
        "media-01"
    };
    TrustAssessment::from_w4(&assess_signer(
        &identity,
        key_id,
        "license",
        &events,
        identity_trust,
        freshness,
        HistoricalEvidence::None,
        playback,
    ))
}
fn trust() -> TrustAssessment {
    assessment(
        Authorization::AuthorizedCurrent,
        CurrentStatus::Active,
        IdentityTrust::Verified,
        Freshness::Fresh,
        None,
    )
}
fn input<'a>(time: Option<TrustedInterval>) -> EvaluationInput<'a> {
    EvaluationInput {
        recording_id: "omp:recording:track-v02-0001",
        license_id: "omp:license:public-free-001",
        subject_id: None,
        trust: trust(),
        time,
    }
}

#[test]
fn public_permanent_needs_no_clock_or_freshness() {
    let license = AuthenticatedLicense::parse_and_verify(
        &serde_json::to_vec(&object("license")).unwrap(),
        &public(),
    )
    .unwrap();
    let mut i = input(None);
    i.trust = assessment(
        Authorization::AuthorizedCurrent,
        CurrentStatus::Active,
        IdentityTrust::Verified,
        Freshness::Unknown,
        None,
    );
    assert_eq!(
        evaluate(&license, &i).unwrap().kind(),
        PermitKind::Authorized
    );
}

#[test]
fn subscription_boundaries_subject_and_recording_fail_closed() {
    let mut v = object("license");
    v["audience"] = "subject".into();
    v["mode"] = "subscription".into();
    v["subject_id"] =
        "omp:party:sha256-0021b78094508e06a0ae32f2bb0afb7a53b6a77361782a5e2ab28f87ad8f5bc9".into();
    v["offline_policy"] = json!({"kind":"time_limited","clock_requirement":"trusted_time"});
    v["valid_from"] = "2026-10-27T03:00:00Z".into();
    v["expires_at"] = "2026-10-27T03:00:10Z".into();
    resign(&mut v, V02Profile::License, "signature");
    let license =
        AuthenticatedLicense::parse_and_verify(&serde_json::to_vec(&v).unwrap(), &public())
            .unwrap();
    let anchor = AuthenticatedTimeAnchor::parse_and_verify(
        &serde_json::to_vec(&object("time_anchor")).unwrap(),
        &public(),
    )
    .unwrap();
    let state = accept_time_anchor(&anchor, trust(), 100, 0, None).unwrap();
    let mut i = input(Some(trusted_interval(&state, 100).unwrap()));
    i.subject_id = v["subject_id"].as_str();
    assert_eq!(
        evaluate(&license, &i).unwrap().kind(),
        PermitKind::Authorized
    );
    i.subject_id =
        Some("omp:party:sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(evaluate(&license, &i), Err(Error::SubjectMismatch));
    i.subject_id = v["subject_id"].as_str();
    i.recording_id = "omp:recording:wrong";
    assert_eq!(evaluate(&license, &i), Err(Error::BindingMismatch));
    let expired = trusted_interval(&state, 110).unwrap();
    i.recording_id = "omp:recording:track-v02-0001";
    i.time = Some(expired);
    assert_eq!(evaluate(&license, &i), Err(Error::Expired));
}

#[test]
fn trusted_time_rollback_age_uncertainty_and_missing_evidence_fail() {
    let anchor = AuthenticatedTimeAnchor::parse_and_verify(
        &serde_json::to_vec(&object("time_anchor")).unwrap(),
        &public(),
    )
    .unwrap();
    let state = accept_time_anchor(&anchor, trust(), 100, 5, None).unwrap();
    assert_eq!(
        trusted_interval(&state, 99),
        Err(Error::TrustedTimeRollback)
    );
    assert_eq!(
        trusted_interval(&state, 86501),
        Err(Error::TrustedTimeUnavailable)
    );
    let bad = assessment(
        Authorization::AuthorizationUnknown,
        CurrentStatus::Active,
        IdentityTrust::Verified,
        Freshness::Fresh,
        None,
    );
    assert_eq!(
        accept_time_anchor(&anchor, bad, 0, 1, None),
        Err(Error::TrustUnknown)
    );
}

#[test]
fn revoked_conflicted_stale_unknown_and_pinned_rules_are_distinct() {
    let license = AuthenticatedLicense::parse_and_verify(
        &serde_json::to_vec(&object("license")).unwrap(),
        &public(),
    )
    .unwrap();
    let mut i = input(None);
    i.trust = assessment(
        Authorization::AuthorizedCurrent,
        CurrentStatus::Revoked,
        IdentityTrust::Verified,
        Freshness::Fresh,
        None,
    );
    assert_eq!(evaluate(&license, &i), Err(Error::Revoked));
    i.trust = assessment(
        Authorization::AuthorizationUnknown,
        CurrentStatus::Unknown,
        IdentityTrust::Verified,
        Freshness::Unknown,
        Some(PlaybackDecision::PlaybackAllowedPinnedAuthUnknown),
    );
    assert_eq!(
        evaluate(&license, &i).unwrap().kind(),
        PermitKind::PinnedAuthorizationUnknown
    );
    i.trust = assessment(
        Authorization::AuthorizationUnknown,
        CurrentStatus::Unknown,
        IdentityTrust::Verified,
        Freshness::Unknown,
        None,
    );
    assert_eq!(evaluate(&license, &i), Err(Error::TrustUnknown));
}

#[test]
fn tampering_and_missing_time_are_rejected() {
    let mut v = object("license");
    v["recording_id"] = "omp:recording:changed".into();
    assert!(matches!(
        AuthenticatedLicense::parse_and_verify(&serde_json::to_vec(&v).unwrap(), &public()),
        Err(Error::SignatureInvalid)
    ));
}
