use super::*;

fn recovery(threshold: usize) -> RecoveryPolicyFact {
    RecoveryPolicyFact {
        threshold,
        key_ids: ["r1", "r2", "r3"].into_iter().map(str::to_owned).collect(),
        public_keys_base64url: BTreeMap::new(),
    }
}

fn document(sequence: u64, previous: Option<&str>, hash: &str) -> ValidatedIdentityDocument {
    ValidatedIdentityDocument {
        complete_hash: hash.repeat(64 / hash.len()),
        identity_id: format!("omp:party:sha256-{}", "a".repeat(64)),
        sequence,
        previous_document_hash: previous.map(str::to_owned),
        genesis_hash: "b".repeat(64),
        recovery: recovery(2),
        operational_keys: BTreeMap::from([
            (
                "manifest-key".into(),
                OperationalKeyFact {
                    key_id: "manifest-key".into(),
                    roles: ["manifest".into()].into_iter().collect(),
                    public_key_base64url: String::new(),
                },
            ),
            (
                "next-key".into(),
                OperationalKeyFact {
                    key_id: "next-key".into(),
                    roles: ["manifest".into()].into_iter().collect(),
                    public_key_base64url: String::new(),
                },
            ),
        ]),
        valid_proof_keys: ["r1".into(), "r2".into()].into_iter().collect(),
    }
}

fn event(sequence: u64, previous: Option<&str>, hash: &str) -> ValidatedLifecycleEvent {
    ValidatedLifecycleEvent {
        complete_hash: hash.repeat(64 / hash.len()),
        identity_id: format!("omp:party:sha256-{}", "a".repeat(64)),
        sequence,
        previous_event_hash: previous.map(str::to_owned),
        kind: LifecycleKind::Revoke,
        key_id: Some("manifest-key".into()),
        successor_key_id: None,
        reason: Some(RevocationReason::Compromised),
        valid_proof_keys: ["r1".into(), "r2".into()].into_iter().collect(),
    }
}

#[test]
fn threshold_chain_and_rollback_are_deterministic() {
    let genesis = document(0, None, "11");
    let next = document(1, Some(&genesis.complete_hash), "22");
    validate_identity_chain(&[genesis.clone(), next]).unwrap();
    let mut insufficient = genesis.clone();
    insufficient.valid_proof_keys = ["r1".into()].into_iter().collect();
    assert!(matches!(
        validate_identity_chain(&[insufficient]),
        Err(Error::KeyUnauthorized)
    ));
    let bad = document(1, Some(&"ff".repeat(32)), "22");
    assert!(matches!(
        validate_identity_chain(&[genesis, bad]),
        Err(Error::TrustRollback)
    ));
}

#[test]
fn lifecycle_revocation_and_threshold_are_enforced() {
    let identity = document(0, None, "11");
    let first = event(0, None, "33");
    validate_lifecycle_chain(
        std::slice::from_ref(&first),
        std::slice::from_ref(&identity),
    )
    .unwrap();
    assert_eq!(
        current_key_status("manifest-key", &[first], false),
        CurrentStatus::Revoked
    );
}

#[test]
fn forks_do_not_depend_on_arrival_order() {
    let left = document(0, None, "11");
    let right = document(0, None, "22");
    assert_eq!(
        detect_identity_forks(&[left.clone(), right.clone()]),
        detect_identity_forks(&[right, left])
    );
}

fn pin(origin: PinOrigin) -> DurablePin {
    DurablePin {
        manifest_hash: "1".repeat(64),
        license_hash: "2".repeat(64),
        assets: BTreeMap::from([("primary".into(), ("3".repeat(64), 100))]),
        identity_id: format!("omp:party:sha256-{}", "a".repeat(64)),
        key_id: "manifest-key".into(),
        roles: ["manifest".into(), "license".into()].into_iter().collect(),
        genesis_hash: "b".repeat(64),
        identity_tip_hash: "c".repeat(64),
        identity_sequence: 0,
        lifecycle_tip_hash: None,
        lifecycle_sequence: None,
        prior_authorization: Authorization::AuthorizedCurrent,
        origin,
        profile: "OMP-v0.2-historical-authorization-amendment-1".into(),
    }
}

#[test]
fn adr013_exception_is_exact_and_never_authorization() {
    let eligible = pin(PinOrigin::Explicit);
    let base = PlaybackInput {
        authorization: Authorization::AuthorizationUnknown,
        current_status: CurrentStatus::Unknown,
        public_unrestricted: true,
        restricted_operation: false,
        pin: Some(&eligible),
        exact_pin_match: true,
        pin_state_integrity: true,
        adr007_conflicted_pinned: false,
        adr008_stale_permanent: false,
    };
    assert_eq!(
        evaluate_playback(&base),
        PlaybackDecision::PlaybackAllowedPinnedAuthUnknown
    );
    assert_eq!(
        evaluate_playback(&PlaybackInput {
            restricted_operation: true,
            ..base
        }),
        PlaybackDecision::PlaybackDenied
    );
    assert_eq!(
        evaluate_playback(&PlaybackInput {
            exact_pin_match: false,
            ..base
        }),
        PlaybackDecision::PlaybackDenied
    );
    let tofu = pin(PinOrigin::TofuUnverified);
    assert_eq!(
        evaluate_playback(&PlaybackInput {
            pin: Some(&tofu),
            ..base
        }),
        PlaybackDecision::PlaybackDenied
    );
}

#[test]
fn revocation_and_conflict_take_precedence() {
    let eligible = pin(PinOrigin::Explicit);
    let base = PlaybackInput {
        authorization: Authorization::AuthorizationUnknown,
        current_status: CurrentStatus::Revoked,
        public_unrestricted: true,
        restricted_operation: false,
        pin: Some(&eligible),
        exact_pin_match: true,
        pin_state_integrity: true,
        adr007_conflicted_pinned: false,
        adr008_stale_permanent: false,
    };
    assert_eq!(evaluate_playback(&base), PlaybackDecision::PlaybackDenied);
    assert_eq!(
        evaluate_playback(&PlaybackInput {
            current_status: CurrentStatus::Conflict,
            ..base
        }),
        PlaybackDecision::PlaybackDenied
    );
}

#[test]
fn backdating_is_not_an_authorization_input() {
    let key = OperationalKeyFact {
        key_id: "manifest-key".into(),
        roles: ["manifest".into()].into_iter().collect(),
        public_key_base64url: String::new(),
    };
    assert_eq!(
        evaluate_authorization(&AuthorizationInput {
            key: Some(&key),
            required_role: "manifest",
            current_status: CurrentStatus::Revoked,
            historical_evidence: HistoricalEvidence::None,
        }),
        Authorization::AuthorizationUnknown
    );
    assert_eq!(
        evaluate_authorization(&AuthorizationInput {
            key: Some(&key),
            required_role: "manifest",
            current_status: CurrentStatus::Revoked,
            historical_evidence: HistoricalEvidence::ProvenPreBoundary,
        }),
        Authorization::AuthorizedHistorical
    );
}

#[test]
fn bundle_merge_is_order_independent() {
    let identity = document(0, None, "11");
    let one = ValidatedTrustBundle {
        complete_hash: "d".repeat(64),
        bundle_id: "bundle-1".into(),
        identity_documents: vec![identity],
        lifecycle_events: vec![],
        conflicts: BTreeSet::new(),
        freshness: Freshness::Fresh,
    };
    let two = ValidatedTrustBundle {
        complete_hash: "e".repeat(64),
        bundle_id: "bundle-2".into(),
        identity_documents: vec![],
        lifecycle_events: vec![],
        conflicts: BTreeSet::new(),
        freshness: Freshness::Unknown,
    };
    assert_eq!(
        merge_trust_facts(&[one.clone(), two.clone()]).unwrap(),
        merge_trust_facts(&[two, one]).unwrap()
    );
}

#[test]
fn durable_state_commit_is_atomic_and_rollback_checked() {
    let store = MemoryTrustStore::default();
    let first = update_trust_state(&store, |state| {
        state.pins.insert("track".into(), pin(PinOrigin::Explicit));
        Ok(())
    })
    .unwrap();
    store.fail_next_write();
    assert!(update_trust_state(&store, |_| Ok(())).is_err());
    assert_eq!(store.load().unwrap(), Some(first.clone()));
    let second = update_trust_state(&store, |state| {
        state.identity_high_water.insert("identity".into(), 2);
        Ok(())
    })
    .unwrap();
    verify_state_progression(&first, &second).unwrap();
}

#[test]
fn tofu_is_not_silently_promoted() {
    let store = MemoryTrustStore::default();
    update_trust_state(&store, |state| {
        state
            .identity_trust
            .insert("identity".into(), IdentityTrust::UnverifiedTofu);
        Ok(())
    })
    .unwrap();
    let next = update_trust_state(&store, |_| Ok(())).unwrap();
    assert_eq!(
        next.identity_trust.get("identity"),
        Some(&IdentityTrust::UnverifiedTofu)
    );
}

impl DurablePinStore for MemoryTrustStore {
    fn rollback_protection_available(&self) -> bool {
        true
    }
}

#[test]
fn durable_pin_assessment_is_opaque_exact_and_rejects_tofu() {
    let identity = document(0, None, "11");
    let store = MemoryTrustStore::default();
    let mut exact = pin(PinOrigin::Explicit);
    exact.identity_tip_hash = identity.complete_hash.clone();
    exact.identity_id = identity.identity_id.clone();
    exact.genesis_hash = identity.genesis_hash.clone();
    update_trust_state(&store, |state| {
        state
            .identity_high_water
            .insert(identity.identity_id.clone(), 0);
        state.pins.insert("track".into(), exact.clone());
        Ok(())
    })
    .unwrap();
    let evidence = PinnedArtifactEvidence {
        pin_id: "track",
        manifest_hash: &exact.manifest_hash,
        license_hash: &exact.license_hash,
        assets: &exact.assets,
    };
    let result = assess_durable_pin(&store, &evidence, &identity, &[]).unwrap();
    assert_eq!(result.authorization(), Authorization::AuthorizationUnknown);
    assert_eq!(
        result.playback(),
        Some(PlaybackDecision::PlaybackAllowedPinnedAuthUnknown)
    );

    update_trust_state(&store, |state| {
        state.pins.get_mut("track").unwrap().origin = PinOrigin::TofuUnverified;
        Ok(())
    })
    .unwrap();
    assert!(assess_durable_pin(&store, &evidence, &identity, &[]).is_err());
}

#[test]
fn semantic_fixture_profile_is_present() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../omp-spec-v0.2-amendments/historical-authorization/semantic-fixtures.json");
    let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        fixture["profile"],
        "OMP-v0.2-historical-authorization-amendment-1"
    );
    assert_eq!(fixture["cases"].as_array().unwrap().len(), 13);
}

fn crypto_vector(kind: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../omp-spec-v0.2-draft/test-vectors/cryptographic-vectors.json");
    let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let object = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["object_type"] == kind)
        .unwrap()["signed_object"]
        .clone();
    serde_json::to_vec(&object).unwrap()
}

fn crypto_fixture() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../omp-spec-v0.2-draft/test-vectors/cryptographic-vectors.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn production_adapter_authenticates_identity_and_lifecycle_vectors() {
    let provider = ProductionFactProvider;
    let identity = provider
        .identity_document(&crypto_vector("identity_document"))
        .unwrap();
    let lifecycle = provider
        .lifecycle_event(&crypto_vector("key_lifecycle_event"), &identity.recovery)
        .unwrap();
    validate_identity_chain(std::slice::from_ref(&identity)).unwrap();
    validate_lifecycle_chain(&[lifecycle], &[identity]).unwrap();
}

#[test]
fn production_adapter_rejects_tampering_and_unauthorized_bundle_signer() {
    let provider = ProductionFactProvider;
    let mut identity: serde_json::Value =
        serde_json::from_slice(&crypto_vector("identity_document")).unwrap();
    identity["issued_at"] = "2026-10-27T00:00:00Z".into();
    assert!(matches!(
        provider.identity_document(&serde_json::to_vec(&identity).unwrap()),
        Err(Error::SignatureInvalid)
    ));

    // Frozen vector root-01 is cryptographically valid but lacks the
    // operational trust-bundle role, so authenticated facts must not cross.
    assert!(matches!(
        provider.trust_bundle(&crypto_vector("trust_bundle")),
        Err(Error::KeyUnknown | Error::KeyUnauthorized)
    ));
}

#[test]
fn production_adapter_rejects_role_authorized_but_revoked_bundle_signature() {
    use omp_crypto::{sign_v02, signing_key_from_base64url, V02Profile};

    let fixture = crypto_fixture();
    let mut bundle = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["object_type"] == "trust_bundle")
        .unwrap()["signed_object"]
        .clone();
    let key = fixture["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["key_id"] == "media-01")
        .unwrap();
    let signing_key =
        signing_key_from_base64url(key["private_seed_base64url"].as_str().unwrap()).unwrap();
    bundle["signatures"][0]["key_id"] = "media-01".into();
    bundle["signatures"][0]["value"] = sign_v02(V02Profile::TrustBundle, &bundle, &signing_key)
        .unwrap()
        .into();
    assert!(matches!(
        ProductionFactProvider.trust_bundle(&serde_json::to_vec(&bundle).unwrap()),
        Err(Error::KeyRevoked)
    ));
}
