use omp_crypto::{public_key_from_base64url, sign_v02, signing_key_from_base64url, V02Profile};
use omp_identity::{
    assess_durable_pin, Authorization, DurablePin, DurablePinStore, Freshness, HistoricalEvidence,
    IdentityTrust, PinOrigin, PinnedArtifactEvidence, ProductionFactProvider, TrustState,
    TrustStateStore, ValidatedFactProvider,
};
use omp_media::{MediaPolicy, PackageRoot};
use omp_player::{decode_headless, play_with_sink, prepare, AudioSink, DecodeLimits, TrustPolicy};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

struct SecureTestStore(Mutex<Option<TrustState>>);
impl TrustStateStore for SecureTestStore {
    fn load(&self) -> Result<Option<TrustState>, omp_identity::Error> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn compare_and_swap(
        &self,
        _: Option<u64>,
        next: &TrustState,
    ) -> Result<(), omp_identity::Error> {
        *self.0.lock().unwrap() = Some(next.clone());
        Ok(())
    }
}
impl DurablePinStore for SecureTestStore {
    fn rollback_protection_available(&self) -> bool {
        true
    }
}

struct MockSink(AtomicBool);
impl AudioSink for MockSink {
    fn play(&self, mut file: File) -> Result<(), omp_player::Error> {
        let mut magic = [0; 4];
        file.read_exact(&mut magic)?;
        assert_eq!(&magic, b"fLaC");
        self.0.store(true, Ordering::SeqCst);
        Ok(())
    }
}
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_slice(
        &std::fs::read("../../omp-spec-v0.2-draft/test-vectors/cryptographic-vectors.json")
            .unwrap(),
    )
    .unwrap()
}
fn object(kind: &str) -> Vec<u8> {
    let f = fixture();
    serde_json::to_vec(
        &f["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["object_type"] == kind)
            .unwrap()["signed_object"],
    )
    .unwrap()
}
fn public() -> ed25519_dalek::VerifyingKey {
    let f = fixture();
    let k = f["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["key_id"] == "media-01")
        .unwrap();
    public_key_from_base64url(k["public_key_base64url"].as_str().unwrap()).unwrap()
}
fn matching_license() -> Vec<u8> {
    let f = fixture();
    let mut value: Value = serde_json::from_slice(&object("license")).unwrap();
    value["license_id"] = "omp:license:license-v02-0001".into();
    let key = f["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["key_id"] == "media-01")
        .unwrap();
    let signing =
        signing_key_from_base64url(key["private_seed_base64url"].as_str().unwrap()).unwrap();
    value["signature"]["value"] = sign_v02(V02Profile::License, &value, &signing)
        .unwrap()
        .into();
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn frozen_public_package_decodes_fully_offline() {
    let identity = ProductionFactProvider
        .identity_document(&object("identity_document"))
        .unwrap();
    let root = PackageRoot::open("../../omp-spec-v0.2-draft").unwrap();
    let policy = TrustPolicy {
        identity: &identity,
        lifecycle: &[],
        key_id: "media-01",
        identity_trust: IdentityTrust::Verified,
        freshness: Freshness::Unknown,
        historical_evidence: HistoricalEvidence::None,
        playback: None,
        pinned_assessment: None,
    };
    let prepared = prepare(
        &object("manifest"),
        &matching_license(),
        &public(),
        &root,
        &policy,
        None,
        None,
        MediaPolicy::default(),
    )
    .unwrap();
    let report = decode_headless(prepared, DecodeLimits::default()).unwrap();
    assert_eq!(report.recording_id, "omp:recording:track-v02-0001");
    assert_eq!(report.asset_id, "primary-flac");
    assert!(report.decoded_frames > 0);
}

#[test]
fn revoked_signer_is_denied_before_decoder() {
    let identity = ProductionFactProvider
        .identity_document(&object("identity_document"))
        .unwrap();
    let event = ProductionFactProvider
        .lifecycle_event(&object("key_lifecycle_event"), identity.recovery())
        .unwrap();
    let root = PackageRoot::open("../../omp-spec-v0.2-draft").unwrap();
    let policy = TrustPolicy {
        identity: &identity,
        lifecycle: &[event],
        key_id: "media-01",
        identity_trust: IdentityTrust::Verified,
        freshness: Freshness::Fresh,
        historical_evidence: HistoricalEvidence::None,
        playback: None,
        pinned_assessment: None,
    };
    assert!(prepare(
        &object("manifest"),
        &object("license"),
        &public(),
        &root,
        &policy,
        None,
        None,
        MediaPolicy::default()
    )
    .is_err());
}

#[test]
fn audio_sink_receives_only_prepared_verified_handle() {
    let identity = ProductionFactProvider
        .identity_document(&object("identity_document"))
        .unwrap();
    let root = PackageRoot::open("../../omp-spec-v0.2-draft").unwrap();
    let policy = TrustPolicy {
        identity: &identity,
        lifecycle: &[],
        key_id: "media-01",
        identity_trust: IdentityTrust::Verified,
        freshness: Freshness::Unknown,
        historical_evidence: HistoricalEvidence::None,
        playback: None,
        pinned_assessment: None,
    };
    let prepared = prepare(
        &object("manifest"),
        &matching_license(),
        &public(),
        &root,
        &policy,
        None,
        None,
        MediaPolicy::default(),
    )
    .unwrap();
    let sink = MockSink(AtomicBool::new(false));
    play_with_sink(prepared, &sink).unwrap();
    assert!(sink.0.load(Ordering::SeqCst));
}

#[test]
fn adr013_opaque_pin_flows_through_w6_and_w7() {
    let identity = ProductionFactProvider
        .identity_document(&object("identity_document"))
        .unwrap();
    let manifest_value: Value = serde_json::from_slice(&object("manifest")).unwrap();
    let license_bytes = matching_license();
    let license_value: Value = serde_json::from_slice(&license_bytes).unwrap();
    let manifest_hash = omp_crypto::canonical_object_sha256(&manifest_value).unwrap();
    let license_hash = omp_crypto::canonical_object_sha256(&license_value).unwrap();
    let assets: BTreeMap<_, _> = manifest_value["assets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["asset_id"].as_str().unwrap().to_owned(),
                (
                    a["sha256"].as_str().unwrap().to_owned(),
                    a["size_bytes"].as_u64().unwrap(),
                ),
            )
        })
        .collect();
    let pin = DurablePin {
        manifest_hash: manifest_hash.clone(),
        license_hash: license_hash.clone(),
        assets: assets.clone(),
        identity_id: identity.identity_id().to_owned(),
        key_id: "media-01".into(),
        roles: ["manifest".into(), "license".into()].into_iter().collect(),
        genesis_hash: identity.genesis_hash().to_owned(),
        identity_tip_hash: identity.complete_hash().to_owned(),
        identity_sequence: identity.sequence(),
        lifecycle_tip_hash: None,
        lifecycle_sequence: None,
        prior_authorization: Authorization::AuthorizedCurrent,
        origin: PinOrigin::Explicit,
        profile: "OMP-v0.2-historical-authorization-amendment-1".into(),
    };
    let mut state = TrustState {
        generation: 1,
        ..TrustState::default()
    };
    state
        .identity_high_water
        .insert(identity.identity_id().to_owned(), identity.sequence());
    state.pins.insert("track".into(), pin);
    let store = SecureTestStore(Mutex::new(Some(state)));
    let evidence = PinnedArtifactEvidence {
        pin_id: "track",
        manifest_hash: &manifest_hash,
        license_hash: &license_hash,
        assets: &assets,
    };
    let assessment = assess_durable_pin(&store, &evidence, &identity, &[]).unwrap();
    let policy = TrustPolicy {
        identity: &identity,
        lifecycle: &[],
        key_id: "media-01",
        identity_trust: IdentityTrust::Verified,
        freshness: Freshness::Unknown,
        historical_evidence: HistoricalEvidence::None,
        playback: None,
        pinned_assessment: Some(&assessment),
    };
    let root = PackageRoot::open("../../omp-spec-v0.2-draft").unwrap();
    let prepared = prepare(
        &object("manifest"),
        &license_bytes,
        &public(),
        &root,
        &policy,
        None,
        None,
        MediaPolicy::default(),
    )
    .unwrap();
    let report = decode_headless(prepared, DecodeLimits::default()).unwrap();
    assert_eq!(
        report.classification,
        omp_license::PermitKind::PinnedAuthorizationUnknown
    );
}
