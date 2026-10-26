use super::*;
use std::sync::Mutex;

/// Origin of an exact local pin.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PinOrigin {
    /// Explicit verification.
    Explicit,
    /// Introduction by an already verified identity.
    VerifiedIntroduction,
    /// Unverified TOFU; never ADR-013 eligible.
    TofuUnverified,
}

/// Exact durable pin facts required by ADR-013.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurablePin {
    /// Exact manifest hash.
    pub manifest_hash: String,
    /// Exact public-license hash.
    pub license_hash: String,
    /// Selected asset hash and size by signed asset ID.
    pub assets: BTreeMap<String, (String, u64)>,
    /// Signer identity.
    pub identity_id: String,
    /// Signer key.
    pub key_id: String,
    /// Demonstrated role.
    pub role: String,
    /// Genesis hash.
    pub genesis_hash: String,
    /// Accepted identity tip.
    pub identity_tip_hash: String,
    /// Identity high-water sequence.
    pub identity_sequence: u64,
    /// Accepted lifecycle tip.
    pub lifecycle_tip_hash: Option<String>,
    /// Lifecycle high-water sequence.
    pub lifecycle_sequence: Option<u64>,
    /// Prior demonstrated authorization.
    pub prior_authorization: Authorization,
    /// Pin provenance.
    pub origin: PinOrigin,
    /// Semantic profile used for verification.
    pub profile: String,
}

impl DurablePin {
    /// Whether this pin may support the narrow unknown-authorization exception.
    pub fn eligible_for_auth_unknown_playback(&self) -> bool {
        matches!(
            self.origin,
            PinOrigin::Explicit | PinOrigin::VerifiedIntroduction
        ) && matches!(
            self.prior_authorization,
            Authorization::AuthorizedCurrent | Authorization::AuthorizedHistorical
        ) && self.profile == "OMP-v0.2-historical-authorization-amendment-1"
    }
}

/// Complete rollback-monotonic local state.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustState {
    /// Atomic state generation.
    pub generation: u64,
    /// Hash of previous complete local state.
    pub previous_state_hash: Option<String>,
    /// Identity sequence high-water marks.
    pub identity_high_water: BTreeMap<String, u64>,
    /// Lifecycle sequence high-water marks.
    pub lifecycle_high_water: BTreeMap<String, u64>,
    /// Exact pins.
    pub pins: BTreeMap<String, DurablePin>,
    /// Explicit trust decisions; observation never promotes TOFU.
    pub identity_trust: BTreeMap<String, IdentityTrust>,
}

/// Platform persistence boundary.
///
/// Production implementations MUST authenticate state, preserve monotonic
/// high-water metadata, and provide durable atomic compare-and-swap. If those
/// guarantees are unavailable, operations requiring them fail closed.
pub trait TrustStateStore: Send + Sync {
    /// Load and integrity-check complete state.
    fn load(&self) -> Result<Option<TrustState>, Error>;
    /// Atomically replace state at the expected generation.
    fn compare_and_swap(
        &self,
        expected_generation: Option<u64>,
        next: &TrustState,
    ) -> Result<(), Error>;
}

/// Test-only/ephemeral atomic store without reboot rollback resistance.
#[derive(Default)]
pub struct MemoryTrustStore {
    state: Mutex<Option<TrustState>>,
    fail_next: Mutex<bool>,
}

impl MemoryTrustStore {
    /// Simulate an interrupted next commit.
    pub fn fail_next_write(&self) {
        *self.fail_next.lock().expect("mutex poisoned") = true;
    }
}

impl TrustStateStore for MemoryTrustStore {
    fn load(&self) -> Result<Option<TrustState>, Error> {
        Ok(self.state.lock().expect("mutex poisoned").clone())
    }

    fn compare_and_swap(
        &self,
        expected_generation: Option<u64>,
        next: &TrustState,
    ) -> Result<(), Error> {
        if *self.fail_next.lock().expect("mutex poisoned") {
            *self.fail_next.lock().expect("mutex poisoned") = false;
            return Err(Error::Integrity("simulated interrupted commit".into()));
        }
        let mut state = self.state.lock().expect("mutex poisoned");
        if state.as_ref().map(|item| item.generation) != expected_generation {
            return Err(Error::TrustRollback);
        }
        *state = Some(next.clone());
        Ok(())
    }
}

/// Atomically mutate state and extend its local hash chain.
pub fn update_trust_state<S: TrustStateStore>(
    store: &S,
    mutate: impl FnOnce(&mut TrustState) -> Result<(), Error>,
) -> Result<TrustState, Error> {
    let current = store.load()?;
    let expected = current.as_ref().map(|item| item.generation);
    let mut next = current.clone().unwrap_or_default();
    next.previous_state_hash = current.as_ref().map(local_state_hash).transpose()?;
    next.generation = match expected {
        Some(value) => value.checked_add(1).ok_or(Error::TrustRollback)?,
        None => 0,
    };
    mutate(&mut next)?;
    store.compare_and_swap(expected, &next)?;
    Ok(next)
}

/// Verify monotonic progression relative to already held trusted state.
pub fn verify_state_progression(previous: &TrustState, next: &TrustState) -> Result<(), Error> {
    if next.generation <= previous.generation
        || next.previous_state_hash.as_deref() != Some(&local_state_hash(previous)?)
    {
        return Err(Error::TrustRollback);
    }
    for (identity, sequence) in &previous.identity_high_water {
        if next.identity_high_water.get(identity).copied().unwrap_or(0) < *sequence {
            return Err(Error::TrustRollback);
        }
    }
    for (identity, sequence) in &previous.lifecycle_high_water {
        if next
            .lifecycle_high_water
            .get(identity)
            .copied()
            .unwrap_or(0)
            < *sequence
        {
            return Err(Error::TrustRollback);
        }
    }
    Ok(())
}
