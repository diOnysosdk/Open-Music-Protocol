use super::*;

/// Order-independent merged trust facts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustFacts {
    /// Identity facts keyed by complete hash.
    pub identity_documents: BTreeMap<String, ValidatedIdentityDocument>,
    /// Lifecycle facts keyed by complete hash.
    pub lifecycle_events: BTreeMap<String, ValidatedLifecycleEvent>,
    /// All conflicts in deterministic order.
    pub conflicts: BTreeSet<(String, u64, Vec<String>)>,
    /// Worst known freshness across merged inputs.
    pub freshness: Freshness,
}

/// Merge already authenticated bundle facts independent of arrival order.
pub fn merge_trust_facts(bundles: &[ValidatedTrustBundle]) -> Result<TrustFacts, Error> {
    let mut facts = TrustFacts::default();
    for bundle in bundles {
        let identity_forks = detect_identity_forks(&bundle.identity_documents);
        let lifecycle_forks = detect_lifecycle_forks(&bundle.lifecycle_events);
        if identity_forks
            .iter()
            .chain(lifecycle_forks.iter())
            .any(|fork| !bundle.conflicts.contains(fork))
        {
            return Err(Error::TrustConflict);
        }
        for document in &bundle.identity_documents {
            facts
                .identity_documents
                .insert(document.complete_hash.clone(), document.clone());
        }
        for event in &bundle.lifecycle_events {
            facts
                .lifecycle_events
                .insert(event.complete_hash.clone(), event.clone());
        }
        facts.conflicts.extend(bundle.conflicts.iter().cloned());
        facts.freshness = merge_freshness(facts.freshness, bundle.freshness);
    }
    Ok(facts)
}

fn merge_freshness(left: Freshness, right: Freshness) -> Freshness {
    if left == Freshness::Stale || right == Freshness::Stale {
        Freshness::Stale
    } else if left == Freshness::Unknown || right == Freshness::Unknown {
        Freshness::Unknown
    } else {
        Freshness::Fresh
    }
}

/// Independent ADR-013 historical evidence classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoricalEvidence {
    /// Durable observation interval is wholly before the adverse boundary.
    ProvenPreBoundary,
    /// Evidence is absent.
    None,
    /// Evidence touches or crosses the boundary.
    CrossesBoundary,
    /// Required trusted time is unavailable.
    MissingTrustedTime,
    /// Durable state regressed.
    Rollback,
}

/// Authorization evaluation inputs.
pub struct AuthorizationInput<'a> {
    /// Accepted operational key facts.
    pub key: Option<&'a OperationalKeyFact>,
    /// Required role.
    pub required_role: &'a str,
    /// Current lifecycle status.
    pub current_status: CurrentStatus,
    /// Independent historical evidence.
    pub historical_evidence: HistoricalEvidence,
}

/// Evaluate authorization without considering signer-controlled timestamps.
pub fn evaluate_authorization(input: &AuthorizationInput<'_>) -> Authorization {
    let Some(key) = input.key else {
        return Authorization::AuthorizationUnknown;
    };
    if !key.roles.contains(input.required_role) {
        return Authorization::Unauthorized;
    }
    if input.current_status == CurrentStatus::Active {
        Authorization::AuthorizedCurrent
    } else if input.historical_evidence == HistoricalEvidence::ProvenPreBoundary {
        Authorization::AuthorizedHistorical
    } else {
        Authorization::AuthorizationUnknown
    }
}

/// Derive current key status from validated lifecycle and conflict facts.
pub fn current_key_status(
    key_id: &str,
    events: &[ValidatedLifecycleEvent],
    identity_conflicted: bool,
) -> CurrentStatus {
    if identity_conflicted {
        CurrentStatus::Conflict
    } else if events
        .iter()
        .any(|event| event.kind == LifecycleKind::Revoke && event.key_id.as_deref() == Some(key_id))
    {
        CurrentStatus::Revoked
    } else {
        CurrentStatus::Active
    }
}

/// Inputs to the narrow playback policy boundary.
#[derive(Clone, Copy)]
pub struct PlaybackInput<'a> {
    /// Authorization axis.
    pub authorization: Authorization,
    /// Current status.
    pub current_status: CurrentStatus,
    /// Content is public and unrestricted.
    pub public_unrestricted: bool,
    /// Operation is restricted or authority-granting.
    pub restricted_operation: bool,
    /// Exact durable pin.
    pub pin: Option<&'a DurablePin>,
    /// Current bytes exactly match all pin bindings.
    pub exact_pin_match: bool,
    /// Platform store confirms integrity and anti-rollback.
    pub pin_state_integrity: bool,
    /// ADR-007 independently authorizes conflicted pinned playback.
    pub adr007_conflicted_pinned: bool,
    /// ADR-008 independently authorizes stale permanent-subject playback.
    pub adr008_stale_permanent: bool,
}

/// Evaluate playback without converting availability into authorization.
pub fn evaluate_playback(input: &PlaybackInput<'_>) -> PlaybackDecision {
    if input.restricted_operation {
        return if input.adr008_stale_permanent
            && input.current_status == CurrentStatus::Active
            && matches!(
                input.authorization,
                Authorization::AuthorizedCurrent | Authorization::AuthorizedHistorical
            ) {
            PlaybackDecision::ValidStale
        } else {
            PlaybackDecision::PlaybackDenied
        };
    }
    if input.current_status == CurrentStatus::Conflict {
        return if input.adr007_conflicted_pinned
            && input.authorization == Authorization::AuthorizedHistorical
        {
            PlaybackDecision::ValidConflictedPinned
        } else {
            PlaybackDecision::PlaybackDenied
        };
    }
    if input.current_status == CurrentStatus::Revoked {
        return PlaybackDecision::PlaybackDenied;
    }
    if input.public_unrestricted
        && matches!(
            input.authorization,
            Authorization::AuthorizedCurrent | Authorization::AuthorizedHistorical
        )
    {
        return PlaybackDecision::PlaybackAllowed;
    }
    if input.public_unrestricted
        && input.authorization == Authorization::AuthorizationUnknown
        && input.current_status == CurrentStatus::Unknown
        && input.exact_pin_match
        && input.pin_state_integrity
        && input
            .pin
            .is_some_and(DurablePin::eligible_for_auth_unknown_playback)
    {
        PlaybackDecision::PlaybackAllowedPinnedAuthUnknown
    } else {
        PlaybackDecision::PlaybackDenied
    }
}
