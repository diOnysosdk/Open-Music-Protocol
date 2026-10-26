use super::*;

/// Validate authenticated identity facts as one strict hash-linked chain.
pub fn validate_identity_chain(
    chain: &[ValidatedIdentityDocument],
) -> Result<&ValidatedIdentityDocument, Error> {
    let first = chain.first().ok_or(Error::IdentityUnknown)?;
    validate_policy(first)?;
    if first.sequence != 0 || first.previous_document_hash.is_some() {
        return Err(Error::TrustRollback);
    }
    threshold(&first.recovery, &first.valid_proof_keys)?;
    for pair in chain.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        validate_policy(current)?;
        if current.identity_id != first.identity_id
            || current.genesis_hash != first.genesis_hash
            || current.sequence != previous.sequence + 1
            || current.previous_document_hash.as_deref() != Some(&previous.complete_hash)
        {
            return Err(Error::TrustRollback);
        }
        threshold(&previous.recovery, &current.valid_proof_keys)?;
    }
    Ok(chain.last().expect("nonempty checked"))
}

/// Validate authenticated lifecycle facts against an accepted identity chain.
pub fn validate_lifecycle_chain(
    events: &[ValidatedLifecycleEvent],
    identity_chain: &[ValidatedIdentityDocument],
) -> Result<(), Error> {
    let identity = validate_identity_chain(identity_chain)?;
    for (index, event) in events.iter().enumerate() {
        if event.identity_id != identity.identity_id || event.sequence != index as u64 {
            return Err(Error::TrustRollback);
        }
        let expected = index
            .checked_sub(1)
            .map(|previous| &events[previous].complete_hash);
        if event.previous_event_hash.as_ref() != expected {
            return Err(Error::TrustRollback);
        }
        threshold(&identity.recovery, &event.valid_proof_keys)?;
        match event.kind {
            LifecycleKind::Activate => {}
            LifecycleKind::Rotate => {
                let (Some(old), Some(new)) = (&event.key_id, &event.successor_key_id) else {
                    return Err(Error::InvalidFact("rotation key IDs missing".into()));
                };
                if !identity.operational_keys.contains_key(old)
                    || !identity.operational_keys.contains_key(new)
                {
                    return Err(Error::KeyUnknown);
                }
            }
            LifecycleKind::Revoke => {
                let Some(key) = &event.key_id else {
                    return Err(Error::InvalidFact("revocation key missing".into()));
                };
                if !identity.operational_keys.contains_key(key) || event.reason.is_none() {
                    return Err(Error::KeyUnknown);
                }
            }
        }
    }
    Ok(())
}

fn validate_policy(document: &ValidatedIdentityDocument) -> Result<(), Error> {
    if document.complete_hash.len() != 64
        || document.genesis_hash.len() != 64
        || document.recovery.threshold == 0
        || document.recovery.threshold > document.recovery.key_ids.len()
    {
        return Err(Error::InvalidFact(
            "invalid validated identity facts".into(),
        ));
    }
    Ok(())
}

fn threshold(policy: &RecoveryPolicyFact, valid: &BTreeSet<String>) -> Result<(), Error> {
    let count = valid.intersection(&policy.key_ids).count();
    if count < policy.threshold {
        Err(Error::KeyUnauthorized)
    } else {
        Ok(())
    }
}

/// Detect identity forks deterministically without arrival-order selection.
pub fn detect_identity_forks(
    documents: &[ValidatedIdentityDocument],
) -> Vec<(String, u64, Vec<String>)> {
    forks(documents.iter().map(|item| {
        (
            item.identity_id.clone(),
            item.sequence,
            item.complete_hash.clone(),
        )
    }))
}

/// Detect lifecycle forks deterministically without arrival-order selection.
pub fn detect_lifecycle_forks(
    events: &[ValidatedLifecycleEvent],
) -> Vec<(String, u64, Vec<String>)> {
    forks(events.iter().map(|item| {
        (
            item.identity_id.clone(),
            item.sequence,
            item.complete_hash.clone(),
        )
    }))
}

fn forks(facts: impl Iterator<Item = (String, u64, String)>) -> Vec<(String, u64, Vec<String>)> {
    let mut grouped: BTreeMap<(String, u64), BTreeSet<String>> = BTreeMap::new();
    for (identity, sequence, hash) in facts {
        grouped
            .entry((identity, sequence))
            .or_default()
            .insert(hash);
    }
    grouped
        .into_iter()
        .filter_map(|((identity, sequence), hashes)| {
            (hashes.len() > 1).then(|| (identity, sequence, hashes.into_iter().collect()))
        })
        .collect()
}
