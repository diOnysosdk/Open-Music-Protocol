//! Concrete W2/W3 authenticated-fact adapter.

use super::*;
use omp_core::v02;
use omp_crypto::{canonical_object_sha256, public_key_from_base64url, verify_v02, V02Profile};
use serde_json::Value;

/// Production adapter using `omp-core` W2 models and `omp-crypto` W3 profiles.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionFactProvider;

impl private::Sealed for ProductionFactProvider {}

impl ValidatedFactProvider for ProductionFactProvider {
    fn identity_document(&self, bytes: &[u8]) -> Result<ValidatedIdentityDocument, Error> {
        let document = v02::parse::<v02::IdentityDocument>(bytes).map_err(core_error)?;
        let expected = omp_crypto::v02_identity_id(&document.genesis_body).map_err(crypto_error)?;
        if expected != document.identity_id {
            return Err(Error::SignatureInvalid);
        }
        let keys: BTreeMap<_, _> = document
            .genesis_body
            .root_keys
            .iter()
            .map(|key| (key.key_id.clone(), key.public_key_base64url.clone()))
            .collect();
        let value = serde_json::to_value(&document)?;
        let proofs = verify_proofs(
            V02Profile::IdentityDocument,
            &value,
            &document.proofs,
            &keys,
        )?;
        Ok(ValidatedIdentityDocument {
            complete_hash: canonical_object_sha256(&document).map_err(crypto_error)?,
            identity_id: document.identity_id,
            sequence: document.sequence,
            previous_document_hash: document.previous_document_hash,
            genesis_hash: canonical_object_sha256(&document.genesis_body).map_err(crypto_error)?,
            recovery: RecoveryPolicyFact {
                threshold: usize::try_from(document.genesis_body.recovery.threshold)
                    .map_err(|_| Error::InvalidFact("recovery threshold overflow".into()))?,
                key_ids: document.genesis_body.recovery.key_ids.into_iter().collect(),
                public_keys_base64url: keys,
            },
            operational_keys: document
                .operational_keys
                .into_iter()
                .map(|key| {
                    (
                        key.key_id.clone(),
                        OperationalKeyFact {
                            key_id: key.key_id,
                            roles: key.roles.into_iter().collect(),
                            public_key_base64url: key.public_key_base64url,
                        },
                    )
                })
                .collect(),
            valid_proof_keys: proofs,
        })
    }

    fn lifecycle_event(
        &self,
        bytes: &[u8],
        recovery: &RecoveryPolicyFact,
    ) -> Result<ValidatedLifecycleEvent, Error> {
        let event = v02::parse::<v02::KeyLifecycleEvent>(bytes).map_err(core_error)?;
        let value = serde_json::to_value(&event)?;
        let proofs = verify_proofs(
            V02Profile::KeyLifecycleEvent,
            &value,
            &event.proofs,
            &recovery.public_keys_base64url,
        )?;
        Ok(ValidatedLifecycleEvent {
            complete_hash: canonical_object_sha256(&event).map_err(crypto_error)?,
            identity_id: event.identity_id,
            sequence: event.sequence,
            previous_event_hash: event.previous_event_hash,
            kind: match event.event_type {
                v02::LifecycleEventType::Activate => LifecycleKind::Activate,
                v02::LifecycleEventType::Rotate => LifecycleKind::Rotate,
                v02::LifecycleEventType::Revoke => LifecycleKind::Revoke,
            },
            key_id: event.key_id,
            successor_key_id: event.successor_key_id,
            reason: event.reason.map(|reason| match reason {
                v02::RevocationReason::Superseded => RevocationReason::Superseded,
                v02::RevocationReason::Compromised => RevocationReason::Compromised,
                v02::RevocationReason::Lost => RevocationReason::Lost,
                v02::RevocationReason::Retired => RevocationReason::Retired,
            }),
            valid_proof_keys: proofs,
        })
    }

    fn trust_bundle(&self, bytes: &[u8]) -> Result<ValidatedTrustBundle, Error> {
        let bundle = v02::parse::<v02::TrustBundle>(bytes).map_err(core_error)?;
        let mut identities = Vec::with_capacity(bundle.identity_documents.len());
        for document in &bundle.identity_documents {
            identities.push(self.identity_document(&serde_json::to_vec(document)?)?);
        }
        let by_identity: BTreeMap<_, _> = identities
            .iter()
            .map(|identity| (identity.identity_id.clone(), identity))
            .collect();
        let mut events = Vec::with_capacity(bundle.lifecycle_events.len());
        for event in &bundle.lifecycle_events {
            let identity = by_identity
                .get(&event.identity_id)
                .ok_or(Error::IdentityUnknown)?;
            events.push(self.lifecycle_event(&serde_json::to_vec(event)?, &identity.recovery)?);
        }
        let identity_forks = detect_identity_forks(&identities);
        let lifecycle_forks = detect_lifecycle_forks(&events);
        let declared_conflicts: BTreeSet<_> = bundle
            .conflicts
            .iter()
            .map(|conflict| {
                let mut hashes = conflict.document_hashes.clone();
                hashes.sort();
                (conflict.identity_id.clone(), conflict.sequence, hashes)
            })
            .collect();
        if identity_forks
            .iter()
            .chain(lifecycle_forks.iter())
            .any(|fork| !declared_conflicts.contains(fork))
        {
            return Err(Error::TrustConflict);
        }
        validate_unforked_chains(&identities, &events, &identity_forks, &lifecycle_forks)?;

        let signer_ids: BTreeSet<_> = bundle
            .signatures
            .iter()
            .map(|signature| signature.key_id.as_str())
            .collect();
        let publisher_identities: BTreeSet<_> = identities
            .iter()
            .filter(|identity| {
                identity.operational_keys.values().any(|key| {
                    signer_ids.contains(key.key_id.as_str()) && key.roles.contains("trust-bundle")
                })
            })
            .map(|identity| identity.identity_id.as_str())
            .collect();
        if identity_forks
            .iter()
            .any(|(identity, _, _)| publisher_identities.contains(identity.as_str()))
        {
            return Err(Error::TrustConflict);
        }
        let mut publisher_keys = BTreeMap::new();
        let mut publisher_owners = BTreeMap::new();
        for identity in &identities {
            for key in identity
                .operational_keys
                .values()
                .filter(|key| key.roles.contains("trust-bundle"))
            {
                if publisher_keys
                    .insert(key.key_id.clone(), key.public_key_base64url.clone())
                    .is_some()
                {
                    // Signature envelopes contain only key_id, so duplicates
                    // across embedded identities are not safely resolvable.
                    return Err(Error::TrustConflict);
                }
                publisher_owners.insert(key.key_id.clone(), identity.identity_id.clone());
            }
        }
        let value = serde_json::to_value(&bundle)?;
        let valid_signers = verify_proofs(
            V02Profile::TrustBundle,
            &value,
            &bundle.signatures,
            &publisher_keys,
        )?;
        for signer in &valid_signers {
            let owner = publisher_owners.get(signer).ok_or(Error::KeyUnknown)?;
            let owner_events: Vec<_> = events
                .iter()
                .filter(|event| &event.identity_id == owner)
                .cloned()
                .collect();
            if current_key_status(signer, &owner_events, false) == CurrentStatus::Revoked {
                return Err(Error::KeyRevoked);
            }
        }
        let result = ValidatedTrustBundle {
            complete_hash: canonical_object_sha256(&bundle).map_err(crypto_error)?,
            bundle_id: bundle.bundle_id,
            identity_documents: identities,
            lifecycle_events: events,
            conflicts: declared_conflicts,
            freshness: Freshness::Unknown,
        };
        merge_trust_facts(std::slice::from_ref(&result))?;
        Ok(result)
    }
}

fn validate_unforked_chains(
    identities: &[ValidatedIdentityDocument],
    events: &[ValidatedLifecycleEvent],
    identity_forks: &[(String, u64, Vec<String>)],
    lifecycle_forks: &[(String, u64, Vec<String>)],
) -> Result<(), Error> {
    let identity_ids: BTreeSet<_> = identities
        .iter()
        .map(|document| document.identity_id.clone())
        .collect();
    for identity_id in identity_ids {
        if identity_forks.iter().any(|fork| fork.0 == identity_id) {
            continue;
        }
        let mut chain: Vec<_> = identities
            .iter()
            .filter(|document| document.identity_id == identity_id)
            .cloned()
            .collect();
        chain.sort_by_key(|document| document.sequence);
        validate_identity_chain(&chain)?;
        if lifecycle_forks.iter().any(|fork| fork.0 == identity_id) {
            continue;
        }
        let mut lifecycle: Vec<_> = events
            .iter()
            .filter(|event| event.identity_id == identity_id)
            .cloned()
            .collect();
        lifecycle.sort_by_key(|event| event.sequence);
        validate_lifecycle_chain(&lifecycle, &chain)?;
    }
    Ok(())
}

fn verify_proofs<T: ProofView>(
    profile: V02Profile,
    value: &Value,
    proofs: &[T],
    keys: &BTreeMap<String, String>,
) -> Result<BTreeSet<String>, Error> {
    let mut valid = BTreeSet::new();
    for proof in proofs {
        let key_id = proof.key_id();
        if !valid.insert(key_id.to_owned()) {
            return Err(Error::KeyUnauthorized);
        }
        let key = keys.get(key_id).ok_or(Error::KeyUnknown)?;
        let key = public_key_from_base64url(key).map_err(crypto_error)?;
        verify_v02(profile, value, proof.value(), &key).map_err(crypto_error)?;
    }
    Ok(valid)
}

trait ProofView {
    fn key_id(&self) -> &str;
    fn value(&self) -> &str;
}

impl ProofView for v02::Signature {
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn value(&self) -> &str {
        &self.value
    }
}

fn core_error(error: omp_core::Error) -> Error {
    Error::InvalidFact(error.to_string())
}

fn crypto_error(error: omp_crypto::Error) -> Error {
    match error {
        omp_crypto::Error::InvalidSignature => Error::SignatureInvalid,
        other => Error::InvalidFact(other.to_string()),
    }
}
