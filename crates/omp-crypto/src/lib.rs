//! Cryptographic primitives for OMP v0.1.
//!
//! This crate fixes the domain separator and canonicalization algorithm so
//! callers cannot accidentally sign ordinary JSON serialization output.

#![deny(missing_docs)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{self, Read};

/// Exact v0.1 signature domain separator, including its trailing NUL.
pub const SIGNING_PREFIX: &[u8] = b"OMP-SIGNED-OBJECT-v0.1\0";

/// Exact OMP v0.2 signed-object profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V02Profile {
    /// Manifest signed with the manifest domain.
    Manifest,
    /// Identity document signed with the identity-document domain.
    IdentityDocument,
    /// Key lifecycle event signed with the lifecycle-event domain.
    KeyLifecycleEvent,
    /// License signed with the license domain.
    License,
    /// Trust bundle signed with the trust-bundle domain.
    TrustBundle,
    /// Time anchor signed with the time-anchor domain.
    TimeAnchor,
}

impl V02Profile {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::Manifest => b"OMP-MANIFEST-v0.2\0",
            Self::IdentityDocument => b"OMP-IDENTITY-DOCUMENT-v0.2\0",
            Self::KeyLifecycleEvent => b"OMP-KEY-LIFECYCLE-EVENT-v0.2\0",
            Self::License => b"OMP-LICENSE-v0.2\0",
            Self::TrustBundle => b"OMP-TRUST-BUNDLE-v0.2\0",
            Self::TimeAnchor => b"OMP-TIME-ANCHOR-v0.2\0",
        }
    }

    /// Exact top-level member excluded from this profile's payload.
    pub const fn excluded_member(self) -> &'static str {
        match self {
            Self::IdentityDocument | Self::KeyLifecycleEvent => "proofs",
            Self::TrustBundle => "signatures",
            Self::Manifest | Self::License | Self::TimeAnchor => "signature",
        }
    }
}

/// Cryptographic operation failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// RFC 8785 serialization failed.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
    /// Base64url decoding failed.
    #[error("invalid unpadded base64url: {0}")]
    Base64(#[from] base64::DecodeError),
    /// A key, signature, or size had an invalid length.
    #[error("invalid Ed25519 key or signature length")]
    Length,
    /// Signature authentication failed.
    #[error("Ed25519 signature verification failed")]
    InvalidSignature,
    /// Streaming input failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Serialize a JSON-compatible value with RFC 8785 JCS.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    serde_jcs::to_vec(value).map_err(|error| Error::Canonicalization(error.to_string()))
}

/// Construct the exact bytes covered by an OMP v0.1 signature.
pub fn signing_bytes(unsigned_object: &Value) -> Result<Vec<u8>, Error> {
    let canonical = canonicalize(unsigned_object)?;
    let mut output = Vec::with_capacity(SIGNING_PREFIX.len() + canonical.len());
    output.extend_from_slice(SIGNING_PREFIX);
    output.extend_from_slice(&canonical);
    Ok(output)
}

/// Construct exact OMP v0.2 signing bytes for one typed profile.
///
/// Only the profile's required top-level envelope member is removed. Missing
/// members and non-object inputs fail; no other profile is attempted.
pub fn v02_signing_bytes(profile: V02Profile, signed_object: &Value) -> Result<Vec<u8>, Error> {
    let mut unsigned = signed_object.clone();
    let object = unsigned
        .as_object_mut()
        .ok_or_else(|| Error::Canonicalization("signed value must be an object".into()))?;
    if object.remove(profile.excluded_member()).is_none() {
        return Err(Error::Canonicalization(format!(
            "missing top-level {}",
            profile.excluded_member()
        )));
    }
    let canonical = canonicalize(&unsigned)?;
    let mut output = Vec::with_capacity(profile.domain().len() + canonical.len());
    output.extend_from_slice(profile.domain());
    output.extend_from_slice(&canonical);
    Ok(output)
}

/// Sign an exact OMP v0.2 object profile with Ed25519.
pub fn sign_v02(
    profile: V02Profile,
    signed_object: &Value,
    key: &SigningKey,
) -> Result<String, Error> {
    Ok(encode_base64url(
        &key.sign(&v02_signing_bytes(profile, signed_object)?)
            .to_bytes(),
    ))
}

/// Verify an exact OMP v0.2 object profile with no domain fallback.
pub fn verify_v02(
    profile: V02Profile,
    signed_object: &Value,
    signature: &str,
    key: &VerifyingKey,
) -> Result<(), Error> {
    let raw = decode_base64url(signature)?;
    let signature = Signature::from_slice(&raw).map_err(|_| Error::Length)?;
    key.verify(&v02_signing_bytes(profile, signed_object)?, &signature)
        .map_err(|_| Error::InvalidSignature)
}

/// Derive the frozen self-certifying identity commitment.
pub fn v02_identity_id<T: Serialize>(genesis_body: &T) -> Result<String, Error> {
    let canonical = canonicalize(genesis_body)?;
    let mut hasher = Sha256::new();
    hasher.update(b"OMP-IDENTITY-GENESIS-v0.2\0");
    hasher.update(canonical);
    Ok(format!("omp:party:sha256-{}", hex(&hasher.finalize())))
}

/// SHA-256 of RFC 8785 canonical bytes for a complete JSON object.
pub fn canonical_object_sha256<T: Serialize>(object: &T) -> Result<String, Error> {
    Ok(hex(&Sha256::digest(canonicalize(object)?)))
}

/// Generate a new Ed25519 signing key using operating-system randomness.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Sign an unsigned top-level JSON object and return unpadded base64url.
pub fn sign_object(unsigned_object: &Value, key: &SigningKey) -> Result<String, Error> {
    let signature = key.sign(&signing_bytes(unsigned_object)?);
    Ok(encode_base64url(&signature.to_bytes()))
}

/// Verify an unsigned top-level JSON object and unpadded base64url signature.
pub fn verify_object(
    unsigned_object: &Value,
    signature: &str,
    key: &VerifyingKey,
) -> Result<(), Error> {
    let raw = decode_base64url(signature)?;
    let signature = Signature::from_slice(&raw).map_err(|_| Error::Length)?;
    key.verify(&signing_bytes(unsigned_object)?, &signature)
        .map_err(|_| Error::InvalidSignature)
}

/// Hash all bytes from a reader with SHA-256 and return `(lowercase_hex, size)`.
pub fn sha256_reader(mut reader: impl Read) -> Result<(String, u64), Error> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size = size.checked_add(read as u64).ok_or(Error::Length)?;
    }
    Ok((hex(&hasher.finalize()), size))
}

/// Decode strictly unpadded base64url text.
pub fn decode_base64url(value: &str) -> Result<Vec<u8>, Error> {
    if value.contains('=') {
        return Err(Error::Length);
    }
    Ok(URL_SAFE_NO_PAD.decode(value)?)
}

/// Encode bytes as unpadded base64url text.
pub fn encode_base64url(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

/// Parse a 32-byte Ed25519 public key from unpadded base64url.
pub fn public_key_from_base64url(value: &str) -> Result<VerifyingKey, Error> {
    let bytes: [u8; 32] = decode_base64url(value)?
        .try_into()
        .map_err(|_| Error::Length)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| Error::Length)
}

/// Parse a 32-byte Ed25519 private seed from unpadded base64url.
pub fn signing_key_from_base64url(value: &str) -> Result<SigningKey, Error> {
    let bytes: [u8; 32] = decode_base64url(value)?
        .try_into()
        .map_err(|_| Error::Length)?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalization_uses_jcs_order_and_number_format() {
        let value = json!({"z": 1.0, "a": "€", "nested": {"b": true, "a": null}});
        assert_eq!(
            String::from_utf8(canonicalize(&value).unwrap()).unwrap(),
            "{\"a\":\"€\",\"nested\":{\"a\":null,\"b\":true},\"z\":1}"
        );
    }

    #[test]
    fn signatures_are_domain_separated_and_tamper_evident() {
        let key = generate_signing_key();
        let object = json!({"schema_version":"0.1"});
        let signature = sign_object(&object, &key).unwrap();
        verify_object(&object, &signature, &key.verifying_key()).unwrap();
        assert!(verify_object(
            &json!({"schema_version":"0.2"}),
            &signature,
            &key.verifying_key()
        )
        .is_err());
    }
}
