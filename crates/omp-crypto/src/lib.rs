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
