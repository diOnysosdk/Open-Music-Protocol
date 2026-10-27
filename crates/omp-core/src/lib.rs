//! Typed OMP v0.1 wire models and schema/semantic validation.
//!
//! Parsing is deliberately stricter than `serde_json::from_str`: duplicate
//! object keys are rejected before conversion to a typed model.

#![deny(missing_docs)]

use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fmt;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Strict OMP v0.2 wire models and validation.
pub mod v02;

/// Stable developer-facing diagnostic categories layered over protocol errors.
pub mod diagnostics;

/// Validation or decoding failure for an OMP object.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The JSON text is malformed or contains duplicate keys.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A schema or semantic rule was violated.
    #[error("validation failed: {0}")]
    Validation(String),
}

/// Implemented by all validated OMP wire models.
pub trait Validate {
    /// Checks schema-equivalent and cross-field constraints.
    fn validate(&self) -> Result<(), Error>;
}

/// Parse UTF-8 JSON while rejecting duplicate keys, then validate the model.
pub fn parse_and_validate<T>(input: &[u8]) -> Result<T, Error>
where
    T: DeserializeOwned + Validate,
{
    let value: NoDuplicateValue = serde_json::from_slice(input)?;
    let model: T = serde_json::from_value(value.0)?;
    model.validate()?;
    Ok(model)
}

/// Parse JSON to a generic value while rejecting duplicate object keys.
pub fn parse_value(input: &[u8]) -> Result<Value, Error> {
    Ok(serde_json::from_slice::<NoDuplicateValue>(input)?.0)
}

struct NoDuplicateValue(Value);

impl<'de> Deserialize<'de> for NoDuplicateValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ValueVisitor;
        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = NoDuplicateValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value without duplicate object keys")
            }
            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::Bool(value)))
            }
            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::Number(value.into())))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::Number(value.into())))
            }
            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .map(NoDuplicateValue)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::String(value.to_owned())))
            }
            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::String(value)))
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::Null))
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(NoDuplicateValue(Value::Null))
            }
            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                Deserialize::deserialize(deserializer)
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<NoDuplicateValue>()? {
                    values.push(value.0);
                }
                Ok(NoDuplicateValue(Value::Array(values)))
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Map::new();
                while let Some((key, value)) = map.next_entry::<String, NoDuplicateValue>()? {
                    if values.insert(key.clone(), value.0).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate object key `{key}`"
                        )));
                    }
                }
                Ok(NoDuplicateValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(ValueVisitor)
    }
}

/// An Ed25519 signature envelope used by every signed v0.1 object.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Must be exactly `Ed25519`.
    pub algorithm: String,
    /// External key registry identifier.
    pub key_id: String,
    /// Unpadded base64url signature bytes.
    pub value: String,
}

fn validate_signature(value: &Signature) -> Result<(), Error> {
    require(
        value.algorithm == "Ed25519",
        "signature algorithm must be Ed25519",
    )?;
    require(
        !value.key_id.is_empty(),
        "signature key_id must not be empty",
    )?;
    require(
        !value.value.is_empty() && value.value.bytes().all(is_base64url),
        "signature value must be nonempty unpadded base64url",
    )
}

/// A byte-addressed audio asset entry in a manifest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    /// Manifest-local asset identifier.
    pub asset_id: String,
    /// Allowlisted audio media type.
    pub media_type: String,
    /// SHA-256 of the exact asset bytes, in lowercase hexadecimal.
    pub sha256: String,
    /// Exact asset byte count.
    pub size_bytes: u64,
}

/// Signed sidecar manifest for one or more encodings of a recording.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Wire schema version (`0.1`).
    pub schema_version: String,
    /// Manifest identifier.
    pub manifest_id: String,
    /// Encoding-independent recording identifier.
    pub recording_id: String,
    /// Musical-work identifier.
    pub work_id: String,
    /// Optional release identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    /// Party issuing the manifest.
    pub issuer_id: String,
    /// Byte-addressed audio encodings.
    pub assets: Vec<Asset>,
    /// Referenced rights agreement.
    pub agreement_id: String,
    /// Referenced license.
    pub license_id: String,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// Manifest signature envelope.
    pub signature: Signature,
}

impl Validate for Manifest {
    fn validate(&self) -> Result<(), Error> {
        version(&self.schema_version)?;
        id(&self.manifest_id, "manifest")?;
        id(&self.recording_id, "recording")?;
        id(&self.work_id, "work")?;
        if let Some(value) = &self.release_id {
            id(value, "release")?;
        }
        id(&self.issuer_id, "party")?;
        id(&self.agreement_id, "agreement")?;
        id(&self.license_id, "license")?;
        timestamp(&self.created_at)?;
        require(!self.assets.is_empty(), "assets must not be empty")?;
        for asset in &self.assets {
            require(!asset.asset_id.is_empty(), "asset_id must not be empty")?;
            require(
                matches!(
                    asset.media_type.as_str(),
                    "audio/flac" | "audio/mpeg" | "audio/ogg" | "audio/wav" | "audio/mp4"
                ),
                "unsupported asset media_type",
            )?;
            require(
                is_lower_hex(&asset.sha256, 64),
                "asset sha256 must be 64 lowercase hex characters",
            )?;
            require(asset.size_bytes > 0, "asset size_bytes must be positive")?;
        }
        validate_signature(&self.signature)
    }
}

/// Rights split within a rights agreement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Split {
    /// Recipient party identifier.
    pub party_id: String,
    /// Recipient share in basis points.
    pub basis_points: u16,
}

/// Immutable version of recording rights allocations.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RightsAgreement {
    /// Wire schema version (`0.1`).
    pub schema_version: String,
    /// Agreement identifier.
    pub agreement_id: String,
    /// Immutable agreement version.
    pub version: u64,
    /// Recording governed by this agreement.
    pub recording_id: String,
    /// RFC 3339 effective timestamp.
    pub effective_from: String,
    /// Three-letter uppercase currency code.
    pub currency: String,
    /// Named allocation pool.
    pub allocation_pool: String,
    /// Rights recipients and shares.
    pub splits: Vec<Split>,
    /// Party issuing the agreement.
    pub issuer_id: String,
    /// Agreement signature envelope.
    pub signature: Signature,
}

impl Validate for RightsAgreement {
    fn validate(&self) -> Result<(), Error> {
        version(&self.schema_version)?;
        id(&self.agreement_id, "agreement")?;
        require(self.version >= 1, "agreement version must be positive")?;
        id(&self.recording_id, "recording")?;
        timestamp(&self.effective_from)?;
        currency(&self.currency)?;
        require(
            matches!(
                self.allocation_pool.as_str(),
                "master_net_receipts" | "composition_net_receipts"
            ),
            "invalid allocation_pool",
        )?;
        require(!self.splits.is_empty(), "splits must not be empty")?;
        let mut parties = HashSet::new();
        let mut total = 0_u32;
        for split in &self.splits {
            id(&split.party_id, "party")?;
            require(
                (1..=10000).contains(&split.basis_points),
                "basis_points out of range",
            )?;
            require(parties.insert(&split.party_id), "duplicate split recipient")?;
            total += u32::from(split.basis_points);
        }
        require(total == 10000, "split basis points must sum to 10000")?;
        id(&self.issuer_id, "party")?;
        validate_signature(&self.signature)
    }
}

/// Offline-capable license for a recording.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct License {
    /// Wire schema version (`0.1`).
    pub schema_version: String,
    /// License identifier.
    pub license_id: String,
    /// Licensed recording identifier.
    pub recording_id: String,
    /// Licensed subject identifier.
    pub subject_id: String,
    /// License mode: free, purchase, or subscription.
    pub mode: String,
    /// Whether offline use is permitted.
    pub offline: bool,
    /// RFC 3339 validity start.
    pub valid_from: String,
    /// Optional RFC 3339 expiry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Party issuing the license.
    pub issuer_id: String,
    /// License signature envelope.
    pub signature: Signature,
}

impl Validate for License {
    fn validate(&self) -> Result<(), Error> {
        version(&self.schema_version)?;
        id(&self.license_id, "license")?;
        id(&self.recording_id, "recording")?;
        require(!self.subject_id.is_empty(), "subject_id must not be empty")?;
        require(
            matches!(self.mode.as_str(), "free" | "purchase" | "subscription"),
            "invalid license mode",
        )?;
        let from = timestamp(&self.valid_from)?;
        if let Some(expiry) = &self.expires_at {
            require(
                from < timestamp(expiry)?,
                "valid_from must precede expires_at",
            )?;
        }
        id(&self.issuer_id, "party")?;
        validate_signature(&self.signature)
    }
}

/// Signed playback receipt forming part of an installation-local chain.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlaybackReceipt {
    /// Wire schema version (`0.1`).
    pub schema_version: String,
    /// Receipt identifier.
    pub receipt_id: String,
    /// Played recording identifier.
    pub recording_id: String,
    /// License used for playback.
    pub license_id: String,
    /// Rights agreement used for playback.
    pub agreement_id: String,
    /// Immutable agreement version.
    pub agreement_version: u64,
    /// Installation-chain identifier.
    pub installation_id: String,
    /// Playback session identifier.
    pub session_id: String,
    /// Monotonic installation-chain sequence.
    pub sequence: u64,
    /// SHA-256 of the complete previous receipt, or `None` for genesis.
    pub previous_hash: Option<String>,
    /// RFC 3339 playback start.
    pub started_at: String,
    /// Reported playback duration in milliseconds.
    pub duration_ms: u64,
    /// Receipt signature envelope.
    pub signature: Signature,
}

impl Validate for PlaybackReceipt {
    fn validate(&self) -> Result<(), Error> {
        version(&self.schema_version)?;
        id(&self.receipt_id, "receipt")?;
        id(&self.recording_id, "recording")?;
        id(&self.license_id, "license")?;
        id(&self.agreement_id, "agreement")?;
        require(
            self.agreement_version >= 1,
            "agreement_version must be positive",
        )?;
        require(
            !self.installation_id.is_empty() && !self.session_id.is_empty(),
            "installation_id and session_id must not be empty",
        )?;
        match (&self.previous_hash, self.sequence) {
            (None, 0) => {}
            (Some(hash), n) if n > 0 => require(
                is_lower_hex(hash, 64),
                "previous_hash must be 64 lowercase hex characters",
            )?,
            _ => {
                return Err(Error::Validation(
                    "receipt sequence/previous_hash invariant violated".into(),
                ))
            }
        }
        timestamp(&self.started_at)?;
        validate_signature(&self.signature)
    }
}

/// Per-party amount in a settlement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Allocation {
    /// Recipient party identifier.
    pub party_id: String,
    /// Unsigned decimal amount in minor currency units.
    pub amount_minor: String,
}

/// Settlement calculated against an immutable agreement version.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Settlement {
    /// Wire schema version (`0.1`).
    pub schema_version: String,
    /// Settlement identifier.
    pub settlement_id: String,
    /// Referenced rights agreement.
    pub agreement_id: String,
    /// Immutable referenced agreement version.
    pub agreement_version: u64,
    /// Inclusive RFC 3339 period start.
    pub period_start: String,
    /// Exclusive RFC 3339 period end.
    pub period_end: String,
    /// Three-letter uppercase currency code.
    pub currency: String,
    /// Unsigned decimal gross amount in minor units.
    pub gross_minor: String,
    /// Unsigned decimal deductions in minor units.
    pub deductions_minor: String,
    /// Net per-party allocations.
    pub allocations: Vec<Allocation>,
    /// Fixture-only Merkle-root placeholder.
    pub receipt_merkle_root: String,
    /// Party issuing the settlement.
    pub issuer_id: String,
    /// Settlement signature envelope.
    pub signature: Signature,
}

impl Validate for Settlement {
    fn validate(&self) -> Result<(), Error> {
        version(&self.schema_version)?;
        id(&self.settlement_id, "settlement")?;
        id(&self.agreement_id, "agreement")?;
        require(
            self.agreement_version >= 1,
            "agreement_version must be positive",
        )?;
        require(
            timestamp(&self.period_start)? < timestamp(&self.period_end)?,
            "period_start must precede period_end",
        )?;
        currency(&self.currency)?;
        decimal(&self.gross_minor)?;
        decimal(&self.deductions_minor)?;
        require(
            decimal_cmp(&self.deductions_minor, &self.gross_minor) != std::cmp::Ordering::Greater,
            "deductions exceed gross",
        )?;
        require(
            !self.allocations.is_empty(),
            "allocations must not be empty",
        )?;
        let mut sum = "0".to_owned();
        for allocation in &self.allocations {
            id(&allocation.party_id, "party")?;
            decimal(&allocation.amount_minor)?;
            sum = decimal_add(&sum, &allocation.amount_minor);
        }
        let net = decimal_sub(&self.gross_minor, &self.deductions_minor);
        require(
            decimal_cmp(&sum, &net) == std::cmp::Ordering::Equal,
            "allocations must equal gross minus deductions",
        )?;
        require(
            is_lower_hex(&self.receipt_merkle_root, 64),
            "receipt_merkle_root must be 64 lowercase hex characters",
        )?;
        id(&self.issuer_id, "party")?;
        validate_signature(&self.signature)
    }
}

/// API error response body.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    /// Structured API error body.
    pub error: ApiErrorBody,
}
/// Inner API error details.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApiErrorBody {
    /// Stable uppercase error code.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
    /// Request correlation identifier.
    pub request_id: String,
    /// Optional non-sensitive structured details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Map<String, Value>>,
}
impl Validate for ApiError {
    fn validate(&self) -> Result<(), Error> {
        let bytes = self.error.code.as_bytes();
        require(
            bytes.len() >= 2
                && bytes[0].is_ascii_uppercase()
                && bytes[1..]
                    .iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_'),
            "invalid API error code",
        )
    }
}

fn require(condition: bool, message: &str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::Validation(message.into()))
    }
}
fn version(value: &str) -> Result<(), Error> {
    require(value == "0.1", "schema_version must be 0.1")
}
fn timestamp(value: &str) -> Result<OffsetDateTime, Error> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| Error::Validation(format!("invalid RFC 3339 timestamp `{value}`")))
}
fn currency(value: &str) -> Result<(), Error> {
    require(
        value.len() == 3 && value.bytes().all(|b| b.is_ascii_uppercase()),
        "currency must be three uppercase ASCII letters",
    )
}
fn is_base64url(value: u8) -> bool {
    value.is_ascii_alphanumeric() || value == b'_' || value == b'-'
}
fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn id(value: &str, expected: &str) -> Result<(), Error> {
    let Some(slug) = value.strip_prefix(&format!("omp:{expected}:")) else {
        return Err(Error::Validation(format!(
            "identifier `{value}` must have kind `{expected}`"
        )));
    };
    require(
        (3..=128).contains(&slug.len())
            && ascii_lowercase_or_digit(slug.as_bytes()[0])
            && slug
                .bytes()
                .all(|b| ascii_lowercase_or_digit(b) || matches!(b, b'.' | b'_' | b'-')),
        "invalid OMP identifier slug",
    )
}
fn ascii_lowercase_or_digit(value: u8) -> bool {
    value.is_ascii_lowercase() || value.is_ascii_digit()
}
fn decimal(value: &str) -> Result<(), Error> {
    require(
        value == "0" || (!value.starts_with('0') && value.bytes().all(|b| b.is_ascii_digit())),
        "invalid unsigned decimal string",
    )
}
fn normalized_decimal(value: &str) -> &str {
    let trimmed = value.trim_start_matches('0');
    if trimmed.is_empty() {
        "0"
    } else {
        trimmed
    }
}
fn decimal_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let (a, b) = (normalized_decimal(a), normalized_decimal(b));
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}
fn decimal_add(a: &str, b: &str) -> String {
    let mut carry = 0;
    let mut out = Vec::new();
    let mut ai = a.bytes().rev();
    let mut bi = b.bytes().rev();
    loop {
        let x = ai.next().map(|v| v - b'0');
        let y = bi.next().map(|v| v - b'0');
        if x.is_none() && y.is_none() && carry == 0 {
            break;
        }
        let n = x.unwrap_or(0) + y.unwrap_or(0) + carry;
        out.push(b'0' + n % 10);
        carry = n / 10;
    }
    out.reverse();
    String::from_utf8(out).expect("digits are UTF-8")
}
fn decimal_sub(a: &str, b: &str) -> String {
    let mut borrow = 0_i16;
    let mut out = Vec::new();
    let mut bi = b.bytes().rev();
    for av in a.bytes().rev() {
        let mut n = i16::from(av - b'0') - borrow - i16::from(bi.next().unwrap_or(b'0') - b'0');
        if n < 0 {
            n += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out.push(b'0' + u8::try_from(n).expect("digit"));
    }
    while out.len() > 1 && out.last() == Some(&b'0') {
        out.pop();
    }
    out.reverse();
    String::from_utf8(out).expect("digits are UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_keys_are_rejected_at_any_depth() {
        let error = parse_value(br#"{"a":{"x":1,"x":2}}"#).unwrap_err();
        assert!(error.to_string().contains("duplicate"));
    }
    #[test]
    fn arbitrary_size_decimal_math_is_exact() {
        assert_eq!(
            decimal_add("999999999999999999999", "1"),
            "1000000000000000000000"
        );
        assert_eq!(
            decimal_sub("1000000000000000000000", "1"),
            "999999999999999999999"
        );
    }
}
