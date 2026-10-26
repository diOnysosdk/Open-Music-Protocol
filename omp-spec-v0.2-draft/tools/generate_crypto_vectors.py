"""Generate deterministic OMP v0.2 cryptographic review vectors.

Requires the independent Python implementations `rfc8785` and `cryptography`.
Every private seed here is public test material and MUST NOT be used outside
interoperability tests.
"""

import base64
import hashlib
import json
import pathlib

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "test-vectors" / "cryptographic-vectors.json"

DOMAINS = {
    "manifest": (b"OMP-MANIFEST-v0.2\x00", "signature"),
    "identity_document": (b"OMP-IDENTITY-DOCUMENT-v0.2\x00", "proofs"),
    "key_lifecycle_event": (b"OMP-KEY-LIFECYCLE-EVENT-v0.2\x00", "proofs"),
    "license": (b"OMP-LICENSE-v0.2\x00", "signature"),
    "trust_bundle": (b"OMP-TRUST-BUNDLE-v0.2\x00", "signatures"),
    "time_anchor": (b"OMP-TIME-ANCHOR-v0.2\x00", "signature"),
}


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def key(label):
    seed = hashlib.sha256(("OMP-v0.2-TEST-ONLY:" + label).encode()).digest()
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, seed, public


def signed(case_name, kind, obj, signer, key_id, plural=False):
    domain, excluded = DOMAINS[kind]
    unsigned = {name: value for name, value in obj.items() if name != excluded}
    canonical = rfc8785.dumps(unsigned)
    payload = domain + canonical
    signature = b64(signer.sign(payload))
    envelope = {"algorithm": "Ed25519", "key_id": key_id, "value": signature}
    obj[excluded] = [envelope] if plural else envelope
    return {
        "case": case_name,
        "object_type": kind,
        "domain_ascii": domain[:-1].decode("ascii"),
        "excluded_top_level_member": excluded,
        "unsigned_jcs_utf8_base64url": b64(canonical),
        "unsigned_jcs_sha256": hashlib.sha256(canonical).hexdigest(),
        "signing_payload_base64url": b64(payload),
        "signing_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_base64url": signature,
        "signed_object": obj,
    }


def main():
    root, root_seed, root_public = key("root-01")
    media, media_seed, media_public = key("media-01")
    genesis = {
        "profile": "omp-self-certifying-identity-v0.2",
        "created_at": "2026-10-26T12:00:00Z",
        "root_keys": [{
            "key_id": "root-01", "algorithm": "Ed25519",
            "public_key_base64url": b64(root_public)
        }],
        "recovery": {"threshold": 1, "key_ids": ["root-01"]},
    }
    commitment = hashlib.sha256(
        b"OMP-IDENTITY-GENESIS-v0.2\x00" + rfc8785.dumps(genesis)
    ).hexdigest()
    identity_id = "omp:party:sha256-" + commitment

    identity = {
        "schema_version": "0.2", "identity_id": identity_id,
        "genesis_body": genesis, "sequence": 0,
        "previous_document_hash": None, "issued_at": "2026-10-26T12:00:00Z",
        "operational_keys": [{
            "key_id": "media-01", "algorithm": "Ed25519",
            "public_key_base64url": b64(media_public),
            "roles": ["manifest", "license", "trust-bundle", "time-anchor"],
            "valid_from": "2026-10-26T12:00:00Z"
        }],
        "proofs": []
    }
    identity_vector = signed(
        "identity-genesis-single-key", "identity_document", identity,
        root, "root-01", plural=True
    )

    manifest = json.loads(
        (ROOT / "test-vectors" / "manifest-metadata-multiasset.valid.json")
        .read_text(encoding="utf-8")
    )
    manifest["issuer_id"] = identity_id
    for credit in manifest["metadata"]["artist_credits"]:
        if "identity" in credit:
            credit["identity"] = identity_id
    for credit in manifest["metadata"]["contributors"]:
        if "identity" in credit:
            credit["identity"] = identity_id
    manifest_vector = signed("manifest-metadata-multiasset", "manifest", manifest, media, "media-01")

    license_obj = {
        "schema_version": "0.2", "license_id": "omp:license:public-free-001",
        "recording_id": "omp:recording:track-v02-0001",
        "audience": "public", "mode": "free", "offline": True,
        "offline_policy": {"kind": "permanent"},
        "valid_from": "2026-10-26T12:00:00Z", "issuer_id": identity_id,
        "signature": {}
    }
    license_vector = signed("license-public-unrestricted", "license", license_obj, media, "media-01")

    event = {
        "schema_version": "0.2", "event_id": "omp:key-event:revoke-media-001",
        "identity_id": identity_id, "sequence": 0, "previous_event_hash": None,
        "event_type": "revoke", "key_id": "media-01", "reason": "compromised",
        "compromise_from": "2026-10-27T00:00:00Z",
        "effective_at": "2026-10-27T00:00:00Z",
        "issued_at": "2026-10-27T01:00:00Z", "proofs": []
    }
    event_vector = signed("key-revocation-preserves-history", "key_lifecycle_event", event, root, "root-01", plural=True)

    trust = {
        "schema_version": "0.2", "profile": "omp-offline-trust-bundle-v0.2",
        "bundle_id": "omp:trust-bundle:crypto-001",
        "created_at": "2026-10-27T02:00:00Z",
        "next_update_at": "2026-11-03T02:00:00Z",
        "identity_documents": [identity_vector["signed_object"]],
        "lifecycle_events": [event_vector["signed_object"]],
        "legacy_bindings": [], "conflicts": [], "provenance": [], "signatures": []
    }
    trust_vector = signed("trust-bundle-with-revocation", "trust_bundle", trust, root, "root-01", plural=True)

    anchor = {
        "schema_version": "0.2", "anchor_id": "omp:time-anchor:anchor-001",
        "authority_id": identity_id, "sequence": 0,
        "observed_at": "2026-10-27T03:00:00Z", "issued_at": "2026-10-27T03:00:01Z",
        "max_age_seconds": 86400, "signature": {}
    }
    anchor_vector = signed("time-anchor-basic", "time_anchor", anchor, media, "media-01")

    output = {
        "profile": "OMP-v0.2-cryptographic-vectors-1",
        "warning": "All private seeds are deterministic public TEST-ONLY material.",
        "canonicalization": "RFC 8785 JCS",
        "identity_commitment_domain_ascii": "OMP-IDENTITY-GENESIS-v0.2",
        "identity_id": identity_id,
        "keys": [
            {"key_id": "root-01", "private_seed_base64url": b64(root_seed), "public_key_base64url": b64(root_public)},
            {"key_id": "media-01", "private_seed_base64url": b64(media_seed), "public_key_base64url": b64(media_public)}
        ],
        "vectors": [identity_vector, manifest_vector, event_vector, license_vector, trust_vector, anchor_vector]
    }
    OUT.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
