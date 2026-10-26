"""Structural validation for frozen OMP v0.2 W0 artifacts."""

import json
import base64
import hashlib
import pathlib
import copy

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(path: pathlib.Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_schemas_and_json_artifacts_are_structurally_valid():
    schemas = {}
    registry = Registry()
    for path in sorted((ROOT / "schemas").glob("*.json")):
        schema = load(path)
        Draft202012Validator.check_schema(schema)
        schemas[path.name] = schema
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))

    for path in sorted(ROOT.rglob("*.json")):
        load(path)

    manifest = load(ROOT / "test-vectors" / "manifest-metadata-multiasset.valid.json")
    Draft202012Validator(
        schemas["manifest.schema.json"],
        registry=registry,
        format_checker=FormatChecker(),
    ).validate(manifest)

    identity_cases = load(ROOT / "test-vectors" / "identity-document-cases.json")
    Draft202012Validator(
        schemas["identity-document.schema.json"],
        registry=registry,
        format_checker=FormatChecker(),
    ).validate(identity_cases["base_document"])

    trust_cases = load(ROOT / "test-vectors" / "trust-bundle-cases.json")
    Draft202012Validator(
        schemas["trust-bundle.schema.json"],
        registry=registry,
        format_checker=FormatChecker(),
    ).validate(trust_cases["base_bundle"])

    license_cases = load(ROOT / "test-vectors" / "license-cases.json")["cases"]
    by_name = {case["name"]: case for case in license_cases}
    validator = Draft202012Validator(
        schemas["license.schema.json"], registry=registry, format_checker=FormatChecker()
    )
    for case in license_cases:
        if "expected_schema_valid" not in case:
            continue
        if "license" in case:
            license_object = copy.deepcopy(case["license"])
        else:
            license_object = copy.deepcopy(by_name[case["inherits"]]["license"])
            license_object.update(case.get("patch", {}))
            for member in case.get("remove", []):
                license_object.pop(member, None)
        assert not bool(list(validator.iter_errors(license_object))) == case["expected_schema_valid"]


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_cryptographic_vectors_verify_with_python_implementations():
    fixture = load(ROOT / "test-vectors" / "cryptographic-vectors.json")
    keys = {item["key_id"]: item for item in fixture["keys"]}
    schema_names = {
        "manifest": "manifest.schema.json",
        "identity_document": "identity-document.schema.json",
        "key_lifecycle_event": "key-lifecycle-event.schema.json",
        "license": "license.schema.json",
        "trust_bundle": "trust-bundle.schema.json",
        "time_anchor": "time-anchor.schema.json",
    }
    registry = Registry()
    schemas = {}
    for path in sorted((ROOT / "schemas").glob("*.json")):
        schema = load(path)
        schemas[path.name] = schema
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))

    for vector in fixture["vectors"]:
        obj = vector["signed_object"]
        Draft202012Validator(
            schemas[schema_names[vector["object_type"]]],
            registry=registry,
            format_checker=FormatChecker(),
        ).validate(obj)
        excluded = vector["excluded_top_level_member"]
        unsigned = {name: value for name, value in obj.items() if name != excluded}
        canonical = rfc8785.dumps(unsigned)
        assert canonical == unb64(vector["unsigned_jcs_utf8_base64url"])
        payload = vector["domain_ascii"].encode() + b"\x00" + canonical
        assert payload == unb64(vector["signing_payload_base64url"])
        assert hashlib.sha256(payload).hexdigest() == vector["signing_payload_sha256"]
        envelope = obj[excluded][0] if isinstance(obj[excluded], list) else obj[excluded]
        public = Ed25519PublicKey.from_public_bytes(
            unb64(keys[envelope["key_id"]]["public_key_base64url"])
        )
        public.verify(unb64(envelope["value"]), payload)

    identity = fixture["vectors"][0]["signed_object"]
    commitment = hashlib.sha256(
        b"OMP-IDENTITY-GENESIS-v0.2\x00" + rfc8785.dumps(identity["genesis_body"])
    ).hexdigest()
    assert fixture["identity_id"] == "omp:party:sha256-" + commitment

