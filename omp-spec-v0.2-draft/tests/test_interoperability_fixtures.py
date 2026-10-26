"""Executable checks for reproducible media and security fixtures."""

import base64
import hashlib
import json
import os
import pathlib
import struct
import tempfile
import unicodedata
import wave

import pytest
import rfc8785
import soundfile
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = pathlib.Path(__file__).resolve().parents[1]
AUDIO = ROOT / "fixtures" / "audio"


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def validate_portable_path(value):
    assert value == unicodedata.normalize("NFC", value)
    assert value and not value.startswith("/")
    assert "\\" not in value and ":" not in value and "%" not in value
    assert all(ord(char) >= 0x20 and ord(char) != 0x7F for char in value)
    segments = value.split("/")
    assert all(segment not in ("", ".", "..") for segment in segments)
    assert all(not segment.endswith((" ", ".")) for segment in segments)


def resolve_without_links(root, relative):
    validate_portable_path(relative)
    current = root
    for segment in relative.split("/"):
        current = current / segment
        if current.is_symlink():
            raise ValueError("symlink traversal is prohibited")
    current.resolve(strict=True).relative_to(root.resolve(strict=True))
    return current


def test_audio_hashes_sizes_decoding_and_multi_asset_selection():
    index = load(AUDIO / "fixture-index.json")
    assert index["license"] == "CC0-1.0"
    verified = []
    for asset in index["assets"]:
        path = ROOT / "fixtures" / asset["relative_path"]
        assert path.stat().st_size == asset["size_bytes"]
        assert digest(path) == asset["sha256"]
        verified.append(asset)
    assert min(verified, key=lambda asset: asset["selection_rank"])["asset_id"] == "primary-flac"

    with wave.open(str(AUDIO / "omp-triangle-250ms.wav"), "rb") as wav:
        assert (wav.getframerate(), wav.getnchannels(), wav.getsampwidth(), wav.getnframes()) == (8000, 1, 2, 2000)
    data, rate = soundfile.read(AUDIO / "omp-triangle-250ms.flac", dtype="int16")
    assert rate == 8000 and data.shape == (2000,)
    assert data.tolist() == [((index % 80) - 40) * 400 for index in range(2000)]


def test_mutated_and_truncated_assets_do_not_match():
    source = (AUDIO / "omp-triangle-250ms.wav").read_bytes()
    expected = digest(AUDIO / "omp-triangle-250ms.wav")
    changed = bytearray(source)
    changed[100] ^= 1
    assert hashlib.sha256(changed).hexdigest() != expected
    assert hashlib.sha256(source[:-1]).hexdigest() != expected


@pytest.mark.parametrize("path", [
    "../outside.wav", "%2e%2e/outside.wav", "audio\\outside.wav",
    "/audio/file.wav", "C:/audio/file.wav", "audio//file.wav",
    "audio/./file.wav", "audio/Cafe\u0301.wav", "audio/file.wav.",
])
def test_invalid_portable_paths(path):
    with pytest.raises(AssertionError):
        validate_portable_path(path)


def test_symlink_escape_is_rejected_when_platform_supports_links():
    with tempfile.TemporaryDirectory() as temporary:
        base = pathlib.Path(temporary)
        root = base / "package"
        root.mkdir()
        outside = base / "outside.wav"
        outside.write_bytes(b"outside")
        link = root / "link.wav"
        try:
            os.symlink(outside, link)
        except OSError as error:
            pytest.skip(f"symlink creation unavailable: {error}")
        with pytest.raises(ValueError):
            resolve_without_links(root, "link.wav")


def test_manifest_assets_bind_to_published_audio():
    manifest = load(ROOT / "test-vectors" / "manifest-metadata-multiasset.valid.json")
    for asset in manifest["assets"]:
        validate_portable_path(asset["relative_path"])
        path = ROOT / asset["relative_path"]
        assert path.stat().st_size == asset["size_bytes"]
        assert digest(path) == asset["sha256"]


def test_security_case_catalog_covers_required_families():
    cases = load(ROOT / "test-vectors" / "security-cases.json")["cases"]
    identifiers = {case["id"] for case in cases}
    required = {
        "asset-one-byte-altered", "multi-asset-lowest-rank", "path-parent-traversal",
        "path-symlink-escape", "signature-altered-field", "signature-truncated",
        "signing-key-unknown", "signing-key-revoked-current", "identity-fork",
        "license-at-exclusive-expiry", "license-no-trusted-time", "metadata-non-nfc",
        "undeclared-critical-extension-field", "undeclared-extension-field",
    }
    assert required <= identifiers


def test_signature_tamper_truncation_wrong_key_and_domain_fail():
    fixture = load(ROOT / "test-vectors" / "cryptographic-vectors.json")
    keys = {key["key_id"]: key for key in fixture["keys"]}
    vector = next(item for item in fixture["vectors"] if item["object_type"] == "manifest")
    obj = vector["signed_object"]
    envelope = obj["signature"]
    public = Ed25519PublicKey.from_public_bytes(
        unb64(keys[envelope["key_id"]]["public_key_base64url"])
    )
    signature = unb64(envelope["value"])
    payload = unb64(vector["signing_payload_base64url"])
    public.verify(signature, payload)

    failures = [
        (signature, payload + b"tampered"),
        (signature[:-1], payload),
        (signature, b"OMP-LICENSE-v0.2\x00" + payload.split(b"\x00", 1)[1]),
    ]
    wrong_key = next(key for key in fixture["keys"] if key["key_id"] != envelope["key_id"])
    wrong_public = Ed25519PublicKey.from_public_bytes(unb64(wrong_key["public_key_base64url"]))
    with pytest.raises(InvalidSignature):
        wrong_public.verify(signature, payload)
    for candidate_signature, candidate_payload in failures:
        with pytest.raises((InvalidSignature, ValueError)):
            public.verify(candidate_signature, candidate_payload)


def test_rfc8785_official_edge_subset():
    fixture = load(ROOT / "test-vectors" / "rfc8785-edge-cases.json")
    for case in fixture["numbers"]:
        value = struct.unpack(">d", bytes.fromhex(case["binary64_hex"]))[0]
        assert rfc8785.dumps(value).decode("ascii") == case["expected"]
    for bits in fixture["reject_binary64_hex"]:
        value = struct.unpack(">d", bytes.fromhex(bits))[0]
        with pytest.raises(rfc8785.FloatDomainError):
            rfc8785.dumps(value)

    ordering = fixture["utf16_property_order"]
    source = {name: index for index, name in enumerate(ordering["input_names"])}
    pairs = json.loads(rfc8785.dumps(source), object_pairs_hook=list)
    assert [name for name, _ in pairs] == ordering["expected_names"]

