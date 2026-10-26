import base64
import hashlib
import json
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).parents[2]


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_media_01_authorized_vector_is_reproducible_and_valid():
    path = ROOT / "omp-spec-v0.2-amendments/trust-bundle-vector/media-01-authorized.json"
    fixture = json.loads(path.read_text(encoding="utf-8"))
    frozen = json.loads(
        (ROOT / "omp-spec-v0.2-draft/test-vectors/cryptographic-vectors.json").read_text(
            encoding="utf-8"
        )
    )
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        "5d375d4684d074d62be49a70cf7182bd235e343bf2fe55adaeaa9c63396e1589"
    )
    obj = fixture["signed_object"]
    unsigned = {key: value for key, value in obj.items() if key != "signatures"}
    payload = b"OMP-TRUST-BUNDLE-v0.2\x00" + rfc8785.dumps(unsigned)
    assert base64.urlsafe_b64encode(payload).rstrip(b"=").decode() == fixture[
        "signing_payload_base64url"
    ]
    assert hashlib.sha256(payload).hexdigest() == fixture["signing_payload_sha256"]
    media = next(key for key in frozen["keys"] if key["key_id"] == "media-01")
    signature = obj["signatures"][0]
    Ed25519PublicKey.from_public_bytes(unb64(media["public_key_base64url"])).verify(
        unb64(signature["value"]), payload
    )
    roles = obj["identity_documents"][0]["operational_keys"][0]["roles"]
    assert signature["key_id"] == "media-01"
    assert "trust-bundle" in roles
    assert obj["lifecycle_events"] == []

