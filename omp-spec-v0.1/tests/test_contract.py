import json, pathlib, base64, hashlib
from jsonschema import Draft202012Validator
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT=pathlib.Path(__file__).resolve().parents[1]
PREFIX=b"OMP-SIGNED-OBJECT-v0.1\x00"

def b64(s): return base64.urlsafe_b64decode(s + "="*((-len(s))%4))

def fixture_jcs(obj):
    # This fixture intentionally uses no difficult JCS number/Unicode cases.
    # Not a replacement for an RFC 8785 implementation!
    return json.dumps(obj,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode()

def test_fixtures():
    public=json.loads((ROOT/'examples/test-public-key.json').read_text())
    key=Ed25519PublicKey.from_public_bytes(b64(public['public_key_base64url']))
    for file in (ROOT/'examples').glob('*.json'):
        name=file.stem
        if name in ('test-public-key','api-error'): continue
        doc=json.loads(file.read_text())
        schema=json.loads((ROOT/'schemas'/f'{name}.schema.json').read_text())
        Draft202012Validator(schema).validate(doc)
        payload={k:v for k,v in doc.items() if k!='signature'}
        key.verify(b64(doc['signature']['value']),PREFIX+fixture_jcs(payload))
        changed=dict(payload); changed['schema_version']='tampered'
        try: key.verify(b64(doc['signature']['value']),PREFIX+fixture_jcs(changed))
        except Exception: pass
        else: raise AssertionError('tampering was accepted')

def test_semantics():
    a=json.loads((ROOT/'examples/rights-agreement.json').read_text())
    assert sum(x['basis_points'] for x in a['splits'])==10000
    s=json.loads((ROOT/'examples/settlement.json').read_text())
    assert sum(int(x['amount_minor']) for x in s['allocations'])==int(s['gross_minor'])-int(s['deductions_minor'])
