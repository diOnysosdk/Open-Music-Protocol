# Role-authorized trust-bundle vector amendment 1

Profile: `OMP-v0.2-trust-bundle-vector-amendment-1`  
Baseline: `OMP-v0.2-w0-freeze.1`

`media-01-authorized.json` is the deterministic positive trust-bundle fixture
approved by ADR-014. Its signer is the operational key `media-01`, which has the
authenticated `trust-bundle` role and is active in the state represented by
this fixture.

The original frozen `root-01` vector is unchanged. It remains a valid W3
signature vector and a negative W4 role-authorization vector.

Reproduce the fixture from the repository root:

```powershell
cargo run --quiet -p omp-crypto --example generate_authorized_trust_bundle_vector
```

SHA-256:

```text
5d375d4684d074d62be49a70cf7182bd235e343bf2fe55adaeaa9c63396e1589  media-01-authorized.json
```

