# Open Music Protocol — OMP v0.2 experimental reference

This offline-first Rust workspace implements OMP v0.1 compatibility and the
approved v0.2 reference components. It contains no network service,
blockchain, registry, payments, telemetry, or GUI.

> **Experimental Alpha / Not Production Ready.** The open high-severity
> `W8-11` FLAC decoder memory-exhaustion finding blocks external alpha and
> production release.

## Build and validate

Rust stable and Python 3 are required. From the repository root:

```text
cargo build --locked --workspace
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
python -m pytest -p no:cacheprovider omp-spec-v0.1/tests omp-spec-v0.2-draft/tests omp-spec-v0.2-amendments/tests
python scripts/verify-frozen.py
```

The `omp` CLI creates and verifies v0.1 manifests. Run `omp --help` and
`omp <command> --help` for exact syntax. The `omp-player` binary is the v0.2
offline reference player; it remains release-blocked by `W8-11`.

## Safe offline manifest workflow

```text
omp keygen --key-id artist-key-01 --private artist.private.json --public artist.public.json
omp pack song.wav --manifest-id omp:manifest:song-001 --recording-id omp:recording:song-001 --work-id omp:work:song-001 --issuer-id omp:party:artist-001 --agreement-id omp:agreement:song-001 --license-id omp:license:song-001 --private-key artist.private.json --output song.omc.json
omp inspect song.omc.json
omp verify song.wav song.omc.json --public-key artist.public.json
```

Private keys are separate files and never enter manifests. `verify` establishes
strict parsing, signature validity, and exact audio-byte binding under the
explicitly supplied public key; it does not establish authorization or legal
ownership. See [the alpha workflow](docs/alpha-package-workflow-v0.2.md) and
[installation guide](docs/alpha-installation-v0.2.md).

## License and security

The code is dual-licensed under Apache-2.0 or MIT. Fixture licensing is
documented beside the fixtures. Report security issues using
[docs/SECURITY.md](docs/SECURITY.md).
