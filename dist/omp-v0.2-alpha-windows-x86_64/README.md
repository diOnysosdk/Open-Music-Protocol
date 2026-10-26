# Open Music Protocol — OMP Core v0.1

This Rust workspace implements the experimental protocol in
`omp-spec-v0.1`. It is offline-only and contains no registry, network,
database, blockchain, payments, royalty engine, DRM, player, or GUI.

## Crates

- `omp-core`: strict wire models, duplicate-key-safe parsing, and semantic validation.
- `omp-crypto`: SHA-256, Ed25519, RFC 8785 JCS, and OMP domain separation.
- `omp-manifest`: sidecar creation, signing, and audio-byte verification.
- `omp-cli`: `keygen`, `pack`/`package`, `inspect`, and `verify`.

## Build and test

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python -m pytest omp-spec-v0.1/tests
```

## Offline workflow

Generate a keypair (private material is written separately and is never put
in a manifest):

```text
omp keygen --key-id artist-key-01 --private artist.private.json --public artist.public.json
```

The specification says protocol IDs are registry-assigned, so packaging
requires the caller to supply them:

```text
omp pack song.flac \
  --manifest-id omp:manifest:song-001 \
  --recording-id omp:recording:song-001 \
  --work-id omp:work:song-001 \
  --issuer-id omp:party:artist-001 \
  --agreement-id omp:agreement:song-001 \
  --license-id omp:license:song-001 \
  --private-key artist.private.json

omp inspect song.flac.omc.json
omp verify song.flac song.flac.omc.json --public-key artist.public.json
```

Output files are created atomically with create-new semantics; existing files
are not overwritten. On Unix, newly generated private-key files use mode
`0600`. On Windows, protect the key file using an appropriate user-only ACL or
an OS-backed secret manager. The CLI accepts external key documents but does
not claim to provide a production key-management system.

## Security boundary

Successful `verify` means that:

1. the JSON is structurally and semantically valid OMP v0.1,
2. its signature is valid under the explicitly supplied trusted public key,
3. the key ID and algorithm match that trusted key record, and
4. the selected local audio file has the signed SHA-256 and size.

It does not establish legal ownership, key authorization, revocation status,
human listening, or rights-registry validity. Those policies are outside v0.1.

See [docs/architecture.md](docs/architecture.md) for decisions and known
specification gaps.

