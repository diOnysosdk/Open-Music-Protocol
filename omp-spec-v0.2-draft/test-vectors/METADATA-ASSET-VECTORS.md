# Proposed metadata and asset-binding vectors

These are design-review vectors, not final cryptographic fixtures.

`manifest-metadata-multiasset.valid.json` is schema-valid under the proposed
v0.2 schemas and illustrates ordered artist credits, contributors, release
metadata, portable paths, roles, and deterministic selection ranks. Its
signature is deliberately a base64url-shaped placeholder. It MUST NOT be used
as a positive signature vector.

`metadata-asset-cases.json` describes mutations using JSON Pointer and the JSON Patch names
`replace`/`add`/`remove`. A future executable vector generator should materialize
each mutation into its own immutable fixture. Tests must distinguish:

1. JSON/schema validity;
2. semantic validity not expressible in JSON Schema;
3. cryptographic signature validity; and
4. local asset-binding validity.

Before v0.2 is frozen, replace the placeholder identity/key and signature with
a fixed public test key and publish, for every positive signed object:

- exact unsigned RFC 8785 JCS UTF-8 bytes;
- exact domain-separated signing bytes and their SHA-256;
- Ed25519 signature and public key;
- asset fixture bytes with independently calculated size and SHA-256; and
- cross-language Rust and TypeScript results.

Required RFC 8785 coverage includes UTF-16 property ordering, escaped control
characters, non-ASCII Unicode, IEEE-754 boundary numbers, exponent formatting,
negative zero, and rejection of values outside I-JSON constraints.

