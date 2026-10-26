# OMP v0.2 interoperability fixtures

The generated audio is a 250 ms mono 8 kHz PCM16 integer triangle pattern,
authored for this repository and released under CC0-1.0. It is not music and
contains no third-party performance or recording.

Files:

- `audio/omp-triangle-250ms.wav` — 4,044 bytes,
  SHA-256 `7968796923996897acaa2a734d5f9aa44023c521a5d8eaeda24a04f3e2745a06`.
- `audio/omp-triangle-250ms.flac` — 2,222 bytes,
  SHA-256 `b7a34c178dc61f86b9e7e542e6c000f1d6f56b8c5b364caef27319b86781d53d`.
- `audio/fixture-index.json` — machine-readable format, generator, hash, size,
  and selection-rank data.

Reproduction requires Python, NumPy 2.5.4, SoundFile 0.14.0, and libsndfile
1.2.2. The generator refuses a different SoundFile/libsndfile version because
FLAC encoder output is not guaranteed stable across versions.

```text
python omp-spec-v0.2-draft/tools/generate_audio_fixtures.py
python -m pytest -p no:cacheprovider omp-spec-v0.2-draft/tests
```

The tests verify byte hashes/sizes, decode both formats, compare their exact
PCM samples, bind the signed multi-asset manifest to both files, mutate and
truncate bytes, validate portable paths, attempt a real symlink escape where
the host permits symlink creation, and check the RFC 8785 edge subset.

On Windows without symlink privileges, the real symlink creation test is
reported as skipped; the normative symlink rejection case remains present in
`test-vectors/security-cases.json`. CI should run the same test on Linux where
unprivileged symlink creation is available.
