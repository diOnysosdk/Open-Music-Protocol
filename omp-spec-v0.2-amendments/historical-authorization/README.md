# Historical authorization semantic fixtures

Profile: `OMP-v0.2-historical-authorization-amendment-1`.

These fixtures exercise ADR-013 independently of production code. They do not
change or extend a wire schema. Inputs model already completed schema,
signature, identity, lifecycle, binding, and durable-pin checks. Expected
outputs keep authenticity, authorization, current trust, playback, and errors
as separate axes.

Run from the repository root:

```text
python -m pytest -p no:cacheprovider omp-spec-v0.2-amendments/tests
```
