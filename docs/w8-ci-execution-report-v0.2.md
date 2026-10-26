# OMP v0.2 W8.2 CI execution report

**Date:** 2026-10-26  
**Revision audited:** `2c0db46` (`main`, tracking `origin/main`)  
**Release status:** no release or tag was created

## Repository and workflow audit

`origin` is `https://github.com/diOnysosdk/Open-Music-Protocol.git`.
`.github/workflows/ci.yml` is tracked at the required location and defines a
Windows/Ubuntu matrix plus formatting, strict Clippy, Rust tests,
documentation, Python specification tests, frozen-hash verification, and a
RustSec audit job. The Ubuntu setup installs the ALSA development package used
by the audio backend.

GitHub CLI authentication was not available (`gh auth status` failed). No
push, workflow dispatch, run ID, URL, hosted operating-system result, or job
log therefore exists for this assessment. Linux Docker was also unavailable.
Linux `openat`, symlink-race, and audio-backend execution remain unverified.

## Owner execution procedure

Authentication must be performed interactively by the repository owner; no
credential should be sent to an agent or stored in the repository.

```powershell
gh auth login
git switch -c w8-alpha-gate
git add --all
git commit -m "Prepare OMP v0.2 external-alpha assurance evidence"
git push -u origin w8-alpha-gate
gh workflow run ci.yml --ref w8-alpha-gate
gh run list --workflow ci.yml --branch w8-alpha-gate
gh run watch <RUN_ID>
gh run view <RUN_ID> --log
gh run download <RUN_ID> --dir artifacts/ci/<RUN_ID>
```

The run ID, run URL, commit SHA, runner image versions, job conclusions, logs,
and downloaded artifact hashes must be appended here before the external-alpha
gate can pass. A pull request is preferred over pushing directly to `main`.

## Result

Local Windows checks are evidence only for the local host. GitHub Windows and
Linux CI are **not executed**. This is an external-alpha release blocker.

