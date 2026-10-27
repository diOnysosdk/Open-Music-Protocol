# OMP v0.2 W8.2 CI execution report

## W8.4 execution gate — 2026-10-27

Local and remote `main` both resolve to
`a384ca834578a44a35cb64760760da718798e78c`. GitHub CLI remains
unauthenticated, so no commit, push, dispatch, run inspection, or evidence
download was performed. The W8.3 fuzz workflow is present locally but is not
committed. The CI workflow is tracked; a minimal uncommitted change adds
`workflow_dispatch` so the owner-requested `gh workflow run ci.yml` command is
valid. Hosted results remain absent and the external-alpha gate remains open.

Required owner action:

```powershell
gh auth login --hostname github.com --web --git-protocol https
gh auth status
```

After explicit review and commit authorization, commit the listed W8.3/W8.4
changes without rewriting history, push the approved branch, and ensure both
workflow runs report the resulting single commit SHA.

## W8.3 execution update — 2026-10-27

The repository was re-audited at commit
`a384ca834578a44a35cb64760760da718798e78c`; local `main` and
`origin/main` resolved to the same SHA and the worktree was initially clean.
The tracked `.github/workflows/ci.yml` remains a Windows/Ubuntu matrix.

Git transport to the public remote succeeded, but GitHub CLI authentication
was still unavailable. `gh run list` therefore could not return authoritative
run metadata, and the public Actions page yielded no usable run evidence. No
push or workflow dispatch was attempted, and there are still no run IDs, run
URLs, hosted job conclusions, or downloaded logs to record.

A separate manual workflow now exists at `.github/workflows/fuzz.yml`. After
reviewing and committing the W8.3 changes, the repository owner can execute:

```powershell
gh auth login
git switch -c w8-alpha-gate
git add .github/workflows/fuzz.yml fuzz docs
git commit -m "Add bounded Linux ASan fuzz gate"
git push -u origin w8-alpha-gate
gh run list --branch w8-alpha-gate --limit 20
gh workflow run fuzz.yml --ref w8-alpha-gate -f seconds_per_target=300
gh run list --workflow fuzz.yml --branch w8-alpha-gate --limit 5
gh run watch <FUZZ_RUN_ID> --exit-status
gh run view <CI_RUN_ID> --json databaseId,url,headSha,jobs,conclusion
gh run view <FUZZ_RUN_ID> --json databaseId,url,headSha,jobs,conclusion
gh run download <CI_RUN_ID> --dir artifacts/ci/<CI_RUN_ID>
gh run download <FUZZ_RUN_ID> --dir artifacts/fuzz/<FUZZ_RUN_ID>
```

The branch push automatically exercises `ci.yml`; no redundant manual CI
dispatch is required because that workflow currently listens to pushes and
pull requests rather than `workflow_dispatch`.

**Date:** 2026-10-26  
**Revision audited in W8.2:** `2c0db46` (`main`, tracking `origin/main`)
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

