# W8-11 task: Raspberry Pi 400 ARM64 validation report

Date: 2026-10-28. Status: **BLOCKED**.

The repository now has a fail-closed native hardware evidence runner and a
Windows-to-Pi SSH workflow. The runner records the exact commit, UTC times,
system-reported hardware/OS/kernel/CPU/toolchain data, dependency checks,
native workspace build and tests, Python specification tests, conformance,
frozen-baseline verification, integration tests, runtime smoke results,
resource use, exit codes, and diagnostics in JSON and Markdown.

Physical execution did not occur: this Windows environment has no configured
SSH directory, Pi connection parameters, or previous Pi evidence. A local
self-test correctly rejected `amd64` with exit code 2 and produced a BLOCKED
report. No ARM64 or Raspberry Pi compatibility claim is made.

The task name conflicts with the existing finding register. In the repository
source of truth, `W8-11` is a High-severity FLAC memory-exhaustion finding, not
the ARM64 gate. It remains **OPEN/HIGH** pending root-cause remediation, a
minimal regression, and clean repeats of all five ASan campaigns. Hardware
validation cannot close it.

Consequently, controlled development remains GO, while external alpha and
production release remain NO-GO.
