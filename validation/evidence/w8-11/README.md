# W8-11 hardware evidence

`scripts/pi400/validate.sh` writes timestamped machine-readable `evidence.json`,
human-readable `report.md`, conformance reports, and per-step logs here.

Generated device evidence is ignored by default because it may contain local
host details. Review and redact it before deliberately adding an approved
evidence bundle. Never add credentials, private keys, hostnames, or addresses.
