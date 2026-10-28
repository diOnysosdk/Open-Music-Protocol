#!/usr/bin/env sh
set -u

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo" || exit 2

stamp=$(date -u +%Y%m%dT%H%M%SZ)
commit=$(git rev-parse HEAD 2>/dev/null || printf unknown)
output=${1:-"validation/evidence/w8-11/${stamp}-${commit}"}

python=python3
if [ -x "$HOME/.venv-omp-validation/bin/python" ]; then python="$HOME/.venv-omp-validation/bin/python"; fi
"$python" scripts/pi400/validate.py --output "$output"
status=$?
if [ -f "$output/evidence.json" ] && [ -f "$output/report.md" ]; then
  printf '%s\n' "Evidence written to $output"
else
  printf '%s\n' "ERROR: validator exited before evidence could be written" >&2
fi
exit "$status"
