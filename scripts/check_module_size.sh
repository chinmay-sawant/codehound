#!/usr/bin/env bash
# Module size policy for src/**/*.rs.
# Soft warn at 400 lines; hard fail at 500 except known data/detector bulk modules.
# Detector domain files and needle tables are listed as notes until split (Phase 8+).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SOFT=400
HARD=500
fail=0
warn=0

is_exempt() {
  case "$1" in
    *source_index.rs|*metadata_overrides.rs|*baseline/store.rs)
      return 0
      ;;
    # Large detector batches — tracked debt; do not block 0.1.0 CI
    *detectors/bad_practices/rules/*|*detectors/perf/domains/*|*detectors/cwe/taint/*)
      return 0
      ;;
    *app/run.rs|*engine/walk/parallel.rs|*detectors/cwe/mod.rs)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

while IFS= read -r -d '' f; do
  lines=$(wc -l < "$f" | tr -d ' ')
  if is_exempt "$f"; then
    if [ "$lines" -gt "$SOFT" ]; then
      echo "note: $f is $lines lines (exempt bulk/detector module)"
    fi
    continue
  fi
  if [ "$lines" -gt "$HARD" ]; then
    echo "ERROR: $f has $lines lines (hard limit $HARD)"
    fail=1
  elif [ "$lines" -gt "$SOFT" ]; then
    echo "WARN: $f has $lines lines (soft limit $SOFT)"
    warn=1
  fi
done < <(find src -name '*.rs' -print0)

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "module size check ok (warns=$warn)"
