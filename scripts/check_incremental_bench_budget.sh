#!/usr/bin/env bash
# Assert warm incremental scan is at least 5× faster than cold scan.
# Missing metrics hard-fail (was soft WARNING + exit 0).
set -euo pipefail

COLD_TIME=$(grep 'incremental_cold' "${1:-bench_output.txt}" | sed -n 's/.*bench:\s*\([0-9]*\)\s*ns\/iter.*/\1/p' | head -1)
WARM_TIME=$(grep 'incremental_warm' "${1:-bench_output.txt}" | sed -n 's/.*bench:\s*\([0-9]*\)\s*ns\/iter.*/\1/p' | head -1)

if [ -z "$COLD_TIME" ] || [ -z "$WARM_TIME" ]; then
  echo "ERROR: incremental_cold or incremental_warm not found in bench output"
  exit 1
fi

if [ "$WARM_TIME" -eq 0 ]; then
  echo "ERROR: incremental_warm is 0 ns (invalid)"
  exit 1
fi

RATIO=$(( COLD_TIME / WARM_TIME ))
echo "incremental_cold: ${COLD_TIME} ns, incremental_warm: ${WARM_TIME} ns (cold/warm ratio: ${RATIO})"

if [ "$RATIO" -lt 5 ]; then
  echo "ERROR: warm scan ratio ${RATIO}× is below 5× budget (cold ${COLD_TIME} ns, warm ${WARM_TIME} ns)"
  exit 1
fi

echo "incremental bench budget ok"
