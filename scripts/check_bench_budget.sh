#!/usr/bin/env bash
set -euo pipefail

THRESHOLD=65000000
BENCH_OUT=$(cat "${1:-bench_output.txt}")
TIME=$(echo "$BENCH_OUT" | grep 'scan_materialized_fixtures' | sed -n 's/.*bench:\s*\([0-9]*\)\s*ns\/iter.*/\1/p')
if [ -n "$TIME" ]; then
  if [ "$TIME" -gt "$THRESHOLD" ]; then
    echo "ERROR: scan_materialized_fixtures time ${TIME} ns exceeds budget ${THRESHOLD} ns"
    exit 1
  fi
  echo "scan_materialized_fixtures: ${TIME} ns (budget: ${THRESHOLD} ns)"
else
  echo "WARNING: scan_materialized_fixtures not found in bench output"
fi
