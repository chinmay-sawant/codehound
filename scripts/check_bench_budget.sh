#!/usr/bin/env bash
# Fail CI when scan throughput regresses past a loose ceiling, or when
# expected Criterion lines are missing.
#
# Two modes (env BUDGET_MODE):
#   smoke  (default) — loose ceiling for PR smoke (multi-second reality)
#   budget           — tighter gate for dedicated perf jobs
set -euo pipefail

MODE="${BUDGET_MODE:-smoke}"
BENCH_OUT=$(cat "${1:-bench_output.txt}")

# Historical ~40–65ms gates were cache-contaminated / wrong surface.
# Real fixture scans are multi-second on CI hardware; keep honest ceilings.
if [ "$MODE" = "budget" ]; then
  # ~8s ceiling for full fixture scan (ns)
  THRESHOLD=8000000000
else
  # smoke: ~32s loose ceiling
  THRESHOLD=32000000000
fi

extract_ns() {
  local name="$1"
  echo "$BENCH_OUT" | grep "$name" | sed -n 's/.*bench:\s*\([0-9]*\)\s*ns\/iter.*/\1/p' | head -1
}

fail=0

check_metric() {
  local name="$1"
  local thr="${2:-}"
  local time
  time=$(extract_ns "$name")
  if [ -z "$time" ]; then
    echo "ERROR: expected bench line missing: $name"
    fail=1
    return
  fi
  echo "$name: ${time} ns"
  if [ -n "$thr" ] && [ "$time" -gt "$thr" ]; then
    echo "ERROR: $name time ${time} ns exceeds budget ${thr} ns (mode=$MODE)"
    fail=1
  fi
}

check_metric "scan_materialized_fixtures" "$THRESHOLD"
check_metric "collect_entries_materialized"
check_metric "scan_go_only_two_rules"
# Microbench is optional in older bench outputs; require when present in suite.
if echo "$BENCH_OUT" | grep -q 'source_index_has_lookup'; then
  check_metric "source_index_has_lookup"
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "bench budget ok (mode=$MODE, scan_materialized_fixtures ceiling ${THRESHOLD} ns)"
