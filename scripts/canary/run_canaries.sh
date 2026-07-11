#!/usr/bin/env bash
# Run in-repo canary budgets. Fails on unexpected finding-count spikes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

BIN="${CODEHOUND_BIN:-}"
if [ -z "$BIN" ]; then
  cargo build -q --release --bin codehound
  BIN="$ROOT/target/release/codehound"
fi

BUDGETS="$ROOT/scripts/canary/budgets.json"
if [ ! -f "$BUDGETS" ]; then
  echo "ERROR: missing $BUDGETS"
  exit 1
fi

python3 - "$BIN" "$BUDGETS" <<'PY'
import json, subprocess, sys
from collections import Counter

bin_path, budgets_path = sys.argv[1], sys.argv[2]
budgets = json.load(open(budgets_path, encoding="utf-8"))
fail = 0
for name, cfg in budgets.items():
    path = cfg["path"]
    profile = cfg.get("profile", "recommended")
    max_f = int(cfg["max_findings"])
    cmd = [bin_path, "--profile", profile, "--format", "json", "--no-cache", path]
    print(f"== canary {name}: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    # Exit codes: findings may yield non-zero; treat crashes (>=128 or 101) as fail.
    if proc.returncode >= 100:
        print(f"ERROR: {name} exited {proc.returncode}\n{proc.stderr}")
        fail = 1
        continue
    try:
        data = json.loads(proc.stdout) if proc.stdout.strip() else []
    except json.JSONDecodeError as e:
        print(f"ERROR: {name} invalid JSON: {e}\nstdout={proc.stdout[:500]}")
        fail = 1
        continue
    if isinstance(data, dict):
        findings = data.get("findings", data.get("results", []))
    else:
        findings = data
    n = len(findings) if isinstance(findings, list) else 0
    print(f"   findings={n} budget<={max_f}")
    if n > max_f:
        print(f"ERROR: {name} spiked: {n} > {max_f}")
        c = Counter(
            (f.get("rule_id") or f.get("ruleId"))
            for f in findings
            if isinstance(f, dict)
        )
        print("   top:", c.most_common(8))
        fail = 1
sys.exit(fail)
PY
