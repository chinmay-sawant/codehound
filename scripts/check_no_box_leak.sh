#!/usr/bin/env bash
# Fail if new Box::leak sites appear outside the documented allowlist.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Allowlisted intentional leaks (intern tables / static lookup tables).
ALLOW_RE='src/rules/finding_wire\.rs|src/lang/source_index\.rs|src/engine/result\.rs'

hits=$(rg -n 'Box::leak' src --type rust || true)
if [ -z "$hits" ]; then
  echo "no Box::leak in src/"
  exit 0
fi

bad=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  file=${line%%:*}
  if echo "$file" | rg -q "$ALLOW_RE"; then
    echo "allowlisted: $line"
  else
    echo "ERROR: unexpected Box::leak: $line"
    bad=1
  fi
done <<< "$hits"

if [ "$bad" -ne 0 ]; then
  echo "Add to allowlist only with review (static tables / interners)."
  exit 1
fi
echo "Box::leak check ok"
