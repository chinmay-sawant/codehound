#!/usr/bin/env bash
# Fail if production code under src/ uses .expect( or .unwrap( outside #[cfg(test)] modules.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

violations=0

while IFS= read -r -d '' file; do
  # Dedicated #[cfg(test)] modules (e.g. dependencies/tests.rs).
  if [[ "$(basename "$file")" == "tests.rs" ]]; then
    continue
  fi

  # Skip modules explicitly gated to tests.
  if grep -q '#\[cfg(test)\]' "$file"; then
    in_test=0
    while IFS= read -r line; do
      if [[ "$line" =~ ^#\[cfg\(test\)\] ]]; then
        in_test=1
        continue
      fi
      if [[ "$line" =~ ^(pub\ )?mod\  ]] && [[ $in_test -eq 1 ]]; then
        in_test=0
      fi
      if [[ $in_test -eq 1 ]]; then
        continue
      fi
      if [[ "$line" =~ ^[[:space:]]*// ]]; then
        continue
      fi
      if [[ "$line" =~ \.(expect|unwrap)\( ]]; then
        echo "ERROR: $file: $line"
        violations=$((violations + 1))
      fi
    done < "$file"
  else
    while IFS= read -r line; do
      if [[ "$line" =~ ^[[:space:]]*// ]]; then
        continue
      fi
      if [[ "$line" =~ \.(expect|unwrap)\( ]]; then
        echo "ERROR: $file: $line"
        violations=$((violations + 1))
      fi
    done < "$file"
  fi
done < <(find src -name '*.rs' -print0)

if [ "$violations" -gt 0 ]; then
  echo "Found $violations production unwrap/expect usage(s) in src/"
  exit 1
fi

echo "OK: no production unwrap/expect in src/"