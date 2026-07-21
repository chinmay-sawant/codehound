#!/usr/bin/env bash
# Pin and scan the decision-quality Go canary corpus (plans/v0.0.5/canary-corpus.md).
# Does not change pack membership or detectors. real-repos/ is gitignored.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PINS_JSON="${CODEHOUND_PINS_JSON:-$ROOT/plans/v0.0.5/canary-corpus-pins.json}"
CORPUS_ROOT="${CODEHOUND_CORPUS_ROOT:-$ROOT}"
REAL_REPOS="${CORPUS_ROOT}/real-repos"
GOPDFSUIT="${CODEHOUND_GOPDFSUIT:-/home/chinmay/ChinmayPersonalProjects/gopdfsuit}"

usage() {
  cat <<'EOF'
Usage:
  scripts/canary/run_decision_corpus.sh pin
  scripts/canary/run_decision_corpus.sh recommended
  scripts/canary/run_decision_corpus.sh only --only ID[,ID...]
  scripts/canary/run_decision_corpus.sh list

Environment:
  CODEHOUND_BIN           Path to codehound binary (default: build release)
  CODEHOUND_CORPUS_ROOT   Parent of real-repos/ (default: repo root)
  CODEHOUND_GOPDFSUIT     Path to gopdfsuit checkout
  CODEHOUND_PINS_JSON     Override pin manifest path

Notes:
  - Run recommended and family --only separately. Never treat recommended silence
    as proof that an all-profile / --only rule is correct.
  - Record reviews in plans/v0.0.5/canary-hit-rates.md using the corpus rubric.
EOF
}

need_python() {
  if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    echo "ERROR: python3 required to read $PINS_JSON" >&2
    exit 1
  fi
  if command -v python3 >/dev/null 2>&1; then
    echo python3
  else
    echo python
  fi
}

resolve_bin() {
  if [ -n "${CODEHOUND_BIN:-}" ]; then
    echo "$CODEHOUND_BIN"
    return
  fi
  if [ -x "$ROOT/target/release/codehound" ]; then
    echo "$ROOT/target/release/codehound"
    return
  fi
  echo "Building release codehound…" >&2
  cargo build -q --release --locked --bin codehound
  echo "$ROOT/target/release/codehound"
}

pin_one() {
  local id="$1" url="$2" rev="$3" dest="$4"
  if [ -d "$dest/.git" ]; then
    echo "== update $id @ $rev"
    git -C "$dest" fetch --quiet origin 2>/dev/null || git -C "$dest" fetch --quiet
    git -C "$dest" checkout --quiet --detach "$rev"
  else
    echo "== clone $id @ $rev"
    mkdir -p "$(dirname "$dest")"
    git clone --quiet "$url" "$dest"
    git -C "$dest" checkout --quiet --detach "$rev"
  fi
  local head
  head="$(git -C "$dest" rev-parse HEAD)"
  if [ "$head" != "$rev" ]; then
    echo "ERROR: $id HEAD $head != pin $rev" >&2
    exit 1
  fi
  echo "   ok $dest"
}

cmd_pin() {
  need_python >/dev/null
  local py
  py="$(need_python)"
  mkdir -p "$REAL_REPOS"
  "$py" - "$PINS_JSON" "$REAL_REPOS" "$GOPDFSUIT" <<'PY' | while IFS=$'\t' read -r id kind url rev path; do
import json, sys
pins_path, real_repos, gopdfsuit = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.load(open(pins_path, encoding="utf-8"))
for t in data["targets"]:
    tid = t["id"]
    url = t["git_url"]
    rev = t["revision"]
    kind = t["kind"]
    if kind == "real_repos":
        path = f"{real_repos}/{tid}"
    else:
        path = t.get("default_path") or gopdfsuit
    print(f"{tid}\t{kind}\t{url}\t{rev}\t{path}")
PY
    if [ "$kind" = "real_repos" ]; then
      pin_one "$id" "$url" "$rev" "$path"
    else
      if [ -d "$path/.git" ]; then
        head="$(git -C "$path" rev-parse HEAD 2>/dev/null || true)"
        echo "== external $id path=$path head=${head:-unknown} pin=$rev"
        if [ -n "$head" ] && [ "$head" != "$rev" ]; then
          echo "   WARN: gopdfsuit (or external) not at pinned revision; scan anyway or checkout $rev" >&2
        fi
      else
        echo "== external $id missing at $path (set CODEHOUND_GOPDFSUIT or clone $url)" >&2
      fi
    fi
  done
}

list_targets() {
  need_python >/dev/null
  local py
  py="$(need_python)"
  "$py" - "$PINS_JSON" "$REAL_REPOS" "$GOPDFSUIT" <<'PY'
import json, sys, os
pins_path, real_repos, gopdfsuit = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.load(open(pins_path, encoding="utf-8"))
for t in data["targets"]:
    if t["kind"] == "real_repos":
        path = os.path.join(real_repos, t["id"])
    else:
        path = os.environ.get("CODEHOUND_GOPDFSUIT", t.get("default_path") or gopdfsuit)
    print(f"{t['id']}\t{t['revision'][:12]}\t{path}")
PY
}

scan_paths() {
  need_python >/dev/null
  local py
  py="$(need_python)"
  "$py" - "$PINS_JSON" "$REAL_REPOS" "$GOPDFSUIT" <<'PY'
import json, sys, os
pins_path, real_repos, gopdfsuit = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.load(open(pins_path, encoding="utf-8"))
for t in data["targets"]:
    if t["kind"] == "real_repos":
        path = os.path.join(real_repos, t["id"])
    else:
        path = os.environ.get("CODEHOUND_GOPDFSUIT", t.get("default_path") or gopdfsuit)
    print(path)
PY
}

run_scan() {
  local profile="$1"
  shift
  local only_args=()
  if [ "$#" -gt 0 ]; then
    only_args=("$@")
  fi
  local bin
  bin="$(resolve_bin)"
  local path
  while IFS= read -r path; do
    if [ ! -d "$path" ]; then
      echo "SKIP missing $path" >&2
      continue
    fi
    echo "=== $(basename "$path") profile=$profile ${only_args[*]:-} ==="
    if [ "${#only_args[@]}" -gt 0 ]; then
      "$bin" "$path" --profile "$profile" "${only_args[@]}" \
        --format json --json-envelope --no-fail --no-cache
    else
      "$bin" "$path" --profile "$profile" \
        --format json --json-envelope --no-fail --no-cache
    fi
    echo
  done < <(scan_paths)
}

cmd_recommended() {
  echo "NOTE: recommended silence is not all-profile proof." >&2
  run_scan recommended
}

cmd_only() {
  local only_val=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --only)
        only_val="${2:-}"
        shift 2 || true
        ;;
      --only=*)
        only_val="${1#--only=}"
        shift
        ;;
      *)
        echo "Unknown argument: $1" >&2
        usage
        exit 2
        ;;
    esac
  done
  if [ -z "$only_val" ]; then
    echo "ERROR: only requires --only ID[,ID...]" >&2
    exit 2
  fi
  echo "NOTE: family --only run; do not substitute recommended silence." >&2
  run_scan all --only "$only_val"
}

main() {
  if [ ! -f "$PINS_JSON" ]; then
    echo "ERROR: missing pin manifest $PINS_JSON" >&2
    exit 1
  fi
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    pin) cmd_pin ;;
    list) list_targets ;;
    recommended) cmd_recommended ;;
    only) cmd_only "$@" ;;
    -h|--help|help|"") usage; [ -n "$cmd" ] || exit 2 ;;
    *) echo "Unknown command: $cmd" >&2; usage; exit 2 ;;
  esac
}

main "$@"
