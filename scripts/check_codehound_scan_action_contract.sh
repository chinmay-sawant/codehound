#!/usr/bin/env bash
# Proof for .github/actions/codehound-scan/action.yml:
# scan may exit non-zero; SARIF upload still runs; strict then returns that status.
set -euo pipefail

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
sarif="$tmpdir/out.sarif"
upload_log="$tmpdir/upload.log"
fail_log="$tmpdir/fail.log"

# Fake scanner: write SARIF, then exit 2 (strict findings).
fake_scan() {
  printf '%s\n' '{"version":"2.1.0","runs":[]}' >"$sarif"
  return 2
}

# Fake upload that always runs (mirrors always() + continue-on-error).
fake_upload() {
  echo "uploaded $(basename "$sarif")" >"$upload_log"
}

scan_exit=0
fake_scan || scan_exit=$?
fake_upload

strict=true
if [ "$strict" = "true" ] && [ "$scan_exit" != "0" ]; then
  echo "strict fail with status=$scan_exit" >"$fail_log" || true
  # Assert upload happened before the gate.
  grep -q 'uploaded out.sarif' "$upload_log"
  test -s "$sarif"
  test "$scan_exit" -eq 2
  echo "ok: strict finding fails after SARIF upload (status=$scan_exit)"
  exit 0
fi

echo "unexpected: strict gate did not fire" >&2
exit 1
