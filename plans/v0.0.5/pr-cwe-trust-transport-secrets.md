# chore(cwe): audit transport-secret trust (CWE-524/538)

## Summary

- Phase 1 slice **A2** — freeze evidence, duplication check, dispositions, and oracle-safe rewrite for transport-secret neighbors **CWE-524** and **CWE-538**.
- **CWE-538**: call-facts primary for `os.WriteFile` + mode `0o644`; corpus co-signals (`DATABASE_URL`, `/var/www/*`) remain required.
- **CWE-524**: no call-facts rewrite (package-level map assignment + exact `tokenCache`/`tokenVault` identifiers); document as fixture museum.
- **CWE-319** left untouched (already dispositioned in §2.10).
- Propose **fixture-only** maturity for both rules (integrator owns `maturity.rs` / NEEDLES / audit).

---

## Motivation / context

Epic [#95](https://github.com/chinmay-sawant/codehound/issues/95) batches residual CWE catalog-trust families. Issue [#97](https://github.com/chinmay-sawant/codehound/issues/97) is slice A2 under `plans/v0.0.5/parallel-catalog-program.md` §1.2.

**Integration base SHA:** `217c0078d8a585e0e08b3b113e665898f6bf62dd`

Owner seam: `src/lang/go/detectors/cwe/domains/information_exposure/secrets_and_transport/`

---

## Evidence freeze (pre-change)

### CWE-524 — Use of Cache Containing Sensitive Information

| Axis | Frozen state |
|------|----------------|
| Primary SI | `map[string]string{}` ∧ `Authorization` ∧ (`tokenCache` ∨ `tokenVault`) |
| Negatives | `context.WithValue(` ∨ `session_token` |
| Emit span | source find of `tokenCache` / `tokenVault` |
| Fixtures | frameworks + stdlib vulnerable/safe pairs in `tests/fixtures/go/{frameworks,stdlib}/CWE-524-*.txt` |
| Maturity (current) | Heuristic default (not in `is_fixture_only`) |
| Profile | eligible for default packs until integrator quarantines |

**Corpus vs real sink:** exact package-level cache identifiers + header name co-signal. No generalized API boundary (map assignment is not `call_facts`).

### CWE-538 — Insertion of Sensitive Information into Externally-Accessible File

| Axis | Frozen state (before rewrite) |
|------|-------------------------------|
| Primary SI | `DATABASE_URL` ∧ `os.WriteFile(` ∧ (`/var/www/` ∨ `/var/www/html/public/`) ∧ `0o644` |
| Negatives | `/var/lib/codehound/private` ∨ `0o600` |
| Emit span | path literal `/var/www/html/public/config-snapshot.txt` or `/var/www/static` |
| Fixtures | frameworks + stdlib vulnerable/safe pairs in `tests/fixtures/go/{frameworks,stdlib}/CWE-538-*.txt` |
| Maturity (current) | Heuristic default |

**Corpus vs real sink:** real sink is `os.WriteFile` + world-readable mode; public path + `DATABASE_URL` are corpus co-signals (path often bound through a local `path` variable).

---

## Duplication check

| Neighbor | Domain | Overlap? | Notes |
|----------|--------|----------|-------|
| CWE-921 | file_permissions | adjacent | WriteFile `0644` + `/tmp/integration.key` — different secret/path shape |
| CWE-250 / 252 | permissions_and_ownership | adjacent | WriteFile mode/error-check; not secret-export |
| CWE-276 | file_permissions | adjacent | session WriteFile `0666` |
| CWE-821 | concurrency/shared_state | token name only | `tokenCache[key] = value` under `RLock` — race, not secret cache |
| CWE-312 | secrets_and_transport/payloads | no | cleartext SSN persistence |
| bootstrap `APP_DATABASE_URL` | password_storage | no | credential config, not public export |
| taint FileWrite | taint core | no | path-injection / user-controlled path, not fixed public export of DSN |

**Conclusion:** no duplicate ownership. CWE-538 remains the public-path secret-export shape; CWE-524 remains the process-wide token-cache museum.

---

## Changes

### Detector (`transport.rs` only)

| Rule | Change |
|------|--------|
| CWE-524 | Comments only — document why no call-facts rewrite; proof boundary unchanged |
| CWE-538 | Call-facts primary: `os.WriteFile` with arg[2] `== "0o644"`; SI prefilter `os.WriteFile(`; SI co-signals `DATABASE_URL` + `/var/www/` paths; SI negatives private path / `0o600`; emit span moves to WriteFile call site |
| CWE-319 | Untouched |

### Explicitly not changed (integrator / out of scope)

- `src/rules/maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`
- `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`
- Sibling streams A1/A3/A4; response_leaks (Phase 2 B2)
- No new fixture files; no fixture renames

---

## Proposed dispositions (integrator)

| Rule | Disposition | Call-facts | Rationale |
|------|-------------|------------|-----------|
| CWE-524 | **fixture-only** quarantine | no | Exact `tokenCache`/`tokenVault` + map + Authorization corpus shape; no generalized API sink |
| CWE-538 | **fixture-only** quarantine | yes — `os.WriteFile` + `0o644` primary | WriteFile+mode is production-shaped, but emit still depends on `DATABASE_URL` + `/var/www/*` corpus paths. **Not** structural (§1.3 bar not met; zero real-module hits) |

Prefer fixture-only quarantine over Heuristic keep: both remain corpus-gated. Do not structural-promote.

### Proposed NEEDLES labels (integrator applies in `source_index.rs`)

| Needle | Proposed label |
|--------|----------------|
| `tokenCache` / `tokenVault` | `fixture-literal` (CWE-524 cache identifiers) |
| `map[string]string{}` | `fixture-literal` / co-signal (CWE-524 process-wide map shape; shared needle) |
| `Authorization` | co-signal (shared; not exclusive to 524) |
| `session_token` / `context.WithValue(` | `negative-gate` (CWE-524 safe-path) |
| `DATABASE_URL` | `fixture-literal` / co-signal (CWE-538 secret env) |
| `/var/www/` / `/var/www/html/public/` | `fixture-literal` (CWE-538 public export path) |
| `/var/lib/codehound/private` | `negative-gate` (CWE-538 safe-path) |
| `0o644` | mode co-signal (call_facts primary after this PR for CWE-538; may remain shared with other rules) |
| `0o600` | `negative-gate` (CWE-538 safe-path mode) |
| `os.WriteFile(` | `negative-gate` prefilter (shared; call_facts primary for CWE-538 mode proof) |

### Proposed maturity.rs (integrator)

```rust
| "CWE-524" // tokenCache/tokenVault + map + Authorization corpus shape
| "CWE-538" // DATABASE_URL + /var/www/* + WriteFile 0o644 corpus shape (call_facts primary mode)
```

Plus matching unit-test asserts in `maturity.rs` tests.

### Fixtures / oracle impact

- No fixture additions or renames.
- Vulnerable fixtures still fire; safe fixtures still silence.
- CWE-538 emit span shifts from path string to `os.WriteFile` call site (fixture oracle checks rule presence only, not line).

---

## Canary

Release binary on this branch; integration base `217c0078d8a585e0e08b3b113e665898f6bf62dd`.

```sh
cargo build --release --locked
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry; do
  echo "=== $t ==="
  target/release/codehound "$t" --profile all \
    --only CWE-524,CWE-538 \
    --format json --json-envelope --no-fail --no-cache 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print('findings', len(d.get('findings',[])), 'files', d.get('stats',{}).get('files_scanned'))"
done
```

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 0 |
| monsoon | `real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |

**Totals:** 126 scanned files. Per-rule: CWE-524 ×0, CWE-538 ×0.

**Decision:** quarantine both as fixture-only (`--profile all` only). Keep CWE-538 call-facts primary for WriteFile mode without structural promotion. Do not rewrite CWE-524. Revisit CWE-538 only when public-path / secret-env classification generalizes beyond corpus paths; revisit CWE-524 only with a generalized process-wide secret-cache fact model.

---

## Validation

```sh
make lint
cargo test --locked --test go_cwe_detector_fixtures
make test   # 442/443 then 443/443 on recheck of flaky engine_baseline_io timing
git diff --check
```

- `make lint` — green
- `go_cwe_detector_fixtures` — 4 passed (oracle preserved)
- `make test` — one unrelated timing flake (`large_baseline_loads_and_filters_under_target` >2s under load); re-ran green at 1.36s
- `git diff --check` — clean

---

## Integrator handoff

1. Apply `is_fixture_only` for **CWE-524** and **CWE-538** (+ maturity unit tests).
2. Label owned NEEDLES as proposed above (do not bulk-relabel shared needles without review).
3. Append dated audit section (transport-secret neighbors) to `cwe-catalog-trust-audit.md` from this evidence; mark residual inventory item closed for 524/538.
4. Wire nothing new into `manifest.toml` (no fixture additions).
5. Integration merge order for epic batch-1: detector/fixture commits first (this PR), then shared maturity/index/manifest, then audit ledger.
6. Re-run combined Phase 1 `--only` canary after all A1–A4 land; this worker canary is evidence, not final integrated proof.
7. No structural promotion for either rule under §1.3.

### Integration note (epic batch-1)

- Branch: `chore/cwe-trust-transport-secrets`
- Integration base: `217c0078d8a585e0e08b3b113e665898f6bf62dd`
- Diff surface: **one file** under `secrets_and_transport/transport.rs`
- Sibling conflict risk: low (A1 password_storage, A3 deserialization, A4 access_control are separate seams)

---

## Impact

| Area | Impact |
|------|--------|
| **Performance** | Neutral (same SI prefilters; one call_facts scan for 538) |
| **Behavior** | CWE-538 emit span on WriteFile; same true/false positive shape outside corpus paths |
| **Pack membership** | Unchanged until integrator adds fixture-only maturity |
| **Dependencies** | None |

---

## Closes

- Closes [#97](https://github.com/chinmay-sawant/codehound/issues/97)
- Relates to [#95](https://github.com/chinmay-sawant/codehound/issues/95)

---

## Reviewer checklist

- [ ] Only `secrets_and_transport/` edited (no maturity/index/manifest/audit)
- [ ] Fixture oracle preserved for CWE-524/538
- [ ] CWE-319 untouched
- [ ] Disposition proposals clear for integrator
- [ ] Canary command and zero-hit totals recorded
- [ ] PR assignee + labels
