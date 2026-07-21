# chore(cwe): audit response-leak trust (B2)

## Summary

- Phase 2 slice **B2** — freeze evidence, dispositions, and oracle-safe rewrites for the **metadata_leaks** response-leak subfamily (**CWE-209**, **CWE-215**, **CWE-756**, **CWE-1230**).
- Selected subfamily over `sensitive_fields` (201/213): plan §2.2 targets **generalized response sinks vs exact response-body/error literals**; metadata_leaks is dominated by exact error/body/header museum strings. `sensitive_fields` already uses call-facts on `c.JSON` / `Encode` and is deferred as a later sibling slice.
- **CWE-209 / 756 / 1230**: call-facts primary for the real sink APIs (`fmt.Sprintf`, `http.Error`/`c.String`, `c.Header`/`w.Header().Set`); corpus co-signals retained → **fixture-only**.
- **CWE-215**: already call-facts primary (`log.Printf` + secret-named user-controlled binding); **keep Heuristic** (quiet real-module canary; not structural — name-substring co-signal).
- Propose maturity/NEEDLES only for integrator; shared surfaces untouched.

---

## Motivation / context

Epic [#105](https://github.com/chinmay-sawant/codehound/issues/105) batches residual CWE catalog-trust families. Issue [#108](https://github.com/chinmay-sawant/codehound/issues/108) is slice B2 under `plans/v0.0.5/parallel-catalog-program.md` §2.2. Integration issue [#111](https://github.com/chinmay-sawant/codehound/issues/111).

**Integration base SHA:** `9d66183c3b29d8589317328170226bff6d4323d1`

Owner seam: `src/lang/go/detectors/cwe/domains/information_exposure/response_leaks/`

**Selected subfamily:** `metadata_leaks.rs` (209 / 215 / 756 / 1230)

**Deferred sibling:** `sensitive_fields.rs` (201 / 213) — already response-sink call-facts gated on corpus field/type names (`APIKey`/`TokenKey`/`userRecord`, `Salary`/`Comp`/`profile`); not the error-body/metadata-literal class §2.2 asks for.

---

## Evidence freeze (pre-change)

### CWE-209 — Generation of Error Message Containing Sensitive Information

| Axis | Frozen state |
|------|----------------|
| Primary SI | exact `fmt.Sprintf("db failure: %v", err)` |
| Negatives | safe fixture uses `log.Printf` + generic `"could not create …"` JSON body (no SI negative needle; absence of sprintf format) |
| Emit span | `source.find` of the sprintf literal |
| Fixtures | frameworks + stdlib vulnerable/safe pairs |
| Maturity (current) | Heuristic default (not in `is_fixture_only`) |

**Corpus vs real sink:** exact format string is the entire proof. No generalized err→client dataflow.

### CWE-215 — Insertion of Sensitive Information Into Debugging Code

| Axis | Frozen state |
|------|----------------|
| Primary | call_facts `log.Printf` + `input_bindings` UserControlled name containing `secret` |
| Negatives | safe logs path/method/trace only (no secret-named binding) |
| Emit span | `log.Printf` call site |
| Fixtures | frameworks + stdlib vulnerable/safe pairs |
| Maturity (current) | Heuristic default |

**Corpus vs real sink:** production-shaped log sink + request-derived binding; intentionally **not** generic log format strings (plan hard-out: do not invent broad log-string findings).

### CWE-756 — Missing Custom Error Page

| Axis | Frozen state (before rewrite) |
|------|-------------------------------|
| Primary SI | `err.Error()` ∧ `FetchProfile` ∧ `SELECT email FROM profiles` ∧ (`c.String(..., err.Error())` ∨ `http.Error(w, err.Error(), …)`) |
| Negatives | `"unable to load profile"` |
| Emit span | `source.find("err.Error()")` |
| Fixtures | frameworks + stdlib vulnerable/safe pairs |
| Maturity (current) | Heuristic default |

**Corpus vs real sink:** real sinks are `http.Error` / `c.String` with raw `err.Error()` body; helper name + SQL are corpus co-signals.

### CWE-1230 — Exposure of Sensitive Information Through Metadata

| Axis | Frozen state (before rewrite) |
|------|-------------------------------|
| Primary SI | (`DownloadRedacted(` ∨ `DownloadRedactedPure(`) ∧ `X-Original-Name` ∧ `X-File-Size` ∧ `[REDACTED CONTENT]` |
| Negatives | `Cache-Control` |
| Emit span | `source.find("X-Original-Name")` |
| Fixtures | frameworks + stdlib vulnerable/safe pairs |
| Maturity (current) | Heuristic default |

**Corpus vs real sink:** real sinks are header writes (`c.Header` / `w.Header().Set`); helper names + redacted body are corpus co-signals.

---

## Subfamily selection rationale

| Candidate | Rules | Why select / defer |
|-----------|-------|--------------------|
| **metadata_leaks** (selected) | 209, 215, 756, 1230 | Direct match for §2.2 “response sinks vs exact response-body/error literals”; three of four rules are pure SI museums of error/body/header text |
| sensitive_fields (deferred) | 201, 213 | Already call-facts on JSON response sinks; residual risk is field-inventory naming (`APIKey`, `Salary`, record type names), not error-body literals |

---

## Changes

### Detector (`metadata_leaks.rs` only)

| Rule | Change |
|------|--------|
| CWE-209 | Call-facts primary: `fmt.Sprintf` with format `"db failure: %v"` and arg `err`; SI prefilter retains exact full sprintf literal; emit at sprintf call site |
| CWE-215 | Comments + freeze documentation only; call-facts/`input_bindings` proof boundary unchanged. **No** SI `log.Printf` prefilter (bare token is not an owned NEEDLE) |
| CWE-756 | Call-facts primary: `http.Error` or `c.String` with arg `err.Error()`; SI co-signals `FetchProfile` + `SELECT email FROM profiles`; SI negative `"unable to load profile"`; emit at error-sink call site |
| CWE-1230 | Call-facts primary: `c.Header` or `w.Header().Set` with arg `"X-Original-Name"`; SI co-signals redacted helpers + `X-File-Size` + `[REDACTED CONTENT]`; SI negative `Cache-Control`; emit at header call site |

### Explicitly not changed (integrator / out of scope)

- `src/rules/maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`
- `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`
- Sibling B1/B3/B4; `sensitive_fields.rs`; secrets_and_transport (Phase 1)
- No new fixture files; no fixture renames
- No broad log-string or generic response-string findings

---

## Proposed dispositions (integrator)

| Rule | Disposition | Call-facts | Rationale |
|------|-------------|------------|-----------|
| CWE-209 | **fixture-only** quarantine | yes — `fmt.Sprintf` + exact format | Exact `"db failure: %v"` museum; without it generic err sprintf would mass-FP |
| CWE-215 | **keep Heuristic** | yes — `log.Printf` + secret binding | Production-shaped; canary quiet; not structural (name.contains("secret") co-signal) |
| CWE-756 | **fixture-only** quarantine | yes — `http.Error`/`c.String` + `err.Error()` | Sink is real, but emit still gated on `FetchProfile` + fixed SELECT corpus |
| CWE-1230 | **fixture-only** quarantine | yes — `c.Header`/`w.Header().Set` + `X-Original-Name` | Header sink is real, but still gated on DownloadRedacted helper names + redacted-body corpus |

Prefer fixture-only quarantine for 209/756/1230 over Heuristic keep: all remain corpus-gated. Do **not** structural-promote any rule. Do **not** broaden CWE-215 to generic log formats.

### Proposed NEEDLES labels (integrator applies in `source_index.rs`)

| Needle | Proposed label |
|--------|----------------|
| `fmt.Sprintf("db failure: %v", err)` | `fixture-literal` (CWE-209 sensitive error format) |
| `err.Error()` | co-signal / prefilter (shared; CWE-756 uses as SI + call_facts arg) |
| `FetchProfile` | `fixture-literal` (CWE-756 helper name) |
| `SELECT email FROM profiles` | `fixture-literal` (CWE-756 SQL co-signal) |
| `c.String(http.StatusInternalServerError, err.Error())` | may demote after call_facts primary (legacy full-call needle) |
| `http.Error(w, err.Error(), http.StatusInternalServerError)` | may demote after call_facts primary (legacy full-call needle) |
| `"unable to load profile"` | `negative-gate` (CWE-756 safe-path) |
| `DownloadRedacted(` / `DownloadRedactedPure(` | `fixture-literal` (CWE-1230 helpers) |
| `X-Original-Name` | co-signal (CWE-1230 header name; call_facts primary after this PR) |
| `X-File-Size` | `fixture-literal` / co-signal (CWE-1230 size header) |
| `[REDACTED CONTENT]` | `fixture-literal` (CWE-1230 redacted body) |
| `Cache-Control` | `negative-gate` (CWE-1230 safe-path) |

### Proposed maturity.rs (integrator)

```rust
| "CWE-209" // fmt.Sprintf "db failure: %v" corpus format (call_facts primary)
| "CWE-756" // FetchProfile + SELECT + err.Error() client sink corpus
| "CWE-1230" // DownloadRedacted* + X-Original-Name/X-File-Size corpus
// leave CWE-215 as default Heuristic (call_facts log.Printf + secret binding)
```

Plus matching unit-test asserts in `maturity.rs` tests.

### Fixtures / oracle impact

- No fixture additions or renames.
- Vulnerable fixtures still fire; safe fixtures still silence.
- Emit spans shift to call sites for 209/756/1230 (fixture oracle checks rule presence only, not line).

---

## Canary

Release binary on this branch; integration base `9d66183c3b29d8589317328170226bff6d4323d1`.

```sh
cargo build --release --locked
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry; do
  echo "=== $t ==="
  target/release/codehound "$t" --profile all \
    --only CWE-209,CWE-215,CWE-756,CWE-1230 \
    --format json --json-envelope --no-fail --no-cache 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print('findings', len(d.get('findings',[])), 'files', d.get('stats',{}).get('files_scanned'))"
done
```

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 0 |
| monsoon | `codehound/real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `codehound/real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |

**Totals:** 126 scanned files. Per-rule: CWE-209 ×0, CWE-215 ×0, CWE-756 ×0, CWE-1230 ×0.

**Decision:** quarantine 209/756/1230 as fixture-only (`--profile all` only). Keep CWE-215 Heuristic without structural promotion. Do not broaden CWE-215. Revisit 756/1230 only when client-error / metadata-header classification generalizes beyond corpus helpers; revisit 209 only with err→response dataflow; revisit 215 only with a typed secret model (not name-substring).

---

## Validation

```sh
make lint
cargo test --locked --test go_cwe_detector_fixtures
make test
git diff --check
```

- `make lint` — green
- `go_cwe_detector_fixtures` — 4 passed (oracle preserved; 350 fixture pairs incl. metadata_leaks)
- `make test` — 443/443 passed
- `git diff --check` — clean

---

## Integrator handoff

1. Apply `is_fixture_only` for **CWE-209**, **CWE-756**, **CWE-1230** (+ maturity unit tests). Leave **CWE-215** Heuristic.
2. Label owned NEEDLES as proposed above (do not bulk-relabel shared needles without review). Optional: demote full-call SI strings for 756 once call_facts is primary.
3. Append dated audit section (response-leak metadata_leaks) to `cwe-catalog-trust-audit.md` from this evidence; mark residual inventory item for B2.
4. Wire nothing new into `manifest.toml` (no fixture additions).
5. Integration merge order for Phase 2: detector/fixture commits first (this PR), then shared maturity/index/manifest, then audit ledger — on branch `chore/epic-105-phase2-integration` (issue #111).
6. Re-run combined Phase 2 `--only` canary after B1–B4 land; this worker canary is evidence, not final integrated proof.
7. No structural promotion for any rule under §1.3. Do not invent broad log-string findings.
8. Deferred: `sensitive_fields` (201/213) for a later slice.

### Integration note (epic Phase 2)

- Branch: `chore/cwe-trust-response-leaks`
- Integration base: `9d66183c3b29d8589317328170226bff6d4323d1`
- Diff surface: **one file** under `response_leaks/metadata_leaks.rs` (+ this PR plan doc)
- Sibling conflict risk: low (B1 credential_lifecycle, B3 access_control sibling, B4 privilege/lifecycle are separate seams)
- Note for integration branch: `chore/epic-105-phase2-integration`

---

## Impact

| Area | Impact |
|------|--------|
| **Performance** | Neutral/slightly better (SI prefilters retained; call_facts scans only when prefilters pass for 209/756/1230) |
| **Behavior** | Emit spans on call sites for 209/756/1230; same true/false positive shape outside corpus paths |
| **Pack membership** | Unchanged until integrator adds fixture-only maturity for 209/756/1230 |
| **Dependencies** | None |

---

## Closes

- Closes [#108](https://github.com/chinmay-sawant/codehound/issues/108)
- Relates to [#105](https://github.com/chinmay-sawant/codehound/issues/105)
- Relates to [#111](https://github.com/chinmay-sawant/codehound/issues/111)

---

## Reviewer checklist

- [ ] Only `response_leaks/` (+ plans PR handoff) edited (no maturity/index/manifest/audit)
- [ ] Fixture oracle preserved for CWE-209/215/756/1230
- [ ] `sensitive_fields.rs` untouched
- [ ] No broad log-string findings introduced
- [ ] Disposition proposals clear for integrator
- [ ] Canary command and zero-hit totals recorded
- [ ] PR assignee + labels
- [ ] Integration branch note `chore/epic-105-phase2-integration`
