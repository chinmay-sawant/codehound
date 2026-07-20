# v0.0.5 — CWE File-Permissions Phase 1 Evidence Baseline

> **Parent plan:** [`cwe-file-permissions-trust.md`](./cwe-file-permissions-trust.md)  
> **Issue:** [#86](https://github.com/chinmay-sawant/codehound/issues/86) (Phase 1 of epic [#85](https://github.com/chinmay-sawant/codehound/issues/85))  
> **Parent audit:** [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §1.3 promotion bar; §2.11 inventories siblings  
> **Branch:** `docs/cwe-file-perm-phase1-evidence`  
> **Status:** Phase 1 complete — frozen evidence only; **no** detector or maturity code changes  
> **Date:** 2026-07-20  
> **Source revision (docs branch base):** `e9485cb81d303382fd50638252f0c63c1bca0c8e` (`origin/master`)

---

## Purpose

Establish a frozen, per-rule evidence baseline for access-control file-permission siblings:

`CWE-276`, `CWE-277`, `CWE-278`, `CWE-279`, `CWE-281`, `CWE-921`

before any Phase 2 detector tightening or Phase 3 real-module canary. Dispositions below are
**candidates** for Phase 2/3; maturity and pack eligibility are **not** changed in this PR.

---

## Surfaces confirmed

| Surface | Path / note | Status |
|--------|-------------|--------|
| Detector | `src/lang/go/detectors/cwe/domains/access_control/file_permissions/file_modes.rs` | All six detectors present |
| Domain re-exports | `.../file_permissions/mod.rs` | `file_modes` re-exported |
| Registry | `src/lang/go/detectors/cwe/registry/registry.access_control.toml` | `cwe = 276/277/278/279/281/921` → `detect_cwe_*` |
| Severity / remediation overrides | `src/lang/go/detectors/cwe/metadata_overrides.rs` | All six High; fix text present |
| Catalogue docs | `ruleset/golang/chunks/cwe-201-9999.json` | Names + MITRE descriptions for all six |
| SourceIndex needles | `src/lang/go/detectors/cwe/source_index.rs` | See per-rule table; **not** labeled for this family yet (Phase 2) |
| Maturity | `src/rules/maturity.rs` | Default **Heuristic** (none on structural allow-list; none in `is_fixture_only`) |
| Default packs | `src/rules/pack.rs` + `src/core/profile.rs` | **Not** in `recommended` (PERF S + taint-core only); **not** in `security` (`SECURITY_PACK_RULES`); available under `--profile all` / explicit `--only` |
| Fixtures | stdlib + frameworks, vulnerable + safe for each ID | Manifest rows in `tests/fixtures/manifest.toml` |

### Maturity and pack membership (current)

| Rule | Maturity | `allowed_in_default_packs` | In recommended allow-list | In security allow-list | `--profile all` |
|------|----------|----------------------------|---------------------------|------------------------|-----------------|
| CWE-276 | Heuristic | yes | no | no | yes |
| CWE-277 | Heuristic | yes | no | no | yes |
| CWE-278 | Heuristic | yes | no | no | yes |
| CWE-279 | Heuristic | yes | no | no | yes |
| CWE-281 | Heuristic | yes | no | no | yes |
| CWE-921 | Heuristic | yes | no | no | yes |

Note: `allowed_in_default_packs` only means maturity does not force quarantine.
Recommended and security packs use explicit allow-lists that omit these IDs today.
Fixture-only quarantine (Phase 2 candidate for some rules) would only matter if a pack
later listed them by glob or expansion.

---

## Per-rule detector inventory

Source of truth: `file_modes.rs` at baseline revision.

### CWE-276 — Incorrect Default Permissions

| Field | Value |
|-------|--------|
| Function | `detect_cwe_276` |
| Sink / API | `os.WriteFile` with third argument exact `"0666"` |
| Primary matching signal | `facts.call_facts`: callee `os.WriteFile`, `arguments.len() >= 3`, `arguments[2] == "0666"` **and** session co-signal |
| Session co-signal | path arg contains `"sessions"` **or** SourceIndex `has_any(&["session_data", "X-Session-Data"])` |
| SourceIndex deps | **Positive gate:** `session_data`, `X-Session-Data` (when path lacks `sessions`) |
| Negative conditions | None explicit. Safe fixtures use mode `0600` so mode match fails. |
| Finding span | `write_call.start_byte` → `unit.line_col` |
| Message | session artifact written world-readable/writable |
| Fixtures | stdlib: path `/var/lib/codehound/sessions/` + `X-Session-Data`; frameworks: `GetString("session_data")` + sessions path |

**Evidence vs plan 1.2:** The production-shaped smell is `WriteFile(..., 0666)`. Emission still
requires session-shaped co-signals (`sessions` path substring or SI session needles). A bare
world-writable write of a non-session path does not fire. Neighbor CWE-250 covers
`WriteFile` + `0o777` without path co-signals as Heuristic.

**Phase 1 disposition candidate:** **fixture-only candidate**  
Corpus session co-signals dominate emission. Keep available under `--profile all`; Phase 2 may
quarantine or keep Heuristic if co-signals are rewritten to a general sensitive-artifact class.

**FP boundary:** Without co-signals, any `0666` write would mass-noise non-secret artifacts.
With co-signals, general insecure defaults outside session museum shapes are silent.

---

### CWE-277 — Insecure Inherited Permissions

| Field | Value |
|-------|--------|
| Function | `detect_cwe_277` |
| Sink / API | `syscall.Umask(0)` co-present with `os.MkdirAll(..., 0777)` |
| Primary matching signal | `call_facts` any `syscall.Umask` with first arg `"0"`; then any `os.MkdirAll` with second arg `"0777"` |
| SourceIndex deps | **None** |
| Negative conditions | Missing either call aborts. Safe: `Umask(027)` + `MkdirAll(..., 0750)`. |
| Finding span | `mkdir_call.start_byte` |
| Ordering | **Not** required — any order in the unit is enough |
| Message | umask cleared before world-writable directory creation |

**Evidence vs plan 1.2:** Condition is generalized call-facts only; no fixture path or helper
name. Exact decimal modes `0` / `0777` (not `0o777`) and no broader “permissive mode”
taxonomy. No real-module review yet (§1.3).

**Phase 1 disposition candidate:** **structural candidate**  
Strongest candidate in the family for later Structural promotion **if** Phase 3 canary + mode
variant coverage + negative near-miss meet §1.3. Until then, default remains Heuristic.

**FP boundary:** Intentional world-writable shared scratch dirs that clear umask; intentional
`0777` installers. Order-independence may link unrelated Umask and MkdirAll in large files.

---

### CWE-278 — Insecure Preserved Inherited Permissions

| Field | Value |
|-------|--------|
| Function | `detect_cwe_278` |
| Sink / API | `os.OpenFile` with mode argument containing `os.FileMode(hdr.Mode)` |
| Primary matching signal | `call_facts`: callee `os.OpenFile`, `arguments.len() >= 3`, `arguments[2].contains("os.FileMode(hdr.Mode)")` |
| SourceIndex deps | **None** |
| Negative conditions | Safe fixtures use fixed mode `0640` (+ optional `Chmod(..., 0640)`); no `hdr.Mode` in OpenFile mode arg |
| Finding span | `open_call.start_byte` |
| Message | archive entry permissions reapplied from untrusted metadata |

**Evidence vs plan 1.2:** Call-facts primary, but the mode proof is an **exact fixture formula**
(`os.FileMode(hdr.Mode)`). Alternate shapes (`header.Mode`, `hdr.FileInfo().Mode()`,
`os.FileMode(h.Mode)`, octal cast, etc.) do not match. No independent archive-metadata fact.

**Phase 1 disposition candidate:** **fixture-only candidate**  
Without a generalized “mode derived from archive header field” fact, emit is museum-shaped.

**FP boundary:** False negatives on renamed headers; false positives only when the exact
expression text appears (rare outside corpus / copy-paste extractors).

---

### CWE-279 — Incorrect Execution-Assigned Permissions

| Field | Value |
|-------|--------|
| Function | `detect_cwe_279` |
| Sink / API | `os.WriteFile` with third arg exact `"0777"` |
| Primary matching signal | SI prefilter `strconv.ParseUint(` **then** `call_facts` WriteFile + `"0777"` |
| SourceIndex deps | **Positive gate:** `strconv.ParseUint(` (file-level co-presence, **not** dataflow) |
| Negative conditions | Safe uses `os.FileMode(mode)` after capped ParseUint — third arg is not literal `0777` |
| Finding span | `write_call.start_byte` |
| Message | handler parses requested mode but still writes hard-coded world-writable mode |

**Evidence vs plan 1.2:** The message claims parse-then-ignore; the detector only proves
coexistence of `ParseUint(` and `WriteFile(..., 0777)` in the same unit. No use of the
parsed value, no assignment linking. Pure `WriteFile(..., 0777)` without ParseUint is silent
here (related world-writable write smells may live under CWE-250 / other rules with different
mode spellings).

**Phase 1 disposition candidate:** **fixture-only candidate**  
Security boundary is not proven by dataflow; ParseUint is a corpus co-signal for the
“execution-assigned” story.

**FP boundary:** Unrelated ParseUint (any base/bitSize) + unrelated WriteFile 0777 in one
file would fire; intentional world-writable drops with an unused parse would fire.

---

### CWE-281 — Improper Preservation of Permissions

| Field | Value |
|-------|--------|
| Function | `detect_cwe_281` |
| Sink / API | `os.Create` plus copy-shaped `io.Copy` |
| Primary matching signal | Negative SI `info.Mode()`; then `call_facts` any `os.Create`; then SI `io.Copy(out, in)` |
| SourceIndex deps | **Negative gate:** `info.Mode()`; **Positive gate:** exact needle `io.Copy(out, in)` |
| Negative conditions | Presence of `info.Mode()` silences (safe OpenFile uses `info.Mode()` as mode) |
| Finding span | `create_call.start_byte` |
| Message | backup recreation uses os.Create and loses source permission bits |

**Evidence vs plan 1.2:** `os.Create` is production-shaped, but emission requires the exact
fixture copy form `io.Copy(out, in)` and absence of `info.Mode()` text. No proof of
backup/sensitive intent beyond museum shape. Generic create+copy would mass-FP tools.

**Phase 1 disposition candidate:** **fixture-only candidate**

**FP boundary:** Any Create + exact `io.Copy(out, in)` without `info.Mode()` substring
(renamed vars `src`/`dst`, `io.Copy(dst, src)`, `io.CopyBuffer`, etc. silent or different).

---

### CWE-921 — Storage of Sensitive Data without Access Control

| Field | Value |
|-------|--------|
| Function | `detect_cwe_921` |
| Sink / API | SourceIndex-only: path + WriteFile needle + mode |
| Primary matching signal | SI has **all** of: `"/tmp/integration.key"`, `"WriteFile("`, `"0644"` |
| SourceIndex deps | **Positive:** `/tmp/integration.key`, `WriteFile(`, `0644`; **Negative:** `APP_SECRET_DIR` or `0600` |
| Negative conditions | Safe path under `APP_SECRET_DIR` + mode `0600` |
| Finding span | `unit.source.find("/tmp/integration.key")` (text search, not call span) |
| Message | sensitive integration key in world-readable temporary file |

**Evidence vs plan 1.2:** Every positive literal is corpus-shaped. There is **no** general
sensitive-key classification (no taint of secrets, no filename heuristics beyond exact path).
Call facts are unused.

**Phase 1 disposition candidate:** **fixture-only candidate**

**FP boundary:** Only exact `/tmp/integration.key` + `0644` + WriteFile needle; alternate
secret paths (`/tmp/api.key`, `0644` on other names) are silent.

---

## Disposition summary table (Phase 1 candidates)

| Rule | Disposition candidate | Concrete evidence | Known FP / FN boundary |
|------|----------------------|-------------------|------------------------|
| **CWE-276** | **fixture-only candidate** | `WriteFile`+`0666` call-facts **requires** `sessions` path or SI `session_data` / `X-Session-Data` | FN: world-writable non-session writes; FP risk if co-signals dropped |
| **CWE-277** | **structural candidate** | `Umask(0)` + `MkdirAll(..., 0777)` fully from `call_facts`; no SI | FP: intentional shared dirs; FN: `0o777` / non-zero permissive umask variants; order-independent coupling |
| **CWE-278** | **fixture-only candidate** | OpenFile call-facts gated on exact `os.FileMode(hdr.Mode)` arg text | FN: renamed header / other FileMode expressions |
| **CWE-279** | **fixture-only candidate** | `WriteFile`+`0777` + SI `strconv.ParseUint(` co-presence (no dataflow) | FP: unrelated parse + write; claim overstates proof |
| **CWE-281** | **fixture-only candidate** | `os.Create` + exact SI `io.Copy(out, in)` without `info.Mode()` | FP: generic create/copy; FN: renamed Copy args |
| **CWE-921** | **fixture-only candidate** | SI museum path `/tmp/integration.key` + `0644` + `WriteFile(` | FN: any other secret path/mode spelling |

No rule is Phase-1 promoted to Structural. No maturity.rs change in this phase.
`keep Heuristic` remains the **runtime** maturity for all six until Phase 2 applies
quarantine where candidates above are confirmed.

---

## SourceIndex needles used by this family (inventory only)

Not labeled in Phase 1 (Phase 2 owns `negative-gate` / `fixture-literal` comments).

| Needle | Used by | Role today |
|--------|---------|------------|
| `session_data` | CWE-276 | positive co-signal |
| `X-Session-Data` | CWE-276 | positive co-signal |
| `strconv.ParseUint(` | CWE-279 | positive co-signal (file-level) |
| `info.Mode()` | CWE-281 | negative gate |
| `io.Copy(out, in)` | CWE-281 | positive gate (exact form) |
| `/tmp/integration.key` | CWE-921 | fixture path literal |
| `WriteFile(` | CWE-921 | positive co-signal |
| `0644` | CWE-921 | positive mode literal |
| `APP_SECRET_DIR` | CWE-921 | negative gate |
| `0600` | CWE-921 | negative gate |
| `0666` | (index present; CWE-276 matches via call arg, not SI.has) | indexed |
| `MkdirAll(dir, 0777)` | (index present; CWE-277 uses call_facts) | indexed neighbor |

Modes `0666` / `0777` matched primarily via **call-fact argument text**, not SI.has, except
where noted.

---

## Fixture oracle

Command:

```sh
cargo test --locked --test go_cwe_detector_fixtures
```

**Result (2026-07-20, worktree on `docs/cwe-file-perm-phase1-evidence`):**

```
running 4 tests
test go_cwe_fixture_inventory_is_sorted_and_unique ... ok
test framework_cwe_393_safe_does_not_false_positive_cwe_89 ... ok
test taint_cwe_fixtures_fire_vulnerable_and_silence_safe ... ok
test go_cwe_fixtures_fire_vulnerable_and_silence_safe ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

All six rules have stdlib + frameworks vulnerable/safe pairs; oracle expects exactly the
named rule on vulnerable and silence on safe.

---

## Six-rule finding multiset (pre-detector-change baseline)

Release `cargo build --release --locked` was started but **not** completed within the Phase 1
agent budget (optional per issue). Multiset recorded with the **debug** binary built from the
same locked tree (`cargo build --locked --bin codehound`), which exercises the same detectors
and rule IDs as release for this purpose.

Materialized fixture roots (from stdlib + frameworks `.txt` fixtures):

```sh
# conceptual command shape (paths = materialized .go from fixtures)
codehound STDLIB_VULN FRAMEWORKS_VULN --profile all \
  --only CWE-276,CWE-277,CWE-278,CWE-279,CWE-281,CWE-921 \
  --format json --json-envelope --no-fail --no-cache
```

### Vulnerable multiset (12 files scanned)

| Rule | Count |
|------|------:|
| CWE-276 | 2 |
| CWE-277 | 2 |
| CWE-278 | 2 |
| CWE-279 | 2 |
| CWE-281 | 2 |
| CWE-921 | 2 |
| **Total** | **12** |

One hit per suite (stdlib + frameworks) per rule. Severity: High ×12.

### Safe multiset (12 files scanned)

| Rule | Count |
|------|------:|
| (none) | 0 |
| **Total** | **0** |

**Frozen oracle multiset:** vulnerable `{276:2, 277:2, 278:2, 279:2, 281:2, 921:2}`; safe empty.
Phase 2 must preserve this multiset unless a documented fixture near-miss is added.

### Real-module canary

**Out of scope for Phase 1** (Phase 3). Not run. Pinned targets remain gopdfsuit / monsoon /
go-retry per parent plan.

---

## Phase 2 implications (record only — do not implement here)

1. **CWE-277:** Prefer call-facts-only hygiene; consider `0o777` / `0o000` mode variants and
   order/function-scope negatives before Structural promotion.
2. **CWE-276 / 279 / 281 / 278 / 921:** Strong fixture-only quarantine candidates after NEEDLES
   labels; do not promote solely on fixture fire.
3. Label owned needles (`session_data`, `/tmp/integration.key`, `io.Copy(out, in)`, etc.) as
   `fixture-literal` or `negative-gate` with rule-named comments — family only, no bulk NEEDLES pass.
4. Maturity tests must assert every quarantine change in the same commit as `is_fixture_only`.

---

## Checklist (Phase 1)

- [x] Record each rule's sink/API, primary signal, SI deps, negatives, finding-span
- [x] Confirm metadata, registry, docs, default-pack membership for all six IDs
- [x] `cargo test --locked --test go_cwe_detector_fixtures` green
- [x] Six-rule `--only` multiset recorded (debug binary; release build deferred optional)
- [x] Per-rule disposition candidates: structural / keep Heuristic runtime / fixture-only candidate
- [x] Evidence written to this file; plan Phase 1 boxes updated
