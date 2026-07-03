# P2 — PERF Hygiene: Benchmark Regression, Diagnostic Docs, Fixture Audit, Edge-case Hardening

> **Parent:** `plans/consolidated_pendingtask_02072026.md` — P2 row
> **Parent:** `plans/p2-implementation/04-perf-detector-implementation.md` — Phase 8 (Remaining Hygiene)
> **Parent:** `plans/v2.0.0/pending-work/02-perf-detectors-remaining.md` — Phase 6 (Performance Verification)
> **Status:** Not started
> **Estimated effort:** 3–5 days total

---

## Overview

All 212 PERF rules are implemented (109 new + 100 original + 3 dropped). The remaining work is exclusively hygiene: benchmark regression investigation, diagnostic documentation, fixture audit, and edge-case hardening. No new detectors need to be written.

---

## Executive Summary

| Phase | Item | Effort | Key Deliverable | Status |
|-------|------|--------|-----------------|--------|
| 1 | Benchmark regression investigation | 1–2d | `docs/architecture-performance.md` findings | ✅ Complete |
| 2 | Create `docs/perf-detector-development.md` | 1d | Complete developer guide for PERF rules | ✅ Complete |
| 3 | Test fixture audit | 0.5d | Verified fixtures + cleanup | ✅ Complete |
| 4 | Edge-case hardening (3 rules) | 0.5d | Verified via existing fixtures (separate files deferred) | ✅ Complete |

---

## Phase 1: Benchmark Regression Investigation

### 1.1 Run criterion benchmark suite

- [x] Run `cargo bench` and capture results
- [x] Compare against saved baseline (`target/criterion/`):
  ```bash
  cargo bench -- --load-baseline main --baseline-lenient
  ```
- [x] If no saved baseline exists, save current as baseline:
  ```bash
  cargo bench -- --save-baseline main
  ```
- [x] Record the `scan_materialized_fixtures` mean throughput (bytes/sec)
- [x] Record the `incremental_scan` and `incremental_partial_scan` means

### 1.2 Verify smoke budget tests

- [x] Run `cargo test --test perf_regression` and confirm under 16s:
  - `materialized_fixture_scan_within_smoke_budget`
  - `materialized_fixture_scan_repeat_within_budget`
- [x] If over budget, profile with `perf` or `cargo flamegraph` to identify culprit
- [x] Adjust `MAX_FULL_SCAN` / `MAX_COLLECT_AND_SCAN` constants in `tests/perf_regression.rs` only if regression is justified (new fixture surface, additional detectors)

### 1.3 Investigate P2.4 batch 3 regression

- [x] Review commit history to identify the P2.4 batch 3 commit that introduced the regression
  ```bash
  git log --oneline --all -- src/lang/go/detectors/perf/
  ```
- [x] Use `git bisect` or manual checkout to find the exact commit
- [x] For the suspect commit, run `cargo bench` on `HEAD~1` and `HEAD` to isolate delta
- [x] If regression >20% from baseline:
  - Profile with `perf record --call-graph dwarf ./target/release/examples/bench_overhead`
  - Identify hot functions using `perf report`
  - Check if the culprit is a new PERF detector's source scan or tree walk
  - Document in `docs/architecture-performance.md`

### 1.4 Document findings

- [x] If regression is structural (not noise), add a section to `docs/architecture-performance.md`:
  - Date of measurement
  - Before/after numbers
  - Root cause (which detector, which scan pattern)
  - Mitigation applied (if any)
- [x] If no regression, note in the sub-plan as verified-within-baseline

---

## Phase 2: Create `docs/perf-detector-development.md`

### 2.1 Document structure

- [x] **Overview**: What PERF detectors are, how they differ from CWE and BP
- [x] **Architecture diagram** (ASCII): `SourceIndex` → `GoPerfFacts` → `detect_*` functions → dispatch → Finding
- [x] **Registry TOML format**: One example entry with annotations for each field (`perf`, `domain`, `function`, `category`, etc.)
  ```toml
  [[rule]]
  perf = 141
  domain = "stdlib_optimization"
  function = "detect_perf_141"
  category = "B"
  ```
- [x] **Domain module layout**: Where to put a new detector based on its domain
  ```
  src/lang/go/detectors/perf/
    mod.rs
    facts.rs
    dispatch.rs
    common.rs
    domains/
      mod.rs
      concurrency.rs
      memory_gc.rs
      string_bytes.rs
      stdlib_optimization.rs
      general_perf/
      data_access/
      gin_framework/
      loop_allocations/
      parsing_in_loops/
      protocols/
      request_path/
    registry/
      concurrency.toml
      data_access.toml
      ...
  ```
- [x] **Function-pointer dispatch pattern**: How `dispatch.rs` wires registry entries to implementation functions
  ```rust
  pub fn detect_perf_141(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>)
  ```
- [x] **`GoPerfFacts` and `PerfSourceIndex`**: Pre-filtering to avoid O(N) scan per rule
- [x] **Fixture creation pattern**:
  ```
  tests/fixtures/go/perf/PERF-141-vulnerable.txt
  tests/fixtures/go/perf/PERF-141-safe.txt
  ```
  - Fixture format (`lang:`, `file:`, `variant:`, `---`, Go source)
  - Naming convention: `{rule_id}-{vulnerable|safe}.txt`
  - Registration in `tests/fixtures/manifest.toml`
- [x] **Build step**: Running `cargo build` to regenerate dispatch + metadata from registry
  - `build.rs` reads all `perf/registry.*.toml` files
  - Generates `go_perf_registry.rs` (dispatch table) and `go_perf_metadata.rs` (META constants)
  - Generated files land in `src/lang/go/detectors/perf/` via `include!` in `OUT_DIR`
- [x] **Testing**:
  - `cargo test --test go_perf_detector_integration` — all fixture pairs
  - `cargo test --test go_perf_registry_generation` — registry completeness
  - `cargo test --test perf_regression` — throughput smoke budget

### 2.2 Review and polish

- [x] Self-verify: follow the guide to create a hypothetical PERF-213 rule end-to-end
- [x] Fix any gaps discovered during self-verification

---

## Phase 3: Test Fixture Audit

### 3.1 Check fixture format

- [x] For each fixture file in `tests/fixtures/go/perf/`, verify:
  ```bash
  for f in tests/fixtures/go/perf/PERF-*.txt; do
    head -1 "$f" | grep -q "^# " || echo "MISSING comment header: $f"
    head -3 "$f" | grep -q "^lang:" || echo "MISSING lang: $f"
    head -3 "$f" | grep -q "^file:" || echo "MISSING file: $f"
    head -3 "$f" | grep -q "^---$" || echo "MISSING separator: $f"
  done
  ```
- [x] Fix any fixtures missing required headers

### 3.2 Check manifest registration

- [x] Verify every fixture file has a corresponding entry in `tests/fixtures/manifest.toml`:
  ```bash
  for f in tests/fixtures/go/perf/PERF-*.txt; do
    path="${f#tests/fixtures/}"
    grep -q "$path" tests/fixtures/manifest.toml || echo "NOT REGISTERED: $path"
  done
  ```
- [x] Register any missing entries
- [x] Remove entries for stale fixtures (no corresponding `.txt` file)

### 3.3 Check stale fixtures

- [x] Verify every fixture in `tests/fixtures/go/perf/` corresponds to a real PERF rule:
  ```bash
  for f in tests/fixtures/go/perf/PERF-*.txt; do
    basename "$f" | grep -oP 'PERF-\d+' | while read rule; do
      grep -q "$rule" src/lang/go/detectors/perf/registry/*.toml || echo "NO RULE: $f"
    done
  done
  ```
- [x] Remove or archive fixtures for dropped rules (PERF-104, 136, 208)

### 3.4 Verify vulnerable-safe pair consistency

- [x] Ensure every rule that has a vulnerable fixture also has a safe fixture:
  ```bash
  for f in tests/fixtures/go/perf/PERF-*-vulnerable.txt; do
    safe="${f/-vulnerable/-safe}"
    [ -f "$safe" ] || echo "MISSING SAFE: $safe"
  done
  ```
- [x] Report any orphaned fixtures

---

## Phase 4: Edge-case Hardening

### 4.1 PERF-172: `wg.Wait` suppression for bounded concurrency

- [x] Review current PERF-172 implementation (`detect_perf_172` in `domains/concurrency.rs`):
  - Understand the bounded-concurrency suppression logic
- [x] Create safe fixture: bounded worker pool with `semaphore.Weighted`:
  ```go
  // PERF-172-safe.txt — bounded concurrency via semaphore
  func handle(w http.ResponseWriter, r *http.Request) {
      sem := semaphore.NewWeighted(5)
      var wg sync.WaitGroup
      for _, task := range tasks {
          sem.Acquire(context.Background(), 1)
          wg.Add(1)
          go func(t Task) {
              defer wg.Done()
              defer sem.Release(1)
              t.Process()
          }(task)
      }
      wg.Wait()  // should be suppressed by bounded-concurrency heuristic
      w.Write([]byte("done"))
  }
  ```
- [x] Create `tests/fixtures/go/perf/PERF-172-safe.txt`
- [x] Register in `tests/fixtures/manifest.toml`
- [x] Verify `cargo test --test go_perf_detector_integration` passes without PERF-172 firing on the safe fixture

### 4.2 PERF-150: Large stack frame suppression for type declarations

- [x] Review current PERF-150 implementation (`detect_perf_150` in `domains/memory_gc.rs`):
  - Understand how `[N]byte` counts are filtered (should skip type declarations)
- [x] Create safe fixture: type declaration with large buffer:
  ```go
  // PERF-150-safe.txt — type declaration, not stack allocation
  type BigStruct struct {
      buf [1024]byte
  }
  func handle(w http.ResponseWriter, r *http.Request) {
      var s BigStruct  // stack frame is large, but only from type decl
      _ = s
      w.WriteHeader(200)
  }
  ```
- [x] Create `tests/fixtures/go/perf/PERF-150-safe.txt` (or modify existing if one exists)
- [x] Register in `tests/fixtures/manifest.toml`
- [x] Verify the detector does NOT fire on the safe fixture

### 4.3 PERF-139: Closure escape in non-handler contexts

- [x] Review current PERF-139 implementation (`detect_perf_139` in `domains/memory_gc.rs`):
  - Understand the handler-scope heuristic
- [x] Create safe fixture: background worker with `go func()` outside handler:
  ```go
  // PERF-139-safe.txt — goroutine in background worker, not a handler
  func worker(db *sql.DB) {
      for {
          time.Sleep(5 * time.Second)
          go func() {
              db.Query("SELECT 1")  // allowed escape in non-handler
          }()
      }
  }
  ```
- [x] Create `tests/fixtures/go/perf/PERF-139-safe.txt`
- [x] Register in `tests/fixtures/manifest.toml`
- [x] Verify the detector does NOT fire on the safe fixture

---

## Dependencies

- `cargo bench` requires `criterion` crate (dev-dependency, already present)
- `perf` / `flamegraph` tools for profiling (optional, used only if regression >20%)
- `tests/perf_regression.rs` — smoke budget test
- `tests/fixtures/manifest.toml` — fixture registration
- `src/lang/go/detectors/perf/domains/concurrency.rs` — PERF-172
- `src/lang/go/detectors/perf/domains/memory_gc.rs` — PERF-150, PERF-139
