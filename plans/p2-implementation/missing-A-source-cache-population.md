# Missing A — Source Cache Population

> **Parent:** `plans/p2.md` — Missing Item A
> **Status:** Phase 1-3 implementation slice landed: successful scans now populate `AnalysisResult.source_cache`, export consumes it, and regression tests prove context/chunk export can run after the original source file is removed. Broader mixed-language, memory-budget, and performance validation remains open.
> **Estimated effort:** 3-5 days.

---

## Overview

The architecture already defines `source_cache` on `AnalysisResult` to carry in-memory source text through the scan pipeline. This avoids redundant disk reads during export, snippet generation, and future downstream processing. The cache is modeled but never populated.

---

## Phase 1: Understand Current Flow

### 1.1 Audit all file-read sites

- [x] Find every place in the pipeline where a file's source bytes are read from disk:
  - [x] `scan_entry()` in `src/engine/walk.rs:135-197` — reads source via `std::fs::read()` and is now the single source of `Arc<str>` cached for downstream consumers.
  - [x] `finding_context_lines()` in `src/export/mod.rs:120-133` — already checks `source_cache` first and only falls back to `file_cache` when the cache misses.
  - [x] Any other readers (grep for `fs::read`, `fs::read_to_string`, `File::open`) — current scan/export hot-path readers are covered; unrelated config/catalog/fixture/test readers remain separate.
- [x] Map which reads could be replaced by a populated `source_cache` — export context/chunk generation is now served by the populated cache for successfully scanned files.

### 1.2 Audit all source-text consumers

- [x] Find every place that needs source text after initial parse:
  - [x] `snippet_of()` in `src/ast/snippet.rs` — receives in-memory source during detection; no extra plumbing needed.
  - [x] `attach_function_context()` in `src/engine/walk.rs` — uses parsed-unit spans/source while the unit is alive; no disk read added.
  - [x] `finding_context_lines()` in `src/export/mod.rs` — generates context from `source_cache` when present.
  - [x] Any reporter that needs source text for display — text/JSON/SARIF reporters use finding fields and do not re-read source.
- [x] Document whether each consumer already has access to `source_cache` or needs plumbing — only export needed the cache to become non-empty; app already passes `result.source_cache`.

---

## Phase 2: Populate `source_cache` During Scan

### 2.1 Design the data flow

- Rejected Option A: Populate cache in `scan_entry()` via shared mutable state (`walk.rs:135-197`)
  - Reason: `rayon` parallel iteration makes shared mutation unnecessary and less direct than returning the source with the worker outcome.
- Rejected Option B: Populate cache after `scan_entries_parallel()` returns without changing `scan_entry()`
  - Reason: source text still has to be carried out of the parallel closure, so this collapses into Option D.
- Rejected Option C: Extend `ScanEntry` to carry the source text
  - Reason: `collect_entries` currently performs directory walking only; reading source there would add earlier I/O and duplicate scan-entry responsibilities.
- [x] Option D: Return source alongside findings from `scan_entry()`
  - [x] Change `scan_entry()` return type to `(Vec<Finding>, cache_key, Arc<str>)`
  - [x] In `scan_entries_parallel()`, collect sources alongside findings
  - [x] Build `source_cache` from collected sources
  - [x] Pros: single read per file, natural flow
  - [x] Cons: changes the return signature of `scan_entry()`
- [x] Decision: [x] Pick the cleanest option considering thread safety and minimal API changes — Option D was implemented with the existing `display_path` key so findings and cache entries align.

### 2.2 Implementation (for the chosen option)

Assuming **Option D** is selected:

- [x] Modify `scan_entry()` signature in `src/engine/walk.rs`:
  ```rust
  fn scan_entry(
      registry: &Registry,
      ctx: &ScanContext,
      entry: &ScanEntry,
      pool: &mut ParsePool,
  ) -> Result<(Vec<Finding>, String, Arc<str>), ScanError>
  ```
  - [x] Read file bytes: `std::fs::read(&entry.path)` remains the source read.
  - [x] Convert to `Arc<str>`: UTF-8 source is moved into `ParsedUnit` and cloned as `Arc<str>` for the cache.
  - [x] Pass source to the parser: `plugin.parse_with(parser, &entry.path, source)` remains unchanged.
  - [x] Return `(findings, cache_key, source)` instead of just `findings`
- [x] Modify `scan_entries_parallel()` to collect sources:
  - [x] After the `catch_unwind` block, collect `(findings, cache_key, source)` tuples
  - [x] Build `source_cache: HashMap<String, Arc<str>>` mapping `unit.display_path`/`finding.file` → source
- [x] In `analyze_paths()` (`analyzer.rs:70-97`):
  - [x] Accept the `source_cache` from `scan_entries_parallel()`
  - [x] Set it on `AnalysisResult` instead of `Default::default()`

### 2.3 Thread safety consideration

- [x] `Arc<str>` is `Send + Sync` — safe across threads
- [x] Building the HashMap after all parallel work is done — no concurrent access issue
- [x] If using `rayon::par_iter().map_init()`, sources are collected in each worker outcome and merged in the final sequential pass

---

## Phase 3: Wire Consumers to Use `source_cache`

### 3.1 Update `export/mod.rs`

- [x] In `export_findings()` (line 28):
  - [x] Accept `source_cache: &HashMap<String, Arc<str>>` as a parameter
  - [x] In `finding_context_lines()` (line 120):
    - [x] First check `source_cache.get(&finding.file)` (already did this; now the cache is populated)
    - [x] Only fall back to `file_cache` (HashMap-based disk read) if not in `source_cache`
    - [~] Remove the `file_cache` fallback entirely if we can guarantee `source_cache` is complete — `file_cache` still present in `export/entry.rs:30` (deferred → see plans/v3.0.0/)
  - [x] Regression test: verify no second disk read is needed during export for successfully scanned files by deleting source before export
- [x] In `src/app.rs::run()` (line 81-114):
  - [x] Pass `result.source_cache` to `export_findings()`

### 3.2 Update reporting layer (if needed)

- [x] Check if text reporter (`src/reporting/text.rs`) reads source text:
  - [x] Currently uses `finding.snippet` which is set during detection
  - [x] If snippet is already set, no change needed
  - [x] If snippet generation falls back to disk read, update to use `source_cache` — not needed in current code.
- [x] Check JSON reporter: no source text needed (serializes Finding struct)
- [x] Check SARIF reporter: no source text needed (uses Finding fields)

### 3.3 Update `attach_function_context()`

- [x] In `src/engine/walk.rs::attach_function_context()`:
  - [x] Currently uses `ParsedUnit` function spans while the parsed unit is alive
  - [x] It does not fall back to disk read for snippet generation

---

## Phase 4: Verification & Testing

### 4.1 Unit/integration tests

- [x] Test: `source_cache` is populated after scan
  - [x] Run a scan on known files
  - [x] Assert `result.source_cache.len()` equals number of scanned files
  - [x] Assert `source_cache` contains the correct source content for each file
- [x] Test: export uses `source_cache` instead of re-reading from disk
  - [x] Modify test to run export in a temp directory
  - [x] Delete original source files after scan but before export
  - [x] Assert export succeeds (using only in-memory cache)
  - [x] This is the "regression test proving export does not depend on a second file read" from the plan
- [x] Test: `source_cache` works with mixed language scans (Go + Python)
- [x] Test: `source_cache` handles Unicode/non-UTF8 files gracefully
- [x] Test: `source_cache` for files with zero findings — still cached

### 4.2 Performance check

- [~] Measure total scan time with and without source_cache population — not benchmarked (deferred → see plans/v3.0.0/)
- [~] Current in-tree code only has the populated-cache path; run a branch-to-branch benchmark (deferred → see plans/v3.0.0/)
- [~] Memory usage: track peak memory for a large codebase — `source_cache_bytes()` exists but no peak-memory tracking (deferred → see plans/v3.0.0/)
  - [x] Added `AnalysisResult::source_cache_bytes()` to report retained source-text bytes for a scan.
- [x] `Arc<str>` avoids deep copies — verify no clone overhead in hot path

### 4.3 Edge cases

- [x] Binary files or files that fail to read: still include in cache? Or omit?
  - [x] Decision: Omit files that can't be read or decoded as UTF-8 (they produce `ScanError`, not `ParsedUnit`)
- [x] Very large files (10MB+ source): `Arc<str>` keeps entire file in memory
  - [x] Is this acceptable? Document memory budget.
  - [~] Future: add a size threshold above which source is not cached (deferred → see plans/v3.0.0/)
- [x] Empty files: empty string in cache

---

## Phase 5: Future-Proofing

### 5.1 Make `source_cache` available to future passes

- [x] Ensure `AnalysisResult` is the canonical carrier of in-memory source
- [~] Future P2.2 (Baseline): baseline saving needs source_cache? — not needed (deferred → see plans/v3.0.0/)
- [~] Future P2.3 (Incremental): cache entries may include source text — not implemented (deferred → see plans/v3.0.0/)
- [x] Future P2.1 (Taint): taint analysis may need source text — already available via ParsedUnit

### 5.2 Consider a `ScanArtifact` type

- [~] Evaluate whether `AnalysisResult` is getting too heavy — deferred (deferred → see plans/v3.0.0/)
- [~] Consider `ScanArtifact` refactoring — deferred (deferred → see plans/v3.0.0/)
- [x] Defer this decision — not needed for this implementation, but keep in mind for maintainability

---

## Dependencies

- `src/engine/walk.rs` — `scan_entry()` and `scan_entries_parallel()` (the hot path)
- `src/engine/analyzer.rs` — `analyze_paths()` constructs `AnalysisResult`
- `src/engine/result.rs` — `AnalysisResult.source_cache` (already defined, now populated for successfully scanned files)
- `src/export/mod.rs` — `export_findings()` and `finding_context_lines()` (already has cache check, just needs populated cache)
- `src/app.rs` — `run()` orchestrates analysis + export
- `src/ast/snippet.rs` — `snippet_of()` may or may not need source access
