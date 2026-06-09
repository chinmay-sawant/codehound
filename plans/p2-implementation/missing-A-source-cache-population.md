# Missing A — Source Cache Population

> **Parent:** `plans/p2.md` — Missing Item A
> **Status:** `AnalysisResult` has `source_cache: HashMap<String, Arc<str>>` but it's always empty. Export falls back to re-reading files from disk.
> **Estimated effort:** 3-5 days.

---

## Overview

The architecture already defines `source_cache` on `AnalysisResult` to carry in-memory source text through the scan pipeline. This avoids redundant disk reads during export, snippet generation, and future downstream processing. The cache is modeled but never populated.

---

## Phase 1: Understand Current Flow

### 1.1 Audit all file-read sites

- [ ] Find every place in the pipeline where a file's source bytes are read from disk:
  - [ ] `scan_entry()` in `src/engine/walk.rs:135-197` — reads source via `std::fs::read()` or similar
  - [ ] `finding_context_lines()` in `src/export/mod.rs:120-133` — falls back to reading file via `file_cache`
  - [ ] Any other readers (grep for `fs::read`, `fs::read_to_string`, `File::open`)
- [ ] Map which reads could be replaced by a populated `source_cache`

### 1.2 Audit all source-text consumers

- [ ] Find every place that needs source text after initial parse:
  - [ ] `snippet_of()` in `src/ast/snippet.rs` — generates snippet from byte range
  - [ ] `attach_function_context()` in `src/engine/walk.rs` — uses function spans + source
  - [ ] `finding_context_lines()` in `src/export/mod.rs` — generates context for export files
  - [ ] Any reporter that needs source text for display
- [ ] Document whether each consumer already has access to `source_cache` or needs plumbing

---

## Phase 2: Populate `source_cache` During Scan

### 2.1 Design the data flow

- [ ] Option A: Populate cache in `scan_entry()` (`walk.rs:135-197`)
  - [ ] Read source bytes once for each file
  - [ ] Convert to `Arc<str>` and insert into a thread-local or shared map
  - [ ] Pass the `Arc<str>` to the parser (or extract from `ParsedUnit` after parse)
  - [ ] Problem: `rayon` parallel iteration makes a shared mutable map tricky
- [ ] Option B: Populate cache after `scan_entries_parallel()` returns
  - [ ] Collect `(file_path, Arc<str>)` tuples from each scanned entry
  - [ ] Merge into a single `HashMap` after the parallel phase
  - [ ] Problem: source text needs to be carried through the parallel closure
- [ ] Option C: Extend `ScanEntry` to carry the source text
  - [ ] Add `source: Option<Arc<str>>` to `ScanEntry` (`walk.rs`)
  - [ ] Populate in `collect_entries()` when reading file metadata (before parallel phase)
  - [ ] Problem: `collect_entries` currently doesn't read file contents — it just walks for paths
- [ ] Option D: Return source alongside findings from `scan_entry()`
  - [ ] Change `scan_entry()` return type to `(Vec<Finding>, Vec<ScanError>, Arc<str>)`
  - [ ] In `scan_entries_parallel()`, collect sources alongside findings
  - [ ] Build `source_cache` from collected sources
  - [ ] Pros: single read per file, natural flow
  - [ ] Cons: changes the return signature of `scan_entry()`
- [ ] Decision: [ ] Pick the cleanest option considering thread safety and minimal API changes

### 2.2 Implementation (for the chosen option)

Assuming **Option D** is selected:

- [ ] Modify `scan_entry()` signature in `src/engine/walk.rs`:
  ```rust
  fn scan_entry(
      entry: &ScanEntry,
      pool: &mut ParsePool,
      plugins: &[Box<dyn LanguagePlugin>],
      ctx: &ScanContext,
      source_cache_enabled: bool,
  ) -> Result<(Vec<Finding>, Arc<str>), ScanError>
  ```
  - [ ] Read file bytes: `let source_bytes = std::fs::read(&entry.path)?;`
  - [ ] Convert to `Arc<str>`: `let source: Arc<str> = Arc::from(String::from_utf8_lossy(&source_bytes).into_owned());`
  - [ ] Pass `&source` to the parser: `plugin.parse_with(parser, &path, &source)`
  - [ ] Return `(findings, source)` instead of just `findings`
- [ ] Modify `scan_entries_parallel()` to collect sources:
  - [ ] After the `catch_unwind` block, collect `(findings, source)` tuples
  - [ ] Build `source_cache: HashMap<String, Arc<str>>` mapping `entry.rel_path → source`
- [ ] In `analyze_paths()` (`analyzer.rs:70-97`):
  - [ ] Accept the `source_cache` from `scan_entries_parallel()`
  - [ ] Set it on `AnalysisResult` instead of `Default::default()`

### 2.3 Thread safety consideration

- [ ] `Arc<str>` is `Send + Sync` — safe across threads
- [ ] Building the HashMap after all parallel work is done — no concurrent access issue
- [ ] If using `rayon::par_iter().map_init()`, sources are collected in the `reduce` or final sequential pass

---

## Phase 3: Wire Consumers to Use `source_cache`

### 3.1 Update `export/mod.rs`

- [ ] In `export_findings()` (line 28):
  - [ ] Accept `source_cache: &HashMap<String, Arc<str>>` as a parameter
  - [ ] In `finding_context_lines()` (line 120):
    - [ ] First check `source_cache.get(&finding.file)` (already does this at line 124 — but cache is empty)
    - [ ] Only fall back to `file_cache` (HashMap-based disk read) if not in `source_cache`
    - [ ] Remove the `file_cache` fallback entirely if we can guarantee `source_cache` is complete
  - [ ] Benchmark: verify no second disk read occurs during export
- [ ] In `src/app.rs::run()` (line 81-114):
  - [ ] Pass `result.source_cache` to `export_findings()`

### 3.2 Update reporting layer (if needed)

- [ ] Check if text reporter (`src/reporting/text.rs`) reads source text:
  - [ ] Currently uses `finding.snippet` which is set during `attach_function_context()`
  - [ ] If snippet is already set, no change needed
  - [ ] If snippet generation falls back to disk read, update to use `source_cache`
- [ ] Check JSON reporter: no source text needed (serializes Finding struct)
- [ ] Check SARIF reporter: no source text needed (uses Finding fields)

### 3.3 Update `attach_function_context()`

- [ ] In `src/engine/walk.rs::attach_function_context()`:
  - [ ] Currently probably accesses source from `ParsedUnit` or similar
  - [ ] If it falls back to disk read for snippet generation, update to use the `Arc<str>` already in memory

---

## Phase 4: Verification & Testing

### 4.1 Unit/integration tests

- [ ] Test: `source_cache` is populated after scan
  - [ ] Run a scan on known files
  - [ ] Assert `result.source_cache.len()` equals number of scanned files
  - [ ] Assert `source_cache` contains the correct source content for each file
- [ ] Test: export uses `source_cache` instead of re-reading from disk
  - [ ] Modify test to run export in a temp directory
  - [ ] Delete original source files after scan but before export
  - [ ] Assert export succeeds (using only in-memory cache)
  - [ ] This is the "regression test proving export does not depend on a second file read" from the plan
- [ ] Test: `source_cache` works with mixed language scans (Go + Python)
- [ ] Test: `source_cache` handles Unicode/non-UTF8 files gracefully
- [ ] Test: `source_cache` for files with zero findings — still cached

### 4.2 Performance check

- [ ] Measure total scan time with and without source_cache population
- [ ] Memory usage: track peak memory for a large codebase
- [ ] `Arc<str>` avoids deep copies — verify no clone overhead in hot path

### 4.3 Edge cases

- [ ] Binary files or files that fail to read: still include in cache? Or omit?
  - [ ] Decision: Omit files that can't be read (they produce `ScanError`, not `ParsedUnit`)
- [ ] Very large files (10MB+ source): `Arc<str>` keeps entire file in memory
  - [ ] Is this acceptable? Document memory budget.
  - [ ] Future: add a size threshold above which source is not cached
- [ ] Empty files: empty string in cache

---

## Phase 5: Future-Proofing

### 5.1 Make `source_cache` available to future passes

- [ ] Ensure `AnalysisResult` is the canonical carrier of in-memory source
- [ ] Future P2.2 (Baseline): baseline saving needs source_cache? (probably not — findings are enough)
- [ ] Future P2.3 (Incremental): cache entries may include source text; `source_cache` should feed that
- [ ] Future P2.1 (Taint): taint analysis may need source text for snippet generation — already available

### 5.2 Consider a `ScanArtifact` type

- [ ] Evaluate whether `AnalysisResult` is getting too heavy
- [ ] If `source_cache` + findings + errors + baseline + taint paths all live on one struct, consider refactoring:
  ```rust
  struct ScanArtifacts {
      analysis: AnalysisResult,
      source_cache: HashMap<String, Arc<str>>,
      baseline: Option<Baseline>,
  }
  ```
- [ ] Defer this decision — not needed for this implementation, but keep in mind for maintainability

---

## Dependencies

- `src/engine/walk.rs` — `scan_entry()` and `scan_entries_parallel()` (the hot path)
- `src/engine/analyzer.rs` — `analyze_paths()` constructs `AnalysisResult`
- `src/engine/result.rs` — `AnalysisResult.source_cache` (already defined, currently empty)
- `src/export/mod.rs` — `export_findings()` and `finding_context_lines()` (already has cache check, just needs populated cache)
- `src/app.rs` — `run()` orchestrates analysis + export
- `src/ast/snippet.rs` — `snippet_of()` may or may not need source access
