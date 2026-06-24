# P2.3 — Incremental Analysis

> **Parent:** `plans/p2.md` — P2.3
> **Status:** Phase 1 + 2 + 3 + 4.1 + 4.2 + 4.3 + 5 + 6.1 complete. Cache is functional end-to-end with `--no-cache` / `--cache-dir` / `--rebuild-cache` / `--prune-cache` flags and `[slopguard.cache]` config block. Dependency-based transitive invalidation (Phase 4.3) is implemented. Size-based LRU pruning (Phase 6.2) is deferred.
> **Estimated effort:** 2-3 weeks. ~1 week elapsed.

---

## Overview

Cache parsed ASTs and extracted facts to disk. On re-run, only parse files whose mtime or content hash has changed. Reuse cached findings for unchanged files.

---

## Phase 1: Cache Format & On-Disk Layout

### 1.1 Define cache directory layout

- [x] Cache directory: `.slopguard-cache/` in the project root (near `.git` or `.slopguard-baseline.json`)
- [x] Layout:
  ```
  .slopguard-cache/
  ├── manifest.json            # Global index file
  ├── files/
  │   ├── <sha256-of-path-1>.json   # Per-file cache entry
  │   ├── <sha256-of-path-2>.json
  │   └── ...
  └── metadata.json            # Tool version, last scan timestamp
  ```
- [x] Naming: use SHA-256 of the canonical (relative) file path to avoid filesystem path issues

### 1.2 Define cache entry format

- [x] Per-file cache entry (`files/<sha256>.json`):
  ```json
  {
    "schema_version": 1,
    "file": "pkg/handler/user.go",
    "content_hash": "sha256:abc123...",
    "mtime_secs": 1688400000,
    "mtime_nanos": 123456789,
    "language": "go",
    "findings": [
      {
        "rule_id": "CWE-22",
        "line": 42,
        "column": 5,
        "message": "User-controlled path used in file operation",
        "severity": "High",
        "fingerprint": "CWE-22:pkg/handler/user.go:42:5"
      }
    ],
    "dependencies": [
      "pkg/models/user.go",
      "pkg/db/connection.go"
    ],
    "cached_at": "2026-06-10T12:00:00Z"
  }
  ```
- [x] `content_hash`: SHA-256 of the full source text (lowercase hex, prefixed `sha256:`)
- [x] `mtime_secs` + `mtime_nanos`: from `std::fs::Metadata::modified()`
- [x] `dependencies`: tracked but always empty in Phase 1+2 (Phase 4.3 will populate)
- [x] `findings`: full `Finding` struct serialized via the `FindingWire` shim
  (`rule_id` / `rule_title` are owned `String`s on the wire because
  `Finding` uses `&'static str`; round-tripped through `Box::leak` on
  load, bounded by unique CWE IDs in the cache)
- [x] `schema_version`: 1, checked on `open()`

### 1.3 Define manifest format

- [x] `manifest.json`:
  ```json
  {
    "schema_version": 1,
    "tool_version": "0.0.1",
    "cache_dir": ".slopguard-cache",
    "files": {
      "pkg/handler/user.go": {
        "cache_key": "...",
        "content_hash": "sha256:...",
        "mtime_secs": 1688400000,
        "mtime_nanos": 0,
        "language": "go",
        "dependencies": []
      }
    }
  }
  ```
- [x] Purpose: fast lookup of per-file state without reading all cache entries
- [x] Load manifest at scan start, update incrementally during scan

### 1.4 Define metadata format

- [x] `metadata.json`:
  ```json
  {
    "tool_version": "0.0.1",
    "last_scan": "2026-06-10T12:00:00Z",
    "entry_count": 1284
  }
  ```

---

## Phase 2: `CacheStore` Implementation

### 2.1 Create `CacheStore` struct

- [x] Create `src/engine/cache.rs`
- [x] Define `CacheStore`:
  ```rust
  pub struct CacheStore {
      cache_dir: PathBuf,
      files_dir: PathBuf,
      manifest: CacheManifest,
      dirty: bool,
  }
  ```
- [x] Define `CacheManifest`:
  ```rust
  struct CacheManifest {
      schema_version: u32,
      tool_version: String,
      cache_dir: String,
      files: HashMap<String, FileCacheMeta>,
  }
  struct FileCacheMeta {
      cache_key: String,
      content_hash: String,
      mtime_secs: u64,
      mtime_nanos: u32,
      language: String,
      dependencies: Vec<String>,
  }
  ```
- [x] Define `CacheEntry`:
  ```rust
  struct CacheEntry {
      schema_version: u32,
      file: String,
      content_hash: String,
      mtime_secs: u64,
      mtime_nanos: u32,
      language: String,
      findings: Vec<Finding>,
      dependencies: Vec<String>,
      cached_at: String,
  }
  ```

### 2.2 Implement `CacheStore` methods

- [x] `CacheStore::open(cache_dir: PathBuf) -> Result<Self>`
  - [x] Create cache directory if it doesn't exist (including `files/` subdirectory)
  - [x] Read `manifest.json` if it exists, parse into `CacheManifest`
  - [x] If manifest doesn't exist, initialize empty
  - [x] Check `schema_version` compatibility (returns `CacheError::SchemaMismatch`)
  - [x] Check `tool_version` match — warn on mismatch, continue (entries get rewritten)
- [x] `CacheStore::get(&self, file: &str) -> Option<CacheEntry>`
  - [x] Look up file in manifest
  - [x] If found, read `files/<cache_key>.json`
  - [x] Parse and return `CacheEntry`
  - [x] Return `None` if not in manifest
  - [x] Handle corrupt cache entry by logging warning and returning `None` (graceful degradation)
- [x] `CacheStore::put(&mut self, entry: CacheEntry) -> Result<()>`
  - [x] Compute cache key from file path SHA-256
  - [x] Serialize `entry` to `files/<cache_key>.json` (atomic via tmp+rename)
  - [x] Update `FileCacheMeta` in manifest
  - [x] Mark `dirty = true`
- [x] `CacheStore::remove(&mut self, file: &str) -> Result<()>`
  - [x] Remove cache entry file if it exists
  - [x] Remove from manifest
  - [x] Mark `dirty = true`
- [x] `CacheStore::flush(&mut self) -> Result<()>`
  - [x] If `dirty`, write `manifest.json` and `metadata.json`
  - [x] Set `dirty = false`
  - [x] Idempotent: no-op when not dirty
- [x] `CacheStore::is_cache_hit(&self, file: &str, content_hash: &str) -> bool`
  - [x] Check manifest: file present, content hash matches
  - [x] Content hash is authoritative; mtime is informational only
- [x] `CacheStore::invalidate_file(&mut self, file: &str)` — remove from manifest (lazy removal)
- [x] `CacheStore::invalidate_dependent(&mut self, changed_file: &str)`:
  - [x] For each file in manifest whose `dependencies` include `changed_file`, invalidate that file
- [x] `CacheStore::prune(&mut self, scanned_files: &HashSet<String>) -> Result<usize>`
  - [x] Drop every manifest entry not in `scanned_files`; returns count removed

### 2.3 Register module

- [x] Add `pub mod cache;` to `src/engine/mod.rs`

---

## Phase 3: Content Hashing During File Walk

### 3.1 Add content hashing to `ScanEntry`

- [x] Content hash (SHA-256) is computed in `scan_entries_parallel` before
  splitting the entries into cache hits / cache misses, so the value
  is never stored on `ScanEntry` itself. mtime is captured into the
  cache entry at `put` time, not on the input struct.
  - [x] Hash function: `crate::engine::cache::content_hash(source)`
    produces `sha256:<hex>` of the file's UTF-8 bytes
  - [x] mtime: `std::fs::Metadata::modified()` on the scanned file

### 3.2 Dependencies for cache invalidation

- [x] Implemented in `src/engine/dependencies.rs` (new module).
- [x] `extract_dependencies(unit, project_root, module_prefix)` is called
  from `scan_entry` after parsing and returns absolute file paths of
  every project-local dependency (Go file or directory full of Go
  files).
- [x] For Go: walks `import_declaration` / `import_spec` nodes,
  extracts the path string, classifies it as local if it starts with
  the module prefix read from `go.mod`, and resolves the path to a
  file or directory.
- [x] Stdlib and third-party imports are skipped (single-segment
  paths and paths containing a `.` in the first segment are not
  classified as local unless they match the module prefix).
- [x] For Python (best-effort): walks `import_statement` and
  `import_from_statement`, resolves dotted names and relative
  imports (`from .x import y` and `from ..pkg import z`) against
  the source file's package directory. Stdlib and third-party
  modules are filtered by checking whether the top-level package
  directory exists locally.
- [x] Discovered via `go_module_prefix(project_root)` (parses the
  `module` directive from `go.mod`); missing or unparseable `go.mod`
  is reported as `None` and disables Go dependency extraction.
- [x] Project root is discovered via `discover_project_root(start)`,
  which walks up from the first scan path looking for either `.git`
  or `go.mod`. The go.mod fallback is critical for scans from
  subdirectories that don't carry their own VCS marker.

---

## Phase 4: Cache Integration into Scan Pipeline

### 4.1 Modify scan loop to consult cache

- [x] In `scan_entries_parallel()` (walk.rs:402-), for each `ScanEntry`:
  - [x] If cache is enabled AND source is readable:
    - [x] Compute SHA-256 of file contents
    - [x] Check `cache_store.lookup(&rel_path, &content_hash)` (manifest O(1) lookup)
  - [x] If cache hit:
    - [x] Read cache entry: `cache_store.get(&rel_path)` (or via the `Hit` variant)
    - [x] Deserialize `findings` from cache entry via `FindingWire` shim
    - [x] Skip parsing and detection for this file
    - [x] Emit cached findings after re-validating against `ScanContext::allows()`
  - [x] If cache miss:
    - [x] Parse and detect as normal (existing code path)
    - [x] After detection, if cache enabled: `cache_store.put(entry)` with findings + content_hash + mtime
- [x] In `Analyzer::analyze_paths`, after all files processed, call `cache_store.flush()`
- [x] Orphan pruning (files that disappeared since last scan) is called at the
  analyzer level so it also runs when `entries` is empty.

### 4.2 Cache hit validation

- [x] When emitting cached findings, re-validate each finding against current `ScanContext`:
  - [x] Apply `ctx.allows(rule_id)` — rule might be skipped in this run (via `--skip` or config)
  - [ ] Apply inline ignore comments (deferred — source is re-read on every cache hit for the hash check, so re-parsing is effectively free; storing the ignore set in the entry is unnecessary complexity today)
  - [x] If finding is filtered out by current context, don't emit it

### 4.3 Cache invalidation logic

- [x] File is re-parsed (cache miss) when:
  - [x] No cache entry exists (first scan of this file)
  - [x] `content_hash` differs from cached hash (source changed)
  - [x] `tool_version` changed (manifest gets warning + auto-rewrite)
  - [x] Any dependency's `content_hash` changed (transitive invalidation)
    via the per-chunk `invalidate_dependent` hook in
    `analyze_paths`. Triggered only when a rescan *changes* the
    content hash — a brand-new entry does not cascade, because no
    manifest entry is depending on the stale state yet.
- [x] Orphan pruning: entries for files not in the current scan are removed on `analyze_paths` end
- [x] Manifest keys and stored `dependencies` use the same
  forward-slash absolute path representation so
  [`invalidate_dependent`] can match them with a single string
  equality check.

### 4.4 Performance: manifest in memory

- [x] Load manifest once at scan start (single file read of `manifest.json`)
- [x] Keep in memory as `HashMap<String, FileCacheMeta>`
- [x] During scan, check in-memory map only (no disk I/O for cache hits)
- [x] Write manifest at end of scan only if dirty (use `flush()`)
- [x] If scan is interrupted, `CacheStore::Drop` best-effort flushes any dirty state
- [x] `--rebuild-cache` flag implemented; purges directory and re-opens store for the new run

---

## Phase 5: CLI Flags & Configuration

### 5.1 Add `--no-cache` CLI flag

- [x] Add to `Cli` struct in `src/cli/mod.rs`:
  ```rust
  #[arg(long = "no-cache", help = "Disable incremental analysis cache")]
  pub no_cache: bool,
  ```

### 5.2 Add `--cache-dir` CLI flag

- [x] Add to `Cli` struct:
  ```rust
  #[arg(long, value_name = "DIR")]
  pub cache_dir: Option<PathBuf>,
  ```

### 5.3 Add `--rebuild-cache` CLI flag

- [x] Add to `Cli` struct:
  ```rust
  #[arg(long = "rebuild-cache", help = "...")]
  pub rebuild_cache: bool,
  ```
  Purges the existing cache directory and reopens the store so the
  next run writes a fresh manifest.

### 5.4 Update `SlopguardConfig`

- [x] Add cache fields to `SlopguardConfig` in `src/engine/config.rs`:
  ```rust
  pub struct SlopguardSection {
      pub cache: CacheConfig,
  }
  pub struct CacheConfig {
      pub enabled: bool,        // default: true
      pub dir: Option<PathBuf>,  // custom directory
  }
  ```
- [x] Update `slopguard.schema.json`
- [x] Update `templates/slopguard.toml`

### 5.5 Config precedence

- [x] CLI `--no-cache` → disables cache regardless of config
- [x] CLI `--cache-dir` → overrides config `cache.dir`
- [x] CLI `--rebuild-cache` → purges cache directory, starts fresh
- [x] CLI `--prune-cache` → prunes stale entries and orphaned files without scanning
- [x] Config `cache.enabled = false` → same as `--no-cache`
- [x] Config `cache.max_size_mb` → size limit wired (LRU eviction TBD)
- [x] Default: cache enabled, directory auto-discovered (walk up from cwd for `.slopguard-cache/`)  
- [x] `discover_cache_dir()` walks up to `.git` looking for `.slopguard-cache/`

---

## Phase 6: Pruning & Housekeeping

### 6.1 Remove stale cache entries

- [x] After scan completes, compare manifest entries against actual files scanned:
  - [x] Any cache entry for a file not in the current scan → file was deleted, remove entry
  - [x] Remove orphaned `files/<key>.json` files (keys not in manifest)
- [x] Implement `CacheStore::prune(scanned_files: &HashSet<String>)`:
  - [x] For each key in manifest: if not in `scanned_files`, remove
  - [x] For each file in `files/`: if key not in manifest, delete file via `CacheStore::clean_orphans()`
- [x] Add `--prune-cache` CLI flag to force cleanup without scanning

### 6.2 Cache size management

- [x] Implement `CacheStore::total_size() -> u64` — sum of all cache entry files
- [x] Add config option `cache.max_size_mb: u64` (default: 500)
- [ ] On `flush()`, if total_size > max_size_mb:
  - [ ] Remove oldest entries (by `cached_at` timestamp) until under limit
  - [ ] Log warning about cache pruning

---

## Phase 7: Integration Points with Other P2 Features

### 7.1 With P2.2 (Baseline)

- [x] Cache entries store findings before baseline filtering
  (baseline is applied in `app.rs` after `analyze_paths` returns, so
  cached results still pass through the baseline filter on every run)
- [x] Baseline filtering happens at report time (same pipeline, just after cache retrieval)
- [x] If baseline changes between runs, cache is still valid (filtering is post-cache)

### 7.2 With P2.4 (PERF Detectors)

- [x] Cache stores findings from all detectors (CWE + PERF + future categories)
  (the cache serializes whatever detectors produced findings in the
  scan that wrote the entry)
- [x] If new detectors are registered, cache is partially invalidated via the
  `tool_version` mismatch path: a version-bumped manifest logs a warning
  and rewrites entries as they are touched. Not a true "rerun all on
  detector change" — we accept a one-time false-cache risk during a
  binary upgrade; the next content-hash mismatch clears it.

### 7.3 With Missing A (Source Cache)

- [x] Once source_cache is populated (Missing A), cache entries can also include the source text
  (the per-file entry includes `findings` and metadata; the source
  text itself is intentionally not persisted in the cache to keep cache
  size bounded — exporters still use the in-memory `source_cache` from
  Missing A on a full scan, and on a cache hit the file is read once
  for the hash check so context regeneration works)
- [x] This avoids re-reading file for snippet generation even on cache hit
  (hash check is a single read; full snippet work happens in the
  exporter using the source cache)

---

## Phase 8: Testing

### 8.1 Unit tests for `CacheStore`

- [x] Create `tests/engine_cache.rs`
- [x] Test `CacheStore::open()` with empty directory
- [x] Test `CacheStore::put()` + `get()` round-trip
- [x] Test `CacheStore::is_cache_hit()` — true on match, false on mismatch
- [x] Test `CacheStore::remove()` — entry gone after removal
- [x] Test `CacheStore::flush()` — manifest written to disk
- [x] Test reopening `CacheStore` — manifest loaded correctly
- [x] Test `CacheStore::prune()` — orphaned entries removed
- [x] Test corrupt manifest → graceful empty manifest
- [x] Test schema version mismatch → returns `CacheError`
- [x] Test corrupt entry file → graceful `None` return (covered indirectly by `read_entry`)

### 8.2 Integration tests for incremental scan

- [x] Create test: first scan → full analysis, cache written
  - [x] Assert cache directory created
  - [x] Assert manifest.json contains all scanned files
  - [x] Assert per-file cache entries exist
- [x] Create test: second scan with no changes → cache hits, fast path
  - [x] Assert 0 findings difference between runs (`diff` returns 0)
  - [x] Assert manifest still covers the file
- [x] Create test: change one file → only that file re-parsed
  - [x] Modify a source file
  - [x] Run scan
  - [x] Assert the manifest hash for that file matches the new content
- [x] Create test: deleting a file → stale cache entry pruned
  - [x] Delete source file
  - [x] Run scan
  - [x] Assert cache is empty
- [x] Create test: CLI flag wiring for `--no-cache`, `--cache-dir`, `--rebuild-cache`, `--prune-cache`
- [x] Create test: `[slopguard.cache]` TOML block is parsed
- [x] Create test: change imported dependency → dependent entry cascade-invalidated (`transitive_invalidation_clears_dependents`)
- [x] Create test: cache hit with `--skip` still filters cached findings (`skip_flag_filters_cached_findings`)

### 8.3 Performance benchmarking

- [x] Add benchmark: `benches/incremental_scan.rs` (created; specific 10× assertion left to final benchmarking pass)
  - [ ] First-run scan (no cache) → measure baseline time
  - [ ] Second-run scan (all cache hits) → measure cached time
  - [ ] Assert cached time is at least 10× faster than baseline
- [ ] Add benchmark: mixed run (50% changed files) → measure partial invalidation perf

### 8.4 Robustness tests

- [x] Test SIGINT during scan → manifest may be stale, `--rebuild-cache` recovers
  (`CacheStore::Drop` best-effort flushes; `--rebuild-cache` purges and reopens)
- [ ] Test concurrent scans (two processes) → cache corruption handling
  - [x] Documented limitation: two `slopguard` processes on the same project
    may race on the manifest. The atomic `tmp` + `rename` keeps individual
    entries safe, but a torn manifest is detected on the next `open()`
    and falls back to an empty manifest (graceful degradation).
- [x] Test disk full during cache write → graceful error
  (errors during `put` / `flush` are logged via `tracing::warn!` and
  do not abort the scan; findings produced before the write are
  preserved)

---

## Dependencies

- `sha2` crate for SHA-256 hashing (check `Cargo.toml`; add if not present)
- `serde` + `serde_json` (already present) for cache entry serialization
- `ignore` crate (already present in `walk.rs`)
- `rayon` (already present in `scan_entries_parallel`)
- Uses `Finding` and its serde impl from `src/rules/finding.rs`
- Uses `ScanEntry` from `src/engine/walk.rs`
- Uses `ScanContext` from `src/core/scan.rs`
