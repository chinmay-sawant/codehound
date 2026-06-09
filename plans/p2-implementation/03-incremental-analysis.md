# P2.3 — Incremental Analysis

> **Parent:** `plans/p2.md` — P2.3
> **Status:** Every `slopguard` invocation re-parses every file. No caching.
> **Estimated effort:** 2-3 weeks.

---

## Overview

Cache parsed ASTs and extracted facts to disk. On re-run, only parse files whose mtime or content hash has changed. Reuse cached findings for unchanged files.

---

## Phase 1: Cache Format & On-Disk Layout

### 1.1 Define cache directory layout

- [ ] Cache directory: `.slopguard-cache/` in the project root (near `.git` or `.slopguard-baseline.json`)
- [ ] Layout:
  ```
  .slopguard-cache/
  ├── manifest.json            # Global index file
  ├── files/
  │   ├── <sha256-of-path-1>.json   # Per-file cache entry
  │   ├── <sha256-of-path-2>.json
  │   └── ...
  └── metadata.json            # Tool version, last scan timestamp
  ```
- [ ] Naming: use SHA-256 of the canonical (relative) file path to avoid filesystem path issues

### 1.2 Define cache entry format

- [ ] Per-file cache entry (`files/<sha256>.json`):
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
- [ ] `content_hash`: SHA-256 of the full source text (uppercase hex, prefixed `sha256:`)
- [ ] `mtime_secs` + `mtime_nanos`: from `std::fs::Metadata::modified()`
- [ ] `dependencies`: files imported by this file (for cache invalidation)
- [ ] `findings`: full `Finding` struct serialized (reuse serde impl from `src/rules/finding.rs`)
- [ ] `schema_version`: for future format evolution

### 1.3 Define manifest format

- [ ] `manifest.json`:
  ```json
  {
    "schema_version": 1,
    "tool_version": "0.1.0",
    "cache_dir": ".slopguard-cache",
    "files": {
      "pkg/handler/user.go": {
        "cache_key": "sha256-of-path-as-filename",
        "content_hash": "sha256:abc123...",
        "mtime_secs": 1688400000,
        "dependencies": ["pkg/models/user.go", "pkg/db/connection.go"]
      }
    }
  }
  ```
- [ ] Purpose: fast lookup of per-file state without reading all cache entries
- [ ] Load manifest at scan start, update incrementally during scan

### 1.4 Define metadata format

- [ ] `metadata.json`:
  ```json
  {
    "tool_version": "0.1.0",
    "last_full_scan": "2026-06-10T12:00:00Z",
    "cache_entry_count": 1284
  }
  ```

---

## Phase 2: `CacheStore` Implementation

### 2.1 Create `CacheStore` struct

- [ ] Create `src/engine/cache.rs`
- [ ] Define `CacheStore`:
  ```rust
  pub struct CacheStore {
      cache_dir: PathBuf,
      manifest: CacheManifest,
      dirty: bool,       // whether manifest needs rewrite
  }
  ```
- [ ] Define `CacheManifest`:
  ```rust
  struct CacheManifest {
      schema_version: u32,
      tool_version: String,
      files: HashMap<String, FileCacheMeta>,  // relative_file_path → meta
  }
  struct FileCacheMeta {
      cache_key: String,        // sha256 of path
      content_hash: String,     // sha256:...
      mtime_secs: u64,
      dependencies: Vec<String>,
  }
  ```
- [ ] Define `CacheEntry`:
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

- [ ] `CacheStore::open(cache_dir: PathBuf) -> Result<Self>`
  - [ ] Create cache directory if it doesn't exist (including `files/` subdirectory)
  - [ ] Read `manifest.json` if it exists, parse into `CacheManifest`
  - [ ] If manifest doesn't exist, initialize empty
  - [ ] Check `schema_version` compatibility
  - [ ] Check `tool_version` match — invalidate all if different major version
- [ ] `CacheStore::get(&self, file: &str) -> Result<Option<CacheEntry>>`
  - [ ] Look up file in manifest
  - [ ] If found, read `files/<cache_key>.json`
  - [ ] Parse and return `CacheEntry`
  - [ ] Return `Ok(None)` if not in manifest
  - [ ] Handle corrupt cache entry by logging warning and returning `None` (graceful degradation)
- [ ] `CacheStore::put(&mut self, entry: CacheEntry) -> Result<()>`
  - [ ] Compute cache key from file path SHA-256
  - [ ] Serialize `entry` to `files/<cache_key>.json`
  - [ ] Update `FileCacheMeta` in manifest
  - [ ] Mark `dirty = true`
- [ ] `CacheStore::remove(&mut self, file: &str) -> Result<()>`
  - [ ] Remove cache entry file if it exists
  - [ ] Remove from manifest
  - [ ] Mark `dirty = true`
- [ ] `CacheStore::flush(&mut self) -> Result<()>`
  - [ ] If `dirty`, write `manifest.json` and `metadata.json`
  - [ ] Set `dirty = false`
- [ ] `CacheStore::is_cache_hit(&self, file: &str, content_hash: &str) -> bool`
  - [ ] Check manifest: file present, content hash matches
  - [ ] Also verify mtime hasn't changed (quick check before computing hash)
- [ ] `CacheStore::invalidate_file(&mut self, file: &str)` — remove from manifest (lazy removal)
- [ ] `CacheStore::invalidate_dependent(&mut self, changed_file: &str)`:
  - [ ] For each file in manifest whose `dependencies` include `changed_file`, invalidate that file

### 2.3 Register module

- [ ] Add `pub mod cache;` to `src/engine/mod.rs`

---

## Phase 3: Content Hashing During File Walk

### 3.1 Add content hashing to `ScanEntry`

- [ ] Add fields to `ScanEntry` in `src/engine/walk.rs`:
  ```rust
  pub struct ScanEntry {
      // ... existing fields ...
      pub content_hash: Option<String>,  // SHA-256 of file contents
      pub mtime: Option<SystemTime>,     // file modification time
  }
  ```
- [ ] In `collect_entries()` (walk.rs:31-72), after confirming a file should be scanned:
  - [ ] Read file contents (already done for parsing)
  - [ ] Compute SHA-256 hash: `sha2::Sha256::digest(&source)`
  - [ ] Format as `sha256:<hex>`
  - [ ] Store in `ScanEntry.content_hash`
  - [ ] Get mtime from `fs::metadata().modified()`

### 3.2 Dependencies for cache invalidation

- [ ] In `scan_entry()` (walk.rs:135-197), after parsing:
  - [ ] Extract import paths from the AST (query tree-sitter for `import_declaration` / `import_spec`)
  - [ ] Resolve import paths to local file paths within the project (map `pkg/db` → `pkg/db/connection.go`)
  - [ ] Store resolved dependencies on the `ScanEntry`
- [ ] For Go: imports resolve to relative package paths within the module
  - [ ] If `go.mod` exists, resolve imports relative to module root
  - [ ] If no `go.mod`, resolve relative to project root
- [ ] For Python: imports resolve similarly
- [ ] For dependencies outside the project (stdlib, third-party), don't include (they never invalidate)

---

## Phase 4: Cache Integration into Scan Pipeline

### 4.1 Modify scan loop to consult cache

- [ ] In `scan_entries_parallel()` (walk.rs:284-335), for each `ScanEntry`:
  - [ ] If cache is enabled AND `content_hash` is available:
    - [ ] Check `cache_store.is_cache_hit(&entry.rel_path, &entry.content_hash)`
    - [ ] Without reading the cache file first — just check manifest (O(1) lookup)
  - [ ] If cache hit:
    - [ ] Read cache entry: `cache_store.get(&entry.rel_path)`
    - [ ] Deserialize `findings` from cache entry
    - [ ] Skip parsing and detection for this file
    - [ ] Emit cached findings (after re-validating: `ScanContext::allows()` still passes for each rule)
  - [ ] If cache miss:
    - [ ] Parse and detect as normal (existing code path)
    - [ ] After detection, if cache enabled: `cache_store.put(entry)` with findings + content_hash + dependencies
- [ ] In `scan_entries_parallel()`, after all files processed, call `cache_store.flush()`

### 4.2 Cache hit validation

- [ ] When emitting cached findings, re-validate each finding against current `ScanContext`:
  - [ ] Apply `ctx.allows(rule_id)` — rule might be skipped in this run (via `--skip` or config)
  - [ ] Apply inline ignore comments (if loaded from source at cache time, store in cache entry)
  - [ ] If finding is filtered out by current context, don't emit it

### 4.3 Cache invalidation logic

- [ ] File is re-parsed (cache miss) when:
  - [ ] No cache entry exists (first scan of this file)
  - [ ] `content_hash` differs from cached hash (source changed)
  - [ ] `mtime` differs (quick check — source may have been touched)
  - [ ] `tool_version` changed (new detector might find new things)
  - [ ] Detector code changed (hard to detect — use tool version as proxy)
  - [ ] Any dependency's `content_hash` changed (transitive invalidation)
- [ ] When a file is re-parsed:
  - [ ] Check if its `dependencies` list changed (new imports added, old ones removed)
  - [ ] If dependencies changed, invalidate old dependency references in manifest

### 4.4 Performance: manifest in memory

- [ ] Load manifest once at scan start (single file read of `manifest.json`)
- [ ] Keep in memory as `HashMap<String, FileCacheMeta>`
- [ ] During scan, check in-memory map only (no disk I/O for cache hits)
- [ ] Write manifest at end of scan only if dirty (use `flush()`)
- [ ] If scan is interrupted (SIGINT), manifest may be stale — add a `--rebuild-cache` flag to force full re-scan

---

## Phase 5: CLI Flags & Configuration

### 5.1 Add `--no-cache` CLI flag

- [ ] Add to `Cli` struct in `src/cli/mod.rs`:
  ```rust
  #[arg(long = "no-cache", help = "Disable incremental analysis cache")]
  pub no_cache: bool,
  ```

### 5.2 Add `--cache-dir` CLI flag

- [ ] Add to `Cli` struct:
  ```rust
  #[arg(long = "cache-dir", help = "Custom directory for incremental analysis cache")]
  pub cache_dir: Option<PathBuf>,
  ```

### 5.3 Add `--rebuild-cache` CLI flag

- [ ] Add to `Cli` struct:
  ```rust
  #[arg(long = "rebuild-cache", help = "Ignore existing cache and rebuild from scratch")]
  pub rebuild_cache: bool,
  ```

### 5.4 Update `SlopguardConfig`

- [ ] Add cache fields to `SlopguardConfig` in `src/engine/config.rs`:
  ```rust
  pub struct SlopguardConfig {
      // ... existing fields ...
      pub cache: Option<CacheConfig>,
  }
  pub struct CacheConfig {
      pub enabled: bool,        // default: true
      pub dir: Option<PathBuf>,  // custom directory
  }
  ```
- [ ] Update `slopguard.schema.json`
- [ ] Update `templates/slopguard.toml`

### 5.5 Config precedence

- [ ] CLI `--no-cache` → disables cache regardless of config
- [ ] CLI `--cache-dir` → overrides config `cache.dir`
- [ ] CLI `--rebuild-cache` → purges cache directory, starts fresh
- [ ] Config `cache.enabled = false` → same as `--no-cache`
- [ ] Default: cache enabled, directory auto-discovered (walk up from cwd for `.slopguard-cache/`)

---

## Phase 6: Pruning & Housekeeping

### 6.1 Remove stale cache entries

- [ ] After scan completes, compare manifest entries against actual files scanned:
  - [ ] Any cache entry for a file not in the current scan → file was deleted, remove entry
  - [ ] Remove orphaned `files/<key>.json` files (keys not in manifest)
- [ ] Implement `CacheStore::prune(scanned_files: &HashSet<String>)`:
  - [ ] For each key in manifest: if not in `scanned_files`, remove
  - [ ] For each file in `files/`: if key not in manifest, delete file
- [ ] Add `--prune-cache` CLI flag to force cleanup

### 6.2 Cache size management

- [ ] Implement `CacheStore::total_size() -> u64` — sum of all cache entry files
- [ ] Add config option `cache.max_size_mb: u64` (default: 500)
- [ ] On `flush()`, if total_size > max_size_mb:
  - [ ] Remove oldest entries (by `cached_at` timestamp) until under limit
  - [ ] Log warning about cache pruning

---

## Phase 7: Integration Points with Other P2 Features

### 7.1 With P2.2 (Baseline)

- [ ] Cache entries store findings before baseline filtering
- [ ] Baseline filtering happens at report time (same pipeline, just after cache retrieval)
- [ ] If baseline changes between runs, cache is still valid (filtering is post-cache)

### 7.2 With P2.4 (PERF Detectors)

- [ ] Cache stores findings from all detectors (CWE + PERF + future categories)
- [ ] If new detectors are registered (tool version bump), cache is invalidated (version check)

### 7.3 With Missing A (Source Cache)

- [ ] Once source_cache is populated (Missing A), cache entries can also include the source text
- [ ] This avoids re-reading file for snippet generation even on cache hit

---

## Phase 8: Testing

### 8.1 Unit tests for `CacheStore`

- [ ] Create `tests/engine_cache.rs`
- [ ] Test `CacheStore::open()` with empty directory
- [ ] Test `CacheStore::put()` + `get()` round-trip
- [ ] Test `CacheStore::is_cache_hit()` — true on match, false on mismatch
- [ ] Test `CacheStore::remove()` — entry gone after removal
- [ ] Test `CacheStore::flush()` — manifest written to disk
- [ ] Test reopening `CacheStore` — manifest loaded correctly
- [ ] Test `CacheStore::prune()` — orphaned entries removed
- [ ] Test tool version mismatch → cache invalidated
- [ ] Test corrupt entry file → graceful `None` return

### 8.2 Integration tests for incremental scan

- [ ] Create test: first scan → full analysis, cache written
  - [ ] Assert cache directory created
  - [ ] Assert manifest.json contains all scanned files
  - [ ] Assert per-file cache entries exist
- [ ] Create test: second scan with no changes → cache hits, fast path
  - [ ] Assert 0 files re-parsed (or all from cache)
  - [ ] Assert findings match first scan
  - [ ] Assert exit code matches first scan
- [ ] Create test: change one file → only that file re-parsed
  - [ ] Modify one source file
  - [ ] Run scan
  - [ ] Assert only that file's cache entry is updated
  - [ ] Assert other files served from cache
- [ ] Create test: change imported dependency → both files re-parsed
  - [ ] Modify `pkg/common/types.go` (imported by `pkg/handler/user.go`)
  - [ ] Run scan
  - [ ] Assert both files (changed + dependent) are re-parsed
- [ ] Create test: `--no-cache` → fresh scan, no cache used or written
- [ ] Create test: `--rebuild-cache` → cache purged, fresh scan, new cache written
- [ ] Create test: cache hit with rule filtering — `--skip` on cached file still works
- [ ] Create test: deleted file → stale cache entry pruned

### 8.3 Performance benchmarking

- [ ] Add benchmark: `benches/incremental_scan.rs`
  - [ ] First-run scan (no cache) → measure baseline time
  - [ ] Second-run scan (all cache hits) → measure cached time
  - [ ] Assert cached time is at least 10× faster than baseline
- [ ] Add benchmark: mixed run (50% changed files) → measure partial invalidation perf

### 8.4 Robustness tests

- [ ] Test SIGINT during scan → manifest may be stale, `--rebuild-cache` recovers
- [ ] Test concurrent scans (two processes) → cache corruption handling
  - [ ] Use file locking or accept that cache may be overwritten (document limitation)
- [ ] Test disk full during cache write → graceful error, scan results still correct (results computed before cache write)

---

## Dependencies

- `sha2` crate for SHA-256 hashing (check `Cargo.toml`; add if not present)
- `serde` + `serde_json` (already present) for cache entry serialization
- `ignore` crate (already present in `walk.rs`)
- `rayon` (already present in `scan_entries_parallel`)
- Uses `Finding` and its serde impl from `src/rules/finding.rs`
- Uses `ScanEntry` from `src/engine/walk.rs`
- Uses `ScanContext` from `src/core/scan.rs`
