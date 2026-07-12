# P2.3 — Cache & Incremental Analysis: Remaining Work

> **Parent:** `plans/p2-implementation/03-incremental-analysis.md` — P2.3
> **Status:** **Phases 1–7 fully implemented.** Phase 4.2 deferred, Phase 8.4 deferred. Minor config/observability/hygiene items remaining.
> **Estimated effort:** 1–2 days total
> **See also:** `documents/incremental-cache.md`, `documents/architecture-performance.md`

---

## Overview

The incremental analysis cache is **largely complete**: on-disk format, SHA-256 content hashing, LRU eviction, dependency extraction (Go + Python), transitive invalidation, CLI flags, config integration, and benchmark harness all exist and are verified by test suites. What remains is a small set of configurable parameters, logging improvements, test-suite gaps, and documentation fixes.

**Situation:** 6 integration test files covering cache, invalidation, inline-ignore, and scan integration. 10/13 plan phases fully shipped. No known correctness bugs.

---

## Executive Summary

- **Capability is complete** — the cache works end-to-end and passes all existing tests.
- **Remaining items are polish**: make `evict_target_ratio` configurable, add logging on eviction, add a size threshold config for source caching, fill test gaps, and update stale docs.
- **Two items are intentionally deferred**: inline-ignore store in cache entry (cost > benefit) and concurrent-process test (non-portable).
- **Estimated effort**: ~1–2 days for all remaining items.

---

## Phase 1 — Configurable Eviction Parameters

> **Status:** ❌ Not started
> **Effort:** 2–3 hours

### 1.1 `evict_target_ratio` config field

Currently the LRU eviction prunes to a hardcoded 90% of `max_size_bytes`:
```rust
// src/engine/cache/store_flush.rs:41
let target = (self.max_size_bytes as f64 * 9.0 / 10.0) as u64; // hardcoded 0.9
```

- [x] Add `evict_target_ratio: f64` to `CacheConfig` in `src/engine/config/types.rs`:
  ```rust
  pub struct CacheConfig {
      pub enabled: Option<bool>,
      pub path: Option<String>,
      pub max_size_mb: Option<u64>,
      pub evict_target_ratio: Option<f64>,  // 0.0–1.0, default 0.9
  }
  ```
- [x] Add default 0.9 in `CacheConfig::apply_defaults()` or wherever defaults are set
- [x] Wire through `CacheStore::open_with_capacity()` and use in `evict_to_size()`
- [x] Validate range (0.1–0.99) with a `tracing::warn!` on out-of-range values (clamp to 0.9)
- [x] Update `codehound.schema.json` with `cache.evict_target_ratio` field
- [x] Update `documents/incremental-cache.md` with the new config option
- [~] Add a test: `flush_evicts_to_configured_ratio` in `tests/engine_cache_store.rs`

### 1.2 `max_file_size_mb` config field

Currently every file under ~4 MiB is cached; the threshold is implicit (based on in-memory buffer sizes).

- [x] Add `max_file_size_mb: Option<u64>` to `CacheConfig` (default 4)
- [x] In the scan preflight / cache-lookup step, skip caching for files larger than this threshold
- [x] Log a `tracing::debug!` when a file is skipped due to size
- [x] Update `codehound.schema.json` with `cache.max_file_size_mb`
- [x] Update `documents/incremental-cache.md`

---

## Phase 2 — Observability Improvements

> **Status:** ❌ Not started
> **Effort:** 2–3 hours

### 2.1 Logging on LRU eviction

- [x] In `CacheStore::evict_to_size()` (`src/engine/cache/store_flush.rs`), after removing entries, emit a `tracing::info!` summary:
  ```rust
  tracing::info!(
      entries_evicted = evicted.len(),
      bytes_freed = bytes_freed,
      current_size_mb = total / (1024 * 1024),
      target_size_mb = target / (1024 * 1024),
      "cache LRU eviction completed"
  );
  ```
- [~] Also emit a `tracing::debug!` for each individual evicted entry (file path + size) for detailed debugging
- [~] Add a test that verifies the log message is emitted (use `tracing_test::span` or similar)

### 2.2 Logging on transitive invalidation cascade

- [x] In `src/engine/analyzer/scan.rs`, the transitive invalidation already logs at `tracing::info!` when count > 0 (wired in E.5 per previous work). Verify the format includes the number of cascaded files and the triggering file.

---

## Phase 3 — Test-Suite Gaps

> **Status:** ⏳ Partially done. 3 test gaps remain.
> **Effort:** 3–4 hours

### 3.1 Concurrent scans test (Phase 8.4)

- [x] Create `tests/engine_cache_concurrent.rs`:
  - Spawn two `std::process::Command` processes running `cargo run -- scan` against the same cache dir
  - Verify both complete successfully and neither loses entries (or manifest falls back gracefully)
  - Use a temp dir with a known Go fixture as the scan target
  - Mark as `#[ignore]` if it proves flaky on CI (documented as non-portable in the plan)
- [~] Update `documents/incremental-cache.md` limitations section to mention this test exists

### 3.2 Transitive invalidation test without `go.mod` (Phase 8.2)

- [x] Add a test variant that creates a synthetic temp dir **without** a `go.mod` file, where dependency paths are resolved via the analyzer's fallback (`cwd` inference).
  - Currently `transitive_invalidation_clears_dependents` requires a real `go.mod` on disk
  - The new test should verify that `no_go_mod_path_inference_falls_back_to_cwd` works and that transitive invalidation still fires

### 3.3 Tool version mismatch test

- [x] Add a test that writes a manifest with `tool_version: "0.0.0-old"`, opens the cache, and verifies:
  - A warning is logged (`tracing::warn!` about version mismatch)
  - The cache is still usable (lazy rewrite on next entry touch)
- [x] Verify that a file cached under the old version is re-cached when touched (content hash check passes, but entry is rewritten)

### 3.4 Corrupt entry file test

- [x] Add a test that writes a malformed JSON entry file in `files/<sha256>.json`, opens the cache, and verifies:
  - The corrupt entry is **not** treated as a cache hit (falls back to `CacheStatus::Miss`)
  - A `tracing::warn!` is emitted for the corrupt entry
- [x] Verify the manifest still works for other (non-corrupt) entries

### 3.5 `CacheStore::clean_orphans()` test

- [x] Add a test that creates an orphaned `.json` file in the `files/` directory (no matching manifest entry), runs `clean_orphans()`, and verifies the orphan is deleted
- [x] Verify the manifest file is not affected

---

## Phase 4 — Documentation Updates

> **Status:** ⏳ Documentation is slightly stale in one area.
> **Effort:** 30 minutes

### 4.1 Fix `documents/incremental-cache.md` claims

- [x] Update line 99–100 which states "Size-based LRU eviction (`max_size_mb`) is wired in config but not yet enforced on `flush()`." — this is **incorrect**; `evict_to_size()` IS implemented and called from `flush()`. Change to: "Size-based LRU eviction (`max_size_mb`) is enforced on `flush()`. See `store_flush.rs:40`." **Already fixed** in current `documents/incremental-cache.md:99-100`
- [x] Add a note that `evict_target_ratio` (default 0.9) controls how aggressively the cache prunes (once Phase 1.1 lands)
- [x] Add a note that `max_file_size_mb` (default 4) controls per-file caching threshold (once Phase 1.2 lands)

### 4.2 Update `documents/architecture-performance.md`

- [x] Ensure the cache architecture section reflects the current state: `files/<sha256>.json` format, manifest, LRU eviction, dependency extraction
- [x] Add a note about the `--prune-cache` flag (was added after the doc was written)

---

## Phase 5 — Deferred Items (Acknowledged, Not Blocking)

The following items are acknowledged as not implemented, but explicitly deferred as not worth the complexity:

| Item | Phase | Reason | Impact |
|------|-------|--------|--------|
| Store inline-ignore set in cache entry | 4.2 | Source is already in memory for hash check; re-parsing is negligible | None |
| Dependencies-list change on identical content hash | 4.3 | Content hash always changes when imports change | None |
| Source text in cache entry | 7.3 | Design choice to keep cache size bounded; source is re-read on hash check | One disk read per cache hit |
| HashMap-based "fallback" file_cache | E.6 | Superseded by on-disk cache | None |

---

## Quick reference

| Phase | Items | Effort | Status |
|-------|-------|--------|--------|
| 1 — Configurable eviction | 2 config fields | 2–3h | ❌ |
| 2 — Observability | 2 logging items | 2–3h | ❌ |
| 3 — Test gaps | 5 tests | 3–4h | ⏳ |
| 4 — Docs fixes | 2 doc files | 30min | ⏳ |
| 5 — Deferred items | 4 acknowledged items | — | ✅ Acknowledged |
