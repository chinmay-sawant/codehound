# Incremental Analysis Cache

CodeHound can cache per-file findings so subsequent scans skip unchanged files.
This is the biggest performance win for CI and local iteration on large
repositories.

## Enabling the cache

The cache is **enabled by default**. It is written to `.codehound-cache/` next
to the project root (discovered by walking up from the scan path for `.git` or
`go.mod`).

```sh
# Use the default cache
codehound .

# Use a custom cache directory
codehound --cache-dir /tmp/codehound-cache .

# Disable the cache for one run
codehound --no-cache .

# Purge the cache and re-scan everything
codehound --rebuild-cache .

# Remove entries for deleted files and orphaned on-disk files, then exit
codehound --prune-cache .
```

## Configuration

Add the optional `[codehound.cache]` block to `codehound.toml`:

```toml
[codehound.cache]
enabled = true
path = ".codehound-cache"      # custom directory
max_size_mb = 500              # size limit; oldest-by-cached_at eviction on flush
evict_target_ratio = 0.9       # evict down to 90% of max_size_mb
max_file_size_mb = 4           # skip cache for files larger than 4 MiB
```

CLI flags override config values.

## On-disk layout

```
.codehound-cache/
├── manifest.json       # schema_version, tool_version, rule_config_hash, file map
├── .manifest.lock      # advisory exclusive lock during flush (fs2)
└── files/
    ├── <sha256>.json   # per-file findings + content_hash + deps + cached_at
    └── ...
```

There is **no** separate `metadata.json`. Tool version and related fields live
in `manifest.json` (`CacheManifest`). Schema version is `CACHE_VERSION = 2`.

## Project roots (two concepts)

| Root | How | Used for |
|------|-----|----------|
| Prep / project root | Walk for `.git` **or** `go.mod` | Pack prep, some discovery |
| Dependency base root | Prefer `go.mod` directory (never bare parent `.git` alone) | Cache keys, dep graph, prune safety |

CI sandboxes that only inherit a parent `.git` without a local `go.mod` rely on
this split — see `src/engine/dependencies/project_root.rs`.

## Invalidation strategy

A file is treated as stale and re-parsed when any of the following is true:

- No cache entry exists (first scan).
- The file's SHA-256 content hash differs from the cached hash.
- The CodeHound **tool version** changed (`manifest.tool_version`).
- The **rule-config fingerprint** changed (`rule_config_hash`): profile,
  only/skip, taint/typed/BP toggles, taint depth, and related knobs from
  `ScanContext::rule_config_fingerprint`.
- `CACHE_VERSION` / schema mismatch (store refuses or rebuilds).
- Any project-local dependency's content hash changed (transitive invalidation).

Content hash is authoritative. Entries record `content_hash`, `dependencies`,
and `cached_at` — **not** mtime.

### Transitive invalidation

For Go files, CodeHound extracts project-local imports from `import`
declarations and resolves them relative to the module prefix read from
`go.mod`. When an imported file changes, every cache entry that listed it as a
dependency is invalidated. Stdlib and third-party imports are ignored.

## Cache hits

On a hit, CodeHound:

1. Reads the file to verify its content hash.
2. Loads the cached findings from `files/<key>.json`.
3. Re-applies the current run's rule filters (`--skip` / `--only`).
4. Re-applies inline/file ignore directives from the source text.
5. Emits the surviving findings.

The source text is already in memory for the hash check, so re-applying
suppressions is essentially free.

## Housekeeping

- At the end of a normal scan, entries for files that no longer exist are
  removed from the manifest **when the scan covers the full dependency root**
  (`covers_dependency_root`). Nested path or single-file scans do **not** prune
  sibling packages.
- `--prune-cache` / `codehound cache prune` perform cleanup plus remove orphaned
  `files/<key>.json` entries whose keys are not in the manifest.
- `--rebuild-cache` deletes the entire cache directory and starts fresh.

### Taint interaction

When taint is enabled, detectors may set `requires_cache_state` so project
finalize still receives units even on “hits”. Expect less free warm-cache
speedup under `--taint` / `--profile security`.

## Same-scan cascade (Phase 5)

When a file’s content hash changes, every cached file that listed it as a
dependency is marked **dirty in the same scan** (reverse-dep fixpoint) and
re-parsed immediately. Dependents are no longer left on stale cache hits until
the next process run.

## Tool-version invalidation

If `manifest.tool_version` ≠ the running `CARGO_PKG_VERSION`, the store
**mass-stales**: all entries are dropped and rebuilt on this scan (not only a
warning). Schema mismatches still refuse to open (`CACHE_VERSION`).

## Path identity

Manifest keys and dependency paths use `normalize_project_path` (forward
slashes, no `./` prefix). See [ADR 0002](./adr/0002-project-path-identity.md).

## Limitations / concurrency policy

- **Single-writer preferred:** one CodeHound process should own a given cache
  directory per scan. Parallel CI jobs should use distinct `--cache-dir` paths.
- Flush uses an **advisory exclusive lock** (`.manifest.lock` via `fs2`). On
  lock contention the writer may **skip flush** rather than corrupt the store —
  this is not a multi-writer merge protocol.
- Entry files are written as whole JSON documents; a torn manifest is detected
  on the next `open()` and falls back to an empty manifest.
- Tests (`engine_cache_concurrent`) assert concurrent open/scan does not panic;
  they do not guarantee merge correctness under dual writers.
- Size-based eviction (`max_size_mb`) is enforced on `flush()` via
  `CacheStore::evict_to_size()` (oldest by `cached_at`). `evict_target_ratio`
  controls how far the cache is trimmed once the limit is exceeded.
- Files larger than `max_file_size_mb` still scan normally, but CodeHound skips
  cache lookups and cache writes for them to avoid bloating the on-disk store.
- In-memory `CacheBackend` exists for tests/embedders; disk is the default.
