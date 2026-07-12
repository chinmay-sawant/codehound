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
max_size_mb = 500              # size limit (LRU eviction TBD)
evict_target_ratio = 0.9       # evict down to 90% of max_size_mb
max_file_size_mb = 4           # skip cache for files larger than 4 MiB
```

CLI flags override config values.

## On-disk layout

```
.codehound-cache/
├── manifest.json       # maps file path → content hash + cache key + deps
├── metadata.json       # tool version, last scan timestamp
└── files/
    ├── <sha256>.json   # per-file findings + metadata
    └── ...
```

## Invalidation strategy

A file is treated as stale and re-parsed when any of the following is true:

- No cache entry exists (first scan).
- The file's SHA-256 content hash differs from the cached hash.
- The CodeHound tool version changed.
- Any project-local dependency's content hash changed (transitive invalidation).

`mtime` is recorded for diagnostics but is not authoritative; the content hash
is.

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
  removed from the manifest.
- `--prune-cache` performs the same cleanup plus removes orphaned
  `files/<key>.json` entries whose keys are not in the manifest.
- `--rebuild-cache` deletes the entire cache directory and starts fresh.

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

- **Single-writer assumption:** one CodeHound process owns a given cache
  directory per scan. Concurrent writers on the same `.codehound-cache/` may
  race on `manifest.json`.
- Entry files are written as whole JSON documents; a torn manifest is detected
  on the next `open()` and falls back to an empty manifest.
- File locking is intentionally **not** implemented yet; prefer exclusive CI
  jobs or distinct `--cache-dir` paths for parallel scans.
- Tests (`engine_cache_concurrent`) assert concurrent open/scan does not panic;
  they do not guarantee merge correctness under dual writers.
- Size-based LRU eviction (`max_size_mb`) is enforced on `flush()` via
  `CacheStore::evict_to_size()`. `evict_target_ratio` controls how far the
  cache is trimmed once the limit is exceeded.
- Files larger than `max_file_size_mb` still scan normally, but CodeHound skips
  cache lookups and cache writes for them to avoid bloating the on-disk store.
