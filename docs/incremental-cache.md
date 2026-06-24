# Incremental Analysis Cache

SlopGuard can cache per-file findings so subsequent scans skip unchanged files.
This is the biggest performance win for CI and local iteration on large
repositories.

## Enabling the cache

The cache is **enabled by default**. It is written to `.slopguard-cache/` next
to the project root (discovered by walking up from the scan path for `.git` or
`go.mod`).

```sh
# Use the default cache
slopguard .

# Use a custom cache directory
slopguard --cache-dir /tmp/slopguard-cache .

# Disable the cache for one run
slopguard --no-cache .

# Purge the cache and re-scan everything
slopguard --rebuild-cache .

# Remove entries for deleted files and orphaned on-disk files, then exit
slopguard --prune-cache .
```

## Configuration

Add the optional `[slopguard.cache]` block to `slopguard.toml`:

```toml
[slopguard.cache]
enabled = true
path = ".slopguard-cache"      # custom directory
max_size_mb = 500              # size limit (LRU eviction TBD)
```

CLI flags override config values.

## On-disk layout

```
.slopguard-cache/
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
- The SlopGuard tool version changed.
- Any project-local dependency's content hash changed (transitive invalidation).

`mtime` is recorded for diagnostics but is not authoritative; the content hash
is.

### Transitive invalidation

For Go files, SlopGuard extracts project-local imports from `import`
declarations and resolves them relative to the module prefix read from
`go.mod`. When an imported file changes, every cache entry that listed it as a
dependency is invalidated. Stdlib and third-party imports are ignored.

## Cache hits

On a hit, SlopGuard:

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

## Limitations

- Concurrent SlopGuard processes on the same cache directory may race on the
  manifest. Individual entry files are written atomically, and a torn manifest
  is detected on the next `open()` and falls back to an empty manifest.
- Size-based LRU eviction (`max_size_mb`) is wired in config but not yet
  enforced on `flush()`.
