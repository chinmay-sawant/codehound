# feat: export findings and chunks during Go scans

## Summary

This change makes scan runs write finding context files and chunk files under
`scripts/` instead of only printing findings to the terminal. It also makes
`make run` quiet and non-failing on findings so the export pipeline can be used
as the primary output path.

---

## Motivation / context

- `plans/v0.0.1/go/reports.md` describes chunk and finding-detail export as the
  intended scan output.
- The current binary was only emitting terminal findings, which meant the Go
  workflow could not consume `scripts/findings/functions` or `scripts/chunks`.

---

## Changes

### Export pipeline

- Added [src/export/mod.rs](/home/chinmay/ChinmayPersonalProjects/codehound/src/export/mod.rs) to:
  - build per-finding text blocks
  - write numbered finding files under `scripts/findings/functions`
  - write `Chunk_<start>_<end>.txt` files under `scripts/chunks`
  - clean prior exported `.txt` files before rewriting

### CLI integration

- Extended [src/cli/mod.rs](/home/chinmay/ChinmayPersonalProjects/codehound/src/cli/mod.rs) with:
  - `--no-terminal`
  - `--no-context`
  - `--no-chunks`
  - `--chunk-size`
  - `--context-output-dir`
  - `--chunks-output-dir`
- Updated [src/main.rs](/home/chinmay/ChinmayPersonalProjects/codehound/src/main.rs) to export findings after analysis and before optional terminal reporting.

### Build workflow

- Updated [makefile](/home/chinmay/ChinmayPersonalProjects/codehound/makefile) so `make run`:
  - defaults to `SCAN_PATH`
  - runs with `--no-fail`
  - runs with `--no-terminal`
  - stays quiet via `cargo run --quiet`

### Scope cleanup

- Removed the earlier rules-reporting path that was not used by chunk/finding export:
  - deleted the temporary ruleset loader
  - deleted the rules text/JSON reporter
  - removed the unused `rules` make targets and CLI wiring

---

## Impact

| Area | Impact |
|------|--------|
| **Behavior / correctness** | Scan runs now produce file outputs under `scripts/` by default. |
| **API / CLI** | New scan flags control terminal output and export destinations. |
| **Developer workflow** | `make run` is silent on success and does not fail just because findings exist. |
| **Dependencies** | None. |

---

## Breaking changes / migration

None.

---

## Files changed (high level)

| Path | Change |
|------|--------|
| `src/export/mod.rs` | Added finding/chunk export implementation |
| `src/cli/mod.rs` | Added export-related scan flags |
| `src/main.rs` | Hooked export into scan execution |
| `src/lib.rs` | Exported the new `export` module |
| `makefile` | Made `make run` quiet and export-oriented |

---

## Test plan

- [x] `cargo test`
- [x] `cargo fmt --all`
- [x] Manual: `cargo run -- target/codehound-fixtures/go --no-fail --no-terminal`
- [x] Manual: `make run SCAN_PATH=target/codehound-fixtures/go`

### Commands

```sh
cargo fmt --all
cargo test
cargo run -- target/codehound-fixtures/go --no-fail --no-terminal
make run SCAN_PATH=target/codehound-fixtures/go
```

---

## Follow-ups (out of scope)

- Reconstruct full function bodies instead of nearby source lines for each finding block.
- Align the exported block format even more closely with the older `deslop` implementation described in `reports.md`.
