## Summary

Restore `retain_sources` when `--export-context` / `--export-chunks` are set so exported finding and chunk files include real source snippets. The lazy cwd disk fallback failed for project-relative finding paths when the scan root is outside the process working directory (the default `make run` / `SCAN_PATH` case).

---

## Motivation / context

- Issue: #200
- Regression from v0.0.7 audit (`f56ff6b`), which forced `retain_sources: false` and assumed export could re-read files from cwd
- Findings use project-relative paths; export keys `source_cache` by the same identity

---

## Changes

### CLI / scan context

- `scan_context_params_for_run`: set `retain_sources: cli.export_context || cli.export_chunks` again
- Default non-export scans still leave sources dropped after each file

### Tests

- Unit: export flags enable retention; default CLI does not
- Integration: retain sources → export includes snippet for project-relative paths
- Integration: empty cache + relative path still documents `<context unavailable>`

### Process / PR record

- Issue body and this PR body under `plans/PR/`

---

## Code snippets (if applicable)

### Before

```rust
// Export lazily reads only files that produced findings.
retain_sources: false,
```

### After

```rust
// Findings store project-relative paths; export resolves snippets from
// source_cache (not cwd). Only pay RAM cost when export is opted in.
retain_sources: cli.export_context || cli.export_chunks,
```

---

## Impact

| Area | Impact |
|------|--------|
| **Performance** | Unchanged for default CI/JSON/SARIF scans |
| **Memory** | Source text retained only when export flags are set (opt-in monorepo cost) |
| **Behavior / correctness** | Export context/chunks show real snippets again for external `SCAN_PATH` |
| **API / CLI** | No flag changes; restores documented export contract |
| **Dependencies** | None |
| **Binary size / build time** | None |

---

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| None | — |

---

## Files changed (high level)

| Path | Change |
|------|--------|
| `src/app/run.rs` | Restore export → `retain_sources`; unit test |
| `tests/engine_source_cache_export_go.rs` | Regression tests |
| `plans/PR/issue-export-context-unavailable-body.md` | Issue body record |
| `plans/PR/pr-export-context-unavailable.md` | This PR body |

---

## Test plan

- [x] Focused: `cargo test --test engine_source_cache_export_go`
- [x] Focused: `cargo test --bin codehound export_flags_enable_source_retention`
- [x] Manual: `make run SKIP_BUILD=1 RUN_ARGS="--export-context --export-chunks"` against gopdfsuit — 0× `<context unavailable>`
- [ ] CI: `make lint` / `make test` on PR

### Commands

```sh
cargo test --test engine_source_cache_export_go
cargo test --bin codehound export_flags_enable_source_retention
make run SKIP_BUILD=1 RUN_ARGS="--export-context --export-chunks"
# confirm scripts/findings/functions/*.txt contain source lines
```

---

## Screenshots / sample output

```
Finding 40/915
Source: internal/handlers/handlers.go:322:2
Rule: BP-1
...
Enclosing function: lines 320–374
Context:
        320: func handleFillPDF(c *gin.Context) {
    >   322: pdfFile, pdfHeader, _ := c.Request.FormFile("pdf")
```

---

## Related issues

- Closes #200

---

## PR metadata checklist (author)

- [x] Self-assigned (`--assignee @me`)
- [x] Labels applied (`bug`)
- [x] Related issues filled with real ticket IDs
- [x] Filled body committed under `plans/PR/pr-export-context-unavailable.md`

---

## Follow-ups (out of scope)

- Optional: lazy re-read only files with findings, resolved against scan roots (lower peak RAM without empty context)
- Documented aggregate source-cache budget for huge monorepos

---

## Reviewer checklist

- [ ] Behavior matches summary and test plan
- [ ] No unrelated changes in diff
- [ ] PR has assignee and labels
- [ ] Related issues use correct Closes/Relates keywords
- [ ] No secrets or generated artifacts committed

---

## Release notes (if user-facing)

- Fixed `--export-context` / `--export-chunks` emitting `<context unavailable>` when scanning a path outside the current working directory.
