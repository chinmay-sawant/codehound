# Deferred Checklist Items — Agent 5 (v0.0.1 audit)

> Source files audited:
> - `plans/v0.0.1/TODO-2026-06-05-session2.md`
> - `plans/v0.0.1/go/generate-cwe-fixtures.md`
> - `plans/v0.0.1/go/perf-heuristics-and-sarif.md`
> - `plans/v0.0.1/go/pure-go-fixtures.md`
> - `plans/v0.0.1/architecture-performance-enhancement/PR/pr-architecture-performance-2026-06-02.md`
> - `plans/v0.0.1/architecture-performance-enhancement/PR/pr-refactor-go-cwe-and-add-perf-plan.md`
> - `plans/v0.0.1/architecture-performance-enhancement/PR/pr-performance-parallel-scan.md`
> - `plans/v0.0.1/architecture-performance-enhancement/PR/architecture-performance-review-2026-06-05.md`

---

## Deferred Items

### TODO-2026-06-05-session2.md

- A2: Split `GoCweScan` into per-rule detectors (macro-based) — still a single `GoCweScan` struct, not macro-split
- `cargo test --all` passes — needs review
- `cargo clippy --all-targets --all-features -- -D warnings` clean — needs review
- Save PR summary to `plans/v0.0.1/PR/` — directory not found

### generate-cwe-fixtures.md

- `cargo test` passes for `go_integration` and `fixture_manifest_integration` — needs review

### perf-heuristics-and-sarif.md

- `make fmt` — needs review
- `make lint` — needs review
- Add rule metadata beyond `id`, `name`, and `shortDescription` in SARIF — needs review
- Include `helpUri` or `properties` in SARIF when rule registry has enough information — needs review
- Include concise message text explaining both hot-path issue and preferred reuse pattern — needs review (now implemented; PERF detector messages use "issue; fix pattern" format, confirmed in `src/lang/go/detectors/perf/domains/`)
- Add focused SARIF regression test for mixed `CWE-*` and `PERF-*` findings — not found

### pure-go-fixtures.md

- Pre-existing off-by-one in `tests/fixtures/go/` ↔ manifest resolved — needs review
- `cargo test --test go_integration` passes — needs review
- `cargo test --test fixture_manifest_integration` passes — needs review

### pr-architecture-performance-2026-06-02.md

- `cargo fmt --check` — needs review
- No unrelated changes in diff — PR diff check needed

### pr-refactor-go-cwe-and-add-perf-plan.md

- No unrelated changes in diff — PR diff check needed
- No secrets or generated artifacts committed — security check needed

---

## Implemented (was [ ] → now [x])

- **perf-heuristics-and-sarif.md:** Add stable fingerprints — implemented via `src/rules/fingerprint.rs` (`Fingerprint` struct) and `partial_fingerprints` in SARIF output (`src/reporting/sarif/log.rs:76-77`)

---

## Count

| Status | Count |
|--------|-------|
### pr-performance-parallel-scan.md
- `cargo run -- target/slopguard-fixtures` — manual verification run, not automated
- Scan large repo and compare wall time vs previous sequential build — manual benchmark

### architecture-performance-review-2026-06-05.md
- Callee-indexed rule scheduling to skip rules when sinks are absent — not implemented
- Incremental tree-sitter parse / file-hash cache — not implemented
- Further shrink `general_security` hot paths beyond `SourceIndex` (tree-sitter queries) — not implemented

| Total unchecked items | 24 |
| Marked [x] (implemented) | 2 |
| Marked [~] (deferred) | 22 |
