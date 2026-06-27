# P2.5 — Bad Practices: Final Scope, Architecture, and Prioritization

> **Parent:** [`05-bad-practices-detection.md`](./05-bad-practices-detection.md) (the full plan, retained for reference).
> **Status:** Scoping and design complete. Implementation deferred to a follow-up plan.
> **Goal:** Define a new rule category (beyond CWE and PERF) for high-signal application-level Go anti-patterns, with a clear MVP cut and a phased roadmap.

---

## 1. Rule ID Scheme

- **Prefix:** `BP-N` (Bad Practice), matching the user's example. Reasons:
  - `GP-` reads as "Good Practice" — confusing because the rule *flags* a violation.
  - `QA-` overlaps with test-quality tooling; using it would suggest this is a test suite.
  - `BP-` is short, unambiguous, and lines up alphabetically with `CWE-` and `PERF-`.
- **Numbering:** Sequential (`BP-1` … `BP-N`) within each sub-category block to make the catalog readable, not interleaved across sub-categories.

## 2. Sub-category Scope

The seven sub-categories proposed in the parent plan are kept, but **only Error Handling and Concurrency are in scope for the MVP** (`BP-1..BP-15`). The other five sub-categories ship in later phases, gated on the MVP detectors proving stable in the field.

| # | Sub-category | MVP (Phase 1) | Phase 2 | Phase 3 | Rationale |
|---|---|---|---|---|---|
| 1 | Error Handling | ✅ BP-1..BP-5 | — | — | Highest signal, lowest false-positive rate, fully AST-detectable. |
| 2 | Concurrency | ✅ BP-6..BP-15 | — | — | High signal; `sync.WaitGroup` / `sync.Mutex` patterns are mechanically AST-detectable. Goroutine leak detection needs the control-flow graph (Phase 2 of MVP, deferred). |
| 3 | Testing | — | ✅ BP-16..BP-25 | — | Detected only in `*_test.go` files; valuable but noisier. |
| 4 | API Design | — | — | ✅ BP-26..BP-35 | Heuristic-heavy (interface size, method receiver consistency); lower signal. |
| 5 | Code Organization | — | — | ✅ BP-36..BP-45 | Mostly `go vet` / `staticcheck` territory; we add only what they miss. |
| 6 | Production Hardening | — | — | ⏳ BP-46..BP-55 | Multi-file analysis; some detectors need the call graph (P2.1 taint). |
| 7 | Dependency Hygiene | — | — | ⏳ BP-56..BP-65 | `go.mod` parsing; some checks overlap with renovate/dependabot. |

**Out of scope for any phase** (and explicitly listed so we do not add them later):
- Stylistic preferences (handled by `gofmt`, `goimports`, `revive`).
- Language-level `go vet` checks.
- Runtime / profiling patterns.
- Naming conventions beyond what's universally agreed.

## 3. MVP — 15 Rules (BP-1..BP-15)

### Error Handling (BP-1..BP-5)

| ID | Title | Pattern | Severity | Notes |
|---|---|---|---|---|
| `BP-1` | Discarded error (`_ = doSomething()`) | `*_ = *` (assignment-discard of a call returning `error`) | Medium | Skip when the function returns no error and the call is in `_test.go` (common idiom for setup helpers). |
| `BP-2` | Naked `return err` without context | `if %err != nil { return %err }` — no wrapping, no logging | Low | Heuristic: only flag if the function is not the canonical `main` and the call site is two or more frames deep. |
| `BP-3` | `panic` outside `main` / test files | `panic(...)` in a non-`main`, non-`*_test.go` file | High | A library that panics forces every caller to `recover()`. |
| `BP-4` | `recover()` without error logging | `func() { recover() }()` — no logging, no re-emit | Medium | Heuristic: skip if the surrounding function returns a sentinel error. |
| `BP-5` | Ignored `Close()` on known resources | `*_ = closer.Close()` where the receiver type is one of `*os.File`, `*http.Response.Body`, `*sql.Rows` | Medium | Tight type-based check; high precision. |

### Concurrency (BP-6..BP-15)

| ID | Title | Pattern | Severity | Notes |
|---|---|---|---|---|
| `BP-6` | `sync.WaitGroup.Add` inside a goroutine | `go func() { wg.Add(1); ... wg.Done() }()` | High | Classic race. |
| `BP-7` | `sync.Mutex` passed by value | `func foo(m sync.Mutex) { ... }` | High | `Mutex` is a struct; copying it copies the lock state. |
| `BP-8` | `defer mu.Unlock()` while holding a copy of a `sync.Mutex` | A `Mutex`-typed local var with `defer m.Unlock()` — same bug as `BP-7` in disguise | High | Detect via the receiver type or local variable's declared type. |
| `BP-9` | `select {}` with no `default` and no timeout | `select { case <-ch: }` (no `default`, no `time.After`, no `ctx.Done()`) | Medium | Heuristic for unbounded blocking. |
| `BP-10` | `time.After` in a loop | `for { select { case <-time.After(d): ... } }` | Medium | Memory leak: each iteration creates a new timer that isn't GC'd until it fires. |
| `BP-11` | `defer` inside a `for`/`range` | `for ... { defer f() }` | High | Defers stack at function scope, not block scope; can grow unboundedly. |
| `BP-12` | Unbuffered channel sent from multiple goroutines without coordination | Heuristic — skip for MVP | — | Too noisy without control-flow analysis; revisit in P2.1 taint. |
| `BP-13` | `context.Background()` in a non-`main` function | A function whose name != `main` calls `context.Background()` | Low | Signals a missing `ctx` parameter. |
| `BP-14` | Goroutine with no `ctx.Done()` select and no timeout | Heuristic — skip for MVP | — | Same as `BP-12`; needs more analysis. |
| `BP-15` | `sync.Once.Do` with a closure that calls itself recursively | `once.Do(func() { once.Do(...) })` | High | Detected as a `call_expression` whose target's argument contains a call to the same `once.Do`. |

> Note: `BP-12` and `BP-14` are deliberately listed but **skipped** in the MVP. They appear so the rule IDs stay contiguous with the plan; they will be filled in once the taint infrastructure (P2.1) is in place. Until then, the gap shows up as `BP-12: not yet implemented` in `--list-rules` and is silent on the wire.

## 4. Architecture Decision

**Choice: Option A — single `GoBadPracticeScan` detector with domain submodules.**

Rationale:
- Consistent with the existing CWE and PERF architectures (`GoCweScan`, `GoPerfScan`). Users learn one pattern, get one mental model.
- Each sub-category is its own submodule (`errors`, `concurrency`, `testing`, `api_design`, `code_org`, `prod_hardening`, `deps`), so the implementation files stay small and focused.
- The `BadPracticeRuleMetadata` is a thin extension of `RuleMetadata` plus a `category: BadPracticeCategory` enum. The detector just iterates the same way `GoCweScan::run` does.
- Per-category filtering at scan time happens via the existing `ScanContext::allows(rule_id)` (filter by rule id) — no special-casing in the registry.

**Rejected options:**
- **Option B (per-category detector structs)** would require 7 new top-level entries in `lang/go/detectors/mod.rs::all()` and 7 separate entries in the registry.toml — boilerplate explosion for marginal benefit.
- **Option C (per-rule detectors)** is what `Python` uses for its single rule; it does not scale to 60+.

## 5. Rule Metadata

```rust
pub enum BadPracticeCategory {
    ErrorHandling,
    Concurrency,
    Testing,
    ApiDesign,
    CodeOrganization,
    ProductionHardening,
    DependencyHygiene,
}

pub struct BadPracticeRuleMetadata {
    pub id: &'static str,            // e.g. "BP-1"
    pub title: &'static str,
    pub description: &'static str,
    pub category: BadPracticeCategory,
    pub severity: Severity,
    pub fix: Option<&'static str>,
}
```

Stored alongside `RuleMetadata` in the existing `GoBadPracticeFacts` struct (or its own `BP_FACTS` if the field set grows). Bad practices do **not** carry a `cwe` field; they may carry a reference to a `go vet` or `staticcheck` rule (e.g. `SA1019` for deprecated APIs) in a future extension.

## 6. Ruleset Format

A new file `ruleset/golang/bad-practices.json` is added alongside `golang.json`. Schema mirrors the existing file but with a `category` field and no `cwe`:

```json
{
  "BP-1": {
    "id": 1,
    "name": "Discarded error",
    "description": "...",
    "category": "error_handling",
    "severity": "Medium",
    "detection_notes": "..."
  }
}
```

`build.rs` is extended to load this file and generate `META_BP_1` … `META_BP_N` constants, mirroring the current `META_CWE_*` and `META_PERF_*` generation. The detector references them by `include!(concat!(env!("OUT_DIR"), "/go_bad_practice_metadata.rs"))`.

## 7. CLI & Configuration

- New `[bad_practices]` block in `slopguard.toml`:
  ```toml
  [bad_practices]
  enabled = true          # default true
  severity = "medium"     # default: only emit findings at or above this severity
  only = ["BP-1", "BP-6"] # optional
  skip = ["BP-13"]        # optional
  ```
- New CLI flag `--bp-only` to mean `--only "BP-*"`. The existing `--only` / `--skip` mechanisms work as-is for individual rules.
- New CLI flag `--no-bp` to disable the entire category.
- `lang/go/detectors/mod.rs::all()` keeps `GoBadPracticeScan` registered; turning the category off is done via `ScanContext::allows` filtering in the scanner wrapper (one-line change, mirrors how `--skip` already works).

## 8. Reporting

- **Text reporter:** Add a `BP-` prefix-color band (different from `CWE-` red and `PERF-` yellow). Use a muted "quality" color (e.g. blue/cyan) so security findings still stand out.
- **JSON reporter:** Add `"category": "bad_practice"` to the finding object. Existing `rule_id` field carries the `BP-N` string.
- **SARIF reporter:** Map `BP-*` rules to a non-security `security-severity` of `5.0` (lowest band) and tag `properties.category = "bad_practice"` so downstream SARIF consumers can filter.

## 9. Phased Roadmap

| Phase | Scope | Effort | Gate |
|---|---|---|---|
| **MVP (P2.5-A)** | BP-1..BP-5, BP-6, BP-7, BP-8, BP-9, BP-10, BP-11, BP-13, BP-15 (13 real rules + 2 reserved IDs) | 2 weeks | MVP detectors stable on `gopdfsuit` and a synthetic corpus with no false-positive regression vs. baseline. |
| **Phase 2 (P2.5-B)** | BP-16..BP-25 (Testing) | 1 week | MVP ships to ≥3 external users without complaint. |
| **Phase 3 (P2.5-C)** | BP-26..BP-35 (API Design), BP-36..BP-45 (Code Org) | 2 weeks | After P2.1 taint ships — leverages the call graph for receiver-consistency heuristics. |
| **Phase 4 (P2.5-D)** | BP-46..BP-65 (Production Hardening + Dep Hygiene) | 2 weeks | Co-developed with the taint tracker. |
| **Reserve** | BP-12, BP-14 (goroutine leak detection) | — | Taint-driven; ship with P2.1 Phase 2. |

## 10. Implementation-Readiness Checklist

- [x] All 5 MVP sub-category scopes defined and reviewed.
- [x] Detection approach documented for each MVP rule.
- [x] Fact extraction needs enumerated (BP-1..BP-11, BP-13, BP-15 are all AST-only; no new fact extractor required).
- [x] Integration points identified (registry.toml, build.rs, lang detector mod.rs, reporter modules, CLI, config).
- [x] Rule ID scheme selected (`BP-N`).
- [x] Prioritized list ready (Section 3).
- [ ] Go/no-go decision: deferred to P2.5-A kickoff (no blockers identified).

## 11. Dependencies

- Existing detector architecture (`src/core/detector.rs`, `src/lang/go/detectors/cwe/mod.rs`, `src/lang/go/detectors/perf/mod.rs`).
- Existing fact extraction infrastructure (AST + tree-sitter queries already in place).
- `build.rs` code generation pipeline (extended to load `bad-practices.json`).
- `slopguard.toml` configuration structure (add `[bad_practices]` block).
- CLI argument definitions (add `--bp-only`, `--no-bp`).
- Reporter modules (add color band for `BP-` prefix, `category: bad_practice` JSON field, SARIF `security-severity: 5.0`).

## 12. Open Questions

1. **Severity for `BP-1` (discarded error):** Medium by default; some teams want Low (just a lint). Defaulting to Medium matches `staticcheck`'s `errcheck`, which is the de-facto standard for this check. If a user wants lower noise, `--no-bp` or per-rule `--skip BP-1` is one flag away.
2. **MVP scope size:** 13 real rules feels right. Cutting to 8 was tempting (drop `BP-9`, `BP-10`, `BP-13`) but those three have high user value. Keeping all 13.
3. **Naming:** `BadPractice` vs. `AntiPattern` vs. `CodeSmell` — "Bad Practice" is the term the parent plan used, and it's clear to non-experts. Keeping it.
