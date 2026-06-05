# Additional Findings — Hardening the Existing Architecture & Performance Review

**Date:** 2026-06-05
**Method:** Forensic static read of every file in `src/`, exhaustive `rg` searches, verification of every claim in `ARCHITECTURE_AND_PERFORMANCE_REVIEW.md` against the live source. All counts verified.
**Companion to:** `ARCHITECTURE_AND_PERFORMANCE_REVIEW.md` (the original review)
**Status:** Completed (research-only, no code changes)

---

## 1. Score corrections to the existing review

| Dimension | Existing | Corrected | Why |
|---|---|---|---|
| Performance — Go CWE detectors | **4.0** | **3.0** | The review under-counts actual cost. Verified: **632** `source.contains(...)` calls per file (mean 3.6/detector, not "1× per rule"). `unit.path.display().to_string()` is called **175× per file** producing 175 identical `String` allocations of the same path. `meta.cwe.to_vec()` is **always** called on `&[]` — a pure waste. `format!` is on the hot path at **12 sites**. |
| Test strategy | **7.0** | **4.0** | `.github/workflows/` is **empty** — no CI of any kind. `insta` is a **dead dev-dep** (0 snapshots, 0 calls). Only **4 `#[test]` over 55 files** in `src/`. Real race condition on `target/slopguard-fixtures/` because all test binaries share the same path. Hard-coded `SCAN_PATH` in `makefile`. |
| Architecture — Module boundaries | **7.5** | **6.5** | Public surface leaks Go-detector internals (`GoUnitFacts`, `InputBinding`, `CallFact`, `AssignmentFact`, `GoCweScan` all `pub`). 175 `META_CWE_*` constants duplicate the curated `cwe::catalog` but link to **zero** of its entries — the catalog is dead weight in the Go path. |
| Architecture — Domain coherence | **5.0** | **4.0** | `ruleset/golang/golang.json` (168 KB, 191 entries) is **never loaded** by the binary — `rg "ruleset\|golang.json"` over `src/` returns 0 matches. The 16 `PERF-001..016` records exist only in planning PRs. |
| Architecture — Test strategy | **7.0** | (already corrected) | |
| **Net** | **5.5 / 6.0** | **4.5 / 5.5** | The skeleton is good; the inner content has more dead/wrong code than the review credits. |

---

## 2. Verified counts that anchor the cost analysis

These are not estimates. They were counted by `rg`:

| Quantity | Count | File |
|---|---|---|
| `detect_cwe_*` functions | **175** (48 + 63 + 64) | `detector_group_{a,b,c}.rs` |
| `META_CWE_*` constants with non-empty `cwe` slice | **0 / 175** | all use `&[]` — `metadata.rs` |
| `unit.path.display().to_string()` per file | **175** (one per detector) | all 3 group files |
| `let source = unit.source.as_ref()` per file | **164** | 11 detectors don't read `source` |
| `source.contains(...)` calls per file (sum across detectors) | **632** | 93 + 235 + 304 |
| `source.find(...)` calls per file | **156** | 10 + 77 + 69 |
| `format!` on CWE hot path | **12** | `detector_group_a.rs:94, 429, 433, 490, 589, 590, 619, 622, 674` + `common.rs:30, 37, 42` |
| `unit.line_col` calls per file (when findings emit) | **175** (one per detector) | — |
| AST walks per file (CWE path) | **2** (full tree, separate) | `facts.rs:44, 80` |
| `kinds.contains(...)` slice length in `walk_nodes` | **2** (always) | `walk.rs:18, 23` |
| `#[test]` annotations in `src/` | **4** | `format.rs:105`, `language_filter.rs:77`, `export/mod.rs:221` |
| `#[test]` annotations in `tests/` | **360** | — |
| `*.snap` files in repo | **0** | dead `insta` dev-dep |
| `unsafe` blocks in `src/` | **0** | — |
| `unwrap()` in `src/engine/` or `src/lang/` hot path | **0** | — |

---

## 3. Findings the review missed (organized by P-number)

### P8. **The 175 Go `META_CWE_*` constants all pass `&[]` for `cwe`** — making `meta.cwe.to_vec()` in `src/rules/emit.rs:21` a guaranteed-empty allocation
Every one of the 175 rules has `cwe: &[]` in its metadata (`rg "&\\[\\]" src/lang/go/detectors/cwe/metadata.rs | wc -l → 175`). `Finding::new(..., meta.cwe.to_vec())` (`src/rules/emit.rs:14-22`) **always** clones an empty slice, so the 24-byte `Vec` header is allocated per finding for content that is provably empty. Changing `Finding.cwe` to `Option<Box<[CweRef]>>` (or `Cow<'static, [CweRef]>`) eliminates the alloc entirely. The curated `src/cwe/catalog.rs` (6 `CweRef` constants, 4 precomposed slices) is used by **only one** detector (`src/lang/python/detectors/re_compile_in_loop.rs:5`) — none of the 175 Go rules reference it. The catalog is **dead infrastructure in the Go path**.

### P9. **`InputKind::TrustedConfig` is dead code in the IR**
`src/lang/go/detectors/cwe/facts.rs:55-58` constructs `InputKind::TrustedConfig` via `is_trusted_config_expr` (which does 2 `String.contains` per assignment), but `rg "TrustedConfig"` over `src/` shows **zero matches** outside the definition site. Pure dead code that costs 2 contains per assignment per file.

### P10. **`walk_assignments` + `walk_calls` = the full AST is walked twice per file**
The review called out `walk_nodes` cost in isolation (P4) but missed that `src/lang/go/detectors/cwe/facts.rs:44, 80` runs **two** full-tree walks per file. A single visitor (matching on `node.kind()` for both `assignment_statement`/`short_var_declaration` and `call_expression`/`call`) would halve tree-sitter node visits.

### P11. **`unit.path.display().to_string()` is called 175× per file, all producing the SAME `String`**
Every detector starts with `let file = unit.path.display().to_string();` (verified at `detector_group_a.rs:8, 37, 80, 129, ...` and the other two group files). For one file, that's 175 identical `String` allocations of the same path. Pre-compute once in `analyze_parsed_unit` (`src/engine/walk.rs:91-105`) and pass `&str` into detectors. This is the single highest-frequency wasted alloc in the codebase.

### P12. **`unit.line_col` is O(tree depth) per finding, called 175× per file**
`src/ast/location.rs:6-12`: `tree.root_node().descendant_for_byte_range(...)` is **O(depth)** in the AST. Called once per detector that emits a finding. A precomputed `Vec<(usize, (usize, usize))>` built once after the walk and binary-searched would be O(log N) per finding.

### P13. **`node.utf8_text(src)` at `facts.rs:45` materializes the entire assignment text** including LHS, `=`, RHS, semicolon. Could use `child_by_field_name("left"|"right")` + `utf8_text_immediate` (the immediate form skips nested nodes).

### P14. **Double-walk of same needle on the same file**
- CWE-256 (`detector_group_b.rs:1066`) searches for `"Password: c.PostForm("password")"` **2×** in the same detector body.
- CWE-408 (`detector_group_b.rs:1133, 1136, 1144`) searches for the same SQL fragment **3×**.
- CWE-93 (`detector_group_a.rs:441, 451`) calls `call_facts.iter().any(...)` then `call_facts.iter().find(...)` on the same predicate — 2× walk of `call_facts` per binding.

### P15. **`format!` on the hot path at 12 sites**, each producing a fresh `String` whose only purpose is to feed `source.contains`. A static prefix + `&binding.name` could be searched directly with multi-pattern matching, or a `write!` into a thread-local `SmallString` could be reused.

### P16. **Tree-sitter cursor iteration allocates a `Vec<Node>` per parent**
`src/ast/walk.rs:11` `node.children(&mut cursor)` returns `Vec<Node>`. The fast tree-sitter 0.25 idiom is `cursor.goto_first_child()` + `cursor.goto_next_sibling()` + `cursor.node()`, which is allocation-free. (Also: `walk_nodes` is **unbounded recursion** — a 5,000-deep expression chain blows the default 8 MiB stack. No iterative variant exists.)

---

## 4. **Correctness bugs the review missed**

### B1. Operator-precedence bug in `detect_cwe_270` (`detector_group_a.rs:1345-1347`)
```rust
let restores_context = source.contains("defer c.Set(\"effective_user\", original)")
    || source.contains("defer func()")
        && source.contains("context.WithValue(r.Context(), effectiveUserKey, original)");
```
`&&` binds tighter than `||`, so this parses as `A || (B && C)`, not `(A || B) && C` as the indentation implies. The `defer func()` branch is silently guarded by a third condition that was likely meant to be part of the same `defer` clause.

### B2. Same precedence bug in `detect_cwe_841` (`detector_group_c.rs:968-970`)
```rust
if source.contains("MFAPassed") && source.contains("if !acct.MFAPassed")
    || source.contains("if !accountMFAPassed[email]")
```
Same pattern; same latent false-positive.

### B3. Silent fallback to `(line=1, col=0)` when a search string is missing
`detector_group_b.rs:246`: `let start_byte = source.find("password").unwrap_or(0);` — `.unwrap_or(0)` is safe (no panic) but produces findings at `line=1, column=0` when the string is missing, with no test covering that branch. A developer removing `password` from a fixture would not see a regression in the integration tests (which only assert *presence* of a rule ID, not location).

These bugs make the existing review's A6 ("codegen from a single rules spec") recommendation even stronger.

---

## 5. **Concurrency / panic / unsafe audit (clean overall, 3 real risks)**

The codebase is **notably well-engineered** in this dimension:

- 0 `unsafe` in `src/`, 0 `unwrap`/`expect` in the hot path (2 `expect` in pool init only).
- Tree-sitter 0.25's `unsafe impl Send for Parser/Tree` is the only inherited `unsafe`, and the code uses only the safe surface.
- Output is fully deterministic — `sort_by` is stable on `(file, line, column)`.
- `ScanContext` is genuinely immutable, no locks.

**Real risks:**

### C1. **No partial-failure recovery** — one bad file kills the whole scan
`src/engine/walk.rs:115-121` does `par_iter().map_init(...).collect::<Result<Vec<_>>>()`. Rayon's `FromParallelIterator<Result>` discards all `Ok` items on the first `Err` and stores only the first error. Combined with the `for chunk in entries.chunks(SCAN_CHUNK_SIZE)` loop in `src/engine/analyzer.rs:68-70` using `?`, **a single unreadable / non-UTF-8 file aborts the entire scan and discards all findings from later chunks**. For repos with a few bad files (mixed encodings, broken symlinks) this is the most user-visible failure mode.

### C2. **Worker panic bypasses the error path**
A tree-sitter bug or OOM inside `parser.parse()` would unwind out of `par_iter` and exit with code **101** (default panic), bypassing `eprintln!("error: …")` at `src/main.rs:21`. Exit-code unification requires either a `catch_unwind(AssertUnwindSafe(...))` wrapper or a custom panic hook.

### C3. **`tracing` is initialized but has no producers**
`tracing_subscriber::fmt()...init()` is called in `main.rs:27-35`, but `rg 'tracing::'` over `src/` returns **zero hits**. `RUST_LOG=debug` does nothing in production. The subscriber is dead infrastructure pending real instrumentation. This contradicts the "Observability: 5.0" line in the existing review (it should be 3.0).

---

## 6. **Test strategy — the existing 7/10 is over-credited by 2-3 points**

Verified by `rg` and `find`:

| Missing surface | Evidence |
|---|---|
| **No CI** at all | `.github/workflows/` is empty. `make lint` is never invoked. No clippy, no fmt-check, no miri, no cargo-audit, no coverage. |
| **`insta` is a dead dev-dep** | 0 `*.snap` files, 0 `insta::*` calls, 0 `assert_snapshot!`. The review scorecard mentions "insta" as if it provides snapshot coverage — **it does not**. |
| **No unit tests for the hot path** | The 4 `#[test]` in `src/` are 1 in `fixture/format.rs`, 2 in `engine/language_filter.rs`, 1 in `export/mod.rs`. **Zero** unit tests for `src/ast/walk.rs`, `src/engine/walk.rs`, `src/engine/parse_pool.rs`, `src/rules/emit.rs`, `src/rules/finding.rs`, `src/lang/go/detectors/cwe/facts.rs` — exactly the files the review itself flagged as performance bottlenecks. |
| **No fuzzing** | 0 `proptest`, 0 `arbitrary`, 0 `cargo-fuzz`, 0 `fuzz/` dir. Tree-sitter is a C library; a panic in the parser crashes the whole scan. |
| **No baseline for the bench** | `cargo bench -- --save-baseline` is never invoked. `benches/baseline.txt` does not exist. No scaling test (1k/10k/100k files, 1 MB files). |
| **Parallel-test race on `target/slopguard-fixtures/`** | `src/fixture/materialize.rs:13` is shared across all test binaries. `fs::write` is not atomic across processes. Two test binaries writing to the same path simultaneously can produce a half-written file that the analyzer reads, parses, and silently produces 0 findings for. |
| **Orphan fixture not caught** | `tests/fixtures/rust/sample.txt` exists on disk but is **absent from `tests/fixtures/manifest.toml`**. The "every fixture is registered" invariant is enforced one direction only (manifest→file, not file→manifest). |
| **Dead test code** | `tests/fixture_manifest_integration.rs:65` ends with `let _ = Analyzer::builder().build();` — a no-op that does not test anything. |
| **"Mixed" test isn't mixed** | `tests/mixed_integration.rs:8` passes empty `go_rules` and only `python_rules = ["SLOP101"]`. There is no test that asserts a mixed-repo scan produces both Go and Python findings. |
| **No Python negative test** | `tests/python_integration.rs` has a single positive case for `SLOP101`. No `assert!(!ids.contains("SLOP101"))` case for a function that does NOT compile a regex. |
| **Hard-coded local path in `makefile:2`** | `SCAN_PATH ?= /home/chinmay/ChinmayPersonalProjects/gopdfsuit` is the maintainer's local path. `make run` is broken for any other contributor. The Windows/WSL fallback at `makefile:5-9` references an undefined `WSL_REPO_ROOT` and is **broken**. |
| **90 KB hand-written `go_cwe_detector_integration.rs`** | 350 `#[test] fn cwe_NNN_framework_fixture_pair()` functions instead of a `static CASES: &[…]` with a `for` loop. Renaming a fixture requires updating 350 lines. |
| **`all-langs = ["go", "python"]` is a literal duplicate of `default`** | `Cargo.toml:21, 27`. Dead feature flag. |
| **`#[allow(dead_code)]` on `tests/helpers/mod.rs:4`** | Unused helper code accumulates silently because no clippy in CI. |

**Net: drop Test strategy from 7.0 to 4.0; add a "No CI" callout in the executive summary.**

---

## 7. **Public API / CLI / config / DX — 50+ findings the review under-covers**

### 7.1 Public surface leaks Go-detector internals
`src/lang/go/detectors/cwe/facts.rs:7, 13, 19, 26, 33, 39`, `src/lang/go/detectors/cwe/mod.rs:3, 20`, `src/lang/go/detectors/mod.rs:3`, `src/lang/go/mod.rs:3, 13`, `src/lang/python/mod.rs:15`, `src/lang/python/detectors/re_compile_in_loop.rs:10` all `pub`. `GoUnitFacts`, `InputBinding`, `CallFact`, `AssignmentFact`, `build_go_unit_facts`, `GoCweScan`, `GoPlugin`, `PythonPlugin`, `ReCompileInLoop` are all part of the stable surface by accident. The whole `pub mod lang` re-exports modules that are **feature-gated** (`#[cfg(feature = "go")]`) — a `--no-default-features --features python` build doesn't have `slopguard::lang::go` at all, but this isn't documented. Add a `slopguard::prelude` and gate properly with `pub(crate)` for detector internals.

### 7.2 Config validation gaps
- `#[serde(deny_unknown_fields)]` is **not** set on `SlopguardConfig` (`src/engine/config.rs:11-15, 17-27`) — typos like `fali_on` or `language` (pluralization) are **silently ignored**.
- No JSON schema. No `slopguard.schema.json`. No `schemars` dependency.
- **No `--config <path>` flag**, no `SLOPGUARD_*` env-var overrides, no upward config walk, no `.slopguardignore`.
- **Precedence bug for `fail_on`** in `config.rs:40-52`: config **wins** over CLI severity flags, which is inverted from how `only`/`skip` work. The README/slopguard.toml comment is wrong on this.

### 7.3 CLI ergonomics
- `--help` has **no `after_help` examples**.
- No subcommands, no `--list-rules`, no `slopguard explain CWE-22`, no `--quiet`/`--verbose`, no `--init`.
- **No stdin reading** — `rg 'io::stdin' src/` → 0 hits.
- **Exit codes are 3-valued** (0/1/2); no distinction between config error and engine internal error. The review's A8 (`anyhow` → `thiserror`) is needed to enable this.
- **Stale README**: `README.md:17` says "SARIF — planned", but `src/reporting/sarif.rs` is implemented and reachable via `--format sarif`.
- **No man page, no shell completion, no Brew/scoop/binstall instructions.** `clap_mangen` and `clap_complete` are not dependencies.

### 7.4 SARIF quality (the review's only reporter line is "minimal")
`src/reporting/sarif.rs` is 135 lines and missing key fields:
- `runs[].tool.driver.informationUri`, `version`, `semanticVersion` — `informationUri` is `Cargo.toml:8`-derivable.
- `runs[].results[].ruleIndex` — pointing each result at its index in the rules array.
- `runs[].results[].locations[].physicalLocation.region.endLine`/`endColumn`/`byteOffset`/`byteLength` — currently only start is emitted; consumers like GitHub Code Scanning need the full range to highlight properly.
- `runs[].results[].properties.tags = ["security", "cwe-89", …]` and `properties.security-severity` — required for Code Scanning integration.
- `runs[].results[].partialFingerprints` — required for stable issue tracking across runs.
- `runs[].invocations[]` — executable path, start time, working directory, exit code.
- `runs[].originalUriBaseIds` — for relative-path handling.
- `rules[]` is in encounter order, not sorted alphabetically.

### 7.5 Text reporter quality
- The severity column is **not color-distinguished** — all 4 levels look like plain lowercase words. A standard convention is `red().bold()` for `high`/`critical`, `yellow()` for `warning`, `cyan()` for `info`.
- CWE list is not sorted before joining → non-deterministic within a finding.
- `fix:` line is **dead in production** — `rg with_fix` over `src/` shows only test code. The line is always printed as `fix: ` with empty content.
- No per-severity or per-rule summary (e.g. "N high, M warning, K info; top rules: CWE-89 ×42, …").

### 7.6 JSON reporter
NDJSON only (`serde_json::to_writer` at `src/reporting/json.rs:13`) — no envelope, no `byteOffset`/`endLine`/`endColumn`/`byteLength`, no `fingerprint`, no `run_id`. `CweRef.id` is numeric, not the `CWE-N` string consumers expect.

### 7.7 `ruleset/golang/golang.json` (168 KB) is never loaded
`rg "ruleset\|golang.json" src/` → **0 matches**. The 191-entry JSON (175 CWE + 16 `PERF-001..016`) is the natural source of truth for `--list-rules` and `slopguard explain` but the binary's `metadata.rs` hand-writes the metadata in Rust constants. Either wire the JSON in via `include_str!` + `serde_json::from_str` and codegen `metadata.rs` from it via `build.rs`, or **delete it as a stale artifact**. The 16 `PERF-001..016` are referenced **only** in `plans/PR/pr-refactor-go-cwe-and-add-perf-plan.md` and `plans/v0.0.1/go/perf-heuristics-and-sarif.md` — no path from spec to code exists.

### 7.8 `plans/` is largely stale
- `plans/p1.md`, `p2.md`, `p3.md` are placeholder scaffolds with all checkboxes unchecked. `README.md:29-34` says "p1: Implemented" but `p1.md` doesn't reflect that.
- `plans/PR/pr-*.md` are merged-PR descriptions, not plans.
- `plans/v0.0.1/go/PR/` is empty.
- No `plans/INDEX.md`.

### 7.9 Docs gaps
Only two files in `docs/`: `adding-a-language.md` (43 lines) and `architecture-performance.md` (44 lines). Missing: `configuration.md`, `output-formats.md`, `rules-catalog.md`, `perf-tuning.md`, `contributing.md`, `security.md`, `architecture.md`, `internals/facts.md`, `internals/registry.md`. No `examples/` directory. No `CHANGELOG.md`. `src/lib.rs:1` is a one-line crate doc with no usage example. No `#![warn(missing_docs)]`.

---

## 8. Concrete rewrites of the existing review's critical findings

| Existing finding | Sharper version |
|---|---|
| **P2 (per-finding allocations)** | Add: `unit.path.display().to_string()` is 175×/file (not "per finding"), all producing identical `String`s. `meta.cwe.to_vec()` is **always** an empty `Vec` allocation. `Finding.message` is **always** a `&'static str` literal but is `into()`-ed to `String` per finding. `Finding.cwe` should be `Option<Box<[CweRef]>>` to compile `&[]` to `None`. |
| **P4 (`walk_nodes` linear `kinds.contains`)** | Add: `kinds` slice is **always length 2** — a 2-arm `match` on `node.kind()` is the right tool (not phf). The real win is the callee-symbol space where 28 sites do `callee == "literal"` on heap-allocated `String`s. |
| **P5 (coarse early-exit)** | Add: verified — `mod.rs:217-228`. The `if !DETECTORS.iter().any(...)` early-return at line 218 only fires when **zero** rules are allowed. As soon as one rule is allowed, full facts are built. |
| **A2 (single Detector for ~175 rules)** | Add: verified `Registry::metadata()` on `GoCweScan` returns only `META_CWE_15`. `META_CWE_*.cwe` is `&[]` for all 175 rules — the curated `cwe::catalog` (6 constants, 4 precomposed slices) is wired to **zero** Go detectors; only the Python `SLOP101` uses it. |
| **A6 (metadata duplication)** | Add: 175 lines of `&[]` in `metadata.rs` is provable-typo bait (any future CWE rule that forgets the link will be silently unwired). Codegen from a single YAML/JSON spec also fixes the CWE-270/CWE-841 precedence bugs (§4 B1, B2). |
| **A8 (error type strategy)** | Add: any `Err` from one worker kills the whole scan via rayon's `FromParallelIterator<Result>` (`rayon-core/result.rs:93-131`). A `thiserror` enum at the engine boundary enables partial-failure recovery and distinct exit codes (config=2, internal=3). |
| **(NEW) P7b: Parallelism stops at file boundary** | Add: tree-sitter 0.25's `unsafe impl Send for Parser/Tree` is what makes rayon-parallel parsing sound — older versions of tree-sitter didn't have this. Pinning `tree-sitter = "0.25"` in `Cargo.toml:42` is a **deliberate correctness choice**, not just a freshness decision. |
| **(NEW) Test strategy 7.0 → 4.0** | Add: no CI, `insta` is a dead dev-dep, 0 unit tests for hot-path files, real race on `target/slopguard-fixtures/`, hard-coded `SCAN_PATH` in `makefile`, "mixed" test isn't mixed, 90 KB hand-written `go_cwe_detector_integration.rs` should be a `for` loop. |
| **(NEW) A9: Public API leaks detector internals** | `GoUnitFacts`/`InputBinding`/`CallFact`/`AssignmentFact`/`GoCweScan`/`GoPlugin`/`PythonPlugin`/`ReCompileInLoop` are all `pub` but should be `pub(crate)`. Whole `lang::*` is `pub` but feature-gated — surface changes per build profile. |
| **(NEW) A10: `ruleset/golang/golang.json` is dead weight** | 168 KB / 191 entries / 0 references in `src/`. The 16 `PERF-001..016` records have no path to code. |
| **(NEW) A11: `plans/` is stale** | `p1/p2/p3.md` are unchecked placeholders that contradict `README.md`. `plans/PR/pr-*.md` are merged-PR records. `plans/v0.0.1/go/PR/` is empty. |
| **(NEW) A12: SARIF is shipped but under-fields** | `informationUri`, `version`, `ruleIndex`, `region.endLine/endColumn/byteOffset/byteLength`, `properties.tags`, `properties.security-severity`, `partialFingerprints`, `invocations[]`, `originalUriBaseIds` are all missing. |

---

## 9. Things the existing review got right (verified)

- **Engine design** is genuinely good — `parse_pool` per worker, `SCAN_CHUNK_SIZE` chunking, language-indexed registry, `ParsedUnit` lifetime. ✓
- **Facts extraction is the right idea** — one AST walk, then rules. The implementation is just allocation-heavy. ✓
- **Build & regression hygiene** — release profile, criterion bench, fixture materialization. ✓ (modulo the gaps in §6).
- **"~175 rules" count** — verified exactly. ✓
- **"`unit.source.contains(...)` per rule"** — the framing was correct, but the count is **632/file**, not "per rule × 1". Sharpen. ✓

---

## 10. Top-5 highest-leverage concrete fixes (re-ranked)

1. **Split `GoCweScan` into generated per-rule detectors** sharing `Arc<GoUnitFacts>` (existing P1, sharpened). Restores registry semantics, enables per-rule `--only` short-circuits, eliminates the 175×-per-file `unit.path.display().to_string()`.
2. **Intern callee + binding-name as `SymbolId` (u16)** via a `phf::Map` built once at startup. Eliminates ~28 string compares per detector per file and ~100 String allocs per file. Highest absolute win.
3. **Change `Finding.cwe` to `Option<Box<[CweRef]>>` and `Finding.message` to `Cow<'static, str>`**. Both are provably alloc-free for current Go detectors (all `cwe: &[]`, all `message: &'static str`).
4. **Wire `ruleset/golang/golang.json` into the build** via `include_str!` + codegen of `metadata.rs` from it. Kills the metadata-typo risk, fixes the `&[]` drift, makes `--list-rules` and `slopguard explain` real, fixes the B1/B2 precedence bugs by giving rules a structured spec.
5. **Add a real CI workflow** (`.github/workflows/ci.yml`): `cargo test` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo fmt --check` + `cargo test --no-default-features --features go` + a Linux/macOS matrix. Single biggest score-lift available; takes ~30 lines of YAML.

---

*Generated from forensic static read of all 55 files in `src/`, all 7 files in `tests/`, `benches/`, `docs/`, `plans/`, `ruleset/`, `scripts/`, `makefile`, and `Cargo.toml`, with `rg` exhaustively verifying every claim in the existing review.*
