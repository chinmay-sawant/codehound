# SlopGuard — Independent Architecture & Performance Review v2

> **Method:** Six independent subagent audits, each reading the full relevant
> source, verifying every claim against actual code at file:line level.
> Disagreements with REVIEW.md flagged and explained.

---

## Executive Summary

REVIEW.md is substantially correct — roughly 85% of its claims are accurate
or partially accurate. The architectural criticism (two parallel fact systems,
hardcoded sinks, O(DxN) dispatch, recursive tree walks) is all real. The
numerical imprecisions are minor (rule count 287->275, field count 17->18).

| Dimension | REVIEW.md Score | Our Assessment |
|-----------|:---:|---|
| Architecture | 6.5/10 | Agree. The trait design is good but the analysis layer has the problems REVIEW.md describes. |
| Performance | 5.5/10 | Agree. The micro-optimizations are real; the macro-architecture drags them down. |
| Overall | 6.0/10 | Agree. Solid v0.0.1 foundation; core engine needs refactor before scaling. |

---

## 1. Claims Verified — Full Audit Table

### Architecture and Design

| # | REVIEW.md Claim | Verdict |
|---|-----------------|---------|
| 1.1 | Two parallel fact systems, three tree walks per Go file | ACCURATE (4 walks) |
| 1.2 | No central sink or source registry | ACCURATE |
| 1.3 | part_N.rs split is bad (by file size) | ACCURATE |
| 1.4 | Monolithic detector files 15-19 KB | ACCURATE |
| 1.5 | Severity -> CVSS mapping is ad hoc | ACCURATE |
| 1.6 | CweRef catalog is 6 entries | ACCURATE |
| 1.7 | Severity enum missing Medium | ACCURATE |
| 1.8 | Finding is a fat struct with 17 fields | PARTIALLY ACCURATE (18 fields) |
| 1.9 | Cow in Finding::new adds no value | ACCURATE |
| 1.10 | init_subcommand template is a const string | ACCURATE |
| 1.11 | Detector trait metadata_for exists only to be overridden | ACCURATE |
| 1.12 | No CI-defined performance budget | ACCURATE |

### Performance

| # | REVIEW.md Claim | Verdict |
|---|-----------------|---------|
| 2.1 | O(DxN) detector dispatch, ~287 rules | PARTIALLY ACCURATE (275 rules) |
| 2.2 | Recursive tree walks will blow stack | ACCURATE |
| 2.3 | SourceIndex::has is O(N) per call | ACCURATE |
| 2.4 | Arc::from allocates String | ACCURATE |
| 2.5 | String::from_utf8 has no fast path | ACCURATE |
| 2.6 | format! in SARIF allocates per finding | ACCURATE |
| 2.7 | Export re-reads files from disk | ACCURATE |
| 2.8 | attach_function_context extra tree walk | ACCURATE |
| 2.9 | Vec<bool> wastes cache lines | PARTIALLY ACCURATE |
| 2.10 | colored is heavyweight | ACCURATE |

### Correctness and Bugs

| # | REVIEW.md Claim | Verdict |
|---|-----------------|---------|
| 3.1 | argument_uses_identifier is exact match -> false negatives | ACCURATE |
| 3.2 | FunctionSpan::enclosing_function max_by_key "unstable" | PARTIALLY ACCURATE |
| 3.3 | Function spans not validated for non-overlap | ACCURATE |
| 3.4 | ScratchContains race on first-call init | INACCURATE |
| 3.5 | walk_nodes with defer_statement in detect_perf_7 | PARTIALLY ACCURATE |
| 3.6 | iso8601_utc_now re-implements calendar math | ACCURATE |
| 3.7 | format_finding_block doesn't escape special chars | PARTIALLY ACCURATE |
| 3.8 | Per-file errors swallowed silently with --quiet | INACCURATE |

### Detectors and Rules

| # | REVIEW.md Claim | Verdict |
|---|-----------------|---------|
| 4.1 | Every detector is substring match — no taint tracking | ACCURATE |
| 4.2 | Hardcoded sinks duplicated across files | ACCURATE |
| 4.3 | No semantic understanding of Go types | ACCURATE |
| 4.4 | No fix-application | ACCURATE |
| 4.5 | No baseline/ignore-once mechanism | ACCURATE |
| 4.6 | argument_uses_identifier misses wrapped args | ACCURATE |
| 4.7 | detect_perf_2 does static += matching | ACCURATE |

### Engine and Core

| # | REVIEW.md Claim | Verdict |
|---|-----------------|---------|
| 5.1 | Per-thread ParsePool is the textbook move | ACCURATE |
| 5.2 | O(log N) line resolution | ACCURATE |
| 5.3 | Arc<str> source + interner | ACCURATE |
| 5.4 | Build-time codegen, no runtime JSON parsing | ACCURATE |
| 5.5 | catch_unwind per worker | ACCURATE |
| 5.6 | tracing over println! | ACCURATE |
| 5.7 | SCAN_CHUNK_SIZE = 1024 | ACCURATE |
| 5.8 | One binary, no default features | INACCURATE |
| 5.9 | Three report formats, NDJSON streaming | ACCURATE |
| 5.10 | Detector trait wider than needed | ACCURATE |
| 5.11 | No LSP, no daemon, no incremental | ACCURATE |
| 5.12 | walk_nodes recursive, TreeCursor available | ACCURATE |
| 5.13 | collect_function_spans records every function node | ACCURATE |

### Reporting, CLI and Export

| # | REVIEW.md Claim | Verdict |
|---|-----------------|---------|
| 6.1 | Severity -> CVSS ad hoc and lossy | ACCURATE |
| 6.2 | CweRef catalog: 6 entries | ACCURATE |
| 6.3 | Severity missing Medium | ACCURATE |
| 6.4 | format! per finding in SARIF | ACCURATE |
| 6.5 | iso8601_utc_now calendar math | ACCURATE |
| 6.6 | Export re-reads files | ACCURATE |
| 6.7 | format_finding_block no escaping | ACCURATE |
| 6.8 | init template is const string | ACCURATE |
| 6.9 | Errors silent with --quiet | INACCURATE |
| 6.10 | colored used for non-terminal formats | PARTIALLY ACCURATE |
| 6.11 | 17 fields, 7 Optional | PARTIALLY ACCURATE |
| 6.12 | Cow always into_owned | ACCURATE |
| 6.13 | with_fix is string, not AST rewrite | ACCURATE |
| 6.14 | No baseline/ignore-once | ACCURATE |
| 6.15 | SARIF correctness | PARTIALLY ACCURATE |
| 6.16 | NDJSON streaming | ACCURATE |

---

## 2. Where REVIEW.md Is Wrong

### 2.1 Section 4.4 — "ScratchContains race on first-call init" — INACCURATE

REVIEW.md labels this a "Critical bug." It is not. The code at engine/walk.rs:344:

```rust
thread_local! {
    static BUF: RefCell<String> = RefCell::new(String::with_capacity(128));
}
```

thread_local! provides per-thread storage with LocalKey. RefCell provides
runtime borrow checking within the same thread. There is no race condition
possible — the reviewer's own body text concedes: "This is fine — thread_local!
is a LocalKey, no race." The concern about rayon dropping TLS between jobs is
speculative. Not a bug.

### 2.2 Section 4.8 — "Per-file errors swallowed silently with --quiet" — INACCURATE

REVIEW.md claims: "If the user runs with --no-terminal --quiet, the errors
are completely silent." This is false. app.rs:71-76:

```rust
if !result.errors.is_empty() {
    eprintln!("{} file(s) could not be scanned:", result.errors.len());
    for err in &result.errors {
        eprintln!("  - [{:?}] {}", err.kind, err);
    }
}
```

This block executes unconditionally — it is NOT gated by --quiet or
--no-terminal. Scan errors are always printed to stderr.

### 2.3 Section 5.8 — "One binary, no default features" — INACCURATE

Cargo.toml:22-23 explicitly declares default = ["go", "python"]. The binary
ships with both languages by default.

### 2.4 Numerical Imprecisions

| What | REVIEW.md | Actual |
|------|-----------|--------|
| Rule function count | ~287 | 275 (175 CWE + 100 PERF) |
| Finding fields | 17 | 18 |
| Optional fields on Finding | 7 | 11 |
| SourceIndex needles (CWE) | 36 | 39 |
| Tree walks per Go file | 3 | 4 |
| Cache lines for Vec<bool> flags | "36 cache lines" | 1 cache line |

---

## 3. Where REVIEW.md Overstates Severity

### 3.1 Section 4.5 — "walk_nodes with defer_statement in detect_perf_7" labeled Critical

The code is correct. It's a performance observation about redundant tree
walking, not a correctness bug. REVIEW.md's own text says: "This is correct."

### 3.2 Section 4.1 — "max_by_key is unstable"

Rust's Iterator::max_by_key is NOT unstable — the documentation explicitly
states: "If several elements are equally maximum, the last element is
returned." The result is deterministic. The underlying concern about
overlapping spans on malformed trees is valid but the characterization is wrong.

### 3.3 Section 4.7 — "doesn't escape backslash or backtick in message"

These characters are inert in plain text files. A bad CWE name with a literal
newline would break the block format, but backslashes and backticks are harmless.

---

## 4. Where REVIEW.md Is Right

### 4.1 argument_uses_identifier (Section 4.3) — genuine false-negative

Affects 7 direct call sites + 2 inline instances across CWE-22, CWE-78,
CWE-89, CWE-90, CWE-79, CWE-15, CWE-214, CWE-215. Any argument that wraps the
variable (e.g., filepath.Join(base, path)) causes a miss.

### 4.2 O(DxN) dispatch (Section 2.1) — the real performance bottleneck

analyze_parsed_unit iterates 275 rule functions, each re-scanning facts.
For a 2,000-line Go file with ~1,500 facts, this is ~412,500 inner iterations.
A sink-name dispatch would drop this to O(F x relevant_detectors).

### 4.3 Four tree walks per Go file (Section 3.1) — straightforward unification

CWE facts + PERF facts + PERF var_spec + function spans all walk the same tree.
A single unified walk would cut wall-clock time by ~3x on the fact-extraction phase.

---

## 5. Revised Priority Matrix

### P0 — correctness (must fix)

1. Fix argument_uses_identifier — false-negatives in 7+2 detectors
2. Decide Severity semantics — pick 4 or 5 levels, document SARIF mapping
3. Validate FunctionSpan non-overlap in debug builds

### P1 — performance (measurable win)

4. Sink registry — phf::Set single source of truth
5. Detector dispatch by callee/RHS name — 5-10x on large files
6. Replace recursive tree walks with TreeCursor — also fixes stack overflow
7. phf::Map for SourceIndex::has — O(1) lookup
8. Bitmask source index — u64 instead of Vec<bool>
9. Stop re-reading files in export path — pass Arc<str> through
10. Combine function-span walk with fact walk — single traversal

### P2 — architecture

11. Unify CWE + PERF fact systems into single tree walk
12. Refactor part_N.rs by CWE cluster, not byte count
13. Split monolithic detector files into subdirectories
14. Fill CWE catalog (auto-generate from golang.json)
15. Move init template to templates/ with include_str!
16. Drop dead Cow in Finding::new
17. Replace iso8601_utc_now with jiff
18. Add Criterion perf budget with CI gate

### P3 — nice to have

19. LSP / daemon mode for incremental analysis
20. Streaming SARIF writer to avoid per-finding allocations
21. Feature-gate colored or switch to owo-colors
22. SIMD-validated UTF-8 via simdutf8
23. Real taint tracking — currently all substring matching

---

## 6. Verdict

REVIEW.md is an honest and mostly accurate critique of a v0.0.1 codebase.
Its two factual errors (Section 4.4, Section 4.8) are not "critical bugs" and should be
downgraded. Its numerical imprecisions are cosmetic. Its core architectural
criticism — duplicate tree walks, O(DxN) dispatch, hardcoded sinks, no taint
tracking — is substantiated by code-level evidence.

The binary infrastructure (parse pool, line resolution, codegen, catch_unwind,
chunked parallelism) is genuinely well-engineered. The analysis layer needs the
refactor described in Section 5 before scaling to production use.

---

Independent review by 6 subagent audits, June 2026
