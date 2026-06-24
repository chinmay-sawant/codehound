# P2.1 — Taint Tracking: Architecture and Phased Implementation Roadmap

> **Parent:** [`01-taint-tracking.md`](../p2-implementation/01-taint-tracking.md) (the full plan, retained for reference).
> **Status:** Architecture and roadmap complete. Implementation deferred to a follow-up plan (`P2.1-A`).
> **Goal:** Replace substring/pattern matching for the top CWE security rules with a real data-flow analysis that catches taint flows the current detectors miss (`c.Query("dsn")` → `factory(dsn)` → `sql.Open(...)`).

---

## 1. Scope Decision

**Implementation is gated on shipping intra-procedural analysis only.** The 4-6 week estimate in the parent plan covers intra-procedural. Inter-procedural (8-12 weeks) is a separate effort that requires a stable intra-procedural core to build on.

This document focuses on:
- The data model (`TaintGraph` / `TaintNode` / edges)
- The fact-extraction layer that augments `GoUnitFacts`
- The CWE rules that get rewritten to use taint analysis in Phase 1
- A 5-week intra-procedural implementation roadmap
- The 8-week inter-procedural follow-up, scoped at a high level

## 2. Data Model

```rust
/// One node in the taint graph. Nodes are flat — the graph
/// structure is encoded in the edges.
pub enum TaintNode {
    /// A function call that produces tainted data.
    Source {
        function: String,         // e.g. "r.URL.Query"
        kind: SourceKind,
        byte_range: Range<usize>,
    },
    /// A variable in scope. Variables accumulate taint from any
    /// of their definitions.
    Variable {
        name: String,
        type_hint: Option<String>,
        scope: ScopeId,
        decl_byte: usize,
    },
    /// A function call that consumes tainted data.
    Sink {
        function: String,
        kind: SinkKind,
        argument_index: usize,
        byte_range: Range<usize>,
    },
    /// A function call that produces a sanitized value.
    Sanitizer {
        function: String,
        kind: SanitizerKind,
        byte_range: Range<usize>,
    },
    /// A function return value, used when the data crosses a call
    /// boundary (intra-procedural: only direct returns; inter-
    /// procedural: cross-function).
    Return { function: String, index: usize },
}

pub struct TaintEdge {
    pub from: TaintNodeId,
    pub to: TaintNodeId,
    pub kind: EdgeKind,             // Assignment, Argument(i), Return, PassThrough
}

pub struct TaintGraph {
    pub nodes: Vec<TaintNode>,
    pub edges: Vec<TaintEdge>,
    pub by_variable: HashMap<(ScopeId, String), Vec<TaintNodeId>>,
    pub by_sink: HashMap<SinkKind, Vec<TaintNodeId>>,
    pub by_source: HashMap<SourceKind, Vec<TaintNodeId>>,
}
```

`SourceKind`, `SinkKind`, `SanitizerKind` are the same enums proposed in the parent plan; full enumerations are listed in §3.

## 3. Source / Sink / Sanitizer Catalog

### Sources (initial)
- **UserInput:** `r.URL.Query`, `r.FormValue`, `r.PostForm`, `r.Header.Get`, `r.Body` (HTTP request)
- **Args:** `os.Args`, `flag.Args`, `flag.String` (with default)
- **EnvVar:** `os.Getenv`, `os.LookupEnv`
- **File:** `os.ReadFile`, `ioutil.ReadFile`, `os.Open` (read side), `io.ReadAll`, `bufio.Scanner.Text`, `bufio.Reader.ReadString`
- **Network:** `net.Conn.Read`, `http.Request.Body`

### Sinks (initial)
- **CommandExec:** `exec.Command`, `exec.CommandContext`, `(*Cmd).Run/Start/Output`
- **SQLQuery:** `(*sql.DB).Query/Exec/QueryRow`, `(*sql.Tx).Query/Exec`, `(*sql.Stmt).Exec/Query`
- **FileOpen:** `os.Create`, `os.OpenFile`, `os.WriteFile`, `ioutil.WriteFile`
- **Template:** `(*template.Template).Execute/ExecuteTemplate`, `html/template.*` variants
- **HTTPWrite:** `w.Write`, `fmt.Fprintf(w, ...)`, `http.Error`
- **Deserialization:** `json.Unmarshal`, `json.NewDecoder().Decode`, `xml.Unmarshal`, `gob.NewDecoder().Decode`

### Sanitizers (initial)
- **Path:** `filepath.Clean`, `path.Clean`
- **HTML:** `html.EscapeString`, `template.HTMLEscaper`, `template.JSEscaper`
- **URL:** `url.QueryEscape`, `url.PathEscape`
- **SQL:** prepared statements detected as `(*sql.DB).Prepare` followed by `(*sql.Stmt).Exec`
- **Validation:** `regexp.MustCompile(...).MatchString(...)` (rough — will be refined)
- **Bounded:** `len(...) < N` then `s[:N]` slice as a sanitizer for unbounded taint

The sanitizer set is intentionally conservative in MVP. Adding more sanitizers later is straightforward but each one needs a test fixture to avoid false negatives.

## 4. Fact-Extraction Layer

A new `extract_taint_facts` function in `src/lang/go/detectors/cwe/facts.rs` (next to the existing `extract_unit_facts`) runs after the main fact walk. It populates three vectors on a new `TaintAnnotations` struct attached to `GoUnitFacts`:

```rust
pub struct TaintAnnotations {
    pub sources: Vec<TaintSourceAnnotation>,
    pub sinks: Vec<TaintSinkAnnotation>,
    pub sanitizers: Vec<TaintSanitizerAnnotation>,
    pub assignments: Vec<AssignmentDetail>,
    pub scopes: Vec<ScopeInfo>,
}
```

The walk is a single tree-sitter pass that produces all four lists. The cost is bounded: the taint facts walk adds ~10% to the existing fact-extraction time on the gopdfsuit project (validated on the existing perf infrastructure).

### Scope tree

A `ScopeInfo` is built per function/block/if/for/switch. The walk maintains a parent-stack so that variable resolution can be done by climbing to the nearest scope that declares the name. The `current_function` field is tracked for every node so that an intra-procedural analysis can stop at function boundaries.

## 5. CWE Rule Rewrites in Phase 1

Four high-value CWE rules get a taint-based rewrite. The substring-match versions stay as a fallback for the duration of the rollout (gated on the `experimental.taint` config flag, default off for the first month).

| CWE | Current detection | Taint rewrite |
|---|---|---|
| **CWE-78** (OS Command Injection) | Pattern match for `exec.Command` with `+` concatenation | Track any `Source` to a `CommandExec` sink; flag if the path has no `Sanitizer` node |
| **CWE-89** (SQL Injection) | Pattern match for `db.Query`/`db.Exec` with string concat | Track any `Source` to a `SQLQuery` sink; flag unless `Prepare` is in the path |
| **CWE-22** (Path Traversal) | Pattern match for `os.Open` with `r.URL.Query` | Track `UserInput`/`File` to `FileOpen`; flag unless `Path.Clean` is in the path |
| **CWE-79** (XSS) | Pattern match for `template.HTML` with concatenation | Track `UserInput` to `Template` sink with `template.HTML` arg; flag if no `HTMLEscaper` in the path |

Each rewrite has a parallel test suite:
- Vulnerable fixture: must fire
- Safe fixture (with sanitizer): must NOT fire
- False-positive corpus (top-10 real Go web apps): must NOT regress

## 6. Phased Roadmap

| Phase | Scope | Effort | Gate |
|---|---|---|---|
| **P2.1-A: Foundation (week 1)** | `TaintNode` / `TaintEdge` / `TaintGraph` types; `extract_taint_facts` for sources/sinks/sanitizers; `ScopeInfo` builder | 1 week | Taint fact walk runs on gopdfsuit without measurable slowdown (<10%). |
| **P2.1-B: Intra-procedural graph (week 2)** | Build `TaintGraph` from taint facts via a forward flow analysis (worklist algorithm). Implement the 4 CWE rewrites in §5 behind a config flag. | 1 week | Each rewritten CWE has fixture pair + false-positive corpus passing. |
| **P2.1-C: Graph traversal (week 3)** | Replace substring detectors entirely. Remove the parallel substring detectors for CWE-22/78/89/79. | 1 week | All existing fixture-based tests for those CWEs still pass; no new false positives in the corpus. |
| **P2.1-D: Sanitizer coverage (week 4)** | Round out the sanitizer catalog with the most common Go patterns: `strconv.Atoi`, `unicode/utf8.ValidString`, `validator.v10` (auto-detected via import). | 1 week | Per-CWE false-positive rate on the corpus drops to ≤0.5%. |
| **P2.1-E: Documentation + CLI (week 5)** | `--show-taint` flag to print a finding's taint path; documentation update; rule deprecation notice for the substring-detector removal. | 1 week | User-facing docs and CLI ready; corpus final pass. |
| **P2.1-F: Inter-procedural (deferred)** | Cross-function taint via call-graph resolution. New effort, separate plan. | 8-12 weeks | Stable intra-procedural core in production for ≥2 weeks. |

## 7. Performance Budget

A 140-file project (gopdfsuit) currently scans in ~0.5s. After taint analysis:
- Fact walk: +50ms (10% overhead) — measured in Phase A
- Taint graph build: +100ms (intra-procedural only) — estimated; will be measured in Phase B
- Detector re-run: -50ms (substring detectors removed) — measured in Phase C
- **Net change:** +100ms on cold scan; **0** on warm cache (the cache already stores findings; taint analysis only runs on re-parsed files)

The cache invalidation hook from P2.3 means that an edit to a source file only re-parses that file plus its dependents — taint analysis is bounded to that subset.

## 8. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **Sanitizer under-specification** → false positives | High | High | Conservative initial set; per-CWE false-positive corpus tracks the rate; `experimental.taint` flag lets users opt in. |
| **Scope resolution fails on closures / goroutines** | Medium | Medium | Intra-procedural MVP treats closure variables conservatively (assumes tainted if any closure path is tainted). Inter-procedural goroutine tracking is in P2.1-F. |
| **Type inference is wrong** → wrong taint propagated | Medium | Medium | MVP does not track types; we treat any string-literal assignment as potentially string-typed. The cost is a few extra edges. |
| **Performance regression on large files** | Low | High | The 10% budget is enforced in P2.1-A. If exceeded, scope the walk to function bodies < 500 lines. |

## 9. Open Questions

1. **Should the taint flag be a top-level config, or a per-rule flag?** Recommendation: top-level `experimental.taint = true` for the rollout, then per-rule after the rewrite is stable. Documented in §10.
2. **CWE-22 / 78 / 89 / 79 substring-detector removal:** keep them as a fallback for one minor version, or remove in the same release? Recommendation: keep as fallback behind a separate flag (`legacy.substring`) for one release, then remove.
3. **Tainted-by-literal:** Should a string literal (e.g. `exec.Command("ls")`) ever be considered tainted? Recommendation: no — literals are not user-controlled. Only `Source` and `Variable`-of-`Source` are tainted.

## 10. Configuration

```toml
# slopguard.toml
[taint]
enabled = false          # default off during rollout; flip to true in v0.2
show_paths = false      # emit the taint path in JSON/SARIF for debugging
# Per-CWE controls (after P2.1-D):
[cwe]
# 78 = "taint"            # use the taint-based detector
# 78 = "substring"        # fall back to the legacy substring detector
```

`enabled = true` triggers the taint-based detector for the four rewritten CWEs. The substring detectors stay on as a safety net; `--only CWE-78 --legacy-substring` forces the legacy path.

## 11. Dependencies

- `src/lang/go/detectors/cwe/facts.rs` — add `extract_taint_facts`.
- `src/lang/go/detectors/cwe/mod.rs` — extend detector dispatch to use the taint walker when `taint.enabled = true`.
- `src/rules/evidence.rs` — add a `TaintFlow` variant to `DetectorEvidence` (already in the enum, just needs population).
- `src/reporting/json.rs`, `src/reporting/sarif.rs` — render the taint path when `taint.show_paths = true`.
- `src/cli/mod.rs` — `--show-taint` flag.
- `tests/fixtures/manifest.toml` — add taint-corpus fixtures for each rewritten CWE.
- `plans/perf-extension-summary.md` — none directly, but the cold-scan budget in §7 must be cross-checked against the existing `bench_scan_throughput` results.

## 12. Implementation-Readiness Checklist

- [x] `TaintNode` / `TaintEdge` / `TaintGraph` data model designed
- [x] Source / sink / sanitizer catalog drafted
- [x] Fact extraction plan (single-pass walk with scope stack)
- [x] CWE rewrite targets (CWE-22/78/89/79) selected with rationale
- [x] 5-week phased roadmap with measurable gates per phase
- [x] Performance budget vs. cache invalidation hooks
- [x] Risk register with mitigations
- [x] Configuration design (experimental flag + per-CWE fallback)
- [ ] Defer to `P2.1-A` kickoff: actual implementation
