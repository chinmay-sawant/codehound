## Review Summary — CWE Detectors

**Verdict:** REQUEST CHANGES

**Overview:** The taint-tracking subsystem (extract → graph → rules) is a well-structured MVP that introduces intra-procedural taint analysis for Go CWE detectors. Architecture is clean, tests pass, and the gated migration pattern (legacy detectors fall through when taint is disabled) is sensible. However, there are correctness bugs in result variable resolution for chained calls and a dead-code source classification that never fires.

### Critical Issues

- **`src/lang/go/detectors/cwe/taint/graph_query/query.rs:63` — Path state cloned on every BFS expansion, O(n²) memory per path.** Each BFS loop clones the entire `path: Vec<TaintNodeId>` when pushing to the queue (`let mut next_path = path.clone(); next_path.push(next)`). For deep taint chains (20+ hops), this amplifies memory and time quadratically. **Fix:** Store parent pointers in a `HashMap<TaintNodeId, (TaintNodeId, bool)>` and reconstruct the path only when found, eliminating per-node cloning.

- **`src/lang/go/detectors/cwe/taint/extract/walker_records.rs:72-86` — `result_variable_of_call` resolves to the wrong variable for chained calls.** For `name := r.URL.Query().Get("x")`, the inner call `r.URL.Query()` is recorded as a Source with `result_variable = "name"` (climbs all the way up to the outer assignment). But `name` holds the result of the entire chain, not `url.Values`. This creates an edge `Source(r.URL.Query()) → Variable(name)` that conflates the intermediate object with the final string. **Fix:** Return `None` when the call's parent chain passes through another `call_expression` before reaching an assignment, or add a `ponytail:` comment acknowledging the known limitation for chained calls and deferring proper chain resolution.

### Important Issues

- **`src/lang/go/detectors/cwe/taint/extract/classify.rs:11` — Dead source classification.** `call == "io.ReadAll(r.Body)"` never matches because tree-sitter extracts the function name as `io.ReadAll` without arguments. This line is dead code (doesn't cause false negatives since `io.ReadAll` is caught on line 25, but misleading). **Fix:** Remove the dead branch.

- **`src/lang/go/detectors/cwe/taint/extract/classify.rs:48-53` — Overbroad SQL sink suffix matching.** `.Query`, `.Exec`, `.QueryRow` suffix matching catches `db.Query` but also any custom type's `.Query()` method. In large codebases this will produce false positives for structs that happen to have methods ending in `Query`. **Fix:** Add a package-qualified check (`sql.DB.` or `sql.Tx.`) or gate with a `ponytail:` comment noting the overapproximation. Currently no `ponytail:` comment exists.

- **`src/lang/go/detectors/cwe/taint/extract/classify.rs:68` — Overbroad `.Write` sink.** `call_name.ends_with(".Write")` matches `w.Write`, `f.Write`, `buf.Write`, and any other `.Write` method, flooding the graph with non-security-relevant sinks. **Fix:** Restrict to known security-relevant writers (`http.ResponseWriter.Write`, `w.Write` only when `w` is typed) or gate with a `ponytail:` efficiency note.

- **`src/lang/go/detectors/cwe/taint/extract/classify.rs:8-9` — `call.contains(".Header.Get")` and `call.contains(".GetHeader")` are too broad.** These match any method whose qualified name contains `.Header.Get` (e.g. `myCustom.Header.Getter`), and `.GetHeader` matches arbitrarily. The contains-based pattern for method names on different receivers is fragile. **Fix:** Use exact suffix matching (`ends_with(".Header.Get")`) instead of `contains`, or use tree-sitter's receiver information.

- **`src/lang/go/detectors/cwe/taint/graph_query/build.rs:194-209` — `is_go_keyword` is incomplete.** Missing `error` (predeclared interface type) and `any` (Go 1.18+ predeclared type). These won't cause incorrect edges in practice (they aren't typical variable names), but completeness improves robustness. **Fix:** Add `"error"` and `"any"`.

### Suggestions

- **`src/lang/go/detectors/cwe/taint/extract/walker_core.rs:46-51` — `entered_scope` uses a bare tuple `(ScopeKind, Range<usize>, Option<SharedText>)`.** A small struct or named field destructuring would improve readability. Minor.

- **`src/lang/go/detectors/cwe/taint/extract/classify.rs:4-35` — Source classification doesn't cover `os.Stdin` or `bufio.Scanner` from stdin.** These are common Go taint sources. Not required for MVP but worth noting for the gap list.

- **`src/lang/go/detectors/cwe/taint/rules/evidence.rs:23` — Hardcoded `"UserInput"` string in `source_info`.** All four CWE detectors currently only scan for `SourceKind::UserInput`. The `source_info` helper hardcodes the kind string. If a future rule adds `Args` or `EnvVar` sources, this helper won't reflect the real kind. Consider taking `source_kind` as a parameter or mapping from the enum.

- **`src/lang/go/detectors/cwe/taint/extract/walker_records.rs:84-90` — `result_variable_of_call` climbs via `parent()` in a while loop.** This is fragile: if tree-sitter's AST structure changes between versions (node types renamed), the loop could escape the intended parent and resolve to an unrelated variable. Currently works, but an explicit depth limit would be defensive.

- **`src/lang/go/detectors/cwe/taint/graph_query/build.rs:131` — `referenced_identifiers` splits on any non-alphanumeric.** This produces tokens like `r`, `URL`, `Query`, `Get` from `r.URL.Query().Get("x")`. Field/method name tokens that aren't variables in `decl_nodes` are harmlessly discarded, but the filtering is O(n * num_tokens) per assignment. For hot-path files, this is wasteful. Consider using tree-sitter patterns instead of text splitting for the MVP.

- **`src/lang/go/detectors/cwe/taint/extract/classify.rs:48` — Method-receiver check for command execution sub-methods (`.Run`, `.Start`, `.Output`).** The `receiver_of_method_call` function correctly checks `exec.Command` as the receiver of these calls, but `exec.Command` by itself returns a `*Cmd`, not the sub-method directly. The receiver text check `receiver.contains("exec.Command") || receiver.starts_with("exec.")` is a reasonable approximation but could miss `exec.CommandContext` or assignment patterns like `cmd := exec.Command(...); cmd.Output()`. The current MVP handles the inline case only.

### What's Done Well

- **Clean layered architecture:** `extract/` → `graph_query/` → `rules/` with clear responsibilities and minimal cross-module coupling. The `kinds.rs` re-export alias module is a nice touch for ergonomic imports.
- **Safe gated migration:** Legacy detectors check `facts.taint_graph.is_some()` and fall through to the old path when taint is disabled. Zero behavioral change for users who don't enable taint.
- **Comprehensive MVP scope documentation:** Module-level doc comments (`taint/mod.rs`, `graph_query/mod.rs`) clearly state the intra-procedural limitation and cross-function tracking deferral.
- **Performance benchmark test:** `taint_extraction_overhead_is_small` in `extract/tests.rs` validates extraction budget at 50ms for 500 functions, preventing regression.
- **Strong test coverage on happy paths:** Extraction tests for source/sink/scope detection and graph query tests for SQL, path traversal, command injection, and sanitized paths all pass. Integration tests (`go_cwe_detector_fixtures::taint_cwe_fixtures_fire_vulnerable_and_silence_safe`) confirm end-to-end behavior against fixture files.
- **Sanitizer path modeling:** `find_taint_paths` correctly tracks sanitized vs unsanitized states using a `(node, bool)` visited set, and reports unsanitized paths preferentially (returning as soon as one is found rather than always completing BFS).

### Verification Story

- **Tests reviewed:** Yes. 8 unit tests in `taint` submodules + 3 integration test suites all pass. The fixture integration test (`taint_cwe_fixtures_fire_vulnerable_and_silence_safe`) validates that vulnerable fixtures fire and safe fixtures are silent.
- **Build verified:** Yes. `cargo check --lib` passes without warnings. `cargo test` passes all taint-related tests.
- **Security checked:** Yes. The source/sink/sanitizer classification coverage is reasonable for MVP but has overbroad patterns (`.Write`, `.Query`, `.Exec`) that will generate false positives. The `filepath.Clean` sanitizer alone is insufficient for path traversal prevention (needs path prefix check). Result variable resolution for chained calls is the most impactful correctness concern. No memory safety or data race issues identified.
