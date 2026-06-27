# P2.1 — Taint Tracking: Remaining Work (Phases C–F)

> **Parent:** `plans/p2-implementation/01-taint-tracking.md` — P2.1
> **Status:** Phases A (Foundation) + B (Intra-procedural graph + CWE rewrites) **shipped**. Phases C–F **not started**.
> **Estimated effort:** ~4–6 weeks total
> **See also:** `plans/p2-remaining-work.md` § P2.1, `plans/v2.0.0/pending-work/05-taint-cli-and-docs.md`

---

## Overview

The taint-tracking foundation is in place: `TaintGraph` data model, tree-sitter fact extraction, BFS path-finding, and four CWE detector rewrites (CWE-22/78/79/89) with graceful fallback to the old pattern-matching logic. What remains is hardening, expansion, CLI integration, documentation, and the large inter-procedural work.

**Situation:** 21 source files in `src/lang/go/detectors/cwe/taint/`. 8 test fixtures. Taint is gated behind `[slopguard.taint] enabled = true` in config (default `false`). No CLI flags exist for taint. The `taint_show_paths` config field is parsed but **never consumed** anywhere.

---

## Executive Summary

- Phase A/B are complete and working (verified via integration tests).
- **Phase C** (remove substring fallback) is blocked — we need a CLI signal + docs warning before making taint default-on.
- **Phase D** (extended sanitizers) is straightforward: add ~10 function matchers.
- **Phase E** (CLI flags + docs) is high-leverage and should land first to make taint user-visible.
- **Phase F** (inter-procedural) is the largest effort — requires call-graph construction + function summaries. Deserves its own sub-plan.

**Recommended order:** E → C → D → F (Phase F is independent and can be deferred to a separate workstream).

---

## Phase C — Remove Substring Fallback for CWE-78/89/22/79

> **Status:** ❌ Not started. Blocked on CLI signal + docs warning.
> **Effort:** 1–2 days

### 1.1 Prerequisites

- [ ] Land Phase E (CLI flags) so users can discover and enable taint without editing `slopguard.toml`
- [ ] Land `docs/taint.md` so users understand what taint does and how to disable it
- [ ] Ensure `--no-taint` / `--taint` flags exist (see Phase E)

### 1.2 Code changes

- [ ] Flip default `slopguard.taint.enabled` from `false` to `true` in `src/engine/config/types.rs:90`
- [ ] Remove the `if facts.taint_graph.is_some() { return taint_version } else { fallback }` pattern in all 4 CWE detectors (`domains/path_traversal.rs`, `domains/injection/sinks.rs`, `domains/input_validation/output_encoding.rs`)
  - Each detector should **always** delegate to the taint-based implementation when taint is enabled
  - The old substring-heuristic fallback remains as a compile-time error only when taint is disabled
- [ ] Update `tests/go_cwe_detector_fixtures.rs` so all 4 CWE integration tests run both with **and without** taint enabled, verifying both paths produce at least one finding
- [ ] Add a `cargo test --all-features` run with taint enabled to CI (`ci.yml`)

### 1.3 Edge cases

- [ ] Test that a file with **no sources** or **no sinks** does not trigger spurious findings when taint is enabled
- [ ] Test that a file with sources but sanitized sinks (e.g. `filepath.Clean` + `os.Open`) does not fire

---

## Phase D — Extended Sanitizer Coverage

> **Status:** ❌ Not started
> **Effort:** 1–2 days

### 2.1 New sanitizer matchers

Add the following sanitizer functions to the classifier in `src/lang/go/detectors/cwe/taint/extract/classify.rs`:

- [ ] `strconv.Atoi`, `strconv.ParseInt`, `strconv.ParseFloat` → `SanitizerKind::Validation` (converts string to number, fails if invalid)
- [ ] `utf8.ValidString` → `SanitizerKind::Validation` (confirms valid UTF-8)
- [ ] `html.EscapeString`, `html.UnescapeString` → `SanitizerKind::HTML` (stdlib HTML escaping, distinct from `template.HTMLEscaper`)
- [ ] `net/url.IsAbs` → `SanitizerKind::URL` (validates absolute URL)
- [ ] `strings.HasPrefix`, `strings.HasSuffix`, `strings.Contains` → `SanitizerKind::Validation` (guard checks that restrict input)

### 2.2 Middleware / framework sanitizers

- [ ] Gin: `c.ShouldBind`, `c.ShouldBindJSON`, `c.ShouldBindQuery` → `SanitizerKind::Validation` (structured binding validates types)
- [ ] Echo: `c.Bind`, `c.BindWith` → `SanitizerKind::Validation`
- [ ] Chi / gorilla/mux: `chi.URLParam`, `mux.Vars` → treat as source, not sanitizer

### 2.3 Tests

- [ ] Add test fixtures for each new sanitizer (one vulnerable pair that the sanitizer blocks, one safe pair where sanitizer is applied)
- [ ] Update `taint_cwe_fixtures_fire_vulnerable_and_silence_safe` to include new sanitizer fixtures
- [ ] Verify that `strconv.Atoi` + SQL query does **not** fire a CWE-89 finding

### 2.4 Name-based heuristic sanitizer detection

- [ ] Add heuristic: functions matching `/^(sanitize|clean|escape|validate|purify)/i` are treated as `SanitizerKind::Validation` with a `tracing::debug!` note
- [ ] Document this in `docs/taint.md` so users know they can create custom sanitizers by naming convention
- [ ] Add test fixture using a custom `sanitizeInput()` function

---

## Phase E — CLI Flags + Documentation

> **Status:** ❌ Not started. This is the highest-leverage item — makes taint user-visible.
> **Effort:** 3–4 days

### 3.1 CLI flags

Add the following to `src/cli/args.rs` and wire in `src/cli/args_impl.rs`:

- [ ] `--taint` (flag): shorthand to enable taint tracking. Equivalent to setting `[slopguard.taint] enabled = true` in config. Takes precedence over config.
  ```rust
  #[arg(long, help = "Enable taint-tracking analysis (CWE-22/78/79/89)")]
  taint: bool,
  ```
- [ ] `--no-taint` (flag): disable taint even if config enables it.
  ```rust
  #[arg(long, help = "Disable taint-tracking analysis")]
  no_taint: bool,
  ```
- [ ] `--taint-show-paths` (flag): emit taint-path evidence in JSON/SARIF output.
  ```rust
  #[arg(long, help = "Include taint propagation paths in evidence output")]
  taint_show_paths: bool,
  ```
- [ ] Wire in `args_impl.rs::scan_context()`:
  ```rust
  if self.taint { ctx.taint_enabled = true; }
  if self.no_taint { ctx.taint_enabled = false; }
  if self.taint_show_paths { ctx.taint_show_paths = true; }
  ```

### 3.2 Consume `taint_show_paths` in evidence

- [ ] In `src/reporting/json/entry.rs`: when `taint_show_paths` is true, include `TaintPath` details in the JSON finding output under `evidence.taint_path`
- [ ] In `src/reporting/sarif/entry.rs`: when `taint_show_paths` is true, include hop information in the SARIF `properties` bag
- [ ] In `src/reporting/text/render.rs`: when `--taint-show-paths` is set, print the taint path (source → hop → sink) in the text output
- [ ] Test: `tests/reporting_json_finding.rs` — add a test that a taint finding with `show_paths=true` includes path details

### 3.3 Documentation: `docs/taint.md`

Create `docs/taint.md` covering:

- [ ] **Overview**: what taint tracking is and which CWE rules use it (CWE-22, 78, 79, 89)
- [ ] **Enabling**: via config (`[slopguard.taint] enabled = true`) and via CLI (`--taint`)
- [ ] **Model**: source kinds (UserInput, Args, EnvVar, File, Network), sink kinds (CommandExec, SQLQuery, etc.), sanitizer kinds (Path, HTML, URL, SQL, Validation, Bounded)
- [ ] **Limitations**: intra-procedural only (no cross-function tracking), single-assignment-per-scope (no full reaching-definitions), no struct-field tracking
- [ ] **Reading output**: how to interpret `evidence.taint_path` in JSON output
- [ ] **Custom sanitizers**: name-based heuristic detection (`sanitize*`, `clean*`, etc.) and how to verify a function is recognized
- [ ] **Performance**: extraction is always performed but graph-building is lazy; enable only for CWE rules that need it

### 3.4 Schema update

- [ ] Add `taint` CLI flags to `slopguard.schema.json` (if schema tracks CLI flags)
- [ ] Update `templates/slopguard.toml` to include a commented-out `[slopguard.taint]` block

---

## Phase F — Inter-Procedural Taint Tracking

> **Status:** ❌ Not started. Requires significant infrastructure.
> **Effort:** 3–4 weeks. Deserves a separate detailed plan.

### 4.1 Call-graph construction

- [ ] Build a per-file call graph from tree-sitter: record call expressions with callee name, argument positions, and return value usage
- [ ] Merge per-file call graphs into a project-level call graph (respect `go.mod` boundaries)
- [ ] Handle: method calls (receiver type + method name), function literals (closures, anonymous functions), interface calls (dispatch at call site)

### 4.2 Function summaries

- [ ] Define `TaintSummary` struct: `{ params: Vec<Option<SourceKind>>, returns: Vec<Option<SourceKind>>, sanitizes: Vec<(usize, SanitizerKind)> }`
- [ ] Compute summaries via intra-procedural taint propagation per function (reuse existing graph builder)
- [ ] Cache summaries per function; invalidate when function body changes (content hash)
- [ ] Store summaries in the `GoUnitFacts` for each parsed function

### 4.3 Cross-function propagation

- [ ] At a call site: map caller arguments to callee params; if callee summary says param → sink, create taint edge from caller's source expression
- [ ] If a callee returns tainted data, create edge from callee return → caller expression
- [ ] Handle recursion: detect cycles and cap depth at a configurable max (default 5)
- [ ] Fixed-point iteration: propagate until no new taint edges are created

### 4.4 Expanded source/sink coverage for inter-procedural

- [ ] Add `SourceKind::Return` — taint from any function that returns user-controlled data
- [ ] Add `SinkKind::DatabaseWrite` — `db.Exec`, `db.Update`, `db.Save`
- [ ] Add `SinkKind::Logging` — `log.Printf`, `log.Println` with user-controlled format strings
- [ ] Add `SinkKind::Redirect` — `http.Redirect` with user-controlled URL

### 4.5 Tests and fixtures

- [ ] Add 5+ multi-hop inter-procedural fixtures (call chain depth 2–4):
  - `funcA → funcB → sink` (unsanitized)
  - `funcA → sanitizer → funcB → sink` (sanitized, should be silent)
  - `funcA → funcB → funcC → sink` (depth 3)
  - Recursive call chain with taint
  - Method call chain (struct receiver)

### 4.6 Edge-case handling

- [ ] Pointer aliasing: if `&x` is passed and the callee modifies `*param`, propagate taint back
- [ ] Map/slice mutations: `m["key"] = tainted` → subsequent reads from `m["key"]` are tainted
- [ ] Deferred function calls: track defer targets and propagate taint from deferred closures
- [ ] Goroutine closures: capture taint at `go func()` creation point

---

## Dependencies

- **Phase C** depends on **Phase E** (CLI flags must exist before flipping default)
- **Phase D** is independent; can be done in parallel with E
- **Phase F** depends on existing intra-procedural infrastructure (Phases A–B)
- **Phase F** may overlap with P2.4 Category C (multi-file/semantic PERF rules) which also needs call-graph infrastructure
- Cross-cutting: `docs/taint.md` (Phase E) is also tracked in `05-cross-cutting-remaining.md`

## Quick reference

| Phase | Items | Status | Effort | Blocked by |
|-------|-------|--------|--------|------------|
| C — Remove substring fallback | ~6 items | ❌ | 1–2d | Phase E |
| D — Extended sanitizers | ~12 items | ❌ | 1–2d | — |
| E — CLI flags + docs | ~10 items | ❌ | 3–4d | — |
| F — Inter-procedural | ~15 items | ❌ | 3–4w | Independent plan |
