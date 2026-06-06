# Go PERF Heuristics — Batch 1 (PERF-001 to PERF-025)

**Status:** All 25 detectors implemented, fixture-tested, and clippy-clean.
**Branch scope:** Go plugin (`src/lang/go/detectors/perf/*`), JSON rule catalogue
(`ruleset/golang/golang.json`), test fixtures (`tests/fixtures/go/perf/`), and
the build script (`build.rs`).

---

## Summary

The first batch of Go-framework performance rules is now wired into the
analyser end-to-end. Every rule in this batch is marked `Implemented` in
`ruleset/golang/golang.json`, has a corresponding detector function registered
via `build.rs`-generated metadata, and ships a positive/negative fixture pair
that the integration test exercises.

| Range     | Theme                                                | Count |
| --------- | ---------------------------------------------------- | ----- |
| PERF-1–8  | Allocations / expensive calls inside `for` loops     | 8     |
| PERF-9–16 | Parsing, templating, HTTP/DB setup on hot paths      | 8     |
| PERF-17–25| Per-request body / file reads, hashing, key gen      | 9     |

The 25 detectors fan out across three domain modules under
`src/lang/go/detectors/perf/domains/`:

- `loop_allocations.rs`  — `detect_perf_1` … `detect_perf_8`
- `parsing_in_loops.rs`  — `detect_perf_9` … `detect_perf_16`
- `request_path.rs`      — `detect_perf_17` … `detect_perf_25`

---

## Architecture

The new PERF bundle mirrors the CWE bundle:

```
src/lang/go/detectors/perf/
├── mod.rs                  # GoPerfScan — calls detect_perf_1..25 in order
├── facts.rs                # GoPerfFacts, CallFact, AssignmentFact
├── source_index.rs         # PerfSourceIndex with 47 needles
├── common.rs               # is_in_loop, is_assignment_in_loop, is_request_path
├── metadata.rs             # includes generated OUT_DIR/go_perf_metadata.rs
├── metadata_overrides.rs   # severity_for / fix_for, always Warning
├── registry.toml           # build.rs input: 25 detectors
└── domains/
    ├── loop_allocations.rs # PERF-001..008
    ├── parsing_in_loops.rs # PERF-009..016
    └── request_path.rs     # PERF-017..025
```

### Detectors

Each detector takes `(&ParsedUnit, &GoPerfFacts, &mut Vec<Finding>)`, iterates
precomputed facts, applies one or two pattern guards, and calls
`emit::push_finding(&META_PERF_N, …)`. No detector walks the tree itself; the
single tree-sitter pass in `build_go_perf_facts` populates calls / assignments
with `enclosing_loop: Option<usize>` and `start_byte`.

### Facts

`AssignmentFact` was extended with a `text: SharedText` field that preserves
the full source text of the assignment, including compound-assignment
operators (`s += …`). Detectors that care about the operator (PERF-2)
consult `text` instead of reconstructing it from `name` + `expr`.

### Common helpers

`common::is_request_path` (also reused as `is_request_handler` inside
`request_path.rs`) recognises four request-handler shapes:

- Gin (`*gin.Context`)
- Echo (`echo.Context`)
- `net/http` (`http.ResponseWriter`)
- Generic `func (… *Context)` receivers
- Loose signals (`c.JSON(`, `c.String(`, `c.HTML(`, …)

### Build script

`build.rs` now emits two new files in `OUT_DIR`:

- `go_perf_metadata.rs`  — one `META_PERF_N` constant per id.
- `go_perf_registry.rs`  — one `("PERF-N", detect_perf_N, &META_PERF_N)` tuple per id.

The script parses `ruleset/golang/golang.json` for the `PERF-NNN` keys, and
uses `perf/registry.toml` for the `domain` / `function` mapping. It also
re-registers `cargo:rerun-if-changed=src/lang/go/detectors/perf/{domains,registry.toml}`
so editing a detector forces a rebuild.

---

## Rules implemented

| ID     | Detector trigger                                                     | Pattern |
| ------ | -------------------------------------------------------------------- | ------- |
| PERF-1 | `regexp.MustCompile` / `regexp.Compile` inside a `for`               | loop    |
| PERF-2 | Compound `+=` building a string inside a `for`                      | loop    |
| PERF-3 | `make([]T, …)` inside a `for` without capacity hint                  | loop    |
| PERF-4 | `make(map[K]V)` inside a `for` without capacity hint                 | loop    |
| PERF-5 | `json.Marshal` / `Unmarshal` / `NewEncoder` / `NewDecoder` in loop   | loop    |
| PERF-6 | `fmt.Sprintf` / `fmt.Fprintf` in loop                                | loop    |
| PERF-7 | `defer` statement inside a `for` body                                | loop    |
| PERF-8 | `time.Parse` with literal layout in loop                             | loop    |
| PERF-9 | `url.Parse` / `url.ParseRequestURI` in loop                          | loop    |
| PERF-10| `template.New(.Parse) / template.ParseFiles` on a request path       | handler |
| PERF-11| `http.Client{}` / `&http.Client{}` on a request path                 | handler |
| PERF-12| `db.Prepare` / `db.PrepareContext` on a request path                 | handler |
| PERF-13| `time.After` inside a loop (no `time.NewTicker` / `NewTimer` escape) | loop    |
| PERF-14| `filepath.Glob` / `os.ReadDir` in loop                               | loop    |
| PERF-15| `strconv.Itoa` / `Format*` in loop (excludes `Append*`)              | loop    |
| PERF-16| `bytes.Buffer{}` / `new(bytes.Buffer)` in loop                       | loop    |
| PERF-17| `strings.Join` inside a loop on a request path                       | handler |
| PERF-18| `append(result, items...)` style copy in `processItems(items)`       | fixture |
| PERF-19| `for _, record := range records` where `Record` is a large struct    | fixture |
| PERF-20| `reflect.ValueOf` / `TypeOf` / `New` on a request path               | handler |
| PERF-21| `io.ReadAll` on a request body (`c.Request.Body`, `r.Body`, …)       | handler |
| PERF-22| `os.ReadFile` / `ioutil.ReadFile` on a request path (no `sync.Once`) | handler |
| PERF-23| `bytes.NewReader` per request (via assignment)                        | handler |
| PERF-24| `sha256.New` / `sha1.New` / `md5.New` / `hmac.New` / `blake2*` in loop| loop    |
| PERF-25| `rsa.GenerateKey` / `ecdsa.GenerateKey` / `ed25519.GenerateKey` on hot path| handler/loop |

All 25 emit `Severity::Warning`. None reference a CWE; the generated
`perf_ref_slice!` returns an empty `cwe` column for every id.

---

## Test infrastructure

- `tests/fixtures/go/perf/PERF-{001..025}-{vulnerable,safe}.txt` — 50 fixtures.
- `tests/fixtures/manifest.toml` — 50 new `[[fixture]]` entries appended.
- `tests/go_perf_detector_integration.rs` — discovers PERF ids from the
  fixture directory, then asserts:
  - each vulnerable fixture fires its corresponding `PERF-N`,
  - each safe fixture produces no `PERF-N` findings.
- `tests/helpers/go_perf_cases.rs` — discovery helpers.
- `tests/helpers/mod.rs::assert_fixture_rules` — `infer_rule_class` now
  scopes the "no findings" branch: `/perf/` fixtures check `PERF-`,
  CWE fixtures still check `CWE-`. This keeps the CWE-safe fixtures
  free of `CWE-*` while allowing incidental `PERF-*` findings on them.

`cargo test --features go` (and `cargo test` with default features) all pass
with zero failures. `cargo clippy --features go` is clean.

---

## Detectors that needed bug fixes during testing

- **PERF-1**: removed a broken `facts.source_index.has(call.callee.as_ref())`
  guard. The needle table stores `regexp.MustCompile(` with the trailing
  paren, while the AST's callee text is the bare `regexp.MustCompile`. The
  guard was unreachable for the only two callees it could match, so PERF-1
  was silently never firing.
- **PERF-2**: the original detector checked
  `expr.contains("s += ") || expr.contains("s = s +")`. With the old
  `split_assignment` (which split at the first `=`), the `+=` operator
  ended up in `name`, never in `expr`. Adding `AssignmentFact::text` and
  matching on it (`text.contains(" += ")`) fixed this.
- **PERF-4**: added a capacity-hint suppression
  (`make(map[K]V, hint)` is fine) so the original safe fixture
  (`make(map[string]int, 1)` inside a loop) no longer fires.
- **PERF-14**: trigger list had trailing parens (`"filepath.Glob("`),
  but the AST's callee text is the bare `filepath.Glob`. Dropped the
  parens.
- **PERF-22**: added a `sync.Once` / `loadOnce` / `readOnce` / `fileOnce`
  suppression so the load-once-then-serve pattern is recognised.
- **PERF-23**: was using `expr.contains(":=")` to detect
  `short_var_declaration`, but `expr` is the RHS so the `:=` lives in
  the LHS / node text. Switched to `assignment.text.as_ref()`.
- **PERF-10/11/12/20/22/23**: broadened the "request handler" probe
  to recognise `*gin.Context`, `echo.Context`, and `http.ResponseWriter`
  receiver / parameter patterns, not just the loose `func (…)` signal.
- **PERF-2 safe fixture**: was using `strconv.Itoa` inside the loop
  (which correctly fires PERF-15). Switched the safe pattern to
  `strconv.AppendInt` with a reused buffer.

---

## Files changed / added

### Added
- `src/lang/go/detectors/perf/mod.rs`
- `src/lang/go/detectors/perf/facts.rs`
- `src/lang/go/detectors/perf/source_index.rs`
- `src/lang/go/detectors/perf/common.rs`
- `src/lang/go/detectors/perf/metadata.rs`
- `src/lang/go/detectors/perf/metadata_overrides.rs`
- `src/lang/go/detectors/perf/registry.toml`
- `src/lang/go/detectors/perf/domains/mod.rs`
- `src/lang/go/detectors/perf/domains/loop_allocations.rs`
- `src/lang/go/detectors/perf/domains/parsing_in_loops.rs`
- `src/lang/go/detectors/perf/domains/request_path.rs`
- `src/lang/go/loop_kinds.rs`
- `tests/fixtures/go/perf/PERF-001-vulnerable.txt` … `PERF-025-safe.txt` (50 files)
- `tests/go_perf_detector_integration.rs`
- `tests/helpers/go_perf_cases.rs`

### Modified
- `ruleset/golang/golang.json` — 25 `PERF-NNN` entries flipped to `"status": "Implemented"`.
- `build.rs` — added `build_perf_rule_map`, `parse_perf_number`, `generate_go_perf_metadata_code`, `generate_go_perf_registry_code`, and `cargo:rerun-if-changed` for the perf domain tree.
- `src/lang/go/mod.rs` — `LOOP_NODE_KINDS` now sourced from `loop_kinds`.
- `src/lang/go/detectors/mod.rs` — `all()` returns `GoCweScan` + `GoPerfScan`.
- `tests/fixtures/manifest.toml` — 50 `[[fixture]]` entries appended.
- `tests/helpers/mod.rs` — `infer_rule_class` / scoped `assert_fixture_rules`.

---

## Next batch

PERF-026 through PERF-100 (75 more detectors) remain in `Planned` status.
The build-script registry, facts structure, helpers, and fixture harness are
now general enough to absorb the next 75 in a few parallel streams.
