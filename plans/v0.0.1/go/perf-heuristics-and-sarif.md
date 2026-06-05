# Plan: Go `PERF-*` Heuristics And SARIF

## Goal

Add a future Go-only performance ruleset that is separate from the existing `CWE-*` security ruleset.

> Scope: Go only. This plan covers both `tests/fixtures/go/stdlib/` and `tests/fixtures/go/frameworks/`.
>
> Non-goal: do not duplicate coverage that already exists in the Go `CWE-*` detector set.

---

## Status

- [x] Registry entries for all planned `PERF-*` rules exist
- [ ] Detector architecture for Go `PERF-*` rules is implemented
- [ ] `PERF-*` fixture set exists for both `stdlib` and `frameworks`
- [ ] Repository-level `PERF-*` integration tests exist under `tests/`
- [ ] SARIF includes richer metadata for `PERF-*` results
- [ ] `make fmt`
- [ ] `make lint`

---

## Why a separate `PERF-*` family

The previous Go `SLOP*` rules mixed performance heuristics with the security-oriented rule inventory. That makes triage, registry management, SARIF output, and severity handling less clear than they should be.

This plan replaces that direction with a dedicated Go performance family:

- rule ids use `PERF-*`
- performance findings remain distinct from `CWE-*` findings
- fixtures and tests stay repository-level under `tests/`
- coverage is limited to rules that are not already represented by the current Go CWE detector set

---

## Explicit non-duplication boundary

Do not add `PERF-*` rules that are already covered, even indirectly, by the active Go `CWE-*` ruleset.

Examples of areas that stay `CWE-*` only:

- injection, traversal, deserialization, SSRF, hardcoded secrets
- weak crypto, insecure randomness, authz/authn mistakes
- unsafe file permissions, temp-file exposure, unsafe downloads
- regex denial-of-service or attacker-driven regex complexity

This `PERF-*` plan is for runtime-efficiency and hot-path waste patterns, not security weaknesses.

---

## Planned rule inventory

### Phase 1: direct replacements for the removed Go slop rules

- [ ] `PERF-001` `regexp_in_loop`
  - Detect `regexp.MustCompile(...)` or `regexp.Compile(...)` inside a `for`/`range` body.
  - Safe pattern: compile once outside the loop and reuse the compiled regexp.

- [ ] `PERF-002` `string_concat_in_loop`
  - Detect `s = s + part`, `s += part`, or equivalent repeated string growth inside a loop.
  - Safe pattern: `strings.Builder`, `bytes.Buffer`, or single-shot join/format after accumulation.

- [ ] `PERF-003` `slice_rebuild_in_loop`
  - Detect loop-local slice re-creation that discards prior capacity or repeatedly rebuilds the same working slice.
  - Examples: `items = []T{}` / `items = make([]T, 0)` in the loop body before repeated `append`.
  - Safe pattern: allocate once outside the loop, reuse with `items = items[:0]`, or pre-size when shape is known.

- [ ] `PERF-004` `map_alloc_in_loop`
  - Detect `make(map[K]V)` inside a loop when the map is repeatedly rebuilt per iteration without necessity.
  - Safe pattern: hoist reusable maps, clear or replace intentionally at the right scope, or use a small literal when one-shot allocation is actually intended.

- [ ] `PERF-005` `json_marshal_in_loop`
  - Detect repeated `json.Marshal`, `json.Unmarshal`, `json.NewEncoder`, or `json.NewDecoder` in a hot loop or row-by-row request path.
  - Safe pattern: batch serialization, reuse encoder/decoder where possible, or move conversion outside the inner loop.

### Phase 2: additional Go-only performance rules not covered by the current CWE set

- [ ] `PERF-006` `fmt_sprintf_in_loop`
  - Detect `fmt.Sprintf` / `fmt.Fprintf` used as repeated string construction inside loops when a builder or direct write is cheaper.

- [ ] `PERF-007` `defer_in_loop`
  - Detect `defer` inside loops where cleanup is repeated per iteration and stacks until function exit.
  - This is primarily a cost and resource-pressure rule here, not a security rule.

- [ ] `PERF-008` `time_parse_in_loop`
  - Detect repeated `time.Parse` / `time.ParseInLocation` inside loops when the layout is constant and parsing is in a hot path.

- [ ] `PERF-009` `url_parse_in_loop`
  - Detect repeated `url.Parse` / `url.ParseRequestURI` inside tight loops over records, retries, or middleware fan-out.

- [ ] `PERF-010` `template_parse_in_request_path`
  - Detect `template.New(...).Parse(...)`, `template.ParseFiles(...)`, or `template.Must(template.Parse...)` on the request path instead of process-start initialization.

- [ ] `PERF-011` `http_client_alloc_per_request`
  - Detect `&http.Client{...}` or `http.Client{...}` construction inside handlers, middleware, or looped call paths when a shared client should be reused.

- [ ] `PERF-012` `db_prepare_in_request_path`
  - Detect `db.Prepare`, `db.PrepareContext`, or equivalent prepared statement setup in a request hot path instead of one-time initialization or cached reuse.

- [ ] `PERF-013` `time_after_in_loop`
  - Detect `time.After(...)` created on every loop iteration in long-running loops, worker polls, or retry loops.
  - Safe pattern: `time.NewTimer`, timer reuse, or ticker-based scheduling.

- [ ] `PERF-014` `filepath_glob_in_loop`
  - Detect repeated `filepath.Glob`, `os.ReadDir`, or equivalent directory scans inside loops when the scan set is stable across iterations.

- [ ] `PERF-015` `strconv_format_in_loop`
  - Detect repeated `strconv.Itoa`, `FormatInt`, `FormatFloat`, or similar in loops where direct buffered writes or cached conversions would be cheaper.

- [ ] `PERF-016` `bytes_buffer_realloc_in_loop`
  - Detect repeated `bytes.Buffer{}` / `new(bytes.Buffer)` allocation in inner loops when a reusable buffer with `Reset()` would avoid churn.

---

## Detector architecture

The future implementation should not restore the old one-file-per-rule `SLOP*` layout.

Use the same architectural direction that worked for the Go CWE rollout:

- one Go-specific bundled detector for performance rules
- one fact/index build per parsed Go unit
- grouped evaluators instead of many tiny detector structs
- repository-level tests only; no inline tests in detector modules

Suggested layout:

- `src/lang/go/detectors/perf/facts.rs`
- `src/lang/go/detectors/perf/model.rs`
- `src/lang/go/detectors/perf/groups/loops.rs`
- `src/lang/go/detectors/perf/groups/io_json.rs`
- `src/lang/go/detectors/perf/groups/init_and_clients.rs`
- `src/lang/go/detectors/perf/mod.rs`
- `tests/go_perf_detector_integration.rs`

The Go plugin registry should eventually register both:

- `GoCweScan`
- `GoPerfScan`

---

## Performance detection model

The implementation should stay fact-based and cheap:

1. Parse the Go file once.
2. Build reusable `GoPerfFacts` in one AST walk.
3. Record loop spans, call sites, assignments, short declarations, and hot-path context markers.
4. Let grouped `PERF-*` evaluators query those facts without rescanning the AST.

Useful facts include:

- loop spans and nesting depth
- call facts for `regexp`, `json`, `fmt`, `time`, `url`, `template`, `database/sql`, `filepath`, `strconv`
- short declarations and assignments inside loop bodies
- handler or middleware context markers for Gin and stdlib `net/http`
- obvious reuse-safe shapes such as `strings.Builder`, `bytes.Buffer.Reset`, shared `http.Client`, and hoisted prepared statements

Default execution model:

- keep parallelism at the existing file-level engine layer
- do not add nested Rayon inside one Go file unless profiling proves it helps

---

## Fixture and test plan

All tests stay under `tests/`.

Required future files:

- `tests/go_perf_detector_integration.rs`
- `tests/fixtures/go/stdlib/PERF-001-vulnerable.txt`
- `tests/fixtures/go/stdlib/PERF-001-safe.txt`
- `tests/fixtures/go/frameworks/PERF-001-vulnerable.txt`
- `tests/fixtures/go/frameworks/PERF-001-safe.txt`
- repeat for every planned `PERF-*` rule

Fixture expectations:

- one vulnerable and one safe fixture per rule per Go fixture family
- safe fixtures must assert no `PERF-*` findings for that rule
- avoid introducing fixtures that are already testing a `CWE-*` security behavior

---

## Registry plan

The Go rules registry at `ruleset/golang/golang.json` should include the planned `PERF-*` records now so reporting and future work can reference stable ids before detector implementation starts.

Registry conventions for `PERF-*`:

- key: `PERF-00N`
- `id`: same string as the rule key
- `category`: `Performance`
- `status`: `Planned` until implemented
- `applicable_to`: include Go plus the current framework tags
- `go_relevance`: `High` or `Medium`
- `detection_notes`: concise future implementation note, not a claim of active detection

---

## SARIF plan

There is already a minimal SARIF reporter in `src/reporting/sarif.rs`. The future `PERF-*` rollout should extend that path instead of creating a separate exporter.

### Phase 1: compatibility

- [ ] Ensure `PERF-*` findings serialize with stable `rule_id` values exactly matching the registry ids.
- [ ] Keep SARIF emission working for mixed `CWE-*` and `PERF-*` results in one run.

### Phase 2: richer rule metadata

- [ ] Add rule metadata beyond `id`, `name`, and `shortDescription`.
- [ ] Include `helpUri` or `properties` when the rule registry has enough information to support it.
- [ ] Attach category metadata so downstream consumers can distinguish `Performance` from `Security`.

### Phase 3: result shaping

- [ ] Map `PERF-*` severities to SARIF levels intentionally.
  - Default expectation: most `PERF-*` rules should be `warning` or `note`, not `error`.
- [ ] Add stable fingerprints if the engine has enough source-span identity to support deduplication across runs.
- [ ] Include concise message text that explains both the hot-path issue and the preferred reuse pattern.

### Phase 4: verification

- [ ] Add a focused SARIF regression test that emits mixed `CWE-*` and `PERF-*` findings and verifies both rule tables and result records.

---

## Rollout order

1. Add registry entries for the planned `PERF-*` rules.
2. Implement `PERF-001` through `PERF-005`.
3. Add stdlib and framework fixtures for those five rules.
4. Add repo-level integration tests.
5. Implement the remaining `PERF-*` rules in grouped batches.
6. Extend SARIF metadata once the rule family is stable.

---

## Exit criteria

This plan is done when:

- every planned `PERF-*` rule has a registry entry
- Go performance detection is implemented without reintroducing the old `SLOP*` layout
- every implemented `PERF-*` rule has stdlib and framework fixtures
- tests live under `tests/` only
- SARIF supports mixed `CWE-*` and `PERF-*` output cleanly
