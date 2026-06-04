# Plan: Implement High-Performance Go CWE Heuristics

## Goal

Add real detection logic for the Go CWE fixtures so the analyzer validates vulnerable and safe cases with a design that is:

- correct on the current fixture corpus
- fast on small files and scalable to larger Go codebases
- easy to extend without creating 175 disconnected mini-detectors
- conservative about abstractions until they are proven useful

> Scope: Go only. This plan covers both `tests/fixtures/go/stdlib/` and `tests/fixtures/go/frameworks/`. Future language support is a follow-on task and must not distort the Go v1 design.

## Progress Snapshot

- [x] Phase 0 enabled real `CWE-*` fixture enforcement in `tests/fixture_manifest_integration.rs`
- [x] Safe fixtures no longer pass vacuously when `required_rules = []`
- [x] `GoUnitFacts` exists and is wired into a bundled `GoCweScan`
- [x] Detector tests have been moved out of `src/lang/go/detectors/` into `tests/`
- [x] Implemented rule coverage so far: `CWE-15`, `CWE-22`, `CWE-41`, `CWE-59`, `CWE-76`, `CWE-78`, `CWE-79`, `CWE-89`, `CWE-90`, `CWE-91`, `CWE-93`, `CWE-112`, `CWE-140`, `CWE-178`, `CWE-179`, `CWE-182`, `CWE-184`, `CWE-186`, `CWE-201`, `CWE-204`, `CWE-208`, `CWE-209`, `CWE-212`, `CWE-213`, `CWE-214`, `CWE-215`, `CWE-250`, `CWE-252`, `CWE-256`, `CWE-257`, `CWE-260`, `CWE-261`, `CWE-262`, `CWE-263`, `CWE-266`, `CWE-267`, `CWE-268`, `CWE-270`, `CWE-272`, `CWE-273`, `CWE-274`, `CWE-276`, `CWE-277`, `CWE-278`, `CWE-279`, `CWE-280`, `CWE-281`, `CWE-283`, `CWE-289`, `CWE-290`
- [ ] Remaining Go fixture rules still need implementation or explicit deferral/redesign notes
- [ ] Performance measurement and tuning phases are not done yet
- [ ] `src/lang/go/detectors/cwe/README.md` is not written yet

---

## Current state

- `tests/fixture_manifest_integration.rs` now enforces `CWE-*` fixtures for real.
- The Go plugin registers both `GoScan` and the bundled `GoCweScan`.
- The manifest is currently being used as the driver for implementation progress: each run surfaces the next uncovered Go CWE fixture.
- Current manifest frontier: `CWE-294`.

---

## Design principles

1. Optimize for the current engine shape first.
   The engine already parallelizes across files in [src/engine/walk.rs](/home/chinmay/ChinmayPersonalProjects/slopguard/src/engine/walk.rs:104). Do not add nested per-file parallelism by default.

2. Build facts once, evaluate many rules cheaply.
   The expensive operation is walking the AST and normalizing source patterns. Do that once per file, then let many rules consume the indexed facts.

3. Keep Go-specific logic in `src/lang/go/` for v1.
   Only extract shared abstractions to `src/core/` after a second language proves they are truly shared.

4. Prefer grouped rule evaluators over one struct per CWE.
   The codebase already prefers bundled scans, as seen in [src/lang/go/scan.rs](/home/chinmay/ChinmayPersonalProjects/slopguard/src/lang/go/scan.rs:1). Follow that shape.

5. Safe logic is evidence-based suppression, not a second detector pipeline.
   A rule can emit a candidate from indexed facts, then optionally suppress it with additional indexed facts. Safe patterns never emit findings on their own.

6. Performance claims must be benchmarked.
   No mandatory Rayon fan-out, no hard latency promises, and no “O(1) regardless of matcher count” language unless measured.

---

## Target architecture

### Stage 0: Parse

The existing engine already reads and parses files once.

### Stage 1: Build `GoUnitFacts`

For each `ParsedUnit`, perform one primary AST walk and optional lightweight source scans to build a compact fact index.

`GoUnitFacts` should capture normalized evidence such as:

- call sites
  - fully-qualified or normalized callee name when possible
  - argument node spans
  - whether an argument is string concatenation, `fmt.Sprintf`, literal, identifier, selector, etc.
- declarations
  - `const` and `var` names
  - literal initializers
  - obvious secret-like identifier names
- assignments and short declarations
  - left-hand identifiers
  - right-hand expression shape
- control-flow guard signals
  - `filepath.Clean`
  - `strings.HasPrefix`
  - allow-list helper calls
  - URL parsing and host validation signals
- source-origin hints
  - request query access
  - request body reads
  - environment variable reads
  - file path joins
- regex-set hits for purely textual patterns

This fact index is the performance center of the design. Rule evaluation should mostly query `GoUnitFacts`, not rescan the tree.

### Stage 2: Rule groups evaluate facts

Rule groups consume `GoUnitFacts` and emit `CandidateFinding`s.

Suggested group layout:

- `src/lang/go/detectors/cwe/facts.rs`
  - builds `GoUnitFacts`
- `src/lang/go/detectors/cwe/model.rs`
  - `CandidateFinding`, suppression state, helper enums
- `src/lang/go/detectors/cwe/groups/call_injection.rs`
- `src/lang/go/detectors/cwe/groups/call_deser.rs`
- `src/lang/go/detectors/cwe/groups/decl_secrets.rs`
- `src/lang/go/detectors/cwe/groups/config_crypto.rs`
- `src/lang/go/detectors/cwe/groups/exposure_regex.rs`
- `src/lang/go/detectors/cwe/mod.rs`
  - orchestrator and registration

Each group owns a coherent family of rules and exposes one function:

```rust
pub fn run_group(
    unit: &ParsedUnit,
    facts: &GoUnitFacts,
    enabled_rules: &EnabledRuleSet,
    out: &mut Vec<CandidateFinding>,
);
```

This is intentionally simpler than one trait object per CWE. v1 should prefer static dispatch and grouped modules.

### Stage 3: Suppression pass

Suppression runs over candidates using the same `GoUnitFacts`.

```rust
pub fn suppress_candidates(
    unit: &ParsedUnit,
    facts: &GoUnitFacts,
    candidates: Vec<CandidateFinding>,
) -> Vec<Finding>;
```

Suppression must be:

- local to the rule id
- cheap because it reuses facts
- deterministic

Examples:

- `CWE-22`
  suppress when the data flow shows `filepath.Clean` on user input and a path-prefix guard before the sink.
- `CWE-89`
  suppress when the query is a literal with placeholders or a prepared statement helper is used.
- `CWE-918`
  suppress when URL parsing and explicit host allow-list validation are both present.

### Stage 4: Materialize final findings

Only after suppression should the system build full `Finding` values and snippets.

This keeps the hot path smaller and avoids allocating snippets for dropped candidates.

---

## Why this architecture is better

### Better than per-CWE matcher objects

- fewer allocations
- less boilerplate
- easier to share normalized logic like “is user-controlled input”
- easier to debug because the fact-builder is explicit

### Better than pushing traits into `src/core` now

- avoids freezing the wrong abstraction too early
- lets Go-specific semantics evolve quickly
- keeps future extraction straightforward once Python or Rust exists

### Better than nested Rayon inside detectors

- the engine already parallelizes across files
- fixtures are small, so per-file fan-out is mostly scheduler overhead
- sequential per-unit execution is simpler and usually faster at this size

---

## Performance plan

### Default execution model

- Parallelism level 1: across files only, using the existing engine behavior.
- Parallelism level 2: inside a single Go unit is disabled by default.

Optional per-unit parallelism can be added later only if profiling shows one Go file with many enabled rules is a real bottleneck.

### Hot-path rules

1. One AST walk to build facts.
2. No AST rescans inside ordinary rule evaluation.
3. Regexes compiled once as `Lazy<Regex>` or `Lazy<RegexSet>`.
4. Rule groups query indexed facts instead of reparsing nodes repeatedly.
5. Final snippets created only for unsuppressed findings.

### Data structures

Use compact, query-friendly structures:

- `Vec<CallFact>`
- `Vec<DeclFact>`
- `Vec<AssignFact>`
- `FxHashMap` or the existing project-preferred fast map if a map is required
- small enums for expression kind instead of storing many strings

Store source spans as byte offsets and only derive line/column when materializing findings.

### Caching guidance

Good caches:

- normalized callee names
- “user-controlled” marker on expressions
- “guard present” markers for path, URL, TLS, prepared-statement patterns

Bad caches:

- global mutable caches across files
- memoization keyed by raw node pointer without a clear ownership model

### Benchmarking targets

Track these before and after implementation:

- `cargo test --test fixture_manifest_integration`
- `cargo test --test go_integration`
- `cargo test --test perf_regression`

Add a focused benchmark or timing test for:

- fact-build time
- candidate evaluation time
- suppression time

Success criterion:

- fixture correctness reaches the expected rule behavior
- total Go fixture runtime stays within a reasonable multiplier of the current baseline
- no single rule group dominates runtime unexpectedly

Do not encode arbitrary goals like “< 5 ms for 50 matchers” unless measured on this repository.

---

## Rule modeling strategy

Not every CWE deserves a bespoke matcher type. Use three implementation tiers.

### Tier 1: Fact-query rules

Use for structured patterns like:

- command injection
- SQL injection
- path traversal
- SSRF
- weak crypto settings
- hardcoded secrets

These rules should be mostly implemented as filters over `GoUnitFacts`.

### Tier 2: Fact-query plus targeted local inspection

Use when the fact index narrows candidates, but one local node inspection is still needed.

Examples:

- verifying a specific argument is `fmt.Sprintf`
- checking a struct literal field like `InsecureSkipVerify: true`

### Tier 3: Regex-backed exposure rules

Use only for patterns that are genuinely textual and do not benefit from AST semantics.

Examples:

- obvious logging or leakage strings
- token-looking constants where AST shape adds little value

Prefer `RegexSet` when multiple exposure signatures scan the same source.

---

## Suppression model

Suppression stays rule-specific, but it should not require a separate suppressor object for every CWE.

Instead, keep suppression logic close to the rule group:

```rust
fn maybe_suppress_cwe_22(facts: &GoUnitFacts, candidate: &CandidateFinding) -> bool
```

This keeps control flow direct and avoids a registry of hundreds of tiny dynamic dispatch entries.

Hard rules:

1. Vulnerable evidence is the only source of findings.
2. Suppression may only drop or annotate a candidate.
3. Suppression logic must read from `GoUnitFacts` first, not rescan the file.
4. A rule may have no suppression if the fixture corpus does not require one yet.
   Add suppression when it improves precision, not because the architecture demands ceremony.

---

## File and module boundaries

Keep files focused, but avoid turning line count into dogma.

Preferred limits:

- target under 800 to 1,200 lines for dense logic files
- split when cohesion drops or navigation gets painful
- avoid giant “assign.rs” or “everything regex.rs” dumps

This is better than a universal 3,000-line hard rule because it optimizes for maintainability, not just counting lines.

---

## Implementation phases

### Phase 0: Turn on real fixture validation

1. Update `tests/fixture_manifest_integration.rs` so `CWE-*` fixtures call `assert_fixture_rules`.
2. Run the test suite and capture the red state.
3. Record current timing for fixture and Go integration tests.

Deliverable:

- red-state proof that the fixtures are now actually enforced

### Phase 1: Build the fact layer

1. Add `src/lang/go/detectors/cwe/facts.rs`.
2. Define `GoUnitFacts` and compact helper enums.
3. Implement one primary AST walk plus optional regex-set scans.
4. Add tests for fact extraction itself.

Deliverable:

- a stable fact-builder that multiple rules can consume

### Phase 2: Add the orchestrator

1. Add `src/lang/go/detectors/cwe/mod.rs`.
2. Implement a bundled detector, for example `GoCweScan`.
3. Register it alongside existing Go detectors in `src/lang/go/detectors/mod.rs`.
4. Keep execution sequential within a unit.

Suggested shape:

```rust
pub struct GoCweScan;

impl Detector for GoCweScan {
    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        let facts = build_go_unit_facts(unit);
        let mut candidates = Vec::new();
        groups::call_injection::run_group(unit, &facts, &enabled, &mut candidates);
        groups::call_deser::run_group(unit, &facts, &enabled, &mut candidates);
        groups::decl_secrets::run_group(unit, &facts, &enabled, &mut candidates);
        groups::config_crypto::run_group(unit, &facts, &enabled, &mut candidates);
        groups::exposure_regex::run_group(unit, &facts, &enabled, &mut candidates);
        out.extend(suppress_candidates(unit, &facts, candidates));
    }
}
```

Deliverable:

- one detector entry point, one fact build, many rule evaluations

### Phase 3: Implement high-value rule groups

Priority order:

1. injection and traversal
   - `CWE-22`, `CWE-78`, `CWE-89`, `CWE-90`, `CWE-91`, `CWE-93`, `CWE-918`
2. deserialization and parser misuse
   - `CWE-502`, `CWE-611`, `CWE-940`, `CWE-941`
3. secrets and crypto config
   - `CWE-256`, `CWE-257`, `CWE-260`, `CWE-261`, `CWE-319`, `CWE-321`, `CWE-327`, `CWE-328`, `CWE-798`
4. exposure and misconfiguration rules that fit the fact model

For each rule:

- make the vulnerable fixture fire
- make the safe fixture suppress or avoid firing
- avoid coding to exact fixture text unless the rule is intentionally regex-only

### Phase 4: Fill out the rest of the manifest

Group remaining rules by implementation shape, not by CWE number ranges.

If a rule cannot be implemented credibly with text heuristics, mark it explicitly in the plan as:

- deferred
- fixture needs redesign
- intentionally regex-only with known precision limits

Do not hide weak rules inside a giant band checklist.

### Phase 5: Tune performance

1. profile fact building
2. profile top rule groups
3. merge duplicate scans
4. convert repeated textual scans to `RegexSet`
5. only then consider optional intra-unit parallelism for very large files

### Phase 6: Document the model

Add `src/lang/go/detectors/cwe/README.md` covering:

- fact-building pipeline
- rule group structure
- suppression philosophy
- how to add a new rule
- when a rule belongs in AST facts versus regex scans

---

## Canonical rule examples

### CWE-22 Path Traversal

Detection:

- sink call uses a path built from user-controlled input
- path-building evidence is captured in `CallFact` and origin markers

Suppression:

- sanitized path via `filepath.Clean`
- guarded by prefix validation before file access

### CWE-78 OS Command Injection

Detection:

- `exec.Command` arguments include concatenation, formatting, or user-controlled strings

Suppression:

- fixed argv construction
- explicit allow-list validation evidence

### CWE-89 SQL Injection

Detection:

- query call receives concatenated SQL or formatted SQL derived from input

Suppression:

- literal query with placeholders
- prepared statement helper evidence

### CWE-798 Hardcoded Credentials

Detection:

- declaration name looks credential-like and initializer is a non-empty string literal

Suppression:

- clearly test-only naming
- redacted or placeholder literal values

### CWE-918 SSRF

Detection:

- outbound HTTP request uses a user-controlled URL or host component

Suppression:

- parsed URL plus explicit host allow-list evidence

---

## Testing strategy

### Correctness

- vulnerable fixture should emit the expected rule id
- safe fixture should not emit that rule id
- existing `SLOP001` to `SLOP004` tests must remain green

### Precision safeguards

Add direct unit tests for:

- fact extraction
- suppression helpers
- deduping if multiple facts point at the same sink

### Performance safeguards

Add at least one targeted performance regression check around the fact-builder or Go CWE detector path.

---

## Explicit non-goals for v1

- no mandatory dynamic trait registry for every CWE
- no mandatory nested Rayon inside detector execution
- no cross-language abstraction in `src/core` unless proven by a second implementation
- no pretending the fixture corpus equals general-purpose security detection quality

---

## Deliverables checklist

- [x] `tests/fixture_manifest_integration.rs` enforces Go `CWE-*` fixtures for real
- [x] `GoUnitFacts` exists
- [x] Go CWE detector builds facts exactly once per unit
- [ ] High-priority rule groups are implemented and passing
- [ ] Remaining Go fixture rules are implemented, deferred explicitly, or redesign-noted
- [x] Safe fixtures no longer pass trivially
- [ ] Existing Go `SLOP001` to `SLOP004` coverage still passes
- [ ] Performance measurements recorded before and after
- [ ] `src/lang/go/detectors/cwe/README.md` documents the architecture

---

## Final assessment target

This plan is successful when:

- the fixtures are truly enforced
- the detector architecture centers on a reusable fact index instead of 175 isolated checks
- performance is dominated by one fact-build pass, not repeated AST walks or nested schedulers
- the code remains maintainable enough to keep extending without another rewrite
