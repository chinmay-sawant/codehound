# Plan: Implement Text-Based Heuristic Detectors for Go CWE Fixtures

## Goal

Add actual detection logic for the 175 CWE rules in `ruleset/golang/golang.json` so that the existing **Go** vulnerable/safe fixtures under `tests/fixtures/go/frameworks/` and `tests/fixtures/go/stdlib/` are **truly exercised** by the analyzer.

> **Scope:** This plan covers **Go only** (stdlib and framework fixtures). Support for other languages (Python, Rust, etc.) will be added in future milestones by replicating the same modular architecture under `src/lang/<lang>/`.

The architecture must be **decoupled, multithreaded and optimized**:  
- **Vulnerable patterns have priority.** Detection is a positive (vulnerable-pattern) first pipeline.  
- **Safe patterns act only as suppressors.** When a vulnerable pattern fires on a `ParsedUnit`, safe-pattern validators run against that candidate; if a safe pattern matches, the finding is dropped. Safe patterns never generate findings on their own.  
- **Multithreading inside the detector.** Matcher groups run in parallel across CPU cores; safe validators run in parallel over the candidate list.  
- **Single-pass, grouped AST walks.** No repeated tree traversals per matcher.  
- **Small files.** No single source file may exceed **3,000 lines**. Every module is split into focused sub-modules.

---

## Current state (confirmed)

- `cargo test --test fixture_manifest_integration` passes.
- However, for every entry whose `required_rules` start with `CWE-`, the test runs `assert_fixture_materializes()` only — it verifies the `.txt` fixture parses and the Go body compiles, but **it does not verify the rule fires**.
- The Go plugin (`src/lang/go/`) currently registers only `GoScan`, which implements `SLOP001–SLOP004` (performance loop detectors). No CWE detectors exist.
- Result: **all 700+ CWE fixtures pass trivially**, both vulnerable and safe, because no code ever checks whether the CWE rule actually triggers.

---

## High-level pipeline (per ParsedUnit)

```
ParsedUnit
    │
    ▼
┌─────────────────────────────────────┐
│ Stage 1 — DETECT (parallel)         │  <-- vulnerable-pattern matchers
│  - Group A: call_expression checks  │      run concurrently via thread pool
│  - Group B: declaration checks    │
│  - Group C: raw-regex scans       │
│  → emits CandidateFindings[]        │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│ Stage 2 — SUPPRESS (parallel)       │  <-- safe-pattern validators
│  - For each candidate, run the     │      run concurrently over candidates
│    safe suppressor(s) for that CWE │
│  - If any suppressor matches → drop│
│  → emits FinalFindings[]           │
└─────────────────────────────────────┘
```

---

## Architecture additions (decoupled & future-proof)

### 1. Traits — `src/core/heuristic_traits.rs` (language-agnostic)

> **Why `src/core/` and not `src/lang/go/`?** These traits define the detect→suppress contract. They are **language-agnostic** so that `src/lang/python/`, `src/lang/rust/`, etc. can implement the same trait interface in future milestones without duplicating logic.

```rust
/// Positive detection pattern for a specific CWE.
pub trait VulnerableMatcher: Send + Sync {
    fn cwe_id(&self) -> &'static str;
    fn match_unit(&self, unit: &ParsedUnit) -> Vec<CandidateFinding>;
}

/// Safe-pattern suppressor for a specific CWE.
/// Only run when the corresponding VulnerableMatcher produced candidates.
pub trait SafeSuppressor: Send + Sync {
    fn cwe_id(&self) -> &'static str;
    /// Return true if the candidate should be suppressed (i.e., the file is safe).
    fn should_suppress(&self, unit: &ParsedUnit, candidate: &CandidateFinding) -> bool;
}
```

**Hard rule:** These traits must live in `src/core/` and must not import any language-specific types (e.g., `tree_sitter::Node` is fine because it is generic, but no `GoPlugin` or `go::matchers::*`).

### 2. Registry — `src/core/heuristic_registry.rs`

> **Why `src/core/`?** `CweRegistry` is a generic registry of `VulnerableMatcher` + `SafeSuppressor` pairs. It is instantiated by each language plugin with that language's concrete matchers.

- Holds two maps:
  - `vulnerable: HashMap<&'static str, Vec<Box<dyn VulnerableMatcher>>>` — keyed by CWE id.
  - `suppressors: HashMap<&'static str, Vec<Box<dyn SafeSuppressor>>>` — keyed by CWE id.
- `register(matcher, suppressor)` pairs are appended atomically (no runtime mutation after init).
- Built statically at plugin construction time; no dynamic rule generation.
- **File size guard:** If the registry implementation grows past 500 lines, split the parallel dispatch helpers into `src/core/heuristic_registry_par.rs`.

### 3. Orchestrator — `src/lang/go/detectors/cwe_orchestrator.rs`

```rust
use slopguard::core::heuristic_registry::CweRegistry;

pub struct GoCweOrchestrator {
    registry: Arc<CweRegistry>,
}

impl Detector for GoCweOrchestrator {
    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        // Stage 1 — parallel detection across matcher groups
        let candidates = self.registry.vulnerable_par(unit);

        // Stage 2 — parallel suppression over candidates
        let findings = self.registry.suppress_par(unit, candidates);

        out.extend(findings);
    }
}
```

> **Naming:** Prefix the orchestrator with `Go` (`GoCweOrchestrator`) so that future Python/Rust orchestrators are unambiguous (`PythonCweOrchestrator`, `RustCweOrchestrator`).

**Threading model:**
- Use `rayon` (add to `Cargo.toml` if absent) for both stages:
  - `registry.vulnerable_par(unit)` uses `rayon::join` / `rayon::scope` to run each matcher group on a separate rayon thread.
  - `registry.suppress_par(unit, candidates)` uses `rayon::filter` over the candidate list.
- If `rayon` is undesirable, fall back to `std::thread::scope` (Rust 1.63+); document the choice.
- The orchestrator is **one** `Detector` implementation registered in `src/lang/go/detectors/mod.rs`; it replaces the monolithic `CweTextHeuristicScan` concept.

### 4. Matcher groups (single-pass, per node kind) — strict file-size limits

Instead of one matcher per CWE doing its own AST walk, matchers are grouped by the node kind they inspect. **No group file may exceed 3,000 lines.** If a group approaches that limit, split it by CWE sub-category into a new file:

| Group module | Node kinds inspected | Example CWEs covered |
|---|---|---|
| `matchers/call_expr_injection.rs` | `call_expression` (injection & traversal) | 22, 78, 89, 90, 91, 93, 434, 611, 918 |
| `matchers/call_expr_deser.rs` | `call_expression` (deserialization & SSRF) | 502, 940, 941 |
| `matchers/decl_crypto.rs` | `const_declaration`, `var_declaration` | 256, 260, 261, 319, 323–328, 331, 335 |
| `matchers/decl_secrets.rs` | `const_declaration`, `var_declaration` | 798, 352, 362, 497, 521, 549, 551, 552, 565, 601, 603, 613, 615, 639, 640, 645, 648, 649, 653, 654, 656 |
| `matchers/assign.rs` | `assignment_statement` | 15, 276, 280, 283, 294, 306, 312, 366, 367, 368, 379, 385, 393, 403, 412, 421, 425, 426, 427, 472, 488, 501, 515, 523, 524, 538, 547, 605, 618, 619, 620, 708, 756, 765, 778, 783, 807, 820, 821, 826, 829, 836, 838, 841, 842, 909, 915, 916, 917, 921, 924, 1051, 1052, 1067, 1125, 1173, 1204, 1220, 1230, 1236, 1240, 1265, 1286, 1289, 1322, 1327, 1333, 1389, 1392 |
| `matchers/raw_regex.rs` | Full source string (pre-compiled `Regex` set) | 200, 201, 204, 208, 209, 212, 213, 214, 215, 497, 532, 544, 548, 598, 612 |

**Splitting rule:** When a `.rs` file hits **2,500 lines**, open a new file before it reaches 3,000. Use descriptive suffixes (`_injection.rs`, `_crypto.rs`, `_secrets.rs`, etc.).

Each group performs **one** `walk_nodes` (or one `regex.find_iter`) and internally dispatches to the individual `VulnerableMatcher` implementations for that group. This keeps AST walks O(1) per unit regardless of matcher count.

### 5. Safe suppressors (mirror structure, same file-size limits)

For every `VulnerableMatcher` there is an optional `SafeSuppressor` in the same group module (or a parallel `suppressors/` submodule if the file grows too large). Example:

- `matchers/call_expr_injection.rs` defines:
  - `Cwe22PathTraversalMatcher` (detects `filepath.Join` + user input without guard)
  - `Cwe22PathTraversalSuppressor` (detects presence of `filepath.Clean` + `strings.HasPrefix` guard)

A suppressor is **only** invoked for candidates produced by its paired matcher. This avoids wasted work on files that do not contain the vulnerable pattern at all.

**If a matcher + suppressor pair exceeds ~200 lines**, move it to its own file under `matchers/cwe_22/` (or similar) and re-export from the group module. The 3,000-line limit applies to every committed `.rs` file without exception.

---

## Detection → Suppression flow (example: CWE-22)

### Vulnerable fixture (`CWE-22-vulnerable.txt`)
```go
target := filepath.Join(vaultRoot, docName)
data, err := os.ReadFile(target)
```
- `Cwe22PathTraversalMatcher` sees `filepath.Join` with `docName` (from `r.URL.Query().Get`) and no guard → emits candidate.
- `Cwe22PathTraversalSuppressor` looks for `filepath.Clean` or `strings.HasPrefix` guard; finds none → **keep** finding.

### Safe fixture (`CWE-22-safe.txt`)
```go
target := filepath.Join(vaultRoot, filepath.Clean("/"+docName))
if !strings.HasPrefix(target, vaultRoot+string(os.PathSeparator)) { ... }
data, err := os.ReadFile(target)
```
- `Cwe22PathTraversalMatcher` sees `filepath.Join` with user input → still emits candidate (the pattern alone cannot distinguish safe vs unsafe; that is the suppressor's job).
- `Cwe22PathTraversalSuppressor` detects `filepath.Clean` + `strings.HasPrefix` guard → **suppress** finding.
- Result: zero findings on safe file.

This design intentionally separates recall (matcher) from precision (suppressor).

---

## Threading & performance requirements

1. **Rayon thread pool**  
   - Add `rayon = "1"` to `Cargo.toml` (or confirm it is already present transitively).  
   - The orchestrator uses `rayon::scope` to launch matcher groups concurrently.

2. **Pre-compiled regexes**  
   - All regex patterns live as `once_cell::sync::Lazy<Regex>` (or `lazy_static!`) in the matcher modules. No runtime compilation per file.

3. **Zero-allocation candidate pass**  
   - `CandidateFinding` holds byte offsets (`start_byte`, `end_byte`) instead of owned strings. Final `Finding` objects (with snippets) are materialized only after suppression, and only for kept findings.

4. **Group-local caches**  
   - If a matcher needs to look up "does this file contain X?", it computes it once per unit and shares the result among sub-matchers in the same group via a lightweight `UnitCache` struct passed down during the walk.

---

## Implementation phases

### Phase 0 — Infrastructure (1 subagent)

1. Add traits `VulnerableMatcher` and `SafeSuppressor` in **`src/core/heuristic_traits.rs`**.
2. Add `CweRegistry` in **`src/core/heuristic_registry.rs`**.
3. Add `GoCweOrchestrator` in `src/lang/go/detectors/cwe_orchestrator.rs`.
4. Wire the orchestrator into `src/lang/go/detectors/mod.rs` (append to `all()`).
5. Add `rayon` to `Cargo.toml` if missing.
6. Update `tests/fixture_manifest_integration.rs`: remove the `pending_cwe` short-circuit so that **all** manifest entries now call `assert_fixture_rules`.
7. Run `cargo test --test fixture_manifest_integration`.
   - **Expectation:** every vulnerable fixture fails because the rule does not fire. This is the "red" state we want.
   - Record the list of failing CWEs.
8. **File-size audit:** run `find src/lang/go/detectors -name '*.rs' -exec wc -l {} +` and confirm no file exceeds 3,000 lines. If any does, split it before proceeding.

### Phase 1 — High-impact matchers & suppressors for Go (3 subagents, parallel)

> **Scope reminder:** Only Go fixtures (`tests/fixtures/go/frameworks/` and `tests/fixtures/go/stdlib/`) are in scope. Do not write matchers for Python or Rust.

Split the 175 Go CWEs into 3 bands by category. Each subagent owns **both** matchers and suppressors for its band.

**Band A — Injection, traversal, SSRF, deserialization**  
CWEs: 15, 22, 41, 59, 76, 78, 79, 89, 90, 91, 93, 112, 434, 502, 611, 918, 940, 941  
- Deliver `matchers/call_expr_injection.rs` and `matchers/call_expr_deser.rs` with vulnerable matchers + safe suppressors.
- If any file approaches 2,500 lines, split by CWE sub-category immediately.

**Band B — Crypto, secrets, auth, authz, config**  
CWEs: 256, 257, 260, 261, 262, 263, 264, 265, 266, 267, 268, 270, 272, 273, 274, 276, 277, 279, 280, 281, 283, 294, 306, 307, 308, 309, 312, 319, 321, 322, 323, 324, 325, 327, 328, 331, 335, 338, 347, 352, 359, 360, 362, 366, 367, 368, 378, 379, 385, 393, 403, 412, 420, 421, 425, 426, 427, 472, 488, 497, 501, 515, 521, 523, 524, 538, 547, 549, 551, 552, 565, 601, 603, 605, 611, 613, 618, 619, 620, 639, 640, 645, 648, 649, 653, 654, 656, 708, 756, 765, 778, 783, 798, 807, 820, 821, 826, 829, 836, 838, 841, 842, 909, 915, 916, 917, 921, 924, 1051, 1052, 1067, 1125, 1173, 1204, 1220, 1230, 1236, 1240, 1265, 1286, 1289, 1322, 1327, 1333, 1389, 1392  
- Deliver `matchers/decl_crypto.rs`, `matchers/decl_secrets.rs`, and `matchers/assign.rs` with vulnerable matchers + safe suppressors.
- **Hard limit:** If `assign.rs` exceeds 2,500 lines, split into `matchers/assign_auth.rs`, `matchers/assign_config.rs`, etc.

**Band C — Exposure, logic, concurrency, misc**  
CWEs: all remaining in the manifest  
- Deliver `matchers/raw_regex.rs` and any additional AST group files with vulnerable matchers + safe suppressors.

**Subagent rules:**
- For each CWE, author **one** `VulnerableMatcher` that reliably fires on the vulnerable fixture.
- For each CWE, author **one** `SafeSuppressor` that suppresses the candidate when run on the safe fixture.
- Register each pair in `CweRegistry::default()` via a `register!` macro or helper.
- Re-run `cargo test --test fixture_manifest_integration` scoped to the band's CWE ids.
- **After each subagent finishes, run:** `find src/lang/go/detectors -name '*.rs' -exec sh -c 'lines=$(wc -l < "$1"); if [ "$lines" -gt 3000 ]; then echo "FAIL: $1 has $lines lines"; exit 1; fi' _ {} \;`

### Phase 2 — Tuning & false-positive audit (1 subagent)

1. Run the full integration suite:
   ```bash
   cargo test --test fixture_manifest_integration --test go_integration
   ```
2. For any **safe** fixture that fires a rule:
   - The suppressor missed. Inspect the safe fixture body, tighten the suppressor condition (e.g., require both `filepath.Clean` **and** `HasPrefix`), or add an additional suppressor.
3. For any **vulnerable** fixture that does *not* fire:
   - The matcher missed. Loosen the matcher slightly (e.g., accept `os.Open` in addition to `os.ReadFile`) or fix an AST node kind mismatch.
4. Ensure no regression on `SLOP001–SLOP004` (`go_integration.rs` must still pass).
5. Profile with `cargo test --test fixture_manifest_integration -- --nocapture` and confirm runtime is acceptable (target: < 2× baseline).

### Phase 3 — Documentation & lock-in (1 subagent)

1. Update this plan's deliverables checklist to mark completed items.
2. Add `src/lang/go/detectors/README.md` describing:
   - The two-stage detect→suppress pipeline.
   - How to add a new `VulnerableMatcher` + `SafeSuppressor` pair for Go.
   - Threading model and performance notes.
   - File-size policy (3,000-line hard limit) and how to split a group module.
   - Note on future language support (refer to `src/core/heuristic_traits.rs` and `src/core/heuristic_registry.rs`).
3. Ensure `cargo test` (full suite) passes cleanly.
4. Final file-size audit: confirm zero `.rs` files in `src/lang/go/detectors/` exceed 3,000 lines.

---

## Starter patterns (canonical examples for subagents)

### CWE-22 — Path Traversal
- **Matcher:** `call_expression` to `filepath.Join` or `os.ReadFile`/`os.Open` where an argument originates from `r.URL.Query().Get` or another user-input source.
- **Suppressor:** Presence of `filepath.Clean` applied to the user-input argument **and** an `if` guard using `strings.HasPrefix(target, base)`.

### CWE-78 — OS Command Injection
- **Matcher:** `call_expression` to `exec.Command` where any argument contains `+` concatenation or `fmt.Sprintf` and the argument derives from user input.
- **Suppressor:** `exec.Command` called with a fixed argv slice (no string concatenation/Sprintf) or input is passed through an explicit allow-list function.

### CWE-89 — SQL Injection
- **Matcher:** `call_expression` to `db.Query`/`QueryRow`/`Exec` where the first argument is a `binary_expression` with `+` or a `call_expression` to `fmt.Sprintf`.
- **Suppressor:** First argument is a raw string literal with only `?` placeholders (no concatenation/Sprintf) or uses a prepared-statement helper.

### CWE-798 — Hardcoded Credentials
- **Matcher:** `const_declaration` or `var_declaration` where identifier matches `(?i)(password|secret|token|apikey|key)` and initializer is a string literal.
- **Suppressor:** Identifier is a well-known test constant (`testPassword`, `mockSecret`) **or** the string literal is `""` / `"*"` / `"redacted"`.

### CWE-319 — Cleartext Transmission
- **Matcher:** `tls.Config` struct literal containing `InsecureSkipVerify: true`.
- **Suppressor:** The struct is immediately wrapped in a function named `InsecureTestConfig` or similar (convention-based test bypass) **or** the file is under a `_test.go` path. (For fixtures, we can use a comment-based pragma instead if needed.)

### CWE-502 — Unsafe Deserialization
- **Matcher:** `call_expression` to `json.Unmarshal` with second argument `interface{}` and input from `r.Body` or query parameter.
- **Suppressor:** Input is validated through a struct tag-based decoder (`Decoder.DisallowUnknownFields`) or the target is a concrete struct (not `interface{}`).

### CWE-918 — SSRF
- **Matcher:** `call_expression` to `http.Get`/`http.Post` where URL string contains `r.URL.Query().Get(...)`.
- **Suppressor:** URL is parsed through `url.Parse` and the host is checked against an explicit allow-list slice before the HTTP call.

---

## Hard rules

1. **Vulnerable patterns are the only source of findings.** Safe patterns may only suppress; they never emit.
2. **Every matcher must have a paired suppressor** (even if the suppressor is a no-op for now). This enforces the architecture and makes future precision improvements trivial.
3. **No monolithic mega-file.** Each matcher group lives in its own module under `src/lang/go/detectors/matchers/`. The orchestrator dispatches; groups do not know about each other.
4. **Strict 3,000-line file limit.** No `.rs` file in the detector tree may exceed 3,000 lines. Split at 2,500 lines proactively. This applies to the orchestrator, registry, traits, and every matcher group.
5. **No dynamic rule generation.** Matchers and suppressors are statically coded Rust structs. Do not read `golang.json` at runtime to build regexes.
6. **Thread safety.** All matcher/suppressor state is immutable after construction (`Send + Sync`). `rayon` is used for parallelism; no manual `Mutex` around matcher logic.
7. **Performance budget.** A single unit with 50 matchers must complete in < 5 ms on a modern laptop. If a matcher is expensive, move it to `raw_regex.rs` and limit regex complexity.

---

## Future language support (out of scope for this plan, but architected for)

The traits (`VulnerableMatcher`, `SafeSuppressor`) and the registry (`CweRegistry`) live in `src/core/` so they are reusable. When adding Python or Rust support in a future milestone, the work is:

1. Implement language-specific matchers under `src/lang/python/detectors/matchers/` and `src/lang/rust/detectors/matchers/`.
2. Instantiate a `CweRegistry` in `src/lang/python/detectors/mod.rs` (or `rust/detectors/mod.rs`) and register the language's concrete pairs.
3. Provide `PythonCweOrchestrator` / `RustCweOrchestrator` implementing the existing `Detector` trait.
4. Register the new orchestrator in that language's `mod.rs`.

No changes to `src/core/`, `src/engine/`, or `src/rules/` are required.

---

## Deliverables checklist

- [ ] Phase 0: Language-agnostic traits in `src/core/heuristic_traits.rs` and registry in `src/core/heuristic_registry.rs`. Go orchestrator wired. `pending_cwe` short-circuit removed. Red state confirmed.
- [ ] Phase 0: File-size audit passes — no `.rs` file in detector tree exceeds 3,000 lines.
- [ ] Phase 1A: Go injection/traversal/SSRF/deserialization matchers & suppressors implemented; band passes.
- [ ] Phase 1B: Go crypto/secrets/auth/authz/config matchers & suppressors implemented; band passes.
- [ ] Phase 1C: Go remaining CWE matchers & suppressors implemented; band passes.
- [ ] Phase 1 (all): No detector source file exceeds 3,000 lines; proactively split at 2,500.
- [ ] Phase 2: All safe fixtures produce zero findings for their CWE rule; all vulnerable fixtures produce exactly one finding.
- [ ] Phase 2: No regression on `SLOP001–SLOP004` (`go_integration.rs` still passes).
- [ ] Phase 2: Multithreading confirmed active (add `RAYON_NUM_THREADS` env test or benchmark note).
- [ ] Phase 3: `cargo test` (full suite) passes cleanly.
- [ ] Phase 3: Go detector README added under `src/lang/go/detectors/` (includes future-language support note).
- [ ] Phase 3: Final file-size audit passes.

---

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| 175 matcher/suppressor pairs in one crate becomes unwieldy. | Already mitigated by group modules. If a group exceeds 30 pairs, split it into sub-groups by node sub-kind. |
| False positives on safe fixtures because suppressor is too weak. | Tighten suppressor by requiring multiple safe signals (e.g., both `Clean` **and** `HasPrefix` for CWE-22). Add negative fixture to unit-test the suppressor in isolation. |
| Tree-sitter node kinds change across grammar updates. | Use only stable kinds (`call_expression`, `binary_expression`, `if_statement`, `short_var_declaration`, `const_declaration`). Avoid child-index assumptions; use named field retrieval where possible. |
| Regex performance degrades with many patterns. | Compile once with `Lazy<Regex>`. Use `regex::RegexSet` when multiple patterns scan the same source region. |
| Rayon overhead hurts on tiny fixtures. | The orchestrator falls back to sequential execution when `unit.source.len() < 512` bytes (configurable threshold). Document this in the code. |

