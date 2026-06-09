# Missing D — Rule-Pack Extensibility Beyond Compile-Time

> **Parent:** `plans/p2.md` -- "Missing From This P2 Plan" -- Item D
> **Status:** Current architecture is clean for bundled rules, but adding new rule families requires shipping them in-tree and rebuilding the binary. No external rule-pack loading.
> **Estimated effort:** This plan covers scoping and design only (~3-5 days). Implementation will be a separate follow-up plan.

---

## Overview

SlopGuard has a strong plugin-like internal structure (detectors implement a trait, registry.toml drives code generation, domain modules organize by category). The next architectural step after bundled maturity is external rule-pack loading -- allowing users or third parties to add detectors without rebuilding the binary.

---

## Phase 1: Define Scope -- What Can Be Externalized?

### 1.1 Categorize rule-pack content types

- [ ] **Type 1: Metadata-only packs**
  - [ ] Pack contains rule descriptions (JSON) + registry (TOML) + test fixtures
  - [ ] Detector logic still compiled in-tree (function pointers in registry)
  - [ ] Use case: Adding rule descriptions for a new framework without writing Rust code
  - [ ] Feasibility: Easy -- metadata is data, not code
- [ ] **Type 2: Pattern-based detector packs**
  - [ ] Pack contains detection patterns expressed in a DSL (not raw Rust code)
  - [ ] DSL can express: find calls to `sql.DB.Query` where first argument contains `%` or `+`
  - [ ] Use case: Adding simple pattern-match detectors without Rust knowledge
  - [ ] Feasibility: Medium -- requires designing a detector DSL
- [ ] **Type 3: Compiled detector packs (WASM or dynamic libs)**
  - [ ] Pack contains compiled WebAssembly modules implementing the Detector trait
  - [ ] Use case: Full-power custom detectors from third parties
  - [ ] Feasibility: Hard -- requires WASM runtime integration, trait compatibility across binary boundaries
- [ ] **Type 4: Script-based detector packs (Lua/Rhai/Starlark)**
  - [ ] Pack contains scripts in a sandboxed scripting language
  - [ ] Scripts receive parsed unit facts and can emit findings
  - [ ] Use case: Quick prototyping, one-off checks
  - [ ] Feasibility: Medium -- requires embedding a scripting runtime

### 1.2 Decision: what is in scope?

- [ ] **Recommendation**: Start with Type 1 (metadata-only packs) as MVP
  - [ ] No code execution boundary to manage
  - [ ] Same safety guarantees as bundled rules
  - [ ] Enables community-contributed rule descriptions without a PR to slopguard
- [ ] **Future**: Type 2 (pattern DSL) for v2 -- highest value-to-effort ratio
- [ ] **Defer**: Type 3 (WASM) and Type 4 (scripting) -- significant complexity, evaluate demand first

### 1.3 Define rule pack format

- [ ] A rule pack is a directory containing:
  ```
  my-rule-pack/
  ├── pack.toml              # Pack manifest
  ├── rules.json             # Rule descriptions (same format as golang.json entries)
  ├── registry.toml          # Registry entries (same format as in-tree)
  └── fixtures/              # Optional test fixtures
      ├── vulnerable_XXX.txt
      └── safe_XXX.txt
  ```
- [ ] `pack.toml` format:
  ```toml
  [pack]
  name = "my-custom-rules"
  version = "1.0.0"
  description = "Custom rules for my team's codebase"
  author = "My Team"
  slopguard_min_version = "0.1.0"

  [language]
  name = "go"

  [category]
  name = "custom"
  ```

---

## Phase 2: Metadata-Only Pack Loading (Type 1 -- MVP)

### 2.1 Design the loading mechanism

- [ ] External packs extend the in-tree ruleset at runtime:
  - [ ] Load external `rules.json` entries and merge with in-tree `golang.json`
  - [ ] Load external `registry.toml` entries and merge with in-tree dispatch table
  - [ ] Detector functions for external rules must already exist in-tree (generic pattern-match detectors)
- [ ] Create a "generic pattern matcher" detector:
  - [ ] `GenericPatternDetector` -- takes a list of patterns and rule IDs
  - [ ] Each pattern specifies: import path, function call, argument constraints, message template
  - [ ] Registered dynamically from external pack's registry.toml
- [ ] Limitation (MVP): External packs can only use patterns the generic detector supports
  - [ ] If external rule needs complex AST analysis -- still needs compiled-in Rust code

### 2.2 Update `SlopguardConfig`

- [ ] Add `rule_packs` section to `SlopguardConfig`:
  ```toml
  [rule_packs]
  paths = ["./my-rules", "/usr/local/share/slopguard/rules/my-pack"]
  enabled = true
  ```
- [ ] Add fields to `SlopguardConfig` struct in `src/engine/config.rs`
- [ ] Update `slopguard.schema.json`

### 2.3 Implement pack discovery and loading

- [ ] Create `src/engine/pack.rs`
- [ ] `PackLoader` struct:
  - [ ] `pack_paths: Vec<PathBuf>`
  - [ ] `loaded_packs: Vec<RulePack>`
- [ ] `RulePack` struct:
  - [ ] `manifest: PackManifest`
  - [ ] `rules: Vec<ExternalRule>`
  - [ ] `registry: Vec<ExternalRegistryEntry>`
- [ ] `ExternalRule` struct:
  - [ ] `rule_id: String`
  - [ ] `description: RuleDescription` (reuse from `cwe::catalog`)
- [ ] `ExternalRegistryEntry` struct:
  - [ ] `rule_id: String`
  - [ ] `pattern: DetectionPattern`
- [ ] `DetectionPattern` struct:
  - [ ] `import_path: Option<String>`: e.g., "database/sql"
  - [ ] `function_selector: Option<String>`: e.g., "(*sql.DB).Query"
  - [ ] `argument_constraints: Vec<ArgConstraint>`
  - [ ] `message_template: String`
  - [ ] `severity: Severity`
- [ ] `ArgConstraint` enum:
  - [ ] `ContainsPlus` -- argument contains string concatenation
  - [ ] `ContainsFormat` -- argument contains `fmt.Sprintf`
  - [ ] `IsUserInput` -- argument comes from user input source
  - [ ] `IsVariable` -- argument is a non-literal variable
- [ ] `PackLoader::load_all() -> Result<Vec<RulePack>>`
  - [ ] Read `pack.toml` from each path
  - [ ] Validate version compatibility
  - [ ] Parse `rules.json`, validate against schema
  - [ ] Parse `registry.toml`, validate patterns
- [ ] Register `pack.rs` in `src/engine/mod.rs`

### 2.4 Integrate into scan pipeline

- [ ] In `app.rs::run()`:
  - [ ] Load external packs after config loading
  - [ ] Merge external rules into rule catalogue at runtime
  - [ ] Register external detector entries with the generic pattern matcher
- [ ] Create `GenericPatternDetector` in `src/lang/go/detectors/`:
  - [ ] Implements `Detector` trait
  - [ ] `rule_ids()` returns dynamically registered rule IDs
  - [ ] `run()` iterates patterns, checks each, emits findings
- [ ] Generic pattern check logic:
  1. Check import exists (if specified): source contains `"<import_path>"`
  2. Find call expressions matching `function_selector`
  3. For each argument with constraints, validate constraints
  4. If all match, emit finding with `message_template` populated
- [ ] Wire into Go plugin: add `GenericPatternDetector` to `src/lang/go/detectors/mod.rs::all()`

### 2.5 Limitations (MVP -- document clearly)

- [ ] Only Go language supported initially
- [ ] Only pattern-matching (no AST context beyond import + call expression)
- [ ] No custom detector logic (WASM/script not supported)
- [ ] No performance optimization for many external rules (all evaluated per file)
- [ ] Error handling: invalid pack -- warn, skip, continue
- [ ] Rule ID collisions: external rules must not use CWE-*, PERF-*, SLOP-* prefixes (reserved)

---

## Phase 3: Future Extensibility (Deferred to Future Plans)

### 3.1 Pattern DSL (Type 2)

- [ ] Design a declarative YAML/TOML DSL for detection rules
- [ ] Support: import checks, call pattern matching, regex on source, AST node matching
- [ ] Compile DSL to internal pattern matcher at load time
- [ ] Estimated effort: 4-6 weeks

### 3.2 WASM detector packs (Type 3)

- [ ] Embed a WASM runtime (`wasmtime` or `wasmer`)
- [ ] Define a stable WASM interface that mirrors the Detector trait
- [ ] Sandbox execution: no filesystem, no network, time budget per invocation
- [ ] Estimated effort: 8-12 weeks

### 3.3 Script-based packs (Type 4)

- [ ] Embed Rhai or Starlark runtime
- [ ] Expose safe API: `query_ast()`, `search_source(pattern)`, `emit_finding()`
- [ ] Sandbox: pure functions only, no I/O
- [ ] Estimated effort: 4-6 weeks

---

## Phase 4: Architecture Decisions (Required Before Implementation)

### 4.1 Preserve compile-time maintainability

- [ ] Rule: In-tree rules always use the Rust `Detector` trait directly (no DSL overhead)
- [ ] Rule: External packs use the generic detector infrastructure only
- [ ] Rule: Build-time code generation (`build.rs` from registry.toml) remains the canonical path for bundled rules
- [ ] Rule: Never mix compiled-in and external rule IDs in a way that makes debugging harder

### 4.2 Avoid weakening startup time

- [ ] Load external packs lazily on first scan (not at binary startup)
- [ ] Validate pack schema at load time with clear error messages
- [ ] Cache parsed packs in memory for the process lifetime
- [ ] Do not re-parse packs on each scan invocation (unless mtime changed)

### 4.3 Avoid weakening rule determinism

- [ ] External packs must declare their minimum slopguard version
- [ ] Version mismatch: warn but attempt to load (or refuse if major incompatibility)
- [ ] External rules with same ID as builtin: error at load time
- [ ] Snapshot the rule set at scan start -- no hot-reload during scan

---

## Phase 5: Testing

### 5.1 Unit tests

- [ ] Test `PackLoader::load_all()` with a valid pack directory
- [ ] Test pack with invalid `pack.toml` -- graceful error
- [ ] Test pack with missing `rules.json` -- graceful error
- [ ] Test pack with malformed patterns -- graceful error
- [ ] Test pack with rule ID collision -- error
- [ ] Test pack with version mismatch -- warning or error

### 5.2 Integration tests

- [ ] Create a test rule pack in `tests/fixtures/packs/valid-pack/`
- [ ] Scan a project with the external pack loaded
- [ ] Assert external rule findings appear alongside builtin findings
- [ ] Test `--only` and `--skip` with external rule IDs
- [ ] Test `--explain <external-rule-id>` works

### 5.3 Configuration tests

- [ ] Test config `rule_packs.paths` with multiple packs
- [ ] Test config `rule_packs.enabled = false` -- packs not loaded
- [ ] Test CLI `--rule-pack-path` overrides config paths

---

## Phase 6: CLI & Configuration

### 6.1 CLI Integration

- [ ] Add `--rule-pack-path` CLI flag:
  ```rust
  #[arg(long = "rule-pack-path", help = "Path to an external rule pack directory (can be repeated)")]
  pub rule_pack_path: Vec<PathBuf>,
  ```
- [ ] Add `--no-rule-packs` CLI flag:
  ```rust
  #[arg(long = "no-rule-packs", help = "Disable external rule pack loading")]
  pub no_rule_packs: bool,
  ```
- [ ] Config precedence: CLI paths add to config paths (union), `--no-rule-packs` disables all

### 6.2 Configuration schema

- [ ] Update `slopguard.schema.json` with `rule_packs` properties
- [ ] Update `templates/slopguard.toml` with commented-out example

---

## Dependencies

- `src/engine/config.rs` -- `SlopguardConfig` (adds `rule_packs` field)
- `src/cli/mod.rs` -- CLI flags
- `src/engine/` -- new `pack.rs` module
- `src/lang/go/detectors/` -- new `GenericPatternDetector`
- `src/app.rs` -- pack loading + detector registration
- `serde` + `serde_json` + `toml` crates (already in Cargo.toml)
- `cwe::catalog::RuleDescription` -- reuse existing struct
