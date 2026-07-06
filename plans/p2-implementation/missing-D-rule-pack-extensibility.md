# Missing D — Rule-Pack Extensibility Beyond Compile-Time

> **Parent:** `plans/p2.md` -- "Missing From This P2 Plan" -- Item D
> **Status:** Scoping and architecture design complete. Implementation of external rule-pack loading has not started and will be a separate follow-up plan.
> **Estimated effort:** Design ~3-5 days (done); implementation TBD.

---

## Overview

SlopGuard has a strong plugin-like internal structure (detectors implement a trait, registry.toml drives code generation, domain modules organize by category). The next architectural step after bundled maturity is external rule-pack loading -- allowing users or third parties to add detectors without rebuilding the binary.

---

## Phase 1: Define Scope -- What Can Be Externalized?

### 1.1 Categorize rule-pack content types

- [x] **Type 1: Metadata-only packs**
  - [x] Pack contains rule descriptions (JSON) + registry (TOML) + test fixtures
  - [x] Detector logic still compiled in-tree (function pointers in registry)
  - [x] Use case: Adding rule descriptions for a new framework without writing Rust code
  - [x] Feasibility: Easy -- metadata is data, not code
- [x] **Type 2: Pattern-based detector packs**
  - [x] Pack contains detection patterns expressed in a DSL (not raw Rust code)
  - [x] DSL can express: find calls to `sql.DB.Query` where first argument contains `%` or `+`
  - [x] Use case: Adding simple pattern-match detectors without Rust knowledge
  - [x] Feasibility: Medium -- requires designing a detector DSL
- [x] **Type 3: Compiled detector packs (WASM or dynamic libs)**
  - [x] Pack contains compiled WebAssembly modules implementing the Detector trait
  - [x] Use case: Full-power custom detectors from third parties
  - [x] Feasibility: Hard -- requires WASM runtime integration, trait compatibility across binary boundaries
- [x] **Type 4: Script-based detector packs (Lua/Rhai/Starlark)**
  - [x] Pack contains scripts in a sandboxed scripting language
  - [x] Scripts receive parsed unit facts and can emit findings
  - [x] Use case: Quick prototyping, one-off checks
  - [x] Feasibility: Medium -- requires embedding a scripting runtime

### 1.2 Decision: what is in scope?

- [x] **Recommendation**: Start with Type 1 (metadata-only packs) as MVP
  - [x] No code execution boundary to manage
  - [x] Same safety guarantees as bundled rules
  - [x] Enables community-contributed rule descriptions without a PR to slopguard
- [x] **Future**: Type 2 (pattern DSL) for v2 -- highest value-to-effort ratio
- [x] **Defer**: Type 3 (WASM) and Type 4 (scripting) -- significant complexity, evaluate demand first

### 1.3 Define rule pack format

- [x] A rule pack is a directory containing:
  ```
  my-rule-pack/
  ├── pack.toml              # Pack manifest
  ├── rules.json             # Rule descriptions (same format as golang.json entries)
  ├── registry.toml          # Registry entries (same format as in-tree)
  └── fixtures/              # Optional test fixtures
      ├── vulnerable_XXX.txt
      └── safe_XXX.txt
  ```
- [x] `pack.toml` format:
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

- [x] External packs extend the in-tree ruleset at runtime:
  - [x] Load external `rules.json` entries and merge with in-tree `golang.json`
  - [x] Load external `registry.toml` entries and merge with in-tree dispatch table
  - [x] Detector functions for external rules must already exist in-tree (generic pattern-match detectors)
- [x] Create a "generic pattern matcher" detector:
  - [x] `GenericPatternDetector` -- takes a list of patterns and rule IDs
  - [x] Each pattern specifies: import path, function call, argument constraints, message template
  - [x] Registered dynamically from external pack's registry.toml
- [x] Limitation (MVP): External packs can only use patterns the generic detector supports
  - [x] If external rule needs complex AST analysis -- still needs compiled-in Rust code

### 2.2 Update `SlopguardConfig`

- [x] Add `rule_packs` section to `SlopguardConfig`:
  ```toml
  [rule_packs]
  paths = ["./my-rules", "/usr/local/share/slopguard/rules/my-pack"]
  enabled = true
  ```
- [~] Add fields to `SlopguardConfig` struct — not implemented (deferred → see plans/v3.0.0/)
- [~] Update `slopguard.schema.json` — not implemented (deferred → see plans/v3.0.0/)

### 2.3 Implement pack discovery and loading

- [~] Create `src/engine/pack.rs` — not implemented (deferred → see plans/v3.0.0/)
- [~] `PackLoader` struct — not implemented (deferred → see plans/v3.0.0/)
- [~] `pack_paths`, `loaded_packs` (deferred → see plans/v3.0.0/)
- [~] `RulePack` struct (deferred → see plans/v3.0.0/)
- [~] `ExternalRule` struct (deferred → see plans/v3.0.0/)
- [~] `ExternalRegistryEntry` struct (deferred → see plans/v3.0.0/)
- [~] `DetectionPattern` struct (deferred → see plans/v3.0.0/)
- [~] `ArgConstraint` enum (deferred → see plans/v3.0.0/)
- [~] `PackLoader::load_all()` (deferred → see plans/v3.0.0/)
- [~] Validate version compatibility (deferred → see plans/v3.0.0/)
- [~] Parse/validate `rules.json` (deferred → see plans/v3.0.0/)
- [~] Parse/validate `registry.toml` (deferred → see plans/v3.0.0/)
- [~] Register `pack.rs` in `src/engine/mod.rs` (deferred → see plans/v3.0.0/)

### 2.4 Integrate into scan pipeline

- [~] In `app.rs::run()`: load external packs — not implemented (deferred → see plans/v3.0.0/)
- [~] Merge external rules into rule catalogue at runtime (deferred → see plans/v3.0.0/)
- [~] Register external detector entries (deferred → see plans/v3.0.0/)
- [~] Create `GenericPatternDetector` — not implemented (deferred → see plans/v3.0.0/)
- [~] Implements `Detector` trait (deferred → see plans/v3.0.0/)
- [~] `rule_ids()` returns dynamically registered IDs (deferred → see plans/v3.0.0/)
- [~] `run()` iterates patterns (deferred → see plans/v3.0.0/)
- [~] Generic pattern check logic (deferred → see plans/v3.0.0/)
1. [~] Check import exists — not implemented (deferred → see plans/v3.0.0/)
2. [~] Find call expressions matching `function_selector` (deferred → see plans/v3.0.0/)
3. [~] For each argument with constraints, validate constraints (deferred → see plans/v3.0.0/)
4. [~] If all match, emit finding (deferred → see plans/v3.0.0/)
- [~] Wire into Go plugin (deferred → see plans/v3.0.0/)

### 2.5 Limitations (MVP -- document clearly)

- [x] Only Go language supported initially
- [x] Only pattern-matching (no AST context beyond import + call expression)
- [x] No custom detector logic (WASM/script not supported)
- [x] No performance optimization for many external rules (all evaluated per file)
- [x] Error handling: invalid pack -- warn, skip, continue
- [x] Rule ID collisions: external rules must not use CWE-*, PERF-*, SLOP-* prefixes (reserved)

---

## Phase 3: Future Extensibility (Deferred to Future Plans)

### 3.1 Pattern DSL (Type 2)

- [~] Design a declarative YAML/TOML DSL for detection rules — future extensibility (deferred → see plans/v3.0.0/)
- [~] Support: import checks, call pattern matching, regex on source, AST node matching (deferred → see plans/v3.0.0/)
- [~] Compile DSL to internal pattern matcher at load time (deferred → see plans/v3.0.0/)

### 3.2 WASM detector packs (Type 3)

- [~] Embed a WASM runtime (`wasmtime` or `wasmer`) — future extensibility (deferred → see plans/v3.0.0/)
- [~] Define a stable WASM interface that mirrors the Detector trait (deferred → see plans/v3.0.0/)
- [~] Sandbox execution: no filesystem, no network, time budget per invocation (deferred → see plans/v3.0.0/)

### 3.3 Script-based packs (Type 4)

- [~] Embed Rhai or Starlark runtime — future extensibility (deferred → see plans/v3.0.0/)
- [~] Expose safe API: `query_ast()`, `search_source(pattern)`, `emit_finding()` (deferred → see plans/v3.0.0/)
- [~] Sandbox: pure functions only, no I/O (deferred → see plans/v3.0.0/)

---

## Phase 4: Architecture Decisions (Required Before Implementation)

### 4.1 Preserve compile-time maintainability

- [x] Rule: In-tree rules always use the Rust `Detector` trait directly (no DSL overhead)
- [x] Rule: External packs use the generic detector infrastructure only
- [x] Rule: Build-time code generation (`build.rs` from registry.toml) remains the canonical path for bundled rules
- [x] Rule: Never mix compiled-in and external rule IDs in a way that makes debugging harder

### 4.2 Avoid weakening startup time

- [x] Load external packs lazily on first scan (not at binary startup)
- [x] Validate pack schema at load time with clear error messages
- [x] Cache parsed packs in memory for the process lifetime
- [x] Do not re-parse packs on each scan invocation (unless mtime changed)

### 4.3 Avoid weakening rule determinism

- [x] External packs must declare their minimum slopguard version
- [x] Version mismatch: warn but attempt to load (or refuse if major incompatibility)
- [x] External rules with same ID as builtin: error at load time
- [x] Snapshot the rule set at scan start -- no hot-reload during scan

---

## Phase 5: Testing

### 5.1 Unit tests

- [~] Test `PackLoader::load_all()` with a valid pack directory — not implemented (deferred → see plans/v3.0.0/)
- [~] Test pack with invalid `pack.toml` (deferred → see plans/v3.0.0/)
- [~] Test pack with missing `rules.json` (deferred → see plans/v3.0.0/)
- [~] Test pack with malformed patterns (deferred → see plans/v3.0.0/)
- [~] Test pack with rule ID collision (deferred → see plans/v3.0.0/)
- [~] Test pack with version mismatch (deferred → see plans/v3.0.0/)

### 5.2 Integration tests

- [~] Create a test rule pack in `tests/fixtures/packs/valid-pack/` — not implemented (deferred → see plans/v3.0.0/)
- [~] Scan a project with the external pack loaded (deferred → see plans/v3.0.0/)
- [~] Assert external rule findings appear (deferred → see plans/v3.0.0/)
- [~] Test `--only` and `--skip` with external rule IDs (deferred → see plans/v3.0.0/)
- [~] Test `--explain <external-rule-id>` (deferred → see plans/v3.0.0/)

### 5.3 Configuration tests

- [~] Test config `rule_packs.paths` with multiple packs — not implemented (deferred → see plans/v3.0.0/)
- [~] Test config `rule_packs.enabled = false` (deferred → see plans/v3.0.0/)
- [~] Test CLI `--rule-pack-path` overrides config paths (deferred → see plans/v3.0.0/)

---

## Phase 6: CLI & Configuration

### 6.1 CLI Integration (design complete, implementation pending)

- [x] Design `--rule-pack-path` CLI flag:
  ```rust
  #[arg(long = "rule-pack-path", help = "Path to an external rule pack directory (can be repeated)")]
  pub rule_pack_path: Vec<PathBuf>,
  ```
- [x] Design `--no-rule-packs` CLI flag:
  ```rust
  #[arg(long = "no-rule-packs", help = "Disable external rule pack loading")]
  pub no_rule_packs: bool,
  ```
- [x] Config precedence: CLI paths add to config paths (union), `--no-rule-packs` disables all
- [~] Implement `--rule-pack-path` flag — not implemented (deferred → see plans/v3.0.0/)
- [~] Implement `--no-rule-packs` flag — not implemented (deferred → see plans/v3.0.0/)

### 6.2 Configuration schema (design complete, implementation pending)

- [x] Design `slopguard.schema.json` updates with `rule_packs` properties
- [x] Design `templates/slopguard.toml` commented-out example
- [~] Apply schema and template updates — not implemented (deferred → see plans/v3.0.0/)

---

## Dependencies

- `src/engine/config.rs` -- `SlopguardConfig` (adds `rule_packs` field)
- `src/cli/mod.rs` -- CLI flags
- `src/engine/` -- new `pack.rs` module
- `src/lang/go/detectors/` -- new `GenericPatternDetector`
- `src/app.rs` -- pack loading + detector registration
- `serde` + `serde_json` + `toml` crates (already in Cargo.toml)
- `cwe::catalog::RuleDescription` -- reuse existing struct
