# Plan 4: Infrastructure — Dependencies, Templates & Build

> **Priority:** Medium (maintenance and portability)

## Background

Several claimed infrastructure improvements were not actually applied. This plan covers the real changes needed.

## Checklist

### Phase 1: Add jiff and wire it up

- [ ] **1.1** Add `jiff = "0.2"` to `Cargo.toml` dependencies
- [ ] **1.2** In `src/reporting/sarif.rs`, replace `iso8601_utc_now()` and `unix_epoch_to_ymdhms()` with `jiff::Timestamp::now().to_string()`
- [ ] **1.3** Remove the 35-line custom calendar math functions
- [ ] **1.4** Remove `use std::time::SystemTime` if no longer needed
- [ ] **1.5** Update `tests/reporting_sarif.rs` if it tests date formatting

### Phase 2: Move init template to templates/

- [ ] **2.1** Create `templates/slopguard.toml` with the content from `src/app.rs:219-240` (`const TEMPLATE`)
- [ ] **2.2** In `src/app.rs`, replace the inline `const TEMPLATE: &str = "..."` with `const TEMPLATE: &str = include_str!("../templates/slopguard.toml");`
- [ ] **2.3** Update the template to reference the new 5-level severity (Medium instead of Warning)

### Phase 3: Feature-gate colored

- [ ] **3.1** Add `terminal-output` feature to `Cargo.toml`:
  ```toml
  [features]
  terminal-output = ["dep:colored"]
  ```
- [ ] **3.2** Make `colored` optional: `colored = { version = "2.1", optional = true }`
- [ ] **3.3** Add `default = ["go", "python", "terminal-output"]` (backward compatible)
- [ ] **3.4** Gate `use colored::Colorize` in `src/reporting/text.rs` behind `#[cfg(feature = "terminal-output")]`
- [ ] **3.5** Gate `colored::control::set_override` in `src/app.rs` similarly
- [ ] **3.6** Provide a no-color fallback in text.rs when the feature is disabled

### Phase 4: Fix default_ruleset_path portability

- [ ] **4.1** In `src/cwe/catalog.rs:default_ruleset_path()`, detect installed-vs-development mode
- [ ] **4.2** For installed binaries: look relative to the binary path or XDG data dir
- [ ] **4.3** Fall back to CARGO_MANIFEST_DIR for development
- [ ] **4.4** Or: embed the ruleset JSON via `include_str!` at compile time (eliminates runtime file dependency)

### Phase 5: Remove dead CLI flag

- [ ] **5.1** Remove `--verbose: u8` from `src/cli/mod.rs:61-62` (parsed but never read)
- [ ] **5.2** OR implement verbosity control by wiring it to tracing level

### Phase 6: Fix CI bench parsing

- [ ] **6.1** In `.github/workflows/ci.yml`, verify the bencher output format actually contains commas
- [ ] **6.2** Replace the fragile `awk -F','` extraction with a regex-based approach
- [ ] **6.3** Test the CI script locally: `cargo bench --bench scan_throughput -- --output-format bencher | bash ci_check.sh`

### Phase 7: Create CHANGELOG.md

- [ ] **7.1** Create `CHANGELOG.md` with entries for:
  - v0.0.2: Sink registry, TreeCursor, module reorganization, CWE catalog expansion
  - v0.0.2: argument_uses_identifier substring fix, phf dependencies, CI perf budget

### Phase 8: Fix benchmarks.md inaccuracies

- [ ] **8.1** Remove/update claims about 5-level severity (not implemented yet)
- [ ] **8.2** Remove/update claims about phf SourceIndex (not implemented yet)
- [ ] **8.3** Remove/update claims about jiff (not implemented yet)
- [ ] **8.4** Remove/update claims about templates/ (not created yet)
- [ ] **8.5** Clearly mark which items are "planned" vs "implemented"

## Verification

- [ ] `cargo build --no-default-features --features go` produces a working binary without colored
- [ ] `cargo build` includes terminal-output by default (backward compatible)
- [ ] `cargo run -- init` creates a valid slopguard.toml with correct template
- [ ] SARIF output includes ISO 8601 timestamps from jiff
- [ ] Installed binary can find the ruleset (or has it embedded)
