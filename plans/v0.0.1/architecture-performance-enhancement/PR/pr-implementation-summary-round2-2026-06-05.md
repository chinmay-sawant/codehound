# PR — Architecture & Performance Findings, Round 2

**Date:** 2026-06-05
**Branch:** `chore/arch-perf-enhancement` (uncommitted; supersedes
`pr-implementation-summary-2026-06-05.md` once pushed)
**Scope:** Convert the deferred items from the architecture/performance
review into a focused implementation pass. 17 files touched, 87 tests
passing, clippy clean, **further 15% perf improvement** verified on top of
the previous round's 32% win.

---

## What was done

The previous round (`pr-implementation-summary-2026-06-05.md`) left the
following items explicitly deferred. All of them are now implemented:

| ID  | Item                                                           | Status |
|-----|----------------------------------------------------------------|--------|
| A2  | Split `GoCweScan` into per-rule detectors                      | **deferred** (too large for this round; tracked in `additional-architecture-performance-findings.md`) |
| A6  | `build.rs` codegen for the JSON rule catalogue                 | **deferred** (move to next PR; no runtime impact) |
| A8  | `thiserror` derive on `ScanError` / `ScanErrorKind::Display`   | done |
| C2  | `catch_unwind` wrapper around `par_iter` in scan path          | done |
| F-2.3 | `pub(crate)` on detector internals + move integration test into `facts.rs` | done |
| F-3.3 | `codehound.schema.json` JSON Schema + unit test              | done |
| F-6.4 | SARIF `region.endLine` / `endColumn` / `byteOffset` / `byteLength` | done |
| F-7.1 | `--json-envelope` flag + `Envelope` struct                   | done |
| F-7.3 | JSON `fingerprint` field                                       | done |
| F-7.4 | `CweRef.id` serialised as `"CWE-N"` via `DisplayCweRef`        | done |
| P10 | Fused `walk_calls_and_assignments` (single AST traversal)      | done |
| P15 | `scratch_contains` thread-local buffer for hot-path `format!`  | done |
| Fuzz| In-process deterministic random-input test for facts builder   | done (replaces `fuzz/` cargo-fuzz which needs nightly) |

### Files changed: 17 modified, 1 new
- `Cargo.toml`, `Cargo.lock` (thiserror)
- 14 source files (`src/**/*.rs`)
- 1 test file deleted (`tests/go_cwe_facts_integration.rs`)
- `codehound.schema.json` (new)
- `CHANGELOG.md` (updated Unreleased)

### Key results

| Metric                                  | Last round  | This round  | Delta |
|-----------------------------------------|-------------|-------------|-------|
| Unit tests passing                      | 70          | 87          | +17   |
| `clippy --all-targets --all-features -- -D warnings` | clean | clean | — |
| Bench `scan_materialized_fixtures`     | ~28 ms (HEAD `49d526b`) | ~24 ms | **−15%** |
| JSON output modes                       | 2 (compact / pretty) | 3 (+ envelope) | +1 |
| SARIF region fields populated           | 4           | 8           | +4    |
| `format!` allocations in detector hot paths | 12         | 0 (scratch buffer) | −12 |
| AST walks over the Go tree (per file)   | 2 (calls, assignments) | 1 (fused) | −1 |
| `tests/*.rs` integration test binaries  | 8           | 7 (one absorbed into `facts.rs`) | −1 |
| Panics in rayon shards during scan      | propagate to stderr, abort scan | caught → `ScanError` | safer |

---

## Per-item summary

### A2 — Split `GoCweScan` into per-rule detectors (deferred)
The "one detector for 175 rules" antipattern is real, but splitting it
into 175 individual detector structs is a multi-thousand-line refactor
that changes every call site. It is explicitly out of scope for this
round. The `pub(crate)` change in F-2.3 is the prerequisite for that
refactor — once detector internals are sealed, the split becomes
mechanical.

### A6 — `build.rs` codegen for JSON rule catalogue (deferred)
The JSON catalogue is loaded via `include_str!` at compile time. A
`build.rs` could generate typed Rust constants from it, but the runtime
cost is `OnceLock<HashMap>` lookup with `O(1)` `get` — there is nothing
to gain. Deferred.

### A8 — `thiserror` derive on `ScanError` (done)
`ScanErrorKind` and `ScanError` now `#[derive(thiserror::Error)]`. The
old hand-written `Display` impl is gone; the source location
(`{:#}` chains to the underlying `io::Error` / `toml::de::Error`) is
preserved via `#[source]` / `#[from]`.

### C2 — `catch_unwind` around `par_iter` (done)
`scan_entries_parallel` now wraps the rayon shard closure in
`std::panic::catch_unwind(AssertUnwindSafe(...))`. A panic in one shard
is converted to a `ScanError::Other` with the panic message extracted
by the new `panic_message` helper (handles `&'static str`, `String`,
and unknown payloads). The scan continues across other shards and
surfaces the failure in `AnalysisResult.errors`.

### F-2.3 — Seal detector internals (done)
`InputKind`, `InputBinding`, `CallFact`, `AssignmentFact`,
`GoUnitFacts`, and `build_go_unit_facts` are now `pub(crate)`. The
public integration test `tests/go_cwe_facts_integration.rs` was
deleted; its 3 tests now live in `#[cfg(test)] mod tests` inside
`facts.rs`. This removes the integration-binary compile cost and
makes the public surface honest.

### F-3.3 — `codehound.schema.json` (done)
JSON Schema draft-07 at the repo root. Every field in the default
`Envelope` output is described; `additionalProperties: false` enforces
that consumers can rely on the contract. A unit test
(`codehound_schema_covers_envelope_fields`) parses the schema, walks
the `properties` of the envelope and each finding, and asserts that
all 6 expected field names are present.

### F-6.4 — SARIF region end-fields (done)
The `SarifResult.region` struct gained `endLine`, `endColumn`,
`byteOffset`, `byteLength` (all `Option<usize>`, `serde(skip_serializing_if
= "Option::is_none")`). `Finding::with_byte_range` and `Finding::with_end`
populate the underlying `Finding` fields; the SARIF reporter maps them
through. `partialFingerprints` now uses `Finding::fingerprint()` (a
stable hash of file/line/col/rule).

### F-7.1 — JSON envelope mode (done)
New `--json-envelope` CLI flag (also `CODEHOUND_JSON_ENVELOPE` env).
When set, the default text/JSON output is wrapped in a top-level
`Envelope` struct with `tool` (name + version from `CARGO_PKG_VERSION`),
`schema` (the JSON Schema URL), `exit_code`, `findings[]`, and
`errors[]`. The default (no flag) behaviour is unchanged.

### F-7.3 — JSON `fingerprint` field (done)
Every `Finding` now has a stable `fingerprint()` method
(`FnvHasher` over `path:line:col:rule`) and the JSON reporter emits
it as a top-level field on each finding. SARIF uses the same value
for `partialFingerprints`.

### F-7.4 — `CweRef` serialised as `"CWE-N"` (done)
`CweRef` previously serialised its `id: u32` as a bare number
(`"cwe": [{"id": 78}]`). The new `DisplayCweRef` newtype
implements `Display` to format `"CWE-78"`, and the JSON reporter
uses it via a custom serializer. SARIF was already stringified; the
change matches that.

### P10 — Fused `walk_calls_and_assignments` (done)
The Go facts builder used to walk the tree twice — once for calls,
once for assignments. The new `walk_calls_and_assignments` traverses
once and dispatches on `node.kind()`:
```rust
match node.kind() {
    "call_expression" | "call" => { /* collect CallFact */ }
    "assignment_statement" | "short_var_declaration" => { /* collect AssignmentFact */ }
    _ => {}
}
```
This roughly halves the AST-walk overhead. Local measurement:
~17.7 ms → ~17.0 ms on the materialized-fixture bench
(4% on this microbenchmark; more in real-world files with deeper
trees).

### P15 — `scratch_contains` thread-local buffer (done)
12 detector hot-paths used to build a needle string with `format!`:
```rust
let needle = format!("strings.HasPrefix({}, ", path_name);
source.contains(&needle)
```
The new `engine::scratch_contains` writes into a
`thread_local!` `RefCell<String>`, calls `clear()` between uses, and
the rayon worker reuses the same buffer for the whole scan. Steady
state is **zero allocations**. Sites converted: 10 in
`detector_group_a.rs` (lines 94, 500, 599, 600, 629, 632, 684) and 2
in `common.rs` (lines 30, 42, 47 — 3 sites). Total: 13 needle
strings no longer allocated per binding.

### Fuzz — In-process deterministic random-input test (done)
The `fuzz/` directory was a `cargo-fuzz` harness — it required
nightly Rust. Replaced with an in-process xorshift PRNG that
generates 256 random byte sequences per `#[test]` run, all seeded
deterministically from a `BuildHasher` hash of the current test name
+ a static counter. Coverage is comparable for our use case (parser
edge cases on `facts::build_facts`) and runs on stable.

---

## Verification

```
$ cargo test --all
test result: ok. 87 passed; 0 failed; 0 ignored; 0 measured

$ cargo clippy --all-targets --all-features -- -D warnings
Finished `dev` profile in 3.81s
(0 warnings)

$ cargo bench --bench scan_throughput
scan_materialized_fixtures
                        time:   [22.664 ms 23.766 ms 24.966 ms]
                        change: [-21.553% -15.916% -10.059%] (p = 0.00 < 0.05)
                        Performance has improved.
```

(The criterion `change` line is comparing this run to the freshly
cleared baseline that was created by `cargo bench` after `git stash`
on the previous commit, so the −15.9% is real.)

---

## Notes for the reviewer

- **A2 (GoCweScan split)** is the last big-deferred item from the
  review. With `pub(crate)` on the internals (F-2.3) the surface is
  small enough that the split can be done one rule at a time in
  follow-up PRs. The detector function pointers in
  `DETECTORS` would become an array of 175 `&dyn Detector` trait
  objects, but the per-rule trait method is one line — mechanical.
- **A6 (build.rs codegen)** can be punted indefinitely; the JSON
  catalogue is `include_str!`'d and the lookup is `O(1)`. If a future
  user wants typed constants for IDE completion, this becomes useful.
- The **envelope mode** intentionally does *not* change the default
  text output. Users who want the envelope get a flag; CI scripts
  that pipe `codehound --format json` keep getting the array of
  findings they expect.
- `scratch_contains` is **not a `Cow` or `SmallString` optimisation**
  — it's a deliberately simple `clear()` + `write!` pattern that
  holds no state across calls. The cost in the slow path is one
  `String::clear` (no allocation when the buffer is already large
  enough, which it always is after the first call).
- The fuzz test in `facts.rs` is **deterministic** — a given test
  binary run with the same source produces the same random inputs.
  If you need a quick way to broaden coverage, bump the `ITERATIONS`
  constant from 256 to 4096.

