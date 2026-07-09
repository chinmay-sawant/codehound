# CodeHound — Rust Engine & Craft Improvements

| Field | Value |
|-------|--------|
| **Date** | 2026-07-10 |
| **Source** | [ultra-senior-go-rust-product-review.md](./ultra-senior-go-rust-product-review.md) |
| **Related** | [improvements.md](./improvements.md) · [go.md](./go.md) |
| **Scope** | Engine, errors, ownership, cache, codegen, API, performance craft, packaging code |

This is the **ultra-senior Rust improvement backlog**: make the chassis match the ambition of a serious offline analyzer.

---

## Goals (Rust-specific)

1. **Typed failures** you can match — no kitchen-sink string variants.  
2. **Hot-path data structures that are actually O(1)** where names claim optimization.  
3. **No process-lifetime leaks** to paper over `&'static str`.  
4. **Cache correctness semantics** that match docs.  
5. **Deep modules stay deep** — narrow public API; language code doesn’t depend on engine leftovers.  
6. **Honest benchmarks** with gates that fail when they should.

---

## What’s already good (don’t regress)

- `#![deny(clippy::unwrap_used)]`, clippy `all = deny`, `redundant_clone = deny`  
- Feature-gated grammars (`go`, `python`), optional `cli` / `terminal-output`  
- `Arc<str>` source sharing, parse pool per Rayon worker, chunked scan (1024)  
- `catch_unwind` per file → non-fatal `ScanError`  
- Atomic cache writes, content-hash primary key  
- Inventory language plugins + `LanguagePlugin` / `Detector` traits  
- Build-time duplicate rule ID checks  
- No `unsafe` in Rust source  
- Release profile: thin LTO, `codegen-units = 1`, strip  

Improvements below **build on** this base.

---

## P0 — Correctness, safety, integrity

### 1. Error taxonomy rewrite

| Today | Problem |
|-------|---------|
| `Error::Walk(String)` | Used for walk **and** atomic write **and** cache lifecycle |
| `Parse` / `Grammar` / `Config` as bags of `String` | Callers cannot match structured causes |
| App `anyhow` vs engine `Error` split | OK at boundary; config domain duplicated |

**Target shape (illustrative):**

```rust
pub enum Error {
    Parse { path: PathBuf, source: ParseError },
    Grammar(GrammarError),
    Config(ConfigError),
    Io { path: PathBuf, op: IoOp, source: std::io::Error },
    Cache(CacheError), // already good — promote, don’t wrap as Walk
    // ...
}
```

| Action | Detail |
|--------|--------|
| Split `Walk` | `Io`, `Cache`, `Walk` as separate variants |
| Prefer `#[source]` / `thiserror` chains | Preserve std::io::Error |
| Map CLI exit codes from kind | Config vs internal already partially exists — make consistent |
| Keep detector `run()` infallible | But document that panics → `ScanError`; don’t pretend detectors return `Result` until needed |

**Acceptance:** No production path constructs `Error::Walk` for non-walk failures; `match` useful in library consumers.

### 2. Eliminate `Box::leak` for findings wire format

| Today | Problem |
|-------|---------|
| `finding_wire.rs` leaks `rule_id` / `rule_title` per deserialized finding | Unbounded RSS with cache churn / long-lived process |
| `&'static str` on `Finding` | Forces the leak |

**Options (pick one):**

| Option | Pros | Cons |
|--------|------|------|
| A. `Arc<str>` / `CompactString` on Finding | Clean ownership | Cache + serde shape change |
| B. Global intern table (`once_cell` + Mutex/DashMap) | Keeps cheap clones | Still shared mutable state |
| C. `Cow<'static, str>` + intern known rule IDs at startup | Best of both for catalog rules | Custom serde |

**Recommendation:** **C or A** — stop leaking; catalog rule IDs are finite and known at startup from metadata.

**Acceptance:** Cache load of 100k findings does not grow process by unique-string × N leaks; loom/integration test optional.

### 3. Mutex poison policy

| Today | Problem |
|-------|---------|
| `.expect("… poisoned")` on taint project state / timing / memory cache | One panic poisons → process death; contradicts worker `catch_unwind` |

**Improvements:**

- Prefer `parking_lot::Mutex` (no poison) **or** handle poison: recover / convert to `ScanError`  
- Document cross-file detector concurrency contract  
- Consider `rayon` + thread-local accumulation + merge in `finalize` to avoid shared Mutex during scan  

**Acceptance:** Poisoned lock cannot hard-crash CLI after isolated detector panic (or poison impossible).

### 4. Untrusted input hardening

| Gap | Improvement |
|-----|-------------|
| No scan-time max file size | Cap read size (separate from cache eligibility) |
| Full source retained always | Only fill `source_cache` when export/snippets need it |
| No parse time budget | Optional timeout / node budget for pathological trees |
| Fixture `filename` join | Reject `..` and absolute paths in `fixture/materialize.rs` |
| `--rebuild-cache` + `remove_dir_all` | Resolve/canon path; refuse to delete outside project / unsafe roots |

**Acceptance:** Multi-GB single file cannot OOM by default; fixture materialize cannot escape out_dir.

### 5. SARIF serde correctness (engine/reporting)

| Issue | Fix |
|-------|-----|
| Snake_case nested location fields | `#[serde(rename = "physicalLocation")]` etc. on all SARIF structs |
| Snapshots freeze wrong shape | Update insta snaps; add schema validation test |
| Thin rule metadata | Optional fullDescription / helpUri from RuleMetadata |

(Product priority also in improvements.md — implementation is Rust reporting code.)

---

## P1 — Performance craft (make the “fast” claim true)

### 6. SourceIndex: O(1) key lookup

| Today | Cost |
|-------|------|
| `needles.iter().position(|n| *n == needle)` | O(N) per `has`, N≈737 for CWE |

**Improvements:**

1. **Const indices** — codegen `const NEEDLE_XML_UNMARSHAL: usize = 42` per needle  
2. **phf::Map<&'static str, usize>** — string → bit index  
3. **Sorted needles + binary_search** — acceptable middle ground  

Build already does `source.contains` per needle once — keep that; fix **lookup**.

**Acceptance:** Criterion microbench `SourceIndex::has` for 737 needles; no linear scan.

### 7. Hash maps on the hot path

| Today | Improvement |
|-------|-------------|
| `std::HashMap` + SipHash | `hashbrown` + `ahash` / `FxHash` for analysis maps (taint, facts, cache session) |
| Document if intentionally avoided | Comment + ADR |

### 8. Project taint accumulation under parallel scan

| Today | Improvement |
|-------|-------------|
| `Mutex` + clone path/source/line_starts/graph per file | Per-thread `Vec<ProjectUnit>`, merge in `finalize` |
| Clone `line_starts` | `Arc<[usize]>` on `ParsedUnit` if shared |
| Hold full source in project state | Store path + sparse annotations only if possible |

### 9. Lazy / selective fact extraction

| Today | Improvement |
|-------|-------------|
| Full CWE/PERF fact vectors even for `--only CWE-22` | Feature flags on fact builders from active rule set |
| Always extract taint annotations | Skip when taint disabled **and** no rule needs them |

Align with targeted-scan regression noted in benchmarks (two-rule scan slower).

### 10. Warm path performance

| Today | Improvement |
|-------|-------------|
| Full file re-read + SHA-256 always | Optional mtime+size prefilter then hash |
| Serial preflight | Parallel preflight per chunk (careful with cache store locking) |
| Serial reparse of all cache hits for `accumulate_state` | Only reparse languages/detectors that need project state; skip if no finalize consumers |

### 11. Benchmark honesty

| Defect | Fix |
|--------|-----|
| Stale ~40ms / 65ms gates vs multi-second reality | Re-bench; set gates from p95 of current surface |
| Cold Criterion reuses warm cache dir | Fresh cache dir **per iteration** |
| Soft fail when metric missing | Hard fail if expected bench lines absent |
| Smoke 32s ceilings only | Separate `perf_smoke` vs `perf_budget` |

**Acceptance:** `check_bench_budget.sh` fails CI when throughput regresses &gt; X%; numbers in `benchmarks.md` match last CI run date.

---

## P1 — Cache correctness

### 12. Same-scan cascade invalidation

| Today | Better |
|-------|--------|
| Preflight hits → re-scan misses → invalidate dependents for **next** run | After miss, requeue dependents in **same** scan (or two-phase: discover dirty set fixpoint) |

### 13. Tool-version invalidation

| Today | Better |
|-------|--------|
| Warn only | If `tool_version` ≠ current, treat all entries stale or bump schema and wipe |

### 14. Path identity

| Today | Better |
|-------|--------|
| Relative vs absolute path string mismatch | Canonicalize to project-relative keys everywhere (manifest, deps, findings paths) |
| Docs disagree relative/absolute | Single ADR + enforce in types (`ProjectPath`) |

### 15. Cache concurrency

| Today | Better |
|-------|--------|
| Multi-process races documented | File lock on manifest (optional) or document “single writer”; improve tests beyond “doesn’t panic” |

---

## P1 — API & module boundaries

### 16. Narrow public surface

| Today | Better |
|-------|--------|
| Most modules `pub` from lib | `pub use` façade: `Analyzer`, `Finding`, config, reporters; keep `lang`/`engine` internals `pub(crate)` where possible |
| Deferred `missing_docs` | Ratchet: enable on public façade modules |

### 17. Stop engine ← language leak

| Leak | Move to |
|------|---------|
| `engine/sinks.rs` Go API sets | `lang/go/sinks.rs` or shared `analysis/sinks` with language tag |
| `scratch_contains` | `ast` or `lang` util |
| `dependencies` Go/Python match arms | `LanguagePlugin` capability: `fn extract_deps(...)` |

**Acceptance:** New language can add dep extraction without editing engine match.

### 18. ScanContext / config god-object

| Today | Better |
|-------|--------|
| Growing flags bag | Grouped subconfigs: `TaintConfig`, `CacheConfig`, `BadPracticesConfig` already partial — finish and avoid flat sprawl |
| Soft `fail_on` string | Enum in serde |

### 19. CLI structure (implementation)

| Today | Better |
|-------|--------|
| 30 top-level flags | Subcommands: `codehound scan`, `rules list`, `cache prune`, `baseline update` |
| Default export on | Default off (product) |

Use clap derive groups; keep env vars.

---

## P2 — Codegen & build system

### 20. Safer codegen

| Today | Better |
|-------|--------|
| String paste of TOML `function` field | Validate identifier regex `^[A-Za-z_][A-Za-z0-9_]*$` |
| Minimal string escape | Full Rust string escaping or `quote!` / `proc-macro2` |
| Duplicated registry readers | One generic TOML reader |
| No needle index codegen | Generate phf map + const indices for SourceIndex |

### 21. Build layout

| Today | Better |
|-------|--------|
| `#[path = "build/..."]` modules | Optional small `codehound-build` crate or `build/` as include tree with clear modules |
| Go-hardcoded paths only | Parameterize ruleset root by language for future multi-lang codegen |

### 22. Dependency hygiene

| Item | Action |
|------|--------|
| `walkdir` + `ignore` dual stack | Prefer one; keep walkdir only if fixture code needs it, document |
| Empty `typescript` feature | Remove until real |
| No Dependabot | Add for Cargo.lock |
| Optional `parking_lot` | If Mutex retained |

---

## P2 — Concurrency & architecture

### 23. Detector finalize model

Document and test:

```
parallel run(unit) → optional accumulate_state
→ single-threaded finalize(project)
```

Avoid shared mutable state during `run` when possible.

### 24. Optional crate split

When compile times hurt:

```
codehound-core    # traits, Finding, Error
codehound-engine  # walk, cache, analyzer
codehound-go      # detectors
codehound-cli     # binary
```

Not urgent until `cargo build` pain is measured.

### 25. Memory product modes

| Mode | Behavior |
|------|----------|
| Default CI | No source_cache; JSON/SARIF only |
| Export mode | Retain sources for context/chunks |
| Streaming SARIF | Write findings incrementally (future) |

---

## P3 — Tooling, docs, release engineering

### 26. Release pipeline (code/repo)

- GitHub Actions: build linux/mac/windows targets  
- `cargo deny` / audit on release  
- SBOM (e.g. `cargo cyclonedx`)  
- Version bump policy for rule-breaking changes  

### 27. Embedder docs

- Minimal stable API example in `lib.rs` (include PERF/BP, not only CWE)  
- Feature matrix table  
- Semver guarantees for `Finding` wire format  

### 28. Internal quality gates

| Gate | Purpose |
|------|---------|
| No new `Error::Walk` for non-walk | Clippy / ripgrep CI check |
| No `Box::leak` in src/ | CI grep allowlist |
| Module ≤400 lines policy | Existing — enforce in CI if not already |
| Public items documented | Ratchet |

---

## Implementation order (Rust)

### Sprint R1 — Integrity

1. Error taxonomy (split Walk / Io / Cache)  
2. Remove finding wire leaks  
3. Fixture path sanitization  
4. Scan max file size  
5. SARIF rename attributes  

### Sprint R2 — Hot path

1. SourceIndex O(1) keys (codegen phf or const idx)  
2. Taint accumulate without Mutex choke (thread-local merge)  
3. Lazy facts when rules filtered  
4. source_cache only if export  

### Sprint R3 — Cache truth

1. Same-scan dirty fixpoint  
2. Tool version bust  
3. ProjectPath canonical keys  
4. Re-bench + honest gates  

### Sprint R4 — Boundaries

1. Move sinks to lang/go  
2. Plugin dep extraction trait  
3. Narrow lib pub surface  
4. clap subcommands (incremental)  

### Sprint R5 — Polish

1. Codegen validation + dedupe readers  
2. Hash map hasher choice  
3. Release workflow  
4. missing_docs on façade  

---

## Acceptance criteria (Rust)

| Criterion | Measure |
|-----------|---------|
| Errors | Library tests match on `Error::Cache` vs `Error::Io` |
| Leaks | No `Box::leak` in production finding path |
| SourceIndex | Microbench + no linear `position` in `has` |
| Cache docs | Documented semantics match tests for same-scan cascade |
| SARIF | Schema validation test green |
| Public API | Embedder compiles against façade without `engine::` deep imports (goal) |
| Benches | CI gate reflects real p95; cold bench not cache-contaminated |

---

## Non-goals (Rust)

- Rewrite engine in async Tokio (Rayon file parallel is fine)  
- Dynamic `.so` plugins  
- Zero-copy everything / arena allocators before profiling proves need  
- Full typed Go analysis inside Rust (optional future; see go.md)  

---

## File touch map (likely)

| Area | Paths |
|------|--------|
| Errors | `src/error.rs`, `src/engine/io.rs`, `src/engine/cache/` |
| Findings / leak | `src/rules/finding.rs`, `finding_wire.rs` |
| SourceIndex | `src/lang/source_index.rs`, `.../cwe/source_index.rs`, build codegen |
| Parallel / taint state | `src/engine/walk/parallel.rs`, `.../cwe/mod.rs` |
| Cache | `src/engine/cache/*`, `src/engine/analyzer/scan.rs` |
| SARIF | `src/reporting/sarif/schema.rs`, `log.rs` |
| Plugin / deps | `src/core/language/plugin.rs`, `src/engine/dependencies/` |
| Sinks | `src/engine/sinks.rs` → move |
| Codegen | `build.rs`, `build/*` |
| CLI | `src/cli/`, `src/app/run.rs` |
| Fixtures safety | `src/fixture/materialize.rs` |
| Benches | `benches/*`, `scripts/check_bench_budget.sh` |

---

## Rust one-liner

> **Typed errors, no leaks, O(1) indexes, cache semantics that match the docs — then the “fast single binary” story stops being cosplay.**

See [improvements.md](./improvements.md) for product packs/defaults and [go.md](./go.md) for detector/taint work that consumes this chassis.
