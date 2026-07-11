# CodeHound — Action Items (from 2026-07-10 feedback)

| Field | Value |
|-------|--------|
| **Date** | 2026-07-11 |
| **Sources** | [ultra-senior-go-rust-product-review.md](./ultra-senior-go-rust-product-review.md) · [improvements.md](./improvements.md) · [go.md](./go.md) · [rust.md](./rust.md) |
| **Version baseline** | `0.0.1` → target `≥0.1.0` after Phase 7 gates |
| **Scan method** | 3 parallel agents (full inventory, action catalog, phase plan) + direct source read |

## North star

> **One job, done well:** a fast, offline Go **PERF + framework-footgun** analyzer that also ships a **curated** CWE pack — complementary to golangci-lint and govulncheck, not a replacement for either.

Everything below should be judged by whether it moves toward that north star or dilutes it.

## How to use this document

- Work **phase order** (0 → 7 for ship; 8–9 after). Prefer Track A (product/trust) before adding more rules.
- Tags: **`[Product]`** · **`[Go]`** · **`[Rust]`**
- Multi-source agreement: **`×N`** (item appears in N of the 4 feedback files).
- Checkboxes are the backlog of record for this feedback set.
- Deferred / non-goals live at the end — do not re-open without an ADR.

### Parallel tracks (after Phase 0)

```
Track A (product/trust):  0 → 1 → 2 → 3 → 7
Track B (engine):         0.9 → 4 → 5.1–5.4 → 6.4–6.6 → 8.4–8.5
Track C (quality):        1.2 + 5.5–5.7 canaries (after packs exist)
Merge for 0.1.0 when A + C minimum is met.
```

### Phase summary

| Phase | One-liner | Cadence | Scope |
|------:|-----------|---------|-------|
| **0** | Fix lies: SARIF, license, export, sanitizers, leaks | 3–7 days | Product + Go + Rust |
| **1** | Curated packs; quarantine fixture museum | 2–4 weeks | Product + Go |
| **2** | PERF tiers + frameworks = product wedge | 2–4 weeks | Go |
| **3** | BP honest vs staticcheck | 1–2 weeks | Go |
| **4** | O(1) indexes, lazy facts, honest benches | 2–3 weeks | Rust |
| **5** | Cache truth + canaries + oracles | 2–4 weeks | Product + Rust + Go |
| **6** | Baseline / ignore / CLI / API maturity | 2–4 weeks | Product + Rust |
| **7** | Tag `0.1.0` and ship binaries | 2–3 weeks | Product + Rust |
| **8** | Taint depth + optional architecture | 1–3 months | Go + Rust |
| **9** | Multi-lang only if funded | Later | Product |

---

## Phase 0 — “Would install without fear”

**Theme:** Correctness bugs, CI blockers, honesty  
**Goal:** Fresh clone scan is side-effect free, SARIF/GitHub-usable, license/docs not lying, CLI doesn’t no-op, security sanitizers don’t lie.

**Status (2026-07-11):** Phase 0 complete for trust/hygiene. Catalog quarantine + profiles remain Phase 1.

### Success criteria

- [x] Clean Go module scan produces **zero filesystem side effects** by default
- [x] SARIF camelCase locations + structural validation test (not full online GH upload)
- [x] License files match `Cargo.toml` claims; README links work
- [x] Docs, schema, and runtime agree on taint default + `fail_on`
- [x] No production no-op or self-conflicting flags left undocumented
- [x] Clean alone is not a Path sanitizer; Join+HasPrefix same-binding confines
- [x] Finding wire uses string interning (bounded leaks); mutex poison recovers instead of hard-crash

### Checklist

#### 0.1 Defaults that don’t dirt the workspace `[Product]` ×3

- [x] Default **context/chunks export OFF** (require `--export-context` / `--export-chunks`)
- [x] Canonical CI one-liner documented in README
- [x] Acceptance: export off by default; `--no-context`/`--no-chunks` kept as hidden no-ops for old scripts

#### 0.2 SARIF 2.1.0 correctness `[Product]` + `[Rust]` ×3

- [x] Emit camelCase nested fields (`physicalLocation`, `startLine`, …) via serde renames
- [x] Update insta snapshots that freeze snake_case
- [x] Align `security-severity` mapping with docs (`0.0`/`2.0`/`5.0`/`7.5`/`9.5`)
- [x] Emit real `workingDirectory.uri` (process CWD), not always `"."`
- [x] Richer rule metadata: `fullDescription` + optional `helpUri` from CWE refs
- [x] Structural SARIF validation test (`sarif_uses_camel_case_location_fields`)

#### 0.3 License & packaging honesty `[Product]` ×3

- [x] Ship `LICENSE-MIT` + `LICENSE-APACHE` (+ short `LICENSE` dual pointer)
- [x] Fix README dual-license links (targets exist)
- [x] Align `Cargo.toml` license field with files on disk (`MIT OR Apache-2.0`)

#### 0.4 Docs / schema / runtime lockstep `[Product]` ×2

- [x] Single source of truth for **taint default** (off): README + `docs/taint.md` + `ScanContext`
- [x] `severity_overrides`: **implemented** parse + apply in `ScanContext`
- [x] README counts pinned + CI test `rule_counts_readme` vs live registry (175/239/65)
- [x] `fail_on`: reject unknown values at config load (allowed: none/never/medium/warnings/high/strict)
- [x] Refresh contributor docs paths (`adding-a-language`, `perf-detector-development` → chunks/)
- [x] Acceptance: `codehound init` template parses; fail_on enum tests; README numbers match registry

#### 0.5 Dead / conflicting CLI flags `[Product]` + `[Rust]` ×2

- [x] `--warnings-as-errors`: explicit `MediumAsErrors` + marks CLI fail policy as set
- [x] `--baseline` + `--no-baseline`: clap `conflicts_with`
- [x] Split `--no-snippet` vs `--sarif-compact` (stop dual-meaning)
- [x] (Subcommands deferred → Phase 6; only fix broken surface here)

#### 0.6 Go taint trust — sanitizer & confinement (security-critical) `[Go]` ×2

- [x] **Stop treating `filepath.Clean` / `path.Clean` alone as path-safe** (`SanitizerKind::Path`)
  - Same-binding `HasPrefix` (and/or Base) confines; Clean alone does not
- [x] **CWE-78:** Validation/Bounded sanitizers only; **not** Path sanitizers
- [x] Drop bare `clean` from name-regex sanitizers (keep sanitize/escape/validate/purify)
- [x] Bare `.Prepare` is **not** a SQL sanitizer (parameterized = literal first arg only)
- [x] **Path confinement:** same-binding HasPrefix (not Clean co-presence)
- [x] Prefer facts: HasPrefix on path-variable name (taint path nodes)
- [x] Acceptance: Clean alone is not a Path sanitizer; unit tests cover classify + common guards
- [x] Touch: `cwe/taint/rules/cwe_22.rs`, path helpers, `taint/extract/classify.rs`

#### 0.7 Injection rule soundness checklist (core only) `[Go]`

- [x] **CWE-22:** keep first-arg-only taint; apply Clean + confinement fixes
- [x] **CWE-78:** keep shell (`sh -c`) focus; fix sanitizer kinds (no Path)
- [x] **CWE-89:** document literal-first-arg heuristic; GORM `.Raw` / sqlx shapes; no full-SQLi claim
- [x] **CWE-79:** Template + HTTPWrite (ResponseWriter-ish receivers only); not full XSS
- [x] **CWE-90/91:** real LDAP/XML sinks documented; long-tail quarantine deferred to Phase 1 packs

#### 0.8 Taint defaults & flags UX `[Go]` + `[Product]` ×2

- [x] **Decide:** taint **off** by default (enable via `--taint` / config; security profile later in Phase 1)
- [x] Sync `docs/taint.md`, README, schema, `ScanContext`
- [x] `--taint` / `--no-taint` + config applied in `build_scan_context` (CLI wins for flags)

#### 0.9 Rust integrity quick wins `[Rust]` ×2

- [x] **Error taxonomy start:** `Error::PathIo` + `IoOp`; cache ops use `Error::Cache`; walk-only for walk
- [x] Prefer `#[source]` on `PathIo`
- [x] Map CLI exit codes from error kind (`exit_code_for_error` in main)
- [x] Keep detector `run()` infallible (unchanged)
- [x] **Finding wire interning** (`finding_wire.rs`): one leak per unique string (bounds cache churn)
- [x] **Mutex poison policy:** recover via `into_inner()` on CWE state, cache memory, timing global
- [x] Document cross-file detector concurrency contract (`cwe/mod.rs`)
- [x] **Untrusted input hardening:**
  - [x] Scan-time max file size (32 MiB default, separate from cache eligibility)
  - [x] Fixture `filename` join: reject `..` and absolute paths (`fixture/materialize.rs`)
  - [x] `--rebuild-cache` + `remove_dir_all`: refuse non-cache-looking / system roots
- [x] Acceptance: large-file skip; fixture path sanitize; interned finding strings

---

## Phase 1 — “Would trust the default gate”

**Theme:** Packs, catalog honesty, signal  
**Goal:** Recommended profile is small and high-signal; BP off; fixture museum quarantined; severities honest; homepage leads with PERF.

**Status (2026-07-11):** Core Phase 1 shipped (profiles, maturity quarantine, docs, sample CI). PERF advice retunes and full NEEDLES rewrite continue in Phase 2.

### Success criteria

- [x] `recommended` pack ≪ full catalog (14 rules; ≤30)
- [x] No `fixture-only` rules in `recommended` or `security` (`tests/profile_packs.rs`)
- [ ] Senior Go triage of ~20 recommended findings: ≥70% actionable (sampled) — needs real-repo pilot
- [x] BP pack off by default in recommended; fail policy strict (high+)
- [x] Homepage / README lead with PERF + frameworks (positioning)

### Checklist

#### 1.1 Profiles instead of “everything on” `[Product]` ×3

- [x] Implement `--profile recommended|perf|security|style|all` (`ScanProfile`, CLI default recommended)
- [x] Pack definitions:
  - [x] **`recommended`** — curated PERF + taint-core CWEs · **CLI default**
  - [x] **`perf`** — broader hot-path PERF · opt-in
  - [x] **`security`** — taint CWE core (+ structural neighbors); taint **on** · opt-in
  - [x] **`style` / `bp`** — bad practices only, advisory (`NoFail`)
  - [x] **`all`** — full catalog · explicit only
- [x] Document: `docs/go-recommended-pack.md` + README CI recipes
- [x] Align fail policy with profile (recommended/security/perf → strict)

#### 1.2 Rule maturity tags + quarantine `[Product]` + `[Go]` ×3

- [x] Tag lookup via `rules::maturity` (`taint-core` | `structural` | `heuristic` | `fixture-only` | `reserved`)
- [x] Default pack membership filters fixture-only/reserved out of recommended/security/perf
- [x] Quarantine known fixture-only CWEs (334/335/338/342/343 PRNG museum + reserved BP)
- [ ] Full audit of every CWE long-tail needle (ongoing; expand maturity table)
- [ ] Enforce rewrite bar for promotion to `structural` (process — Phase 2 authoring)
- [ ] Track hit rate on canaries; plan delete zero-hit after N months (Phase 5)

#### 1.3 NEEDLES hygiene (first pass) `[Go]`

- [x] Document hygiene policy on `NEEDLES` + annotate worst fixture needles
- [ ] Prefer call facts + callee classification over `SourceIndex.has` primary detect (Phase 2 depth)
- [ ] Use needles as **negative gates** where possible (Phase 2)
- [x] Flag top fixture-shaped needles (`Intn(4096)`, `lastOTP++`, PRNG formulas, hard-coded paths)
- [ ] Full comment pass on remaining ~700 needles (incremental)

#### 1.4 Severity & confidence discipline `[Product]` + `[Go]` ×2

- [ ] Micro-opts → `info`/`low` across full PERF catalog (Phase 2 tiers)
- [x] BP pack off in recommended; style pack is advisory (`NoFail`)
- [x] Never fail CI on godoc-style rules under recommended (BP not in pack)
- [x] Populate `confidence` for taint-core findings (~0.7–0.75) and fixture needles (~0.35)
- [ ] Fix bad PERF advice patterns (http.Get, fmt.Errorf, Body.Close) — Phase 2

#### 1.5 Product repositioning (docs-first) `[Product]` ×2

- [x] README sample: prefer **PERF-101** over CWE theater
- [x] Explicit complementary positioning vs staticcheck / govulncheck / golangci-lint
- [x] Non-goals stated: no CodeQL parity, no CVE replacement, no default-on full BP

#### 1.6 Sample CI recipe `[Product]`

- [x] Sample `.github/workflows/codehound.yml` (cargo build until binary release)
- [x] Document baseline + ignore brownfield workflow (`docs/go-recommended-pack.md`)

---

## Phase 2 — “PERF is the product”

**Theme:** PERF tiers, hot-path signal, frameworks  
**Goal:** S-tier PERF shippable in CI; hot_path not a name soup; framework plan started without catalog inflation.

**Status (2026-07-11):** Phase 2 core shipped (tiers, hot_path, advice, framework sources, docs).

### Success criteria

- [x] PERF tiers S/A/B/C defined and wired into packs (`perf/tiers.rs` + profiles)
- [x] Cold CLI/config builders not flooded by hot_path false positives (`main`/`init`/package-level cold; no bare `func (`)
- [x] Top S-tier rules have real-world-ish fixtures (`perf_real_world/http_handler_timeouts-vulnerable`)
- [x] Framework gap list published (`docs/perf-tiers.md`); no catalog inflation this phase

### Checklist

#### 2.1 Split PERF into tiers `[Go]`

- [x] **S (ship):** 1, 7, 50, 58, 71, 101, 103, 189, 190 → **recommended**
- [x] **A (framework):** 11, 12, 22, 31, 82, 85, 142, 143, 164, 183, 210, 213 → **perf** profile
- [x] **B (micro-opt):** 15, 17–19, 35, 42, 120, 122, 127, 146, 157, 188 → **Info** severity
- [x] **C (overlap):** 2, 3, 4, 6, 16 documented as staticcheck-adjacent; **Info**

#### 2.2 Fix `is_hot_path` over-breadth `[Go]` ×2

- [x] Prefer handler signatures + codec/signing names; loops always hot
- [x] Drop bare `func (` as handler-shaped
- [x] Drop broad `build|process|handle|serve` name primary
- [x] Suppress `main` / `init` / package-level cold paths

#### 2.3 PERF advice quality `[Go]` (if not finished in 1.4)

- [x] PERF-118: only GET/HEAD + nil body without headers/context/custom client
- [x] PERF-103: same-function Body.Close scan (enclosing function body)

#### 2.4 Framework coverage plan (execute top priority) `[Go]` ×2

- [x] net/http + Gin solid; Echo existing; Chi needles + local handler shape; Fiber local shape
- [x] Real-world cmd/api fixture for timeouts (PERF-101)
- [x] Cap: no new rule IDs this phase (policy + quality only)

#### 2.5 Sink / source classification (no `go/types` yet) `[Go]`

- [x] Chi `URLParam` + Fiber `c.Params` as taint sources
- [x] GORM/sqlx SQL sinks (from Phase 0/1)
- [ ] Package-aware `*sql.DB` assign facts (deeper — optional later)
- [x] Typed facts API still non-blocking for 0.1.0

---

## Phase 3 — “Stop losing to staticcheck on BP”

**Theme:** BP dedup + broken detectors  
**Goal:** BP is an honest policy pack, not a worse staticcheck.

### Success criteria

- [x] Overlap matrix published (`docs/bad-practices.md`)
- [x] BP-8 / 9 / 1 / 6 fixed or disabled
- [x] BP off in recommended; unique policy rules only in style pack
- [x] Reserved/empty (CVE feed) wired or removed from catalog
  - BP-63 remains **reserved** (curated advisory snapshot, not govulncheck); documented

### Checklist

#### 3.1 Dedup matrix vs golangci ecosystem `[Go]` ×2

- [x] For each BP-1..65 classify:
  - [x] Strictly weaker than go vet / staticcheck / errcheck → **default-off or delete**
    - Documented as weaker; stay style-only (recommended never enables BP)
  - [x] Same idea, worse precision → **fix or drop**
  - [x] Unique policy (rate limits, dep hygiene with real signal) → **style pack only**
  - [x] Reserved / empty (CVE feed, e.g. BP-63) → **wire govulncheck-style feed or remove**
    - BP-63 kept reserved with honest snapshot docs (prefer govulncheck for real CVEs)
- [x] Document: “Overlaps X — enable only if you don’t run X”

#### 3.2 Fix known broken BP detectors `[Go]` ×2

- [x] **BP-8 Unlock:** value-mutex param evidence (not file-level mutex + any defer Unlock)
- [x] **BP-9 select:** brace-depth block matching (not first `{` to first `}`)
- [x] **BP-1 discarded err:** assignment shapes; skip non-error builtins; don’t flag when `err` bound
- [x] **BP-6 WaitGroup:** brace-matched `go func` body (not line state machine)
- [x] **BP-21 Parallel:** info severity; default-off in style; off in recommended
- [x] **BP-28 single-method iface:** info severity; **off by default** in style

#### 3.3 BP severity & pack membership `[Go]` ×2

- [x] Default BP pack **off** in recommended CI profile
- [x] When on: almost all **info/low**; only concurrency footguns → medium (BP-6/7/8/15)
- [x] Never fail CI on “missing godoc” style rules by default (style = NoFail + info)

---

## Phase 4 — “Fast claim is real” (Rust hot path + memory)

**Theme:** Engine performance craft  
**Goal:** SourceIndex O(1), no export RAM tax, honest benches, lazy facts, taint accumulate without Mutex choke.

### Success criteria

- [x] `SourceIndex::has` not linear over ~737 needles (Criterion microbench `source_index_has_lookup`)
- [x] Two-rule / filtered scans don’t pay full fact cost (skip taint annotations + call graph when taint off)
- [x] `source_cache` only when export/snippets need it (`retain_sources`)
- [x] Bench gates reflect real p95; cold Criterion not cache-contaminated
- [x] No unbounded finding-path leak (cache intern table remains; needle lookup tables are intentional static)

### Checklist

#### 4.1 SourceIndex O(1) key lookup `[Rust]` ×2

- [x] Process-lifetime `HashMap` per static needle table (pointer-keyed); not linear `position`
- [x] Keep build-time `source.contains` pass; fix **lookup** only
- [x] Acceptance: unit tests + `source_index_has_lookup` microbench

#### 4.2 Lazy / selective fact extraction `[Rust]` + `[Product]` ×2

- [x] `FactBuildOpts` / `for_scan(taint_enabled)` on CWE fact builder
- [x] Skip taint annotations + call graph when taint disabled
- [x] Two-rule bench uses structural-only path (taint off)

#### 4.3 Memory product modes `[Rust]` + `[Product]` ×2

- [x] Default CI: no `source_cache` (`retain_sources: false`)
- [x] Export mode: CLI sets `retain_sources` for `--export-context` / `--export-chunks`
- [x] Streaming SARIF → Phase 8 / deferred

#### 4.4 Project taint accumulation under parallel scan `[Rust]` ×2

- [x] Build `ProjectUnit` off-lock; short Mutex push only when taint on
- [x] `Arc<[usize]>` line_starts on project units
- [x] No project accumulate / cache-hit reparse when taint disabled
  - Full TLS merge without Mutex deferred; critical section minimized + documented

#### 4.5 Hash maps on hot path `[Rust]`

- [x] ADR: intentional SipHash for general maps; SourceIndex uses shared HashMap lookup
  - See `docs/adr/0001-hash-maps-on-hot-path.md`

#### 4.6 Warm path performance `[Rust]` + `[Product]` ×2

- [x] Skip cache-hit reparse when taint off (no finalize consumers)
- [ ] Optional mtime+size prefilter then hash confirm — deferred (schema change)
- [ ] Parallel preflight per chunk — deferred
- [x] Only reparse cache hits that need project state (taint-gated)

#### 4.7 Benchmark honesty `[Rust]` ×2

- [x] Drop stale ~40ms/65ms as CI truth; smoke 32s / budget 8s ceilings
- [x] Fresh cache dir **per Criterion iteration** for cold incremental
- [x] Hard fail if expected bench lines missing
- [x] `BUDGET_MODE=smoke|budget` split in `check_bench_budget.sh`
- [x] `benchmarks.md` honesty note + re-bench instructions

---

## Phase 5 — “Cache & quality loop match the docs”

**Theme:** Cache correctness + testing oracles + canaries  
**Goal:** Same-scan cascade, tool-version bust, real-repo canaries, exclusive oracles.

### Success criteria

- [x] Documented cache semantics match tests (same-scan cascade, tool version)
- [x] Project-relative path keys consistent for cache/deps/findings
- [x] CI canary on 3 budgets (in-repo clean / HTTP / dogfood `src`) with finding-count gates
- [x] Core rules assert line + exclusive fire + evidence kind
- [x] Python safe-test class inference fixed (`SLOP` prefix for python fixtures)

### Checklist

#### 5.1 Same-scan cascade invalidation `[Rust]` + `[Product]` ×2

- [x] Dirty fixpoint over reverse deps in preflight; force re-scan of dependents **same** scan
  - Deps stored project-relative so reverse edges match

#### 5.2 Tool-version invalidation `[Rust]` + `[Product]` ×2

- [x] If `tool_version` ≠ current: **mass-stale** (empty manifest + delete entry files)

#### 5.3 Path identity `[Rust]` + `[Product]` ×2

- [x] `normalize_project_path` on put, deps, cascade match, cache keys
- [x] ADR `docs/adr/0002-project-path-identity.md`
- [x] Fix absolute vs relative cascade misses (strip to project-relative deps)

#### 5.4 Cache concurrency policy `[Rust]`

- [x] Document **single-writer** policy in `docs/incremental-cache.md`
- [x] Concurrent open/scan test retained (no panic); correctness not claimed under dual writers

#### 5.5 Fixture & test oracle bar `[Go]` + `[Product]` ×2

- [x] Variant fixtures for taint core: `CWE-89-renamed-{vulnerable,safe}` under `tests/fixtures/go/taint/`
- [x] `perf_real_world` clean file smoke retained
- [x] Assert **line**, exclusive fire (taint-core family), evidence kind for CWE-22/78/89
- [x] Safe parameterized SQL silence (renamed safe fixture)
- [x] Dual stdlib/framework inventories kept; framework CWE-393 FP test retained
- [x] Cross-rule FP suite:
  - [x] Safe SQL param ↛ CWE-89 (renamed-safe)
  - [x] Clean file zero findings (`go_clean_file_smoke`)
  - [x] Recommended canary on clean_lib budget 0
- [x] Python safe-test class inference: `infer_rule_class` → `SLOP` for `/python/`

#### 5.6 Canary corpus CI `[Go]` + `[Product]` ×3

- [x] Three in-repo canaries (no flaky network pins for v1):
  1. `tests/canary/clean_lib` — expect 0 recommended findings
  2. `tests/canary/http_service` — small HTTP budget
  3. `src` dogfood under recommended — spike guard
- [x] `scripts/canary/run_canaries.sh` + `budgets.json`; CI job `canary`
- [x] Finding-count budgets fail on spike
- [ ] External commit-SHA module pins + golden TP/FP labels — deferred follow-up
- [x] Dogfood gate via CI canary job

#### 5.7 Observability seeds `[Product]`

- [ ] Per-rule hit rate telemetry (local opt-in) — deferred
- [x] `--explain` includes confidence + analysis mode (taint vs structural vs style)
- [ ] CHUNK_VALIDATOR / LLM review process — process note only; not a product feature

---

## Phase 6 — “CI product surface maturity”

**Theme:** Baseline, ignore, CLI structure, API boundaries  
**Goal:** Brownfield adoption tools complete; public API narrower; incremental subcommands.

### Success criteria

- [x] Baseline list/prune/update/diff + show-baselined
- [x] Block/range/EOL ignore; multi-lang comments when relevant
- [x] CLI subcommands started without breaking core scan UX
- [x] New language can add dep extraction without editing engine match (trait)

### Checklist

#### 6.1 Baseline maturity `[Product]`

- [x] Fingerprint v2 = rule + file + message digest (line-shift resilient); location fallback retained
- [x] `codehound baseline list|prune|update|diff|save`
- [x] `--show-baselined` (mirror `--show-ignored`)
- [x] Optional `reason`, `expires` in baseline schema (serde defaults; v1 files load)

#### 6.2 Ignore system completeness `[Product]`

- [x] Python `#` comments
- [x] `codehound-ignore-start` / `-end` block ranges
- [x] Trailing end-of-line ignore
- [x] `nolint` alias: **documented non-goal** (`docs/finding-identity.md`)

#### 6.3 CLI structure `[Product]` + `[Rust]` ×2

- [x] Subcommands: `scan`, `rules`, `cache prune`, `baseline …`, `init` (default bare args still scan)
- [x] clap derive; env vars retained on global scan flags

#### 6.4 Narrow public surface & engine←language leaks `[Rust]` ×2

- [x] `LanguagePlugin::extract_deps` + plugin dispatch (no Go/Python engine match)
- [x] Go sinks → `lang/go/sinks.rs` (engine re-export for compat)
- [x] `scratch_contains` → `ast` (engine/walk re-export)
- [ ] Full `pub use` façade ratchet / missing_docs on entire public API — deferred
- [x] Acceptance: new language overrides `extract_deps` without engine edit

#### 6.5 ScanContext / config god-object `[Rust]` + `[Product]`

- [ ] Full grouped subconfigs refactor — deferred (CacheConfig already exists; larger split later)
- [x] Soft `fail_on` / fail policy — already present from earlier phases

#### 6.6 Detector finalize model documented `[Rust]`

- [x] Documented on `Detector` trait + architecture-performance.md
- [x] Go CWE path already builds off-lock / short Mutex (Phase 4)

---

## Phase 7 — “Ship 0.1.0”

**Theme:** Release engineering + Go packaging docs + process  
**Goal:** Tagged multi-arch release, honest docs, CONTRIBUTING/ADRs, 0.1.0 bar from review.

### Success criteria

- [x] Version **0.1.0** + multi-arch release workflow (tag `v*` to publish binaries + checksums)
- [x] SARIF workflow / composite action ready for GitHub upload (Phase 0 SARIF shape)
- [x] FP canary budgets on ≥3 in-repo targets (clean / HTTP / dogfood); external SHA pins deferred
- [x] Dual license MIT OR Apache-2.0; SBOM job + cargo audit in CI
- [x] Live roadmap (`ROADMAP.md`); plans archived via `plans/README.md`

### Checklist

#### 7.1 Release pipeline `[Product]` + `[Rust]` ×2

- [x] GH Actions: linux / mac / windows targets (`.github/workflows/release.yml`)
- [x] Checksums (`.sha256` per artifact); crates.io optional later
- [x] SBOM (cargo-cyclonedx job) + `cargo audit` in CI
- [x] Dependabot for Cargo.lock + Actions
- [x] Version bump policy in `ROADMAP.md`
- [ ] Homebrew / deb — deferred

#### 7.2 GitHub Action packaging `[Product]`

- [x] Composite action `.github/actions/codehound-scan` (build → scan → upload SARIF)
- [x] Sample workflow `.github/workflows/codehound.yml`

#### 7.3 Go product packaging of rules `[Go]`

- [x] Rule RFC template: `docs/rule-rfc-template.md`
- [x] detection_notes quality called out in RFC + CONTRIBUTING
- [ ] Codegen validates function exists / fixture inventory CI — partial (existing build.rs + tests); full gate deferred
- [x] PERF detector guide already points at chunks paths (`docs/perf-detector-development.md`)
- [x] Docs:
  - [x] `docs/go-recommended-pack.md`
  - [x] `docs/go-vs-staticcheck.md`
  - [x] Expanded `docs/taint.md` limitations

#### 7.4 Embedder docs `[Rust]`

- [x] Minimal stable API example in `lib.rs` (recommended pack + Finding loop)
- [x] Feature matrix table in crate docs
- [x] Semver notes for Finding wire format

#### 7.5 Process & branding hygiene `[Product]`

- [x] ADRs: taint model (0003), default profile (0004); cache identity (0002); hash maps (0001)
- [x] One live roadmap (`ROADMAP.md`); `plans/README.md` archive note
- [x] Branding: `SLOP101` / slop documented as historical alias (`CONTEXT.md`, crate docs)
- [x] `CONTRIBUTING.md`
- [x] `CONTEXT.md`

#### 7.6 Internal quality gates `[Rust]`

- [x] CI: Box::leak allowlist script; module size policy (exempt bulk detectors)
- [x] Existing no-prod-expect + clippy -D warnings
- [ ] Full public-items missing_docs ratchet — deferred

#### 7.7 0.1.0 gate (review strategic #8) `[Product]` ×2

- [x] SARIF path ready for GitHub code scanning upload
- [x] Release workflow ready for first public binary tag (`v0.1.0`)
- [x] Canary budgets (≥3 targets)
- [x] Dual license present (`LICENSE`, `LICENSE-MIT`, `LICENSE-APACHE`)
- [x] Recommended pack curated (Phase 1)

**Human step to finish the public release:** push branch, tag `v0.1.0`, let `release.yml` publish artifacts.

---

## Phase 8 — “Depth & differentiation”

**Theme:** Taint depth, optional architecture  
**Goal:** Honest deeper analysis without claiming CodeQL; optional crate split when pain measured.

### Success criteria

- [x] Intra-proc taint upgrades shipped with documented limitations
- [x] Optional multi-hop summary behind `--taint-depth` (1–4)
- [x] Channels/goroutines explicit unsupported FNs (not silent pretends)
- [x] Crate split deferred until compile pain measured (documented in ROADMAP)

### Checklist

#### 8.1 Intra-procedural taint upgrades `[Go]`

- [x] Versioned assignments / last-write by `decl_byte` at use site
- [x] Limited field keys (`user.Path` vs whole struct)
- [x] Map/slice index conservative taint (whole-base; low precision)
- [x] Channel/goroutine: `UnsupportedFlow` records; no fake assignment edges

#### 8.2 Inter-procedural summary upgrades `[Go]` + `[Rust]`

- [x] Bounded multi-hop via `refine_summaries_multihop` + `ScanContext.taint_max_depth`
- [x] Prefer first-wins `func_to_file` (avoid parallel order name collisions)
- [x] Import-map skip for external method prefixes (existing + retained)
- [x] Full source clone under Mutex → Phase 4 off-lock project units (done earlier)

#### 8.3 Optional hybrid `go/packages` (big bet — do **not** block 0.1.0) `[Go]`

- [ ] Design detector APIs so typed fact layer can feed same rules later
- [ ] Optional `--typed` only after 0.1.0; needs Go toolchain
- [x] **Deferred as product milestone until PERF pack trusted**

#### 8.4 Codegen & build system polish `[Rust]`

- [x] Validate TOML `function` identifier regex `^[A-Za-z_][A-Za-z0-9_]*$`
- [ ] Full Rust string escaping or `quote!` / proc-macro2 — deferred
- [ ] One generic TOML registry reader — deferred
- [x] Needle index O(1) lookup (Phase 4)
- [ ] Optional `codehound-build` crate — deferred
- [ ] Parameterize ruleset root by language — deferred
- [ ] Prefer one of walkdir/ignore — deferred
- [ ] Remove empty `typescript` feature — deferred to Phase 9
- [ ] Optional `parking_lot` — deferred (std Mutex + poison recovery OK)

#### 8.5 Optional crate split `[Rust]` + `[Product]` ×2

- [x] Not urgent until `cargo build` pain measured — noted in ROADMAP

#### 8.6 Streaming SARIF / monorepo RAM (future) `[Rust]`

- [ ] Incremental findings write — after default memory modes proven (Phase 4 retain_sources)

---

## Phase 9 — Platform & multi-lang (later / decision-gated)

**Theme:** Growth only if funded  
**Goal:** Marketing matches capability; no multi-lang cosplay.

### Success criteria

- [x] Explicit **demote (Go-first)** decision recorded in ADR 0005
- [x] Marketing matches capability (README, ROADMAP, frontend copy, schema)

### Checklist

#### 9.1 Multi-language honesty `[Product]` ×2

- [x] **Option A — Invest:** rejected for 0.1.x (revisit only with funding + new ADR)
- [x] **Option B — Demote:** Python opt-in feature; default features Go-only; README Go-first
- [x] Remove empty `typescript` feature + `LanguageId::TypeScript`
- [x] Fixture languages: only `go` / `python`; `lang: rust` rejected with clear error + test

#### 9.2 Dynamic plugins `[Product]` — out of scope

- [x] ~~Runtime loadable plugins~~ — permanent non-goal (ADR 0005)

#### 9.3 Ecosystem extras `[Product]`

- [ ] Homebrew / deb if demand — deferred
- [ ] Public FP / TP dashboard — deferred

---

## Explicitly deferred / non-goals

| Item | Source | Reason |
|------|--------|--------|
| Full sound interprocedural taint | go non-goals | Wrong cost model for tree-sitter MVP |
| Replace govulncheck for CVEs | all | Different job; BP-63 reserved → wire feed or remove only |
| Replace errcheck / staticcheck / golangci-lint | all | Permanent non-goal; BP/PERF overlap must defer not compete |
| Claiming every CWE “covered” in audit sense | go | Catalog honesty over marketing |
| Full CodeQL parity | improvements non-goals | Wrong cost model |
| Runtime loadable plugins / dynamic `.so` | improvements / rust | Compile-time inventory enough |
| Default-on full BP pack in CI | all | Noise death spiral |
| Add 100 more CWE IDs without precision bar | improvements / review | Inflation destroys trust |
| Async Tokio engine rewrite | rust non-goals | Rayon file parallel is fine |
| Zero-copy / arena allocators pre-profile | rust non-goals | Profile first |
| Full typed Go analysis as 0.1.0 blocker | go P2.18 | Optional later `--typed` |
| `nolint` alias | improvements | Optional; may stay non-goal |
| Streaming SARIF | rust P2.25 | After memory modes |
| Multi-crate split | all | Only when compile pain measured |
| Public crates.io if policy prefers GH releases only | packaging | Optional |

---

## Decisions still required (before coding lockstep)

| # | Decision | Options | Blocks |
|---|----------|---------|--------|
| D1 | **Taint default** | On for `security` only vs global on with docs | Phase 0.4 / 0.8 |
| D2 | **Dual license** | Ship both files vs drop dual claim | Phase 0.3 |
| D3 | **`--warnings-as-errors`** | Implement vs remove | Phase 0.5 |
| D4 | **Multi-lang** | Invest Python vs demote Go-first | Phase 9 / branding |
| D5 | **Finding ownership** | Arc/CompactString vs Cow+intern for rule IDs | Phase 0.9 |
| D6 | **Mutex strategy** | parking_lot vs poison recovery vs TLS merge | Phase 0.9 / 4.4 |
| D7 | **`nolint` alias** | Implement vs document non-goal | Phase 6.2 |

---

## System success metrics (definition of done)

| Metric | Baseline (today) | Target |
|--------|------------------|--------|
| Recommended-pack FP rate on canary repos | Unknown | < 15% of findings dismissed as noise (sampled) |
| Default scan side effects | Writes `scripts/` | Zero unless opted in |
| SARIF GitHub upload | Broken/unreliable | Green without transform |
| Rule catalog honesty | ~470 “on” | Tagged maturity; recommended ≪ all |
| Release | Source-only `0.0.1` | Tagged `≥0.1.0` binary |
| Docs drift incidents | Several known | Zero known schema/README lies |
| Recommended pack trust | Unmeasured | Senior Go triage: ≥70% of 20 findings actionable |
| Sanitizer correctness | Clean-only may suppress | Dedicated tests: Clean-only still flags CWE-22 |
| SourceIndex lookup | O(N) ~737 | O(1) / binary_search; microbench gated |
| Canary stability | None | ±N findings budget on pinned modules |

---

## Source coverage matrix

| Feedback cluster | Phase |
|------------------|-------|
| Export default off | 0.1 |
| SARIF camelCase / severity / workingDirectory | 0.2 |
| License dual claim | 0.3, 7.1 |
| Docs/schema drift (taint, counts, severity_overrides, fail_on) | 0.4 |
| CLI no-ops / conflicts / snippet split | 0.5, 6.3 |
| Sanitizer Clean / Path / CWE-78 | 0.6 |
| Path confinement dataflow-local | 0.6 |
| Injection core CWE-22/78/79/89/90/91 | 0.7 |
| Taint default + `--taint` UX | 0.8 |
| Error::Walk taxonomy | 0.9, 7.6 |
| Box::leak findings | 0.9, 4 |
| Mutex poison | 0.9, 4.4 |
| Max file size / fixture path / rebuild-cache safety | 0.9 |
| Profiles recommended/perf/security/style/all | 1.1 |
| Maturity tags + fixture-only quarantine | 1.2 |
| NEEDLES museum / rewrite bar | 1.3, 2.5 |
| Severity/confidence / BP-off recommended | 1.4, 3.3 |
| PERF-first positioning | 1.5, 7.3 |
| Sample workflow | 1.6, 7.2 |
| PERF S/A/B/C tiers | 2.1 |
| is_hot_path | 2.2 |
| PERF advice quality | 1.4 / 2.3 |
| Framework Gin/Echo/Chi/GORM plan | 2.4 |
| Sink classification without types | 2.5 |
| BP vs staticcheck matrix | 3.1 |
| BP-8/9/1/6/21/28 | 3.2 |
| SourceIndex O(1) | 4.1 |
| Lazy facts | 4.2 |
| source_cache / memory modes | 4.3 |
| Taint parallel accumulate | 4.4 |
| FxHash / hashbrown | 4.5 |
| mtime prefilter / warm path | 4.6 |
| Bench honesty | 4.7 |
| Same-scan cascade | 5.1 |
| Tool-version bust | 5.2 |
| Path keys ProjectPath | 5.3 |
| Cache multi-process policy | 5.4 |
| Fixture variants / exclusive oracles / FP suite | 5.5 |
| Canary 3 modules + dogfood | 5.6 |
| Hit-rate telemetry / explain confidence | 5.7 |
| Baseline list/prune/fingerprint/expires | 6.1 |
| Ignore block/EOL/lang comments | 6.2 |
| CLI subcommands | 6.3 |
| Pub surface + sinks move + dep trait | 6.4 |
| Config subobjects | 6.5 |
| finalize model | 6.6 |
| Release multi-arch / SBOM / audit | 7.1 |
| GH Action | 7.2 |
| Go docs packs + RFC + detection_notes | 7.3 |
| Embedder docs / Finding semver | 7.4 |
| ADR / CONTRIBUTING / branding / roadmap | 7.5 |
| Internal CI quality gates | 7.6 |
| Intra/inter taint depth | 8.1–8.2 |
| Optional go/packages typed | 8.3 deferred |
| Codegen safety / build layout | 8.4 |
| Crate split | 8.5 |
| Streaming SARIF | 8.6 deferred |
| Multi-lang invest vs demote | 9.1 |
| Dynamic plugins | 9.2 OOS |
| Review composite scores / competitive table | framing only |
| Non-goals lists | deferred table above |

---

## Critical file map (likely touch points)

| Area | Paths |
|------|--------|
| SARIF | `src/reporting/sarif/`, snapshots |
| CLI / config | `src/cli/`, `src/app/`, schema/templates |
| Taint / sanitizers | `src/lang/go/detectors/cwe/taint/` |
| CWE / needles | `.../cwe/domains/`, `.../cwe/source_index.rs` |
| PERF | `src/lang/go/detectors/perf/` |
| BP | `src/lang/go/detectors/bad_practices/` |
| Findings / leak | `src/rules/finding.rs`, `finding_wire.rs` |
| Errors | `src/error.rs`, `src/engine/io.rs`, cache |
| SourceIndex | `src/lang/source_index.rs`, build codegen |
| Cache | `src/engine/cache/*`, `src/engine/analyzer/scan.rs` |
| Parallel / taint state | `src/engine/walk/parallel.rs` |
| Sinks | `src/engine/sinks.rs` → move to lang/go |
| Fixtures safety | `src/fixture/materialize.rs` |
| Registries | `ruleset/golang/`, `.../registry/*.toml` |
| Fixtures | `tests/fixtures/go/` |
| Benches | `benches/*`, `scripts/check_bench_budget.sh` |
| Docs | `docs/taint.md`, `docs/bad-practices.md`, README, LICENSE* |

---

## Related docs

| Doc | Use for |
|-----|---------|
| [ultra-senior-go-rust-product-review.md](./ultra-senior-go-rust-product-review.md) | Ratings, evidence, strategic recommendations |
| [improvements.md](./improvements.md) | Product priorities, packs, CI, packaging |
| [go.md](./go.md) | Detectors, taint, PERF, BP, fixtures |
| [rust.md](./rust.md) | Engine errors, perf craft, cache, API, codegen |

---

*Checklist covers all actionable feedback from the four source files under `plans/feedback/10072026/`. Ratings and competitive narrative from the review are treated as framing, not implementable tasks.*
