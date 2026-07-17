# v0.0.3 — Executive Summary

> **Branch:** `feat/bp-implementations` (`2c01a83`)  
> **Base:** `master` (`3a91c1b`)  
> **Commits:** 28 non-merge · **Diff:** 408 files · **+20,678 / −1,068**  
> **Date:** 2026-07-16  
> **Method:** Detailed scan of every branch commit (message, files, logic) plus plan/checklist markdown, produced via three parallel read-only analysis passes:
>
> 1. **BP product track** — rules, detectors, fixtures, admission gates  
> 2. **Rust engine quality track** — lifecycle, cache, taint, performance, review ledger  
> 3. **Branch inventory / plans track** — full categorization, D1–D5 backlog, deliberate non-goals  

**Primary sources of truth**

| Document | Role |
|----------|------|
| [`plans/v0.0.3/new-bad-practices/CHECKLIST.md`](../plans/v0.0.3/new-bad-practices/CHECKLIST.md) | BP shipping gate & ID status |
| [`plans/v0.0.3/new-bad-practices/README.md`](../plans/v0.0.3/new-bad-practices/README.md) | Curated BP program purpose |
| [`plans/v0.0.3/new-bad-practices/IMPLEMENTABLE-DEFERRED-BP-PLAN.md`](../plans/v0.0.3/new-bad-practices/IMPLEMENTABLE-DEFERRED-BP-PLAN.md) | Deferred promotion batches |
| [`v0.0.3/codex-review.md`](./codex-review.md) | Closed Rust remediation ledger |
| [`plans/v0.0.3/rust_audit_report.md`](../plans/v0.0.3/rust_audit_report.md) | Domain-level Rust audit |
| [`plans/v0.0.3/performance_analysis.md`](../plans/v0.0.3/performance_analysis.md) | Scan cost analysis |
| [`plans/v0.0.3/README.md`](../plans/v0.0.3/README.md) | Deferred D1–D5 inventory |
| [`documents/bad-practices.md`](../documents/bad-practices.md) | User-facing BP docs |

---

## 1. One-paragraph summary

This branch is a **dual investment**: it roughly **doubles** CodeHound’s Go bad-practice catalog (**65 → 136** rules, **+71** curated detectors with ~**368** fixtures) across core language, concurrency, HTTP frameworks, data layers, observability, and testing—while **keeping BP off** in recommended/security profiles so default CI stays honest—and in parallel it closes a multi-agent **Rust engine remediation** (scan lifecycle, cache cold/warm parity, taint correctness, allocation cuts, typed boundaries, docs ratchet) that lifts review scores from ~**8.0–8.2** to **9.7 / 9.8** on Best Practices and Development Patterns. Together those tracks make CodeHound both **more useful on real Go services** and **safer to scale as detector count grows**.

---

## 2. Why this work mattered

| Theme | Problem before | What we delivered | Why it matters |
|-------|----------------|-------------------|----------------|
| **Detection coverage** | Only BP-1..65; many service-level Go mistakes invisible | +71 rules (frameworks, GORM/sqlx, resources, logging/JSON/gRPC/CLI) | Catches high-regret production footguns stock default linters miss or only cover via optional plugins |
| **Catalog discipline** | Risk of dumping 100 speculative BP-66..165 candidates | 71 admitted / **29 deferred** with written reasons | Protects trust; deferred list is roadmap, not silent debt |
| **Default-profile honesty** | Expanding BP could poison CI | BP remains **off** in `recommended` / `perf` / `security` | Recommended pack stays high-signal (PERF + taint-core) |
| **Engine correctness under load** | Global timing races, fragile detector reset, warm-cache drift, taint over-claim | Scan-owned lifecycle, cache parity, function-local taint, typed wire | Findings stay correct under parallel scans, panics, and warm cache |
| **Scale economics** | BP suite already ~**89%** of scan thread time; catalog 2× | Engine alloc/index/cache work + performance plan documented | Repeat CI / partial rescan stay viable as rules grow |
| **Maintainability** | Multi-agent reviews ~8/10; unwrap/fmt/cache test failures | Closed ledger, Clippy `-D warnings`, docs ratchet | Lower chance next BP tranche reopens engine debt |

**Stakeholder takeaway:** detectors without engine trust amplify false confidence and cost; engine polish without detectors leaves everyday Go production bugs invisible. This branch does **both**.

---

## 3. Scope metrics

| Metric | Value |
|--------|------:|
| Non-merge commits (`master..HEAD`) | 28 |
| Files changed | 408 |
| Lines added / removed | +20,678 / −1,068 |
| Live BP rules | **136** (was **65**) |
| Admitted from BP-66..165 candidates | **71** of 100 |
| Explicitly deferred candidates | **29** |
| BP fixture files (checklist) | ~368 |
| Rust Best Practices (closed) | **9.7 / 10** (target ≥ 9.5) |
| Rust Development Patterns (closed) | **9.8 / 10** (target ≥ 9.5) |
| Integration posture | `go_bad_practice_integration` green; Clippy/fmt locked gates recovered |

### Progressive BP count ratchets

| Milestone | Rules |
|-----------|------:|
| Pre-tranche baseline | 65 |
| First curated tranche | 81 |
| Next curated batch | 89 |
| Phase 4 promotion | 100 |
| Phase 5 + deferred promotion | **136** |

### Domain coverage of the +71 new rules

| Domain (candidate parts) | Approx. shipped | Deferred |
|--------------------------|----------------:|---------:|
| A — Core language/context (BP-66..85) | 15 | 5 |
| B — Concurrency/resources (BP-86..100) | 15 | 0 |
| C — HTTP/frameworks (BP-101..125) | 13 | 12 |
| D — Data persistence (BP-126..145) | 14 | 6 |
| E — Observability/config/JSON/gRPC/CLI (BP-146..160) | 10 | 5 |
| F — Testing/API hygiene (BP-161..165) | 4 | 1 |
| **Total** | **71** | **29** |

### Version-name note

Plan folders use **v0.0.3**; published product bar in `CHANGELOG.md` / `ROADMAP.md` is **0.1.0**. This branch is the **v0.0.3 execution track** (BP expansion + engine quality) and is **not yet** reflected as a named CHANGELOG release entry for the 65→136 expansion.

---

## 4. Commit categorization (all 28)

| Category | Count | Share | Role |
|----------|------:|------:|------|
| **BP product** | 7 | 25% | Catalog expansion 65→136 |
| **Rust quality** | 9 | 32% | Lifecycle, cache, taint, alloc, boundaries |
| **Docs/plans** | 5 | 18% | Gates, checklists, perf analysis, API docs |
| **Tooling/hygiene** | 4 | 14% | lint/fmt, JSON sort, makefile, gitignore |
| **Tests** | 3 | 11% | ignore unicode, cache/API, taint depth fixtures |

**Branch shape:** product BP commits first, then a second half almost entirely engine quality. Grow detectors, then harden the scanner that must run them.

### Full ledger (oldest → newest)

| SHA | Subject | Category |
|-----|---------|----------|
| `fc6bcc9` | feat(go): ship curated v0.0.3 bad-practice batches | BP product |
| `dd952a8` | feat(go): ship next curated bad-practice batch | BP product |
| `8f98bc1` | chore: fix lint and formatting issues | Tooling/hygiene |
| `bdf5c9a` | docs: record BP quality gates | Docs/plans |
| `9ebaf14` | feat(go): add phase 4 HTTP bind checks | BP product |
| `73f824a` | feat(go): ship phase 4 curated bad-practice checks | BP product |
| `ca90357` | Sorted the json | Tooling/hygiene |
| `fcbc9e5` | Updated the checklist | Docs/plans |
| `c5caab4` | Updated the gitignore for the codex | Tooling/hygiene |
| `9dc274a` | feat(go): ship phase 5 bad-practice batch | BP product |
| `8c25209` | Updated the makefile for generating the chunks | Tooling/hygiene |
| `4989c70` | Updated the checklist | Docs/plans |
| `840b882` | feat(go): add deferred HTTP framework bad practices | BP product |
| `9ff505d` | feat(bp): implement deferred bad-practice batch | BP product |
| `205469e` | refactor: adhere to Rust best practices and development patterns | Rust quality |
| `e32eaab` | added the performance analysis | Docs/plans |
| `8b04cf8` | fix(rust): recover quality gates and source retention contract | Rust quality |
| `dfa5d8b` | test(rust): cover unicode ignore offsets | Tests |
| `a3a4a64` | refactor(rust): harden scan lifecycle and cache contracts | Rust quality |
| `c2c9093` | test(rust): cover cache and API hardening | Tests |
| `bf81cd5` | perf(rust): reduce review hot-path allocations | Rust quality |
| `d6d4e2e` | refactor(rust): index taint lookups and narrow API | Rust quality |
| `bede6d9` | refactor(rust): close review lifecycle and allocation gaps | Rust quality |
| `f6c27ac` | refactor(rust): close review checklist slice | Rust quality |
| `6382652` | docs(rust): ratchet contracts and module boundaries | Docs/plans |
| `1a6ae6d` | perf(rust): optimize taint and timing paths | Rust quality |
| `56a1ac9` | refactor(rust): close review checklist with typed boundaries and docs | Rust quality |
| `2c01a83` | test(fixtures): enable multi-hop taint depth for manifest fire checks | Tests |

---

## 5. Workstream A — Curated Go bad-practice expansion

### 5.1 Strategy and logic

1. **Do not ship 100 equal-status candidates.** Admit only high-signal, statically provable rules.
2. **Every shipped rule** gets: JSON metadata → codegen/dispatch → detector → vulnerable/safe `.txt` fixtures (+ variants) → `manifest.toml` → docs → integration green.
3. **Framework rules fire only when the import is present** (same pattern as PERF); stay out of pure PERF/CWE territory.
4. **BP remains advisory** under `style` / `bp` / `all`; **off** in recommended/security/perf.
5. **Parallel workers** own detectors + fixtures; **coordinator** owns ruleset, dispatch, manifest, docs, checklist.

### 5.2 Admission gates (continuous policy)

| Gate | Requirement |
|------|-------------|
| Overlap | Not a pure duplicate of BP-1..65 / CWE / PERF / `go vet` / staticcheck / errcheck / bodyclose / sqlclosecheck |
| Unique value | If overlap exists, document CodeHound-unique value (framework gate, multi-statement lifecycle, zero-dep) |
| Static proof | Tree-sitter / local facts only — no invented types, SSA, or interprocedural certainty |
| Fix text | Canonical remediation in one actionable sentence |
| Fixtures | Vulnerable + safe (often variants) **before** promotion |
| Framework honesty | Import + typed context; never bare method-name matching |
| Severity / profile | Severity + suppression/intent boundary recorded |

### 5.3 Phase-by-phase delivery

#### Phase 0 — Baseline & policy lock

- Baseline: **65** rules, BP advisory-only in default product posture.
- Decision: curate, don’t flood; tier existing pack (trusted / review-required / style / reserved BP-63).
- **Why:** Protects recommended-profile credibility before adding detectors.

#### First curated tranche — `fc6bcc9`

**Logic:** Seed high-signal core/HTTP/data rules with dedicated detector modules and full fixture pairs.

**Representative IDs:** BP-67, 72, 73, 75, 79, 80, 84, 88, 98, 99, 101, 109, 116, 131, 145, 159  

**Product value:** Classic production footguns — panics (nil maps, bad `errors.As`), silent typed-nil bugs, broken HTTP header/body order, cancel/TODO hygiene.

**Files:** `ruleset/golang/bad-practices.json`, `batch_*` / `bp72_*` / `bp79_*` / `bp84_*` / `bp101_*` detectors, ~16×4 fixture variants, `documents/bad-practices.md`, checklist.

#### Next curated batch — `dd952a8`

**IDs:** BP-68, 85, 102, 136, 142, 151, 162, 164  

**Product value:** Service-shaped problems — handler status contracts, GORM `AutoMigrate` on request path, sqlx `In` without `Rebind`, secret env logging, flaky parallel tests, functional options mutating globals.

#### Phase 4 HTTP bind — `9ebaf14` + Phase 4 curated — `73f824a`

**IDs:** BP-66, 86, 87, 89, 110, 117, 120, 138, 141, 161, 163 (bind suite 110/117/120)  

**Product value:** Bind/parser errors ignored across Gin/Echo/Fiber; mutex/channel panic classes; prod DSN in tests; unguarded golden updates.  
**Catalog:** → **100** rules. Modules later renamed off temporary `batch_phase4_*` names.

#### Phase 5 — `9dc274a` (breadth phase)

**IDs include:** BP-76, 81, 90–94, 96, 97, 100, 104, 105, 107, 122, 128, 132–135, 140, 143, 146, 147, 149, 155, 156, …  

**Product value — ecosystem breadth:**

| Area | Examples |
|------|----------|
| Reliability under load | errgroup without context, unbounded fan-out, map races |
| HTTP production hygiene | Cookie Secure/HttpOnly, mux overlap, middleware missing `next` |
| Dominant ORM correctness | GORM Error / First not-found / global DB without Session |
| Security-adjacent hygiene | Sensitive logging, unbounded JSON body, omitempty on security fields |

#### Deferred HTTP — `840b882` + multi-domain deferred — `9ff505d`

| ID | Logic (detector intent) |
|----|-------------------------|
| BP-70 | `err != nil` branch logs and continues without return/panic/exit |
| BP-82 | `time.Parse` layout without zone (advisory; no timezone policy inference) |
| BP-83 | Production `time.Sleep` as synchronization (excludes tests/backoff shapes) |
| BP-111 | Gin `*gin.Context` used in goroutine without `c.Copy()` (import + type + local) |
| BP-119 | Fiber context lifetime across goroutine (framework-gated) |
| BP-126 | Local `Begin`/`BeginTx` with no Commit/Rollback or ownership transfer |
| BP-95 | Client response without body close (zero-dep; bodyclose overlap documented) |
| BP-154 | Bare `json.Unmarshal(...)` expression statement (blank assign left to BP-1) |
| BP-158 | gRPC-shaped naked error when status helpers imported |
| BP-160 | Cobra `Run` instead of `RunE` (advisory) |

**Catalog:** → **136** rules.

### 5.4 Full shipped BP-66+ inventory (71)

**Core / errors / time:**  
BP-66, 67, 68, 70, 72, 73, 75, 76, 79, 80, 81, 82, 83, 84, 85  

**Concurrency / resources:**  
BP-86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100  

**HTTP / frameworks:**  
BP-101, 102, 104, 105, 107, 109, 110, 111, 116, 117, 119, 120, 122  

**Data:**  
BP-126, 128, 131, 132, 133, 134, 135, 136, 138, 140, 141, 142, 143, 145  

**Observability / config / JSON / CLI / testing / API:**  
BP-146, 147, 149, 151, 154, 155, 156, 158, 159, 160, 161, 162, 163, 164  

### 5.5 Deferred remaining (29) — and why

| IDs | Dominant defer reason |
|-----|------------------------|
| BP-69, 71, 74, 77, 78 | Contract/intent, aliasing, interprocedural context propagation |
| BP-103, 106, 108, 112–115, 118, 121, 123–125 | Auth/deploy intent, CWE/data-flow, whole-package middleware graphs |
| BP-127, 129, 130, 137, 139, 144 | Driver semantics, SQL injection tooling, package-wide config/namespace |
| BP-148, 150, 152, 153, 157, 165 | Runtime/config intent, multi-file lifecycle/constructor contracts |

**Themes:** intent/deployment, whole-package auth, CWE/data-flow, or type depth beyond current tree-sitter architecture.

### 5.6 Engineering surface area

| Area | Path |
|------|------|
| Ruleset | `ruleset/golang/bad-practices.json` |
| Dispatch | `src/lang/go/detectors/bad_practices/dispatch.rs` |
| Detectors | `src/lang/go/detectors/bad_practices/rules/` |
| Docs | `documents/bad-practices.md` |
| Fixtures | `tests/fixtures/go/bad_practices/BP-*` |
| Manifest | `tests/fixtures/manifest.toml` |
| Plans | `plans/v0.0.3/new-bad-practices/` |

---

## 6. Workstream B — Rust engine quality, lifecycle, taint, performance

### 6.1 Score progression

| Milestone | Best practices | Dev patterns |
|-----------|---------------:|-------------:|
| Fresh five-agent baseline | ~8.2 median | ~8.0 median |
| After Priority 1 (lifecycle) | 8.7 | 8.9 |
| After Priority 2 (boundaries + taint correctness) | 9.2 | 9.4 |
| After Priority 3–4 (alloc + docs) — **closed** | **9.7** | **9.8** |
| Target | ≥ 9.5 | ≥ 9.5 |
| 10/10 | **Not claimed** (hardware timing + full prose intentionally non-gating) | same |

### 6.2 Remediation timeline (logic)

| Commit | What changed | Why it mattered |
|--------|--------------|-----------------|
| `205469e` | SHA-256 cache fingerprints (was unstable DefaultHasher); reduce clones; ignore-in-strings fix; RAII temp dirs; error-type preservation for exit codes | Foundation for portable, correct warm cache |
| `e32eaab` | Performance analysis: BP suite ~**89.5%** of thread time; redundant AST walks; cursor overhead | Named the hotspot (BP micro-opts still planned, not fully closed) |
| `8b04cf8` | Unblock Clippy/fmt; align source-cache tests with `retain_sources` contract | Quality gates green without weakening memory design |
| `dfa5d8b` | Unicode ignore offset regressions | Multi-byte source correctness |
| `a3a4a64` | Detector session lifecycle; suppressed_count on cache entries; library-level rule-config fingerprint | Cold/warm parity; panic-safe scan boundaries |
| `c2c9093` | Cache/API/finding construction tests | Lock in contracts |
| `bf81cd5` | Borrowed cache put (no findings clone); taint path reconstruction; span sweep | Hot-path cost as finding volume grows |
| `d6d4e2e` | Indexed taint name maps; narrower public API | Faster lookups; smaller surface |
| `bede6d9` | Scan-owned timing collectors; `FindingWire` checked constructors; analyzer scan gate documented | Parallel scan isolation; malformed wire cannot invent findings |
| `f6c27ac` | Accessors, benches, panicking-detector fixtures, example smokes | Proof for lifecycle + API claims |
| `6382652` | `# Errors` / lifecycle docs; missing_docs ratchet | Maintainability for multi-agent development |
| `1a6ae6d` | Single taint graph reuse; first-hit reachability BFS; function-local summaries; package root scope; `requires_cache_state`; CI benches | Correctness + cost at finalize; multi-hop honesty |
| `56a1ac9` | Typed registry/cache errors; close ledger at 9.5+ | Boundary failures are typed, not opaque |
| `2c01a83` | Manifest fire checks use multi-hop taint depth | Fixture inventory matches integration semantics |

### 6.3 Correctness themes (detail)

**Lifecycle**

- Detectors retain cross-file project state → need real scan boundaries.
- Delivered: scan-gate mutex (one analyzer serializes scans), RAII `reset_state`, `catch_unwind` isolation, Go project state published only after per-file rules succeed.

**Cache**

- SHA-256 rule-config fingerprint includes only/skip/taint/severity/depth.
- Suppressed counts persist → warm diagnostics match cold.
- `Detector::requires_cache_state` replaces taint-only reparse gate.
- Wire validation: zero/inverted ranges, confidence, intern cap → typed errors, not silent corruption.

**Taint**

| Bug class | Fix |
|-----------|-----|
| Cross-function name collision | Function-range / scope ownership filters |
| Direct sink over-claim | Sources/sinks restricted to owning function |
| Multi-hop return FP | Requires `returns_result` |
| Multi-hop param FP | Explicit argument bindings |
| Package-level panic | Package root scope before walk |
| Graph rebuild divergence | One graph + shared adjacency index for finalize/summary |

### 6.4 Performance: what was optimized vs what remains

**Identified (analysis):** sample ~5.4s wall / ~110s cumulative thread time for 78 files; BP dominates via N independent AST walks and missing short-circuits.

**Optimized on this branch:** timing contention, cache write clones, taint graph rebuilds, summary path allocations, span enrichment, ignore parse, portable fingerprints.

**Still open:** BP rule-level substring short-circuits and single-cursor package-scope scans from `performance_analysis.md` Phase 1–4 (unchecked). Engine work still matters because warm cache + correct finalize keep **repeat CI** viable under a 2× BP catalog.

### 6.5 Priority 1–4 (codex-review) — all closed

| Priority | Theme | Status |
|----------|-------|--------|
| P1 | Scan-owned timing; detector lifecycle; cache capability | Closed |
| P2 | FindingWire checked path; accessors; function-local taint; package root | Closed |
| P3 | No findings clone on cache; shared taint index; reachability BFS; benches/CI | Closed |
| P4 | missing_docs ratchet; # Errors/# Panics; example smoke | Closed |

---

## 7. Plans inventory and remaining backlog

### 7.1 Plans used on this branch

| Plan | Status |
|------|--------|
| `new-bad-practices/*` | Primary product delivery — largely shipped |
| `codex-review.md` | Rust remediation — **closed** |
| `performance_analysis.md` | Analysis done; BP micro-opts **open** |
| `rust_audit_report.md` | Audit findings largely resolved |
| `pending-work_v3.0.0.md` | Banner still “not started” for fix engine / deep taint — **stale vs BP checklist**; treat as engine/fix backlog, not BP status |
| `deferred/D1–D5` | Historical inventory (~288 items; many still open) |

### 7.2 D1–D5 themes still not shipped (later sprints)

1. **Auto-fix engine** (apply / dry-run / gofmt / rescan)  
2. **Deeper taint** (defer tracking, more sinks, hop_details)  
3. **PERF residuals** (Category C, timing on cache hits)  
4. **BP polish** (existing-pack noise hardening, severity override wiring)  
5. **Architecture DI** (ScanRun, Registry/CacheBackend injection)  
6. **External gopdfsuit** — out of CodeHound product scope  

### 7.3 Open checklist items (product-relevant)

- [ ] Harden noisiest **existing** BP-1..65 detectors (trust cleanup)  
- [ ] Real-module canaries vs `go vet` / staticcheck  
- [ ] Reassess 29 deferred candidates with field evidence  
- [ ] BP performance short-circuits (plan Phase 1+)  
- [ ] CHANGELOG entry when this track merges as a named release  

---

## 8. Deliberately not done — and why that is good

| Non-goal | Risk avoided |
|----------|--------------|
| Ship all 100 BP-66..165 candidates | Low-signal noise / false confidence |
| Ship 29 deferred (auth intent, deploy config, CWE overlap) | Security-looking FPs; tool duplication |
| Enable BP in recommended/security | Default CI pollution |
| Full fix engine | Broken auto-edits before model stabilizes |
| Claim Rust 10/10 | False perfectionism gates |
| Re-encode PERF/CWE as BP | User confusion; overlap matrix collapse |

**Policy in one line:** grow where proof exists; keep defaults honest; leave unprovable work on a written backlog.

---

## 9. Risks mitigated

| Risk if expanded naively | Mitigation on branch |
|--------------------------|----------------------|
| Default CI unusable | BP off in recommended/security |
| False positives destroy trust | Admission gates, import/type gates, safe near-miss fixtures, review-only labels |
| Overlap with staticcheck/CWE confuses buyers | Explicit defer/drop; framework-specific value only |
| More detectors → wrong/slow scans | Lifecycle, cache parity, taint precision, alloc/index work |
| Warm-cache lies / parallel races | Scan-owned timing, panic-safe reset, stateful-detector capability |
| Multi-agent churn without bar | Closed review ledger, typed errors, docs ratchet, locked Clippy |
| Silent unfinished backlog | Written deferred IDs + D1–D5 inventory |

---

## 10. Stakeholder narrative

### The problem

Pre-branch BP stopped at **BP-1..65**. Production Go services still accumulate mistakes that **neither default `go vet`/staticcheck nor pure CWE packs fully catch**: framework context misuse across goroutines, GORM/sqlx error-chain hygiene, resource close/flush gaps, sensitive logging, JSON/gRPC/CLI footguns, concurrency lifecycle shapes. Expanding without discipline either dumps speculative rules (burns trust) or leaves users with a thin pack while the engine accumulates lifecycle/cache debt.

### What this branch invested in

1. **Product depth** — ~**2.1×** BP catalog (**65 → 136**), curated in PR-sized batches with fixtures, dispatch, metadata, and docs. **71 new detectors**, **~368** fixtures, **29** candidates deferred with reasons.  
2. **Engineering foundation** — multi-agent remediation to **9.5+**: scan-owned timing, panic-safe lifecycle, cache suppression parity, function-local taint, fewer hot-path allocations, typed boundaries, documentation ratchet.

### Why both together

Detectors without engine trust amplify false confidence and cost (BP alone is already ~**89%** of scan thread time). Engine polish without new detectors leaves everyday production mistakes invisible. This branch does **both**, and refuses the third failure mode: shipping unprovable rules or turning BP into a default-blocking CI club.

### What to expect next

- Not yet a named CHANGELOG ship for this track; release hygiene remaining (canaries, noise audit, optional BP short-circuits).  
- Later sprints: fix engine, deeper taint, PERF residuals — **not** more speculative BP dumps.

### Bottom line

**This track converts research-style BP-66..165 proposals into a curated, fixture-backed product surface while hardening the scanner so those rules do not undermine correctness, cache honesty, or CI trust.** The deferred list is a feature of the process, not a failure of delivery.

---

## 11. Analysis method (subagents)

| Pass | Focus | Key outputs used above |
|------|--------|------------------------|
| **1 — BP product** | feat commits, CHECKLIST, deferred plan, fixtures, admission gates | Metrics 65→136; phase IDs; deferred table; product value narrative |
| **2 — Rust engine** | refactor/perf/fix/test/docs commits, codex-review, audit, performance plan | Score progression; lifecycle/cache/taint fixes; P1–P4; hotspot vs optimized |
| **3 — Branch inventory** | All 28 commits categorized; plans README; D1–D5; CHANGELOG/ROADMAP gap; non-goals | Category roll-up; open items; risks mitigated; stakeholder narrative |

---

## 12. References

| Artifact | Path |
|----------|------|
| This summary | `v0.0.3/executive-summary.md` |
| Rust remediation ledger | `v0.0.3/codex-review.md` |
| Plans index | `plans/v0.0.3/README.md` |
| BP checklist (SoT) | `plans/v0.0.3/new-bad-practices/CHECKLIST.md` |
| Deferred BP plan | `plans/v0.0.3/new-bad-practices/IMPLEMENTABLE-DEFERRED-BP-PLAN.md` |
| Performance plan | `plans/v0.0.3/performance_analysis.md` |
| Rust audit | `plans/v0.0.3/rust_audit_report.md` |
| Pending work (engine/fix backlog) | `plans/v0.0.3/pending-work_v3.0.0.md` |
| Published changelog | `CHANGELOG.md` |
| Live roadmap | `ROADMAP.md` |
| User-facing BP docs | `documents/bad-practices.md` |
