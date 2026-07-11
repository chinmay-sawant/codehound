# CodeHound: Ultra-Senior Go + Rust Product Review (Post Phases 0–9)

| Field | Value |
|-------|--------|
| **Date** | 2026-07-11 |
| **Branch** | `feat/feedback-improvements` |
| **Version reviewed** | `0.1.0` |
| **Review type** | Product + architecture + rule quality + Rust craft (delta vs 2026-07-10) |
| **Method** | 4 parallel explore subagents (Rust craft, Go product, CLI/packaging, architecture/positioning) + checklist triage |
| **Prior review** | [`ultra-senior-go-rust-product-review.md`](./ultra-senior-go-rust-product-review.md) (0.0.1 / `feat/enhanced-perf`) |

---

## Executive summary

**Useful product?**  
**Yes — as a complementary Go PERF + framework-footgun scanner with real CI plumbing.**  
**Still no — as a security SAST replacement, golangci-lint replacement, or multi-language platform.**

After phases 0–9, CodeHound is no longer “excellent bones, muddy value prop.” Defaults, packs, SARIF, export, BP demotion, taint honesty, Go-first marketing, and 0.1.0 packaging engineering are **aligned with the only defensible niche**. Residual gaps are **external FP proof**, **public `v0.1.0` tag**, long-tail CWE under `all`, and a few engine/API polish items.

| Market pitch (0.0.1) | What 0.1.0 actually is |
|---|---|
| “CWE security analyzer with 175+ entries” | **Recommended pack** is S-tier PERF; taint-core CWEs only fire with `--taint` / security profile |
| “Multi-language” | **Go-first** (ADR 0005); Python opt-in; TypeScript stub **removed** |
| “Complement existing tooling” | Still correct — now the docs and defaults enforce it |

---

## Ratings (post 0–9)

### Overall scores

| Dimension | Prior (0.0.1) | **Now (0.1.0)** | Grade | Notes |
|-----------|-------------:|----------------:|:-----:|-------|
| **Product usefulness (scoped)** | 7.0 | **7.8** | B+ | PERF wedge + honest packs |
| **Product usefulness (as marketed)** | 4.5 | **7.2** | B | Marketing debt largely closed |
| **Go analysis depth** | 5.5 | **7.0** | B | Taint depth + BP fixes; still no types/SSA |
| **Rule signal / noise (recommended)** | 4.0 | **8.5** | A− | Small pack; BP off; fixture quarantine |
| **Rust engineering craft** | 7.5 | **8.5** | A− | Review bullets fixed for real |
| **Architecture (engine)** | 8.0 | **8.6** | A− | Cascade, path ID, SourceIndex O(1) |
| **Architecture (rules)** | 5.0 | **6.5** | B− | Tiers/maturity better; long tail under `all` |
| **Test discipline** | 7.5 | **8.0** | B+ | Oracles stronger; canaries exist |
| **CLI / CI product surface** | 6.0 | **7.8** | B+ | Subcommands, baseline, Action |
| **Multi-language maturity** | 3.0 | **4.0** | D+ | Honesty ↑; capability still Go-only |
| **Packaging / release readiness** | 3.5 | **7.2** | B | Dual license + multi-arch workflow; tag human step open |
| **Docs fidelity** | 6.0 | **7.0** | B | Residual: severity table / historical bench tables |
| **Security of the tool itself** | 7.0 | **7.6** | B+ | Offline, audit, export opt-in |
| **Competitive differentiation** | 7.0 | **7.8** | B+ | Defaults match the wedge |

### Perspective-specific grades

#### Ultra-senior Go (~20y)

| Area | Prior | **Now** | One-liner |
|------|:-----:|:-------:|-----------|
| Architecture | B | **B+** | Packs + hot-path + framework rules |
| CWE-22/78/89 depth | C+/B- | **B** | Clean honesty; field keys; still name-string |
| CWE long tail | D | **C−** | Quarantine started; museum remains under `all` |
| PERF pack | C- | **A−** | S-tier is the product |
| BP pack | C | **B** | Fixed 1/6/8/9; style advisory only |
| CI hard-gate trust | F | **B−** | Strict high+ soft on Medium PERF by design |
| **Overall Go product** | **C+** | **B+** | Run as complement; not stack replace |

#### Ultra-senior Rust

| Area | Prior | **Now** | One-liner |
|------|:-----:|:-------:|-----------|
| Hot-path architecture | B+ | **A−** | SourceIndex O(1), retain_sources, cascade |
| Error taxonomy | C | **B** | PathIo/Cache; Walk still string bag |
| Perf craft | B- | **A−** | Lazy taint facts; honest benches |
| API encapsulation | C+ | **B** | Still fat engine re-export |
| Codegen | B | **A−** | Validated function idents |
| Packaging / release | D+ | **A−** | Dual license + release.yml |
| **Overall Rust craft** | **B** | **A− / 8.5** | Fixed the bullets |

### Adoption readiness

| Adoption mode | Prior | **Now** | Rating |
|---------------|:-----:|:-------:|:------:|
| Optional CI job, SARIF/JSON, baseline | Yes | **Yes** | **8 / 10** |
| Required gate for curated PERF (after pilot) | Plausible | **Plausible** | **7 / 10** |
| Required gate for full CWE+BP+PERF default | No | **No** | **2 / 10** |
| Replace security SAST / govulncheck / golangci | No | **No** | **1 / 10** |
| Local Go review loop | Yes | **Yes** | **8 / 10** |

### Composite product rating

```
┌────────────────────────────────────────────────────────────┐
│  CODEHOUND OVERALL (complementary Go tool)    7.7 / 10     │
│  CODEHOUND OVERALL (as marketed platform)     7.2 / 10     │
│  Prior complementary                          6.5 / 10     │
│  Prior marketed                               4.5 / 10     │
│  Repositioned potential (prior)               8.0 / 10     │
│  Gap to potential: external canaries + v0.1.0 tag         │
└────────────────────────────────────────────────────────────┘
```

---

## Strategic recommendations (prior #1–8) — status

| # | Recommendation | Status |
|---|----------------|--------|
| 1 | PERF-first homepage / packs | **DONE** |
| 2 | Quarantine fixture-needle CWEs | **PARTIAL** (list short; long tail under `all`) |
| 3 | Sanitizer honesty (Clean) | **DONE** |
| 4 | High-signal default profile | **DONE** |
| 5 | SARIF + license + export off | **DONE** |
| 6 | BP dedup vs staticcheck | **DONE** |
| 7 | Multi-lang honesty | **DONE** (demote) |
| 8 | 0.1.0 bar | **PARTIAL** (engineering ready; public tag + external FP rates open) |

---

## Remaining open checklist (post-drift)

Drift fixed in `action-items.md` (typescript, parking_lot, PERF tiers/advice).  
**Consolidated backlog table:** see **Post-0.1 backlog** section in [`action-items.md`](./action-items.md) (B01–B28).

**Pursue next sprints:** B01 (real-repo triage), B03 (rewrite bar process), B06 (needle negative gates), B09–B11 (warm path + external canaries), B14/B17/B18 (API + codegen integrity).

---

## Final verdict

| Question | Answer |
|----------|--------|
| Is it useful? | **Yes** — scoped Go PERF + framework smells as a *second* tool |
| Is it a great product yet? | **Almost for the scoped niche** — 7.7/10 complement; still not CodeQL |
| Go senior | *Finally ships the PERF sidearm with honest defaults; don’t hard-gate Medium findings under Strict high+ without measuring FPs.* |
| Rust senior | *You fixed SourceIndex, export, SARIF, license, and poison recovery — `Error::Walk(String)` is the remaining drunken uncle.* |
| Together | *Tag `v0.1.0`, run a real monorepo pilot, keep quarantining fixture CWEs. Stop adding catalog width until hit rates exist.* |

```
Overall (complementary Go tool):     7.7 / 10   (was 6.5)
Overall (as marketed platform):      7.2 / 10   (was 4.5)
Rust craft:                          8.5 / 10   (was 7.5)
Go product:                          B+         (was C+)
```

---

*Stored for product feedback after phases 0–9. Not a substitute for measured FP rates on external Go monorepos.*
