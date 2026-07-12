# CodeHound: Ultra-Senior Go + Rust Product Review (Post 0.1.0 + site/docs wave)

| Field | Value |
|-------|--------|
| **Date** | 2026-07-12 |
| **Branch** | `feat/feedback-improvements` |
| **HEAD** | `2cef4f6` |
| **Version reviewed** | `0.1.0` (crate; **no public `v0.1.0` tag**) |
| **Review type** | Product + architecture + rule quality + Rust craft (delta vs 2026-07-11 post-P0–9) |
| **Method** | 4 parallel explore subagents (Rust craft, Go product, CLI/packaging, architecture/positioning) + direct runtime verification |
| **Prior reviews** | [`ultra-senior-go-rust-product-review-post-p0-9.md`](./ultra-senior-go-rust-product-review-post-p0-9.md) · [`ultra-senior-go-rust-product-review.md`](./ultra-senior-go-rust-product-review.md) |

---

## Executive summary

**Useful product?**  
**Yes — as a complementary Go PERF + framework-footgun checklist (local + optional SARIF).**  
**Still no — as a security SAST replacement, golangci-lint replacement, multi-language platform, or “install and hard-gate tomorrow” product for strangers.**

Phases 0–9 still hold. The engineering north star is coherent: **recommended pack**, Go-first, export off, taint opt-in, BP demoted, SARIF/baseline/cache real. Post–P0–9 commits mostly improved **audience positioning** (hobby/small-scale Go, cost vs unbounded agents) and the **marketing site** — and that site is now the largest honesty regression relative to the CLI.

| What improved | What the re-review sharpened |
|---|---|
| Audience story (README + site) is clearer | **S-tier PERF is Medium + recommended fail is Strict (high+)** → default CI **never fails** on the product wedge |
| Rust craft still A− / slight up | Marketing site still sells **export-by-default** and full-catalog theater |
| Engine/packs unchanged and solid | **No `v0.1.0` tag**, no release artifacts, Action builds from source and **`exit 0` always** |
| Fingerprint v2 + test alignment | Canary `http_service` uses `ListenAndServe` — **misses PERF-101** (`http.Server{` needle only) |

```
┌────────────────────────────────────────────────────────────┐
│  CODEHOUND OVERALL (complementary Go tool)    7.8 / 10     │
│  CODEHOUND OVERALL (as marketed platform)     7.0 / 10     │
│  Prior complementary (post P0–9)              7.7 / 10     │
│  Prior marketed (post P0–9)                   7.2 / 10     │
│  Rust craft                                   8.7 / 10     │
│  Go product                                   B  / 7.6     │
│  Gap to scoped potential: proof + gate + ship + site truth │
└────────────────────────────────────────────────────────────┘
```

**One-line product truth (2026-07-12):**  
*Excellent bones, honest README, soft CI gate, unshipped release, marketing site half a version behind the CLI.*

---

## What changed since post-P0–9 (2026-07-11)

| Area | Delta |
|------|--------|
| Engine / packs / taint | **Essentially flat** — phases 0–9 still the product bar |
| Tests | Fingerprint v2, always-on stats, Go-first defaults aligned |
| Docs path | `documents/` consolidation; historical `plans/` demoted in README/ROADMAP |
| Audience | Explicit hobby/small-scale + “after golangci” + bounded agent triage |
| Frontend / GH Pages | Major narrative + deep links; **export defaults and PERF counts drift** |
| Public ship | Still **no** `v*` tag in repo; `release.yml` unfired |

---

## Ratings (2026-07-12)

### Overall scores

| Dimension | Prior (0.0.1) | Post P0–9 | **Now** | Grade | Notes |
|-----------|-------------:|----------:|--------:|:-----:|-------|
| **Product usefulness (scoped)** | 7.0 | 7.8 | **7.9** | B+ | Niche clear; gopdfsuit evidence; B01 still open |
| **Product usefulness (as marketed)** | 4.5 | 7.2 | **7.0** | B− | Site re-muddies export + catalog theater |
| **Go analysis depth** | 5.5 | 7.0 | **7.0** | B | Flat; Clean opacity FN + no types/SSA |
| **Rule signal / noise (recommended)** | 4.0 | 8.5 | **8.5** | A− | Small pack still excellent |
| **Rust engineering craft** | 7.5 | 8.5 | **8.7** | A− | Lazy taint + codegen integrity visible |
| **Architecture (engine)** | 8.0 | 8.6 | **8.6** | A− | Hold; path topology unfinished |
| **Architecture (rules)** | 5.0 | 6.5 | **6.7** | B− | Packs good; severity×fail coupling |
| **Test discipline** | 7.5 | 8.0 | **8.1** | B+ | Oracles + canaries; weak external pins |
| **CLI / CI product surface** | 6.0 | 7.8 | **8.0** | B+ | Profiles/baseline strong; Action soft |
| **Multi-language maturity** | 3.0 | 4.0 | **3.8** | D+ | Honesty ↑; capability still Go-only |
| **Packaging / release readiness** | 3.5 | 7.2 | **6.5** | C+ | Workflow ready; **unshipped** = adoption blocker |
| **Docs fidelity** | 6.0 | 7.0 | **7.3** | B | README/registry locked; site/config drift |
| **Security of the tool itself** | 7.0 | 7.6 | **7.8** | B+ | Offline, audit, export opt-in |
| **Competitive differentiation** | 7.0 | 7.8 | **7.8** | B+ | Wedge unique; soft gate blunts process story |
| **Marketing honesty** | — | ~7.5* | **7.2** | B | README A−; frontend C+ |

\*Implied from post-P0–9 narrative; not a separate line item then.

### Perspective-specific grades

#### Ultra-senior Go (~20y)

| Area | Prior (0.0.1) | Post P0–9 | **Now** | One-liner |
|------|:-------------:|:---------:|:-------:|-----------|
| Architecture | B | B+ | **B+** | Packs + hot-path + framework rules |
| CWE-22/78/89 depth | C+/B− | B | **B** | Clean honesty in docs; opaque-call FN on Clean |
| CWE long tail | D | C− | **C+** | 6 fixture-only tags; museum still under `all` |
| PERF pack | C− | A− | **A−** | S-tier is the product |
| BP pack | C | B | **B+** | Off by default; matrix honest |
| CI hard-gate trust | F | B− | **C** | Medium S-tier + Strict = exit 0 on PERF-101 |
| **Overall Go product** | **C+** | **B+** | **B / 7.6** | Sidearm yes; gate story oversold |

**Runtime proof (2026-07-12):**

```text
# http.Server{} missing timeouts → PERF-101 Medium
codehound --profile recommended /tmp/server.go     → exit 0
codehound --profile recommended --strict ...       → exit 0
codehound --profile recommended --warnings-as-errors ... → exit 1

# tests/canary/http_service uses ListenAndServe → "no slop detected"
```

S-tier severity is intentionally Medium (`severity_for_tier`); recommended fail policy is `FailPolicy::Strict` (high+ only). README severity table is honest; “CI gate” language is easy to misread.

#### Ultra-senior Rust

| Area | Prior | Post P0–9 | **Now** | One-liner |
|------|:-----:|:---------:|:-------:|-----------|
| Hot-path architecture | B+ | A− | **A** | SourceIndex O(1), retain_sources, lazy taint |
| Error taxonomy | C | B | **B** | PathIo/Cache; Walk/Config still string bags |
| Perf craft | B− | A− | **A** | Pay only for enabled packs |
| API encapsulation | C+ | B | **B+** | Lean `lib.rs`; fat `engine` re-export remains |
| Codegen | B | A− | **A** | Validated function idents + duplicate asserts |
| Packaging / release craft | D+ | A− | **A−** | Dual license + release.yml; tag human step open |
| **Overall Rust craft** | **B** | **A− / 8.5** | **A− / 8.7** | Disciplined orchestration craft |

### Adoption readiness

| Adoption mode | Post P0–9 | **Now** | Rating |
|---------------|:---------:|:-------:|:------:|
| Optional CI job, SARIF/JSON, baseline | Yes | **Yes** | **8.5 / 10** |
| Required gate for curated PERF (after pilot) | Plausible | **Only with flags** | **5.5 / 10** |
| Required gate for full CWE+BP+PERF default | No | **No** | **2 / 10** |
| Replace security SAST / govulncheck / golangci | No | **No** | **1 / 10** |
| Local Go review loop | Yes | **Yes** | **8.5 / 10** |
| Stranger installs from GitHub Release / crates.io | Partial eng | **No** | **3 / 10** |

---

## Composite product rating

```
┌────────────────────────────────────────────────────────────┐
│  CODEHOUND OVERALL (complementary Go tool)    7.8 / 10     │
│  CODEHOUND OVERALL (as marketed platform)     7.0 / 10     │
│  Prior complementary (post P0–9)              7.7 / 10     │
│  Prior marketed (post P0–9)                   7.2 / 10     │
│  Original complementary (0.0.1)               6.5 / 10     │
│  Original marketed (0.0.1)                    4.5 / 10     │
│  Scoped potential                             8.6–9.0 / 10 │
│  Gap drivers: B01 proof · gate policy · tag · site truth   │
└────────────────────────────────────────────────────────────┘
```

**Why complementary +0.1:** audience clarity + held engine/packs + fingerprint/docs hygiene.  
**Why marketed −0.2:** website still claims default export to `scripts/` and full-catalog “1,042 findings” theater; packaging still unshipped for outsiders.

---

## Deep dives (evidence)

### 1. Product wedge — still correct

| Market pitch (0.0.1) | What 0.1.0 actually is (still true) |
|---|---|
| “CWE security analyzer with 175+ entries” | **Recommended** = 9 S-tier PERF + 6 taint-core CWEs (taint **off** unless `--taint` / security) |
| “Multi-language” | **Go-first** (ADR 0005); Python opt-in `SLOP101`; TS stub **gone** |
| “Complement existing tooling” | Correct — README + competitive docs enforce it |

**Recommended pack (code truth):**  
PERF `1, 7, 50, 58, 71, 101, 103, 189, 190` + CWE `22, 78, 79, 89, 90, 91`. BP off. Fail Strict.

### 2. The soft-gate self-own (new critical finding)

| Layer | Behavior |
|-------|----------|
| S/A-tier PERF severity | **Medium** (`src/lang/go/detectors/perf/tiers.rs`) |
| Recommended fail policy | **Strict** → High/Critical only (`src/core/profile.rs`) |
| Default taint | **Off** → pack CWEs do not fire |
| Net default exit | **0** even with PERF-101 present |
| Composite Action | Scan status captured; **always `exit 0`** |
| `--warnings-as-errors` | Correctly fails on Medium |

This may be intentional brownfield safety. It is **not** a hard PERF gate. Do not sell it as one without `--warnings-as-errors` / `fail_on = medium` or promoting S-tier to High.

### 3. Go analysis — strengths and debts

**Strengths**

- S-tier PERF: timeouts, body close/drain, regex/defer-in-loop, GORM N+1, Gin body — real production value.
- Framework hot-path heuristics without bare-`func (` FP trap.
- Taint docs: not security-grade; Clean not a Path sanitizer; channels/goroutines unsupported.
- Versioned last-write + field-qualified keys shipped (Phase 8).
- BP vs staticcheck matrix; style pack advisory.

**Debts**

1. **PERF-101 misses `http.ListenAndServe`** — canary uses it → false green.
2. **Opaque-call kill** makes `filepath.Clean(path)` behave like an implicit sanitizer (FN vs docs that say Clean alone should still flag).
3. Name-string sinks; no types/SSA; long-tail CWE museum under `all` (only 6 fixture-only IDs quarantined).
4. `documents/perf-rules.md` narrative drifts vs live ruleset for some IDs.

### 4. Rust craft — strengths and debts

**Strengths**

- `FactBuildOpts::for_scan`, `retain_sources`, SourceIndex O(1), ParsePool, poison recovery, no product `unsafe`, `deny(clippy::unwrap_used)`.
- Same-scan reverse-dep cascade, tool-version mass-stale, project path normalize (separators/`./`).
- Codegen: validated idents, duplicate rule-id asserts, escaped strings.
- Lean crate root re-exports.

**Debts**

1. `Error::Walk(String)` / `Config(String)` / re-wrap as Walk in scan path.
2. Path identity does not bridge **absolute walk keys** vs **relative dep edges** (cascade half-correct in the wild).
3. Fat `engine` public re-export surface (prelude helps; drawer remains).
4. Some engine tests lag `retain_sources` semantics; cascade tests under-assert re-parse.

### 5. CLI / packaging / site

| Surface | Score | Evidence |
|---------|------:|----------|
| CLI profiles, baseline, export opt-in | Strong | Subcommands, packs, fingerprint v2 |
| Internal CI | Strong | Matrix, audit, canaries, MSRV, benches |
| Release workflow | Ready, **unfired** | Multi-arch + SBOM on `v*` |
| Public tag / artifacts | **Missing** | No `v*` tags in clone |
| GitHub Action (third-party) | Weak | Source-build only; never fails job |
| README / `documents/` | Strong | Rule counts CI-locked |
| Frontend | Mixed | Audience good; export-default + PERF 224 + “1,042 findings” theater |
| Cargo `repository` | Drift | `chinmay/codehound` vs live `chinmay-sawant/codehound` |

### 6. Strategic recommendations (original #1–8) — status

| # | Recommendation | Status |
|---|----------------|--------|
| 1 | PERF-first homepage / packs | **DONE** (README); site still dual-narrative |
| 2 | Quarantine fixture-needle CWEs | **PARTIAL** (6 IDs; long tail under `all`) |
| 3 | Sanitizer honesty (Clean) | **PARTIAL** — docs/classify yes; opaque-call FN no |
| 4 | High-signal default profile | **DONE** for noise; **soft** for exit codes |
| 5 | SARIF + license + export off | **DONE** in product; **site lag** on export |
| 6 | BP dedup vs staticcheck | **DONE** |
| 7 | Multi-lang honesty | **DONE** (demote) |
| 8 | 0.1.0 bar | **PARTIAL** — engineering ready; public tag + external FP rates open |

### 7. Post-0.1 backlog (still open)

Record: [`action-items.md`](./action-items.md) B01–B28.

**Pursue next (trust + ship, not catalog width):**

| ID | Why now |
|----|---------|
| **B01** | Real-repo TP/FP ≥70% — only real trust metric left |
| **Gate policy** | S-tier High *or* recommended MediumAsErrors *or* stop saying “CI gate” |
| **Action** | Download pinned binary; fail job on findings after SARIF upload |
| **Tag `v0.1.0`** | Fire `release.yml`; document install beyond `cargo install --path .` |
| **Site** | Export opt-in; PERF **239**; default `codehound .` is high-signal, not 1,042 exports |
| **B03** | Rewrite bar for structural promotion (cheap process) |
| **B06 / B11** | Needle negative gates + external SHA canaries |
| **PERF-101** | Detect `ListenAndServe` / fix canary |
| **Clean flow** | Propagate through Clean (not kill / not sanitize) |
| B14/B17/B18 | API façade + codegen integrity |

**Do not:** add catalog width, multi-lang investment, or typed go/packages until B01 lands.

---

## Final verdict

| Question | Answer |
|----------|--------|
| Is it useful? | **Yes** — scoped Go PERF + framework smells as a *second* tool |
| Is it a great product yet? | **Almost for the niche** — 7.8/10 complement; soft gate + unshipped install hold it back |
| Go senior | *I’d run recommended as a post-lint SARIF checklist on a side project tomorrow — I would not treat green CI as “no PERF issues” until Medium fails the build and ListenAndServe counts.* |
| Rust senior | *Disciplined hot-path craft: pay only for enabled packs, recover poison, validate codegen. `Error::Walk(String)` and unfinished path topology are the remaining unfinished business.* |
| Together | *Ship the tag, fix the gate story (or the marketing), align the site with export-off, prove B01 on real repos. Stop adding rules until hit rates exist.* |

```
Overall (complementary Go tool):     7.8 / 10   (was 7.7 post P0–9 · 6.5 at 0.0.1)
Overall (as marketed platform):      7.0 / 10   (was 7.2 post P0–9 · 4.5 at 0.0.1)
Rust craft:                          8.7 / 10   (was 8.5 · 7.5)
Go product:                          B  / 7.6   (was B+ · C+)
CLI / CI surface:                    8.0 / 10   (was 7.8 · 6.0)
Packaging / release:                 6.5 / 10   (was 7.2 eng-ready · 3.5)
```

### Scorecard matrix (both hats)

| Dimension | Go senior | Rust senior | Notes |
|-----------|:---------:|:-----------:|-------|
| Useful product? | Yes (scoped) | n/a | PERF sidearm |
| Analysis depth | B | — | Taint MVP + museum tail |
| Engineering craft | — | A− / 8.7 | Engine deep |
| Default noise | A− | — | Recommended pack |
| Hard-gate trust | C / no | — | Medium + Strict |
| Install / ship | D | A− workflow | Tag missing |
| Multi-lang | D+ honesty | B chassis | Go product only |
| Replace stack | **No** | — | Complement only |

---

## Quotable lines

> **Go:** “I’d run recommended as a post-lint SARIF checklist on a side project tomorrow — but I wouldn’t call green CI a PERF gate until Medium findings actually fail the build and `ListenAndServe` counts as a server.”

> **Rust:** “SourceIndex and lazy taint are the right kind of lazy: the expensive graph is behind a bool, not a hope. `PathIo` shows you know structured errors; `Walk(String)` shows you stopped halfway.”

> **Product:** “CodeHound 0.1.0 is a credible Go-first PERF + footgun scanner with an unusually honest recommended pack — but it is not yet installable or CI-plug-and-play for outsiders. The gap is not more rules: it is **tag, binaries, failing Action, gate policy, and a website that matches the CLI.**”

---

*Stored for product feedback after the post-0.1 site/docs wave. Not a substitute for measured FP rates on external Go monorepos (B01).*
