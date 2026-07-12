# CodeHound — System Improvements

| Field | Value |
|-------|--------|
| **Date** | 2026-07-10 |
| **Source** | [ultra-senior-go-rust-product-review.md](./ultra-senior-go-rust-product-review.md) |
| **Related** | [go.md](./go.md) · [rust.md](./rust.md) |
| **Version reviewed** | `0.0.1` |

This document is the **cross-cutting system roadmap**: product defaults, packaging, analysis model, testing, docs, and ops. Language-specific work lives in `go.md` and `rust.md`.

---

## North star

> **One job, done well:** a fast, offline Go **PERF + framework-footgun** analyzer that also ships a **curated** CWE pack — complementary to golangci-lint and govulncheck, not a replacement for either.

Everything below should be judged by whether it moves toward that north star or dilutes it.

### Target outcomes (6–12 months)

| Outcome | Success metric |
|---------|----------------|
| High-signal default profile | ≤ ~30 rules in “recommended CI pack”; FP rate measured on 3 real repos |
| Trustworthy CI integration | SARIF validates against GitHub Code Scanning; no workspace dirt by default |
| Honest catalog | Fixture-only CWEs quarantined or rewritten; long-tail hit rate tracked |
| Ship-ready binary | Signed multi-arch release, correct dual license, semver ≥ `0.1.0` |
| Measurable quality | Public (or internal) FP/TP dashboard on canary repos |

---

## Priority framework

| Priority | Meaning | Cadence |
|:--------:|---------|---------|
| **P0** | Trust / correctness / CI blockers — do before marketing more rules | Days–2 weeks |
| **P1** | Signal quality & product positioning — unblocks adoption | 2–6 weeks |
| **P2** | Depth & scale — competitive differentiation | 1–3 months |
| **P3** | Platform / multi-lang / nice-to-have | Later |

---

## P0 — Trust & product hygiene (do first)

### 1. Fix CI-hostile defaults

| Problem | Improvement |
|---------|-------------|
| Context/chunks export **on by default** writes into `scripts/` | Default **off**; require explicit `--export-context` / config |
| Fail-on-medium + full CWE+PERF+BP is noisy | Ship **profiles**: `recommended`, `perf`, `security`, `strict`, `all` |
| Teams must remember many flags | Document a canonical CI one-liner that matches defaults |

**Acceptance:** Fresh clone scan of a clean Go module produces zero filesystem side effects and a usable default gate.

### 2. Fix SARIF correctness

| Problem | Improvement |
|---------|-------------|
| `physical_location` / `start_line` snake_case | Emit SARIF 2.1.0 **camelCase** (`physicalLocation`, `startLine`, …) |
| Snapshots lock the bug | Update snapshots + validate against schema / GitHub upload |
| Severity docs ≠ code | Align `security-severity` mapping and docs |
| `workingDirectory.uri` always `"."` | Emit real scan root / CWD as URI |

**Acceptance:** Upload to GitHub Advanced Security (or SARIF validator) without post-processing.

### 3. License & packaging honesty

| Problem | Improvement |
|---------|-------------|
| Dual MIT/Apache claimed; only MIT on disk | Ship `LICENSE-MIT` + `LICENSE-APACHE` **or** drop dual claim |
| README broken license links | Fix links |
| `0.0.1` + `cargo install --path .` only | Release workflow: tags, multi-arch binaries, checksums, optional crates.io |

**Acceptance:** License files match `Cargo.toml`; at least one tagged release artifact.

### 4. Align docs / schema / runtime

| Drift | Fix |
|-------|-----|
| Taint default (docs vs `ScanContext`) | Single source of truth; document in README + `documents/taint.md` |
| `severity_overrides` in schema/template but not parsed | Implement **or** remove from schema/template |
| PERF/CWE/BP counts lag README/CHANGELOG | Auto-generate counts from registry at build/docs time |
| `fail_on` free-string typos → silent medium | Enum + reject unknown values |
| Contributor docs (`adding-a-language`, perf-dev) stale paths | Refresh against `chunks/` + real module layout |

**Acceptance:** `codehound init` template parses; schema only describes real fields; README numbers match `--list-rules`.

### 5. Dead / misleading CLI flags

| Problem | Improvement |
|---------|-------------|
| `--warnings-as-errors` is a no-op | Implement real semantics **or** remove with deprecation note |
| `--baseline` + `--no-baseline` both parse | clap `conflicts_with` |
| `--no-snippet` doubles as SARIF compact | Split `--no-snippet` and `--sarif-compact` |
| Flat 30-flag surface | Introduce subcommands over time: `scan`, `rules`, `cache`, `baseline`, `init` |

---

## P1 — Signal quality & product positioning

### 6. Product packs instead of “everything on”

| Pack | Contents (illustrative) | Default CI? |
|------|-------------------------|:-----------:|
| **`recommended`** | Curated PERF (timeouts, body close, regex-in-loop, request thrash) + top taint CWEs | Yes |
| **`perf`** | Framework + hot-path PERF only | Opt-in |
| **`security`** | Taint CWE core + high-value non-fixture CWEs | Opt-in |
| **`style` / `bp`** | Bad practices (low severity, advisory) | Off by default |
| **`all`** | Full catalog | Explicit only |

CLI sketch:

```bash
codehound --profile recommended .
codehound --profile security --fail-on high .
```

### 7. Quarantine fixture-only rules

| Action | Detail |
|--------|--------|
| Audit | Tag rules: `production` / `heuristic` / `fixture-only` / `reserved` |
| Quarantine | Fixture-only **disabled in `recommended` and `security`** |
| Rewrite or delete | Needles that encode exact fixture strings (`lastOTP++`, magic PRNGs, exact PostForm shapes) |
| Track | Hit rate on canary repos; delete zero-hit rules after N months |

See [go.md](./go.md) for the CWE/PERF/BP rewrite bar.

### 8. High-signal default severity policy

| Today | Better |
|-------|--------|
| Many PERF/BP at medium; fail medium | Micro-opts → `info`/`low`; only proven footguns → `medium`+ |
| BP often low but still noisy volume | BP pack off in recommended profile |
| No confidence field used well | Populate `confidence` for taint vs needle heuristics |

### 9. Baseline maturity

| Gap | Improvement |
|-----|-------------|
| Line-shift fragility | Prefer fingerprint + optional content/AST-stable identity |
| No prune/diff/audit | `codehound baseline list|prune|update|diff` |
| Baselined findings invisible | `--show-baselined` (mirror `--show-ignored`) |
| No justification/expiry | Optional `reason`, `expires` fields in baseline schema |

### 10. Ignore system completeness

| Gap | Improvement |
|-----|-------------|
| `//` only | Python `#`, eventually language-aware comments |
| No range/block ignore | `codehound-ignore-start` / `-end` |
| No end-of-line ignore | Support trailing ignore on same line |
| Ecosystem familiarity | Optional `nolint`-style alias (document as non-goal or implement) |

---

## P2 — Analysis depth & system scalability

### 11. Analysis model upgrades (language-agnostic engine)

| Capability | Why | Notes |
|------------|-----|-------|
| Same-scan cascade re-scan | Dependents currently fixed next run | Invalidate + requeue in same scan |
| Tool-version cache bust | Docs claim it; code only warns | Mass invalidate on tool version change |
| Path normalization for cache/deps | Relative vs absolute cascade misses | Always store canonical absolute or project-relative keys |
| Optional mtime prefilter | Full rehash every warm file is costly | Fast path then hash confirm |
| Lazy fact extraction | Two-rule scans pay full fact cost | Build fact vectors only if consumers enabled |
| Streaming / drop `source_cache` | Monorepo RAM | Keep sources only when export enabled |

Details for Go taint/types: [go.md](./go.md).  
Details for SourceIndex/errors/leaks: [rust.md](./rust.md).

### 12. Testing upgrades (system-level)

| Gap | Improvement |
|-----|-------------|
| Class-scoped safe silence only | Rule-specific silence + “exclusive fire” oracles |
| No real-world canary | CI job: scan 3 fixed public Go modules; track finding count deltas |
| Coarse asserts (ID present only) | Assert location + message class + evidence for core rules |
| Python safe-test bug | Fix class inference so `SLOP101` silence is actually tested |
| Loose 32s smoke budgets | Split “smoke” vs “budget”; keep tight Criterion gates for core benches |
| No precision metrics | Script: TP/FP vs golden labels on canary corpus |

### 13. Observability & quality feedback loop

| Improvement | Purpose |
|-------------|---------|
| Per-rule hit rate telemetry (local opt-in) | Find dead / noisy rules |
| `--explain` includes confidence + analysis mode (taint vs needle) | User trust |
| CHUNK_VALIDATOR / LLM review → automated quarantine candidates | Rule hygiene |
| Dogfood gate on own `gopdfsuit` (or successor) every release | Regression |

### 14. Architecture splits (optional, when compile pain hits)

| Split | Benefit |
|-------|---------|
| `codehound-engine` + `codehound-go` crates | Faster iteration, clearer boundaries |
| Move Go sinks out of `engine/sinks.rs` | True plugin isolation |
| Language hooks for dependency extraction | New languages without engine edits |

---

## P3 — Platform & growth

### 15. Multi-language honesty

| Option A | Option B |
|----------|----------|
| **Invest:** 10–20 high-value Python rules + fixtures | **Demote:** feature-flag Python; README “Go-first” only |
| Empty `typescript` feature | Remove until real plugin exists |
| Fixture `lang: rust` docs | Match `FixtureLanguage` or implement |

### 16. Ecosystem packaging

- GitHub Action: install binary → scan → upload SARIF  
- Sample `.github/workflows/codehound.yml`  
- Homebrew / deb optional  
- SBOM + `cargo audit` in release pipeline  
- Dependabot/renovate for Cargo.lock  

### 17. Domain / process hygiene

| Gap | Improvement |
|-----|-------------|
| No CONTEXT.md / ADRs | Short `documents/adr/` for taint model, default profile, cache identity |
| Plan sprawl / status drift | One live roadmap; archive v0.0.1 session notes |
| Branding leftovers (`slop`, SLOP101, slopguard docs) | Rename or document historical alias |
| CONTRIBUTING missing | How to add a rule, run fixtures, land a PR |

---

## Suggested phased roadmap

### Phase A — “Would install in CI” (2–4 weeks)

1. Export defaults off  
2. SARIF camelCase + schema validate  
3. License files fixed  
4. Profiles: `recommended` / `all`  
5. documents/schema/runtime alignment (taint, fail_on, counts)  
6. Canonical CI recipe + sample workflow  

### Phase B — “Would trust findings” (1–2 months)

1. Quarantine fixture-only CWEs  
2. Sanitizer model fixes (see go.md)  
3. Severity/confidence cleanup  
4. Real-repo canary + exclusive oracles for core rules  
5. Baseline list/prune/show  

### Phase C — “Would recommend to others” (2–4 months)

1. Taint depth upgrades (go.md)  
2. Rust craft P0/P1 (rust.md): errors, SourceIndex, no leaks  
3. Cache same-scan cascade + tool-version bust  
4. Binary releases `0.1.0`  
5. Public FP rates / impact writeup  

### Phase D — “Platform” (later)

1. Multi-crate split if needed  
2. Multi-lang only if funded  
3. Dynamic plugins (likely never; keep compile-time inventory)  

---

## What *not* to improve (non-goals)

| Temptation | Why not |
|------------|---------|
| Add 100 more CWE IDs | Catalog inflation without precision destroys trust |
| Replace golangci-lint / staticcheck | Permanent non-goal; compete on unique value |
| Full CodeQL parity | Wrong cost model for a single-binary heuristic tool |
| Runtime loadable plugins | Inventory + features are enough for years |
| Default-on full BP pack in CI | Noise death spiral |

---

## Improvement backlog (checklist)

### P0

- [ ] Default export (context/chunks) **off**
- [ ] SARIF camelCase locations + validated upload path
- [ ] License files match dual-license claim (or claim fixed)
- [ ] Align taint default docs vs code
- [ ] Remove or implement schema-only config fields
- [ ] Strict `fail_on` parsing
- [ ] Fix no-op / conflicting CLI flags

### P1

- [ ] `--profile recommended|perf|security|style|all`
- [ ] Rule maturity tags + quarantine fixture-only
- [ ] Severity/confidence retune for micro-opts
- [ ] Baseline list/prune/show-baselined
- [ ] Broader ignore syntax (block + multi-lang comments)
- [ ] Sample GitHub Action workflow

### P2

- [ ] Same-scan dependency cascade re-scan
- [ ] Tool-version cache invalidation
- [ ] Canonical path keys for cache/deps
- [ ] Real-repo canary CI + finding-count budgets
- [ ] Tighter test oracles (location, exclusive fire)
- [ ] Lazy fact extraction for targeted scans

### P3

- [ ] Multi-lang decision (invest vs demote)
- [ ] Release pipeline + SBOM
- [ ] CONTEXT.md / ADRs / CONTRIBUTING
- [ ] Optional crate split

---

## How to use these docs

| Doc | Audience | Use for |
|-----|----------|---------|
| **improvements.md** (this file) | Product / roadmap | Priorities, packs, CI, packaging |
| **[go.md](./go.md)** | Detector / analysis authors | CWE, PERF, BP, taint, fixtures |
| **[rust.md](./rust.md)** | Engine / systems authors | Errors, perf, cache, API, codegen |
| **[ultra-senior-go-rust-product-review.md](./ultra-senior-go-rust-product-review.md)** | Context | Ratings and evidence |

---

## Success metrics (definition of done for the *system*)

| Metric | Baseline (today) | Target |
|--------|------------------|--------|
| Recommended-pack FP rate on canary repos | Unknown | &lt; 15% of findings dismissed as noise (sampled) |
| Default scan side effects | Writes `scripts/` | Zero unless opted in |
| SARIF GitHub upload | Broken/unreliable | Green without transform |
| Rule catalog honesty | ~470 “on” | Tagged maturity; recommended ≪ all |
| Release | Source-only `0.0.1` | Tagged `≥0.1.0` binary |
| Docs drift incidents | Several known | Zero known schema/README lies |

---

*System improvements only. Language-specific detector and Rust-engine work: see sibling files.*
