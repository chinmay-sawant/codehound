# CodeHound — Go Analysis Improvements

| Field | Value |
|-------|--------|
| **Date** | 2026-07-10 |
| **Source** | [ultra-senior-go-rust-product-review.md](./ultra-senior-go-rust-product-review.md) |
| **Related** | [improvements.md](./improvements.md) · [rust.md](./rust.md) |
| **Scope** | Go parsing, facts, CWE, PERF, BP, taint, fixtures, rule quality |

This is the **Go-veteran improvement backlog**: how to make findings trusted by people who already run `go vet`, staticcheck, errcheck, and govulncheck.

---

## Goals (Go-specific)

1. **High precision** on a small set of rules beats **high recall theater** on 175 CWEs.  
2. **No false security** — sanitizers and suppressions must match real Go semantics.  
3. **Zero competition with staticcheck** unless CodeHound is clearly better or unique.  
4. **PERF is the differentiator** — framework + request-path value is the product wedge.  
5. **Fixtures prove generality**, not only “this exact string matches.”

---

## Current Go pipeline (context)

```
tree-sitter-go parse
  → GoUnitFacts / GoPerfFacts + SourceIndex
  → optional taint graph (name-based sources/sinks/sanitizers)
  → rule functions (CWE / PERF / BP bundles)
  → findings
```

**Ceiling today:** no `go/types`, no SSA, no packages/build tags — name-string and CST heuristics only.

---

## P0 — Correctness & trust (security-critical)

### 1. Sanitizer model must stop lying

| Issue | Fix |
|-------|-----|
| `filepath.Clean` / `path.Clean` as `SanitizerKind::Path` | **Do not** treat Clean alone as path-traversal safe. Require confinement evidence (e.g. join under root + `Abs`/`EvalSymlinks` + prefix check **on the same dataflow path**), not file-level substring co-presence |
| CWE-78 using **Path** sanitizers | Use command-specific sanitizers only (argv separation, no shell, allowlists) |
| Name-regex sanitizers `sanitize\|clean\|escape\|…` | Require call on tainted value / known-safe APIs; drop over-broad name matching or mark low confidence |
| `len` as Bounded, `Prepare` without same-Stmt proof | Tighten: Prepare only if *same* variable reaches Query/Exec |

**Acceptance:** Safe fixtures still pass; known FN where only Clean is used should **fire** (or document as known limitation with low confidence, not silent suppress).

### 2. Path confinement must be dataflow-local

| Today | Better |
|-------|--------|
| `is_path_confined` scans whole file for Abs + HasPrefix | Guard must dominate sink on taint path / same function at minimum |
| Co-presence of strings | Prefer facts: calls on the same binding |

**Code touchpoints:** `cwe/taint/rules/cwe_22.rs`, path helpers, `facts/`.

### 3. Taint defaults & docs (single truth)

| Action | Detail |
|--------|--------|
| Decide default | On for `security` profile; off for `recommended`/`perf` **or** document clearly if on globally |
| Sync | `documents/taint.md`, README, schema, `ScanContext` |
| UX | `--taint` / `--no-taint` + config must match explain output |

### 4. Injection rule soundness checklist

| Rule | Improvement |
|------|-------------|
| **CWE-22** | First-arg-only taint (keep); fix Clean over-trust; confinement on path |
| **CWE-78** | Keep shell (`sh -c`) focus; add common variants carefully; fix sanitizer kinds; avoid Path sanitizers |
| **CWE-89** | Literal-first-arg heuristic: document; add GORM/sqlx string-concat shapes without claiming full SQLi |
| **CWE-79** | Wire `HTTPWrite` / template sinks consistently; don’t claim full XSS coverage |
| **CWE-90/91** | Same bar as above: real sources/sinks or quarantine |

---

## P1 — Catalog honesty (CWE long tail)

### 5. Maturity tags for every CWE

| Tag | Meaning | Default packs |
|-----|---------|---------------|
| `taint-core` | Graph-based injection/XSS family | security, recommended (subset) |
| `structural` | AST/facts, generalized patterns | security if precision ≥ bar |
| `heuristic` | Useful smell, higher FP | all / explicit |
| `fixture-only` | Encodes test corpus strings | **never** recommended/security |
| `reserved` | Placeholder | disabled |

### 6. Fixture-only rewrite bar (or delete)

**Delete or quarantine** rules that only match:

- Magic numbers from fixtures (`Intn(4096)`, specific PRNG formulas)  
- Exact identifiers (`lastOTP++`, fixture-only names)  
- Exact multi-token source snippets that never appear in production  
- Hard-coded path strings from test corpus  

**Rewrite bar for promotion to `structural`:**

1. Pattern expressed via facts/calls/args, not one literal needle.  
2. ≥1 safe + ≥1 vulnerable fixture **plus** ≥1 variant (rename identifiers, different API alias).  
3. Clean-file and cross-rule FP check pass.  
4. Runs on one real module without nonsense hits (manual or canary).  

### 7. Shrink the NEEDLES table

| Today | Better |
|-------|--------|
| ~740 string needles, many fixture-shaped | Split: (a) cheap structural prefilters, (b) rule-local checks |
| Global `SourceIndex.has("xml.Unmarshal(")` style | Prefer call facts + callee classification |
| Needles as primary detector | Needles only as **negative gates** (early exit) where possible |

**Goal:** Every remaining needle has a comment: why production code contains this substring.

### 8. Sink classification improvements (without full types)

| Improvement | Detail |
|-------------|--------|
| Package-aware callees | Use import map: `db.Query` only when `db` is `*sql.DB`/`*sql.Tx` **heuristic** from assign facts |
| Reduce bare `.Query` / `.Exec` | Prefer known stdlib + popular ORM patterns explicitly |
| Shared sink registry | Expand `engine/sinks` or Go-local phf maps from **data**, not ad-hoc per rule |
| Framework tables | Gin/Echo/Chi/Fiber request sources already partial — complete and test |

Still not `go/types` — but much better than global method-name soup.

---

## P1 — PERF pack (the real product)

### 9. Split PERF into tiers

| Tier | Examples | CI default |
|------|----------|:----------:|
| **S (ship)** | Regex compile in loop; http.Server without timeouts; response Body not closed; defer in loop; clear N+1 / Query thrash | Yes |
| **A (framework)** | Gin logger mutex I/O; static handlers without cache headers; GORM preload/session footguns | Yes in `perf` profile |
| **B (micro-opt)** | `time.Since`, TrimPrefix, fmt verb micro-rules, string/`[]byte` churn | Off / info only |
| **C (overlap)** | Rules already covered well by staticcheck/gocritic/prealloc | Drop or document “duplicate, disabled by default” |

### 10. Fix `is_hot_path` over-breadth

| Today | Better |
|-------|--------|
| Function name contains `handle\|serve\|build\|process\|…` | Prefer: HTTP handler signatures, middleware shapes, loops in request path, explicit annotations |
| Any `func (` makes file “handler-shaped” | Drop; use structural handler detection |
| Cold CLI/config builders flagged | Suppress package `main` init / `cmd/` heuristics optionally |

### 11. PERF advice quality

| Bad advice pattern | Fix |
|--------------------|-----|
| Prefer `http.Get` over `NewRequest` always | Only when no headers/context/custom client |
| Static `fmt.Errorf` as medium | Severity → info or drop |
| Window-scan for `.Body.Close()` | Prefer dataflow / same function + defer detection |

### 12. Framework coverage plan

Prioritize by adoption:

1. **net/http** stdlib (always)  
2. **Gin** (already started)  
3. **Echo / Chi / Fiber**  
4. **GORM / sqlx / pgx**  
5. **gRPC / redis** (protocols pack)  

Each framework rule needs real-world safe/vuln fixtures, not only synthetic `package sample`.

---

## P1 — Bad practices (BP)

### 13. Dedup matrix vs golangci ecosystem

For each BP-1..65:

| Outcome | Action |
|---------|--------|
| Strictly weaker than go vet / staticcheck / errcheck | **Disable by default** or delete |
| Same idea, worse precision | Fix or drop |
| Unique policy (rate limits, dep hygiene with real signal) | Keep in `style` pack only |
| Reserved / empty (CVE feed) | Wire govulncheck-style feed **or** remove from catalog |

Document matrix in `documents/bad-practices.md`: “Overlaps X — enable only if you don’t run X.”

### 14. Fix known broken BP detectors

| Rule area | Problem | Direction |
|-----------|---------|-----------|
| BP-8 Unlock | File-level mutex presence + any defer Unlock | Require same lock object / AST pairing |
| BP-9 select | First `{` to first `}` | Proper block matching via tree-sitter |
| BP-1 discarded err | No types | Prefer `_ , err :=` / assignment shapes; don’t flag non-error `_` |
| BP-6 WaitGroup | Line state machine | AST-based go-stmt + Add/Done facts |
| BP-21 Parallel | Policy | Keep low; off in recommended |
| BP-28 single-method iface | Opinion | Off by default |

### 15. Severity discipline

- Default BP pack: **off** in recommended CI profile.  
- When on: almost all **info/low**; only concurrency footguns that vet misses → medium.  
- Never fail CI on “missing godoc” style rules by default.

---

## P2 — Taint depth (keep MVP honest)

### 16. Intra-procedural upgrades

| Capability | Why |
|------------|-----|
| Versioned assignments / branch-aware last-write | Reduce wrong edges from “latest assign wins” |
| Field-insensitive → limited field keys | `user.Path` vs whole struct blob |
| Map/slice index conservative taint | Optional, high FP — use low confidence |
| Channel / goroutine: explicit “unsupported” | Don’t pretend; document FNs |

### 17. Inter-procedural (summary) upgrades

| Today | Better |
|-------|--------|
| One-hop summary application | Fixpoint or bounded multi-hop with depth flag |
| Name-based callee resolve | Prefer same-package path + signature arity; avoid cross-package collisions |
| Import-map skip heuristics | Explicit rules; tests for external methods |
| Full source clone under Mutex | See rust.md — architecture, not Go semantics |

### 18. Optional future: hybrid with `go/packages` (big bet)

| Approach | Pros | Cons |
|----------|------|------|
| Stay tree-sitter only | Fast, no toolchain, offline simple | Precision ceiling |
| Optional `--typed` using go/packages + go/types | Real types, build tags | Needs Go toolchain; slower; complex |

**Recommendation:** Do **not** block 0.1.0 on typed mode. Design detector APIs so a later typed fact layer can feed the same rules.

---

## P2 — Fixtures & test oracles (Go)

### 19. Raise the fixture bar

| Today | Better |
|-------|--------|
| One safe + one vulnerable microfile per rule | Add **variant** fixtures: renamed ids, wrapper funcs, different imports |
| `package sample` only | Add `perf_real_world` / multi-file packages for S-tier rules |
| Assert “rule ID present” | Assert **line**, exclusive fire (no extra CWE-X), evidence kind for taint core |
| Safe silence = class prefix | Rule-specific silence for that ID |
| Dual stdlib/framework CWE inventories | Keep; extend to PERF framework pairs where relevant |

### 20. Canary corpus (Go modules)

Pick 3 fixed modules (pin commit SHAs):

1. Small clean library (expect ~0 recommended findings)  
2. Medium HTTP service (Gin or chi)  
3. CodeHound dogfood target (e.g. gopdfsuit)  

Track: finding counts by pack/rule; fail CI on unexpected spike.

### 21. Cross-rule FP suite

Expand beyond single CWE-393 ↛ CWE-89 case:

- Safe SQL parameterization must not fire injection family  
- Path confined handlers must not fire CWE-22  
- Staticcheck-clean code should be quiet under recommended pack  

---

## P3 — Go product packaging of rules

### 22. Authoring workflow improvements

| Improvement | Detail |
|-------------|--------|
| Rule RFC template | Threat model, FP examples, overlap with staticcheck, pack assignment |
| `detection_notes` quality gate | No vague “taint analysis…” without implementation match |
| Codegen validates function exists | Already compile-fails; add registry ↔ fixture inventory CI (partially exists) |
| PERF detector dev guide | Refresh paths: chunks not flat `golang.json` |

### 23. User-facing Go docs

| Doc | Content |
|-----|---------|
| `documents/go-recommended-pack.md` | Exact rule list + why |
| `documents/go-vs-staticcheck.md` | Overlap matrix (start from existing comparison notes) |
| `documents/taint.md` | Limitations table expanded: Clean, fields, channels, depth |
| README sample | Prefer PERF finding over only CWE-22 theater |

---

## Implementation order (Go)

### Sprint G1 — Trust

1. Fix Path sanitizer / Clean semantics  
2. CWE-78 sanitizer kinds  
3. Path confinement locality  
4. Taint default + docs lockstep  

### Sprint G2 — Catalog

1. Tag all CWEs with maturity  
2. Disable fixture-only in non-`all` packs  
3. Delete or rewrite top 20 worst needles  
4. NEEDLES hygiene pass  

### Sprint G3 — PERF product

1. Define S/A/B/C tiers  
2. Fix hot_path heuristics  
3. Retune severities  
4. Framework gap list + top 10 new rules max  

### Sprint G4 — BP cleanup

1. Overlap matrix  
2. Fix BP-8/9/1/6  
3. BP off in recommended  

### Sprint G5 — Depth & canaries

1. Variant fixtures for taint core  
2. Canary CI  
3. Summary multi-hop optional flag  

---

## Acceptance criteria (Go)

| Criterion | Measure |
|-----------|---------|
| Recommended pack trusted | Senior Go reviewee triages 20 findings; ≥70% actionable |
| Fixture-only not in default | Audit script: no `fixture-only` in recommended |
| Sanitizer correctness | Dedicated tests: Clean-only still flags CWE-22 |
| Overlap honesty | BP matrix published; duplicates default-off |
| Canary stability | ±N findings budget on pinned modules |

---

## Non-goals (Go)

- Full sound interprocedural taint  
- Replacing govulncheck for CVEs  
- Replacing errcheck/staticcheck for API correctness  
- Claiming every CWE number is “covered” in a security-audit sense  

---

## File touch map (likely)

| Area | Paths |
|------|--------|
| Taint model | `src/lang/go/detectors/cwe/taint/` |
| Classify sources/sinks | `.../taint/extract/classify.rs` |
| CWE rules | `.../cwe/domains/`, `.../taint/rules/` |
| Needles | `.../cwe/source_index.rs` |
| Facts | `.../cwe/facts/`, `.../perf/facts/` |
| PERF domains | `.../perf/domains/` |
| BP | `.../bad_practices/rules/`, `dispatch.rs` |
| Registries | `.../registry/*.toml`, `ruleset/golang/chunks/` |
| Fixtures | `tests/fixtures/go/` |
| Docs | `documents/taint.md`, `documents/perf-rules.md`, `documents/bad-practices.md` |

---

## Go one-liner

> **Promote generalized PERF and fix the taint core; quarantine the fixture museum; stop losing to staticcheck on BP.**

See [improvements.md](./improvements.md) for packs/profiles and [rust.md](./rust.md) for engine support work.
