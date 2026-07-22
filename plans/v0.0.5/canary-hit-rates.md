# Canary reviewed hit rates (by family and date)

> **Parent:** [`canary-corpus.md`](./canary-corpus.md)  
> **Program:** [`parallel-catalog-program.md`](./parallel-catalog-program.md) §4.1  
> **Rubric:** actionable · narrower · false-positive · duplicate · no-hit  
> **Rule:** Append new dated sections; do not rewrite history.

This ledger tracks **reviewed** hit quality for promotion, quarantine, and pack
trust. Raw finding counts alone are insufficient.

**Reviewed hit rate (family)** =

```text
actionable / (actionable + false-positive + narrower + duplicate)
```

`no-hit` is recorded per repository when a family `--only` scan emits nothing; it
is not part of the finding-level rate denominator.

---

## How to append

1. Pin the corpus (`scripts/canary/run_decision_corpus.sh pin` or verify SHAs).
2. Build release binary from the commit under review.
3. Run **recommended** and/or **family `--only`** separately (see corpus doc).
4. Review findings with the rubric; sample at least the novel or disputed rows.
5. Copy the template below; fill counts, dispositions, and the catalog decision.

```markdown
### YYYY-MM-DD — <family or recommended>

- **Binary / commit:**
- **Profile / command:**
- **Pin set:** gopdfsuit, monsoon, go-retry, gorl, no-mistakes @ SHAs in canary-corpus-pins.json
- **Per-repo counts:**

| Repository | Files | Findings |
|------------|------:|---------:|
| gopdfsuit | | |
| monsoon | | |
| go-retry | | |
| gorl | | |
| no-mistakes | | |

- **Reviewed rows:** (rule | repo | file:line | disposition | note)
- **Reviewed hit rate:**
- **Decision:** keep / narrow / quarantine / retire / no change
- **Links:** PR / issue / evidence path
```

---

## 2026-07-21 — corpus expansion pilot (recommended + CWE-916)

- **Binary / commit:** release binary at main-repo
  `/home/chinmay/ChinmayPersonalProjects/codehound/target/release/codehound`;
  corpus pins as of base SHA `7d912d5be8528f80df0122259d24130c6f394df9`
  (issue #117 / §4.1 docs).
- **Profile / command:**
  - recommended: `--profile recommended --format json --json-envelope --no-fail --no-cache`
  - family: `--profile all --only CWE-916 --format json --json-envelope --no-fail --no-cache`
- **Pin set:** see [`canary-corpus-pins.json`](./canary-corpus-pins.json)

### Recommended counts

| Repository | Revision (short) | Files scanned | Findings | By rule |
|------------|------------------|--------------:|---------:|---------|
| gopdfsuit | `26d7126` | 78 | 38 | PERF-1 ×38 |
| monsoon | `e0f1027` | 43 | 3 | PERF-1, PERF-7, PERF-190 |
| go-retry | `d3eb50a` | 5 | 0 | — |
| gorl | `ec54aaf` | 28 | 0 | — |
| no-mistakes | `0a2c82f` | 222 | 2 | PERF-189, PERF-7 |
| **Total** | | **376** | **43** | |

### CWE-916 `--only` counts

| Repository | Findings | Note |
|------------|---------:|------|
| gopdfsuit | 2 | encrypt.go:79, encryption_inhouse.go:241 |
| monsoon | 0 | no-hit |
| go-retry | 0 | no-hit |
| gorl | 0 | no-hit |
| no-mistakes | 0 | no-hit |

### Reviewed rows (rubric)

| Rule | Repo | Location | Disposition | Note |
|------|------|----------|-------------|------|
| PERF-1 | monsoon | `cmd/fuzz/main.go:91` | false-positive | Setup-once pattern compile |
| PERF-7 | monsoon | `reporter/reporter.go:202` | actionable | Loop-level defer |
| PERF-190 | monsoon | `response/runner.go:293` | actionable | Client without timeout |
| PERF-189 | no-mistakes | `internal/telemetry/telemetry.go:305` | false-positive | defer Close + drain order is correct |
| PERF-7 | no-mistakes | `internal/update/archive.go:58` | false-positive | defer + return; no stacked loop defers |
| CWE-916 | gopdfsuit | `internal/pdf/encryption/encrypt.go:79` | actionable | PDF password MD5 |
| CWE-916 | gopdfsuit | `internal/pdf/redact/encryption_inhouse.go:241` | actionable | Same family |

### Rates and decisions

| Slice | Reviewed hit rate | Decision |
|-------|-------------------|----------|
| Mixed pilot sample (7 rows) | 4 actionable / 7 = **57%** | Process pilot only; documents rubric + expanded pins |
| CWE-916 family (2 hits, both reviewed) | 2 / 2 = **100%** actionable among hits; 4× no-hit repos | **keep Heuristic** (no Structural); consistent with prior audit |
| Recommended pack (new members) | go-retry/gorl quiet; no-mistakes introduces 2 FPs in sample | **no pack change** in #117; file PERF-189/PERF-7 no-mistakes shapes for a future noise issue |

- **Links:** [`canary-corpus.md`](./canary-corpus.md) pilot section; issue #117;
  prior monsoon/gopdfsuit recommended pilot in [`pending-work.md`](./pending-work.md) §3.1

---

## 2026-07-23 — P1 post R1–R8 catalog residuals (#166 / epic #151)

- **Binary / commit:** `target/release/codehound` @ `f3eaaf8` (`origin/master` after R5–R8 integration #176 + ledger #177)
- **Profiles:** (1) `--profile recommended` (2) `--profile all --only` FO quarantine set from R1–R8 (3) `--only CWE-201,CWE-213` Heuristic keep
- **Pin set:** gopdfsuit, monsoon, go-retry, gorl, no-mistakes @ SHAs in `canary-corpus-pins.json`

### Recommended pack — per-repo counts

| Repository | Files | Findings | By rule |
|------------|------:|---------:|---------|
| gopdfsuit | 78 | **38** | PERF-1 ×38 |
| monsoon | 43 | **3** | PERF-1 ×1, PERF-7 ×1, PERF-190 ×1 |
| go-retry | 5 | **0** | — |
| gorl | 28 | **0** | — |
| no-mistakes | 222 | **2** | PERF-189 ×1, PERF-7 ×1 |

**Core three total:** 41 — **identical multiset** to 2026-07-21 recommended-pack pilot (§5 in [`recommended-pack-pilot.md`](./recommended-pack-pilot.md)).

### FO quarantine family `--only` (R1–R8 maturity batch)

Rules: CWE-260,455,289,290,294,301,303,322,408,324,262,263,549,640,618,829,1125,619,917

| Repository | Files | Findings |
|------------|------:|---------:|
| gopdfsuit | 78 | 0 |
| monsoon | 43 | 0 |
| go-retry | 5 | 0 |
| gorl | 28 | 0 |
| no-mistakes | 222 | 0 |
| **Total** | **376** | **0** |

### Heuristic keep (R2) — `--only CWE-201,CWE-213`

| Repository | Files | Findings |
|------------|------:|---------:|
| all five pins | 376 | **0** |

### Reviewed rows / rates

| Slice | Result | Decision |
|-------|--------|----------|
| Recommended core sample | Unchanged vs 2026-07-21 (95% senior sample still valid) | **no pack change**; stop-the-line **not** triggered |
| R1–R8 FO `--only` | 0/376 (all no-hit) | Quarantine holds; no real-module promotion evidence |
| CWE-201/213 Heuristic | 0/376 | Keep Heuristic; no pack membership change this PR |

- **Links:** issue #166; epic #151; integrations #171 / #176; [`process-canary-and-pack-pilot.md`](../v0.0.6/process-canary-and-pack-pilot.md)

---

## Prior related ledgers (pointers)

These predate the unified rubric location; do not duplicate full tables here.

| Date / period | Topic | Where |
|---------------|-------|--------|
| 2026-07-18 | Recommended-pack pilot (original 3 repos), 95% sample | [`pending-work.md`](./pending-work.md) §3.1 |
| 2026-07-18 | gorl full-catalog noise-reduce-1 | [`noise-reduce-1.md`](./noise-reduce-1.md) |
| 2026-07-18+ | CWE family canaries (password storage, file perms, Phase 1–2) | [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md), family `evidence-*.md` / `pr-cwe-trust-*.md` |

When citing those for new promotion decisions, re-run on the **expanded** pin set
and append a new dated section here.
