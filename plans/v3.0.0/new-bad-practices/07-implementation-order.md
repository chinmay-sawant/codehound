# 07 — Implementation Order & PR Slices

> **Parent:** `plans/v3.0.0/new-bad-practices/README.md`
> **Status:** Plan only

---

## Principles

1. **Scaffold once**, then ship vertical slices (JSON + detector + **txt fixtures** + manifest + docs + test green).
2. Prefer **stdlib-only rules first** (Parts A–B) before framework import-gated rules (C–E).
3. Never merge a detector without **vulnerable + safe `.txt` snippets**.
4. One PR ≈ one sub-batch (5–10 rules) to keep reviewable diffs.
5. If a rule collides with CWE/PERF/staticcheck during implementation, **drop or rewrite** and pull from Part F stretch backlog — update CHECKLIST.

---

## Phase 0 — Scaffold (PR0)

**Goal:** empty IDs + plumbing, zero false confidence.

- [ ] Confirm max BP id = 65
- [ ] Add `BadPracticeCategory` variants if needed: `HttpFrameworks`, `DataPersistence`, `Observability`, `Configuration`, `CoreLanguage` (only those you will use)
- [ ] Wire category → reporting (same as existing BP)
- [ ] Extend `source_index.rs` NEEDLES list for upcoming parts (can grow per PR)
- [ ] Extend `dispatch.rs` table structure for new modules
- [ ] Create empty module files: `http_frameworks.rs`, `data_persistence.rs`, `observability.rs`, `config_cli.rs` (stub `pub fn detect_*`)
- [ ] Add `ruleset/golang/bad-practices.json` **placeholder** entries BP-66..BP-165 with `"status": "planned"` **or** add incrementally per batch (prefer incremental to avoid huge dead metadata)
- [ ] Makefile target draft: `run-bp-new` (optional in PR0)

**PR title:** `chore(bp): scaffold v3 bad-practice categories and modules`

---

## Phase 1 — Part A batches (PR1–PR3)

| PR | Rules | Focus |
|----|-------|--------|
| PR1 | BP-66..BP-71 | Deep error handling |
| PR2 | BP-72..BP-76 | Nil / slice / map correctness |
| PR3 | BP-77..BP-85 | Context, time, asserts |

Each PR must include:

- [ ] Detectors
- [ ] `BP-N-vulnerable.txt` + `BP-N-safe.txt` for every N in the PR
- [ ] `manifest.toml` rows
- [ ] `documents/bad-practices.md` bullets
- [ ] `cargo test --test go_bad_practice_integration` green

**PR titles:**

- `feat(bp): BP-66..71 error-handling deep patterns`
- `feat(bp): BP-72..76 nil and collection correctness`
- `feat(bp): BP-77..85 context time and type assert`

---

## Phase 2 — Part B (PR4–PR5)

| PR | Rules | Focus |
|----|-------|--------|
| PR4 | BP-86..BP-94 | Mutex, channels, errgroup, races |
| PR5 | BP-95..BP-100 | Resource lifecycle + unbounded fan-out |

**Note:** BP-95/BP-96 may overlap bodyclose/sqlclosecheck — document “zero-dep default coverage” rationale in PR body.

---

## Phase 3 — Part C HTTP (PR6–PR9)

| PR | Rules | Focus |
|----|-------|--------|
| PR6 | BP-101..BP-108 | net/http correctness |
| PR7 | BP-109..BP-115 | Gin correctness (not PERF) |
| PR8 | BP-116..BP-121 | Echo + Fiber |
| PR9 | BP-122..BP-125 | Chi + cross-framework |

**Fixture variants:** set `variant: gin|echo|fiber|chi|stdlib` in snippet headers.  
**Overlap review:** BP-111 vs PERF gin copy rule before merge.

---

## Phase 4 — Part D data (PR10–PR12)

| PR | Rules | Focus |
|----|-------|--------|
| PR10 | BP-126..BP-132 | database/sql |
| PR11 | BP-133..BP-139 | GORM correctness |
| PR12 | BP-140..BP-145 | sqlx + redis + pgx |

**CWE check:** BP-129 / BP-139 vs CWE-89 before implementing.

---

## Phase 5 — Part E observability/config (PR13–PR14)

| PR | Rules | Focus |
|----|-------|--------|
| PR13 | BP-146..BP-153 | Logging + config/secrets hygiene |
| PR14 | BP-154..BP-160 | JSON + gRPC + CLI |

---

## Phase 6 — Part F tail + release (PR15–PR16)

| PR | Rules | Focus |
|----|-------|--------|
| PR15 | BP-161..BP-165 | Testing + API lifecycle |
| PR16 | documents/makefile/changelog | Release polish |

- [ ] Replace any dropped rules from stretch backlog
- [ ] Final count = **100** net-new (BP-66..BP-165 contiguous or documented holes)
- [ ] Update root README BP count
- [ ] CHANGELOG `[3.0.0]` section

---

## Risk register

| Risk | Mitigation |
|------|------------|
| False positives on error-continue patterns | Tight AST windows; safe fixtures for log-and-return-OK cases |
| Framework API churn | Gate on import path + stable method names; pin fixture module paths |
| Double-firing with PERF | Shared helper or skip if PERF already enabled for same span — prefer unique rule text |
| Double-firing with CWE | Prefer CWE for true vulns; BP only for engineering practice |
| Huge `bad-practices.json` | Optional future chunk split (like PERF); not required for plan start |
| Snippet materialization failures | Keep fixtures compilable enough for tree-sitter; follow existing BP-1 style |

---

## Definition of done (implementation)

For the v3.0.0 new-bad-practices epic:

- [ ] 100 rules with detectors
- [ ] **200 text fixtures** minimum (vulnerable + safe × 100) under `tests/fixtures/go/bad_practices/`
- [ ] Manifest complete
- [ ] Docs complete
- [ ] Integration tests green
- [ ] Gap policy in `00-gap-and-scope.md` respected
- [ ] CHECKLIST.md all phase boxes checked
