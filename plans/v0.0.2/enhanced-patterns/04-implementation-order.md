# Enhanced Patterns — Implementation Order

> **Parent:** `plans/v0.0.2/enhanced-patterns/README.md`
> **Status:** **Shipped** (verified 2026-07-10)
> **Authority for 1:1 theme outcomes:** [05-one-to-one-mapping.md](./05-one-to-one-mapping.md)
> **Master checklist:** [CHECKLIST.md](./CHECKLIST.md)

---

## Why this order (historical)

1. Tighten first — existing IDs, broader matching.
2. High-value new rules — clone / re-copy / compress pool / PEM.
3. Loop-invariant & string chains.
4. Tiny fan-out + compress level (228, 233).
5. 1:1 verify on real trees + visibility (`run-perf-enhanced`).

---

## Phase status (verified against repo)

| Phase | Plan | Shipped? | Evidence |
|-------|------|----------|----------|
| A Shared hot-path helper | `is_hot_path` in `common.rs` | **Yes** | `fn is_hot_path`, unit tests in `common.rs` |
| B Tighten (02) | T1–T10 | **Yes** | See [02-tighten-existing.md](./02-tighten-existing.md) inventory table |
| C New rules (03) | 225–231, 233; 232 merged | **Yes** | See [03-new-rules-batch-225.md](./03-new-rules-batch-225.md) inventory table |
| D Optional / residual | 228, 027 large-make, 233 | **Yes** (228/233/027 large-make) | Detectors + fixtures; suite green |
| E Closeout + 1:1 | docs, makefile, agent pass | **Yes** | `05` Agents A–E; `make run-perf-enhanced` in makefile |
| Push/PR | human | **Not verified here** | Branch may need `git push` |

**Integration (this pass):** `cargo test --test go_perf_detector_integration` → **4/4 ok**.

---

## Phase A — Shared hot-path helper

**File:** `src/lang/go/detectors/perf/common.rs`

- [x] `is_hot_path` (loop \| handler window \| hot function name) — **not** whole-file request path
- [x] `enclosing_function_name` / `enclosing_function_is_hot` / body helpers
- [x] Name heuristics (Handle, Serve, Write, Encode, Build, Generate, Render, Compress, Sign, …)
- [x] Unit tests in `common.rs`
- [x] Wired into tightened + new detectors

**Exit:** Met.

---

## Phase B — Tighten batch

| Step | Item | Shipped? |
|------|------|----------|
| B1 | PERF-215 | [x] |
| B2 | PERF-217 | [x] |
| B3 | PERF-027 | [x] (large-make too; live gopdfsuit **Partial** due to pools) |
| B4 | PERF-192 | [x] |
| B5 | PERF-054 | [x] |
| B6 | PERF-018 | [x] |
| B7 | PERF-032 | [x] |
| B8 | PERF-218 / 219 | [x] |
| B9 | PERF-109 | [x] |

- [x] Phase B green (integration)
- [x] Non-HTTP fixtures where applicable

---

## Phase C — New core rules

- [x] Chunk `ruleset/golang/chunks/perf-225-232.json` (includes 225–231, 233)
- [x] Registry entries 225–231, 233
- [x] Detectors in `copies_and_compress.rs`
- [x] Fixtures + manifest for each shipped ID
- [x] 232 merged into 231 (no separate ID)
- [x] Integration green

| Step | Rule | Shipped? |
|------|------|----------|
| C1 | 225 | [x] |
| C2 | 226 | [x] |
| C3 | 227 | [x] |
| C4 | 231 | [x] |
| C5 | 229 | [x] |
| C6 | 230 | [x] |
| C7 | 232 | [x] merged → 231 |
| C8 | 228 | [x] |
| C9 | 233 | [x] |

---

## Phase D — Optional / residual

- [x] PERF-228 shipped (not deferred forever)
- [x] PERF-027 large make shipped
- [x] PERF-233 shipped (BestSpeed theme)
- [x] Noise: integration safe fixtures + clean path covered by suite
- [ ] Optional: finer PERF-027 pool suppress (function-scoped) — **not shipped**

---

## Phase E — Closeout

- [x] README status **Shipped**
- [x] Checkboxes in `02` / `03` / `04` / `05` / CHECKLIST aligned to **verified** ship state
- [x] Pointer from `pending-work/02-perf-detectors-remaining.md`
- [x] CHANGELOG Unreleased note
- [x] `make run-perf-enhanced`
- [x] 1:1 mapping doc Agents A–E complete
- [ ] Push/PR on remote (human)

**Folder DoD:**

- [x] Gap matrix reviewed (project-agnostic)
- [x] Tighten fixtures beyond original toy shapes
- [x] New rules in chunks + registry + detectors + fixtures + manifest
- [x] Integration + registry generation green
- [x] Non-web / enhanced set visible via `make run-perf-enhanced`
- [x] 1:1 static themes **Yes** except **027 Partial** + permanent **OOS**

---

## Out of scope (still)

- klauspost recommendation
- GOMAXPROCS / GOMEMLIMIT
- Product compliance policy
- Auto-`--fix` for these rules
