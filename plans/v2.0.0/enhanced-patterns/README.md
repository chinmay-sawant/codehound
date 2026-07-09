# V2.0.0 — Enhanced PERF Patterns

> **Parent:** `plans/v2.0.0/`
> **Status:** **Shipped (core)** — see [CHECKLIST.md](./CHECKLIST.md)
> **Date:** 2026-07-09
> **Estimated effort:** ~1.5–2.5 weeks (executed in-session for core path)

---

## Purpose

Close the gap between **profiler-driven hot-path smells** (buffer churn, redundant copies, compress/pool reuse, static recompute, crypto setup reuse) and what CodeHound actually fires today.

Source of truth for “what’s missing”:

1. Cross-check of external high-throughput workload hotspots (alloc/copy/flate/crypto/table-write families) against PERF-001–224 (baseline before this batch).
2. Audit of **fixture-shaped / overly gated** detectors that claimed the right smell but missed real code.

**Constraints (non-negotiable):**

- **Project-agnostic.** No product-only rules. Product names may appear only as *examples* in descriptions.
- **Module-level is fine.** Prefer general Go/stdlib patterns; framework tags only when the API is framework-specific.
- **Static-analyzable only.** Out of scope: GOMAXPROCS, GOMEMLIMIT, compression level policy, compliance policy.
- **Same shipping shape as prior batches:** JSON rule + registry entry + detector + vulnerable/safe fixtures + `manifest.toml` + integration green.

---

## Documents in this folder

| File | Contents |
|------|----------|
| **[CHECKLIST.md](./CHECKLIST.md)** | **Primary tracker** — completion status for all phases |
| [01-gap-matrix.md](./01-gap-matrix.md) | Hotspot → existing PERF → missing / tighten / OOS |
| [02-tighten-existing.md](./02-tighten-existing.md) | Detection sketches for tighten items |
| [03-new-rules-batch-225.md](./03-new-rules-batch-225.md) | Detection sketches for PERF-225+ |
| [04-implementation-order.md](./04-implementation-order.md) | Phase rationale / PR titles |

**Track progress in [CHECKLIST.md](./CHECKLIST.md) only.**

---

## What shipped

| Bucket | Result |
|--------|--------|
| **Shared hot-path helper** | `is_hot_path` / enclosing function name heuristics in `perf/common.rs` |
| **Tighten existing** | PERF-018, 027, 032, 054, 109, 192, 215, 217, 218, 219 |
| **New rules** | PERF-225, 226, 227, 229, 230, 231 |
| **Merged** | PERF-232 → 231 |
| **Deferred** | PERF-228 (tiny parallel fan-out); optional large `make([]byte)` in 027 |

Detectors live mainly in:

- `src/lang/go/detectors/perf/common.rs`
- `…/stdlib_misuse/caching_and_allocation.rs` (215–219)
- `…/stdlib_misuse/copies_and_compress.rs` (**225–231**)
- plus targeted edits to 018 / 027 / 032 / 054 / 109 / 192

Ruleset chunk: `ruleset/golang/chunks/perf-225-232.json`

---

## Definition of done (folder-level)

- [x] Gap matrix reviewed; no product-only rule slipped in
- [x] Tighten items have broader fixtures beyond original toy shapes
- [x] PERF-225..231 in chunks, registry, detectors, fixtures, manifest
- [x] `cargo test --test go_perf_detector_integration` green
- [x] `cargo test --test go_perf_ruleset_audit` green
- [x] Non-web fixtures fire clone / grow / pool / static / compress smells without Gin
- [ ] PR merged *(human step)*
