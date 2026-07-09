# V2.0.0 — Enhanced PERF Patterns

> **Parent:** `plans/v2.0.0/`
> **Status:** **Shipped** — core Phases A–E + **1:1 static mapping complete** — see [CHECKLIST.md](./CHECKLIST.md) and [05-one-to-one-mapping.md](./05-one-to-one-mapping.md)
> **Date:** 2026-07-10
> **Estimated effort:** ~1.5–2.5 weeks (core + parallel agent 1:1 pass)

---

## Purpose

Close the gap between **profiler-driven hot-path smells** (buffer churn, redundant copies, compress/pool reuse, static recompute, crypto setup reuse) and what CodeHound actually fires today.

**1:1 goal:** every static-analyzable theme from the external high-ops improvement plan maps to a PERF rule that fires on real hot-path shapes (project-agnostic). Track mapping status and agent evidence in [05-one-to-one-mapping.md](./05-one-to-one-mapping.md).

Source of truth for “what’s missing”:

1. Cross-check of external high-throughput workload hotspots (alloc/copy/flate/crypto/table-write families) against PERF-001–224 (baseline before this batch).
2. Audit of **fixture-shaped / overly gated** detectors that claimed the right smell but missed real code.
3. Living theme → PERF table in **[05-one-to-one-mapping.md](./05-one-to-one-mapping.md)**.

**Constraints (non-negotiable):**

- **Project-agnostic.** No product-only rules. Product names may appear only as *examples* in descriptions.
- **Module-level is fine.** Prefer general Go/stdlib patterns; framework tags only when the API is framework-specific.
- **Static-analyzable only.** Permanent OOS: GOMAXPROCS, GOMEMLIMIT, klauspost/third-party compress choice, product compliance — see checklist [Permanent non-goals](./CHECKLIST.md#permanent-non-goals-oos).
- **Same shipping shape as prior batches:** JSON rule + registry entry + detector + vulnerable/safe fixtures + `manifest.toml` + integration green.

---

## Quick verify (enhanced PERF set)

Findings for the 1:1 / enhanced set are easy to bury under BP/CWE noise. Use:

```bash
make run-perf-enhanced
# override target tree:
make run-perf-enhanced SCAN_PATH=/path/to/project
# override rule list if needed:
make run-perf-enhanced PERF_ENHANCED_ONLY=PERF-225,PERF-226
```

`--only` defaults to: **018, 027, 032, 054, 109, 192, 215, 217–219, 225–231, 233**.

---

## Documents in this folder

| File | Contents |
|------|----------|
| **[CHECKLIST.md](./CHECKLIST.md)** | **Primary tracker** — phases A–E + permanent OOS + 1:1 pointer |
| **[05-one-to-one-mapping.md](./05-one-to-one-mapping.md)** | **1:1 theme → PERF** living table + agent evidence |
| [01-gap-matrix.md](./01-gap-matrix.md) | Hotspot → existing PERF → missing / tighten / OOS |
| [02-tighten-existing.md](./02-tighten-existing.md) | Tighten batch — **Shipped** (verified inventory) |
| [03-new-rules-batch-225.md](./03-new-rules-batch-225.md) | New rules 225–233 — **Shipped** (verified inventory) |
| [04-implementation-order.md](./04-implementation-order.md) | Phase A–E order — **Shipped** (phase checkboxes verified) |

**Track phase completion in [CHECKLIST.md](./CHECKLIST.md). Track 1:1 theme acceptance in [05](./05-one-to-one-mapping.md).**

---

## What shipped

| Bucket | Result |
|--------|--------|
| **Shared hot-path helper** | `is_hot_path` / enclosing function name heuristics in `perf/common.rs` |
| **Tighten existing** | PERF-018, 027, 032, 054, 109, 192, 215, 217, 218, 219 |
| **New rules** | PERF-225–231 (incl. 228 tiny fan-out), **PERF-233** (slow compress level on hot encode) |
| **Merged** | PERF-232 → 231 |
| **PERF-027 extra** | Large `make([]byte, N≥4KiB)` inside loops without pool |
| **Makefile UX** | `make run-perf-enhanced` prints only the enhanced PERF set |

Detectors live mainly in:

- `src/lang/go/detectors/perf/common.rs`
- `…/stdlib_misuse/caching_and_allocation.rs` (215–219)
- `…/stdlib_misuse/copies_and_compress.rs` (**225–231, 233**)
- plus targeted edits to 018 / 027 / 032 / 054 / 109 / 192

Ruleset chunk: `ruleset/golang/chunks/perf-225-232.json` (includes PERF-233)

---

## Definition of done (folder-level)

- [x] Gap matrix reviewed; no product-only rule slipped in
- [x] Tighten items have broader fixtures beyond original toy shapes
- [x] PERF-225..231 (+ 233) in chunks, registry, detectors, fixtures, manifest
- [x] `cargo test --test go_perf_detector_integration` green
- [x] `cargo test --test go_perf_ruleset_audit` green
- [x] Non-web fixtures fire clone / grow / pool / static / compress smells without Gin
- [x] Permanent OOS documented (klauspost, GOMAXPROCS, GOMEMLIMIT, compliance, auto-fix)
- [x] `make run-perf-enhanced` for 1:1 scan visibility
- [ ] 1:1 mapping acceptance complete ([05](./05-one-to-one-mapping.md))
- [ ] PR merged *(human step)*
