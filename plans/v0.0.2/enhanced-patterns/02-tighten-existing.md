# Enhanced Patterns — Tighten Existing Detectors

> **Parent:** `plans/v0.0.2/enhanced-patterns/README.md`
> **Status:** **Shipped** (verified 2026-07-10)
> **Verification:** detector `fn detect_perf_*` present, registry entry, vulnerable+safe fixtures, `go_perf_detector_integration` green
> **Goal:** Same rule IDs; broader, facts-based matching so real library/hot-path code fires — not only fixture string shapes.
> **Track progress:** [CHECKLIST.md](./CHECKLIST.md) · 1:1 evidence [05-one-to-one-mapping.md](./05-one-to-one-mapping.md)

---

## Verification summary (code, not intent)

| Item | PERF | Detector | Registry | Fixtures | JSON status | Result |
|------|------|----------|----------|----------|-------------|--------|
| T1 | 018 | `detect_perf_18` | yes | yes | Implemented | **Shipped** — no `processItems` hard-code; `make(..., 0, len(src))+append` |
| T2 | 027 | `detect_perf_27` | yes | yes | Implemented | **Shipped** — hot path + Buffer/Builder + large `make([]byte,N≥4KiB)` in loop |
| T3 | 032 | `detect_perf_32` | yes | yes | Implemented | **Shipped** — hot path + loop/request |
| T4 | 054 | `detect_perf_54` | yes | yes | Implemented | **Shipped** — hot path, non-Gin fixtures |
| T5 | 192 | `detect_perf_192` | yes | yes | Implemented | **Shipped** — map without hint when `range`/`len` knowable |
| T6 | 215 | `detect_perf_215` | yes | yes | **Implemented** (was Draft; fixed after verify) | **Shipped** — name-agnostic + Grow / multi-write |
| T7 | 217 | `detect_perf_217` | yes | yes | **Implemented** (was Draft; fixed after verify) | **Shipped** — not HTTP-only; static builder names |
| T8 | 218 | `detect_perf_218` | yes | yes | **Implemented** (was Draft; fixed after verify) | **Shipped** — zero-value pool + concurrency |
| T9 | 219 | `detect_perf_219` | yes | yes | **Implemented** (was Draft; fixed after verify) | **Shipped** — Put without cap on []byte-ish helpers |
| T10 | 109 | `detect_perf_109` | yes | yes | Implemented | **Shipped** — expensive map-key in loop |

**Shared prerequisite (Phase A):** `is_hot_path` / `enclosing_function_name` in `src/lang/go/detectors/perf/common.rs` — **present** (unit tests in same file).

**Integration:** `cargo test --test go_perf_detector_integration` — **green** (verified this pass).

---

## Principles (kept for reference)

1. Prefer facts over multi-token `source.contains("exact fixture line")`.
2. Hot path ≠ HTTP only (`is_hot_path`).
3. Safe fixtures must silence after broaden.
4. No product-only APIs in match lists.

Acceptance (batch):

- [x] Vulnerable fixture(s) still fire (suite green)
- [x] Non-HTTP / realistic fixtures for tighten set where applicable
- [x] Safe fixtures silent for rule class
- [x] Clean smoke / integration green

---

## Per-item notes (shipped state)

### T1 — PERF-018

- [x] Broader than `processItems` fixture shape
- [x] Classic `make([]T, 0, len(src)); append(dst, src...)`
- [x] Fixtures + integration green

### T2 — PERF-027

- [x] Hot-path Buffer/Builder without pool
- [x] Large `make([]byte, N)` in loop (N≥4096)
- [x] File-level `sync.Pool` still suppresses whole unit (known coarseness; 1:1 **Partial** on live pooled trees)

### T3 — PERF-032

- [x] string↔[]byte on hot path / loop
- [x] Fixtures + integration green

### T4 — PERF-054

- [x] Builder on hot path without Reset/pool
- [x] Non-Gin fixtures

### T5 — PERF-192

- [x] `make(map)` without size hint when bound knowable
- [x] Status Implemented in JSON

### T6 — PERF-215

- [x] Buffer/Builder without Grow when size estimable
- [x] Function-scoped Grow checks (post–Agent B)

### T7 — PERF-217

- [x] Static recompute on hot path without HTTP-only gate
- [x] ICC / generate / profile-style names

### T8 — PERF-218

- [x] Unsharded zero-value `sync.Pool` under concurrency

### T9 — PERF-219

- [x] Oversized Put without cap guard (not Recycle-only)

### T10 — PERF-109

- [x] Expensive map-key computation in loop
- [x] Loop-invariant pure helpers also covered by **PERF-230** (new rules batch)

---

## Not claimed as shipped in this file

- Product-named `drawTable` APIs — intentionally generic (PERF-230)
- File-scoped pool suppress refinements for PERF-027 — open gap (Partial)
