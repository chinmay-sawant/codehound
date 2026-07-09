# Enhanced Patterns — New Rules Batch (PERF-225+)

> **Parent:** `plans/v2.0.0/enhanced-patterns/README.md`
> **Status:** **Shipped** (verified 2026-07-10)
> **Verification:** each rule has JSON + registry + `detect_perf_N` + fixture pair + integration green
> **Chunk:** `ruleset/golang/chunks/perf-225-232.json` (keys include 225–231, **233**)
> **Detectors:** `…/stdlib_misuse/copies_and_compress.rs`
> **1:1 evidence:** [05-one-to-one-mapping.md](./05-one-to-one-mapping.md)

---

## Verified inventory

| ID | Name | JSON | Registry | `detect_perf_N` | Fixtures | Integration | Result |
|----|------|------|----------|-----------------|----------|-------------|--------|
| 225 | Redundant Large Slice Clone | Implemented | yes | yes | yes | green | **Shipped** |
| 226 | Post-Producer Buffer Re-Copy | Implemented | yes | yes | yes | green | **Shipped** |
| 227 | Compress Writer Without Pool | Implemented | yes | yes | yes | green | **Shipped** |
| 228 | Parallel Fan-Out Tiny Workset | Implemented | yes | yes | yes | green | **Shipped** |
| 229 | Intermediate String On Byte Append | Implemented | yes | yes | yes | green | **Shipped** |
| 230 | Pure Fn Re-Eval In Loop | Implemented | yes | yes | yes | green | **Shipped** |
| 231 | PEM/Key Parse On Hot Path | Implemented | yes | yes | yes | green | **Shipped** |
| 232 | Crypto scaffold rebuild | — | — | — | — | — | **Not shipped as separate ID** — **merged into 231** |
| 233 | Slow Compress Level On Hot Path | Implemented | yes | yes | yes | green | **Shipped** (1:1 BestSpeed theme) |

**Suite:** `cargo test --test go_perf_detector_integration` — **4/4 green** (verified this pass).

---

## Per-rule checklist (only items verified shipped)

### PERF-225 — Redundant Large Slice Clone

- [x] JSON + registry + detector
- [x] Fixtures + manifest
- [x] Tests green
- [x] 1:1: double `slices.Clone` (e.g. gopdfsuit `generator.go:1490`)

### PERF-226 — Post-Producer Buffer Re-Copy

- [x] JSON + registry + detector
- [x] `make([]byte, …Len())` + `copy` / Clone after Bytes/Close
- [x] Fixtures + manifest
- [x] Tests green
- [x] 1:1: compress own-copy (e.g. `generator.go:822`)

### PERF-227 — Compress Writer Allocated Without Pool

- [x] JSON + registry + detector
- [x] Function-scoped suppress (not file-wide pool silence)
- [x] Fixtures + manifest
- [x] Tests green
- [x] 1:1: unpooled NewWriter* (e.g. xfdf / redact)

### PERF-228 — Parallel Fan-Out For Tiny Workset

- [x] JSON + registry + detector
- [x] Fixtures + manifest
- [x] Tests green
- [x] 1:1: N≤2 composite + fan-out (fixtures; dynamic N correctly silent on gopdfsuit)

### PERF-229 — Intermediate String On Byte Append Path

- [x] JSON + registry + detector
- [x] Fixtures + manifest
- [x] Tests green
- [x] 1:1: draw path largely already uses AppendInt (theme “already fixed” where no hit)

### PERF-230 — Pure Function Re-Evaluated In Loop

- [x] JSON + registry + detector
- [x] parse/measure/width/props/font style names; not time.Parse / pool.Get
- [x] Fixtures + manifest
- [x] Tests green
- [x] 1:1: drawTable-class props/width (e.g. `draw.go` parseProps / width helpers)

### PERF-231 — PEM Or Key Material Parsed On Hot Path

- [x] JSON + registry + detector
- [x] Fixtures + manifest
- [x] Tests green
- [x] 1:1: e.g. `signature.go:133` pem.Decode

### PERF-232 — Crypto Scaffold (merged)

- [x] Decide merge → **merged into PERF-231**
- [x] No separate detector/fixture/ID shipped

### PERF-233 — Slow Compress Level On Hot Encode Path

- [x] JSON + registry + detector
- [x] Default/BestCompression vs BestSpeed
- [x] Fixtures + manifest
- [x] Tests green
- [x] 1:1: BestSpeed theme (reclassified from OOS)

---

## Shipping template (historical reference)

Still the required shape for any future PERF IDs:

1. Rule JSON under `ruleset/golang/chunks/`
2. Registry entry
3. `detect_perf_N`
4. Vulnerable + safe fixtures
5. Manifest
6. Integration green

---

## Not shipped / not claimed

| Item | Why |
|------|-----|
| klauspost drop-in | Permanent OOS (dependency choice) |
| GOMAXPROCS / GOMEMLIMIT | Permanent OOS (runtime) |
| Compliance policy | Permanent OOS |
| Auto-`--fix` | Separate plan |
