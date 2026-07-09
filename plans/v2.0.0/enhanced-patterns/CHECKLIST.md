# Enhanced PERF Patterns — Master Checklist

> **Parent:** `plans/v2.0.0/enhanced-patterns/README.md`
> **Status:** **Shipped (core)** — Phase A–C done; 228 deferred; PR merge is human step
> **Date:** 2026-07-09
> **How to use:** Check boxes as you complete work. Detail / detection sketches live in `01`–`04` if needed.

**Constraints (always — followed for this work):**

- [x] Stay **project-agnostic** (no product-only rules; description examples OK)
- [x] Prefer **stdlib / module-level** smells
- [x] **Static-only** (no GOMAXPROCS / GOMEMLIMIT / compress-level policy / compliance policy)
- [x] Ship shape: JSON + registry + detector + vulnerable/safe fixtures + manifest + tests green

---

## 0. Preflight

- [x] Read gap matrix (`01-gap-matrix.md`) — confirm no product-only rule slipped in
- [x] Grep codebase for hard-coded max PERF id `224` (tests/build/docs)
  - No hard ceiling in tests/build that blocked PERF-225+
  - Historical docs still mention “224” as prior milestone (OK); live count updated where relevant
- [x] Note files to touch (common hot-path helper, chunks, registry, detectors, fixtures, manifest)

---

## Phase A — Shared hot-path helper

- [x] Add `is_hot_path` / `enclosing_function_name` / `function_name_is_hot` in `src/lang/go/detectors/perf/common.rs`
- [x] Include loop membership as primary hot signal
- [x] Include secondary name heuristics (`Handle`, `Serve`, `Write`, `Encode`, `Build`, `Generate`, `Render`, `Compress`, `Sign`, `Marshal`, `Emit`, `Serialize`, …)
- [x] Do **not** use whole-file `is_request_path` inside `is_hot_path` (package-init safety)
- [x] Wire helper into detectors without regressions
- [x] Unit tests for helper in `common.rs`
- [x] `cargo test --test go_perf_detector_integration` green after helper land

---

## Phase B — Tighten existing detectors

### B1 — PERF-215 Buffer/Builder without pre-sizing

- [x] Name-agnostic matching (not only `buf` / `builder`)
- [x] Match `var x bytes.Buffer` / `strings.Builder`, `x := …{}`
- [x] Match `Write` / `WriteString` (and related write APIs in detector path)
- [x] Detect size knowable via `len(arg)` matching write arg (avoids PERF-002-safe noise)
- [x] Suppress when `Grow(` appears on that name
- [x] Non-HTTP vulnerable/safe fixtures (`Encode` / `out`)
- [x] Integration green for PERF-215

### B2 — PERF-217 Static computation rebuilt per operation

- [x] Remove hard HTTP-only gate (`http.ResponseWriter` / gin / echo)
- [x] Fire on loop **or** hot function + zero-arg static builder
- [x] Package-level init stays cold (enclosing-function body check)
- [x] Keep description examples (ICC/font/metadata) as prose only
- [x] Non-HTTP vulnerable/safe fixtures (`GenerateDoc`)
- [x] Integration green for PERF-217

### B3 — PERF-027 Missed sync.Pool reuse

- [x] Broaden beyond request-path-only gate (use hot helper)
- [x] Flag `bytes.Buffer{}` / `new(bytes.Buffer)` / `strings.Builder{}` on hot path
- [x] ~~Optional: large `make([]byte, n)` in loop~~ — **deferred** (noise; not needed for plan exit)
- [x] Suppress when `sync.Pool` already used in file
- [x] Non-HTTP loop vulnerable fixture + pooled safe
- [x] Integration green for PERF-027
- [x] Gin path still covered by `is_handler_shaped` (fixture swapped to non-HTTP deliberately)

### B4 — PERF-192 Map without size hint

- [x] Detect `make(map[K]V)` without capacity when bound knowable (`range` / `len` in function)
- [x] Suppress maps with only a few fixed keys (no range/len)
- [x] Existing vulnerable + safe fixtures still valid
- [x] Set status **Implemented** in JSON
- [x] Integration green for PERF-192

### B5 — PERF-054 strings.Builder Reset missed

- [x] Fire on hot path (not Gin-only)
- [x] Flag `strings.Builder{}` without Reset/pool
- [x] Non-Gin vulnerable + safe fixtures
- [x] Integration green for PERF-054

### B6 — PERF-018 Unnecessary slice copy

- [x] Remove fixture-only `processItems` hard-coding
- [x] Detect classic `make([]T, 0, len(src)); append(dst, src...)`
- [x] Do **not** flag accumulating `append(keys, batch...)` (PERF-081/210 safe)
- [x] Vulnerable + safe fixtures (`CopyAll`)
- [x] Integration green for PERF-018

### B7 — PERF-032 String/byte conversion on hot path

- [x] Hot path via `is_hot_path` + request-path fallback
- [x] Suppress compile-time literals `[]byte("…")`
- [x] Non-HTTP vulnerable/safe fixtures
- [x] Integration green for PERF-032

### B8 — PERF-218 Pool without per-CPU sharding

- [x] Zero-value package `var p sync.Pool` + concurrent/handler use
- [x] Suppress sharded markers / composite `var p = sync.Pool{New:…}` noise on safe pools
- [x] Existing fixtures still green
- [x] Integration green for PERF-218

### B9 — PERF-219 Oversized object returned to pool

- [x] Remove `func Recycle`-only coupling
- [x] Flag `Put` of buffer-named `[]byte` param without `cap` guard
- [x] Avoid false positives on `pool.Put(b)` for `*bytes.Buffer` from Get
- [x] Integration green for PERF-219

### B10 — PERF-109 Map key recompute / expensive key in loop

- [x] Expand expensive markers (fmt/strconv/filepath/strings)
- [x] Map-index context in loop body
- [x] Set status **Implemented** in JSON
- [x] Integration green for PERF-109
- [x] Loop-invariant pure calls also covered by **PERF-230** (new)

### Phase B validation

- [x] `cargo test --test go_perf_detector_integration`
- [x] `cargo test --test go_perf_ruleset_audit`
- [x] Scan `tests/fixtures/go/perf_real_world/clean_go_file.txt` — no catastrophic noise (`no slop detected`)
- [x] Commit on `feat/enhanced-perf` (`05f6343`)
- [ ] Phase B/C PR pushed & merged *(needs GitHub auth: `gh auth login` or SSH remote)*

---

## Phase C — New rules (PERF-225+)

### C0 — Catalogue / build plumbing

- [x] Add chunk `ruleset/golang/chunks/perf-225-232.json`
- [x] Confirm build glob loads new chunk
- [x] No test hard-ceiling blocked new IDs (`go_perf_registry_generation` green)
- [x] Update live docs that claimed “224 PERF” where appropriate

### C1 — PERF-225 Redundant large slice clone

- [x] JSON + registry + `detect_perf_225`
- [x] Double `slices.Clone` / append-nil full copies (same function chain)
- [x] Fixtures + manifest
- [x] Integration green

### C2 — PERF-226 Post-producer buffer re-copy

- [x] JSON + registry + `detect_perf_226`
- [x] `make`+`copy` / Clone after `Bytes()`/`Close()`
- [x] Fixtures + manifest
- [x] Integration green

### C3 — PERF-227 Compress writer allocated without pool

- [x] JSON + registry + `detect_perf_227`
- [x] `flate`/`zlib`/`gzip` `NewWriter*` on hot path without pool+Reset
- [x] Do **not** flag compression level choice
- [x] Fixtures + manifest
- [x] Integration green

### C4 — PERF-231 PEM / key material parsed on hot path

- [x] JSON + registry + `detect_perf_231`
- [x] `pem.Decode` / `x509.Parse*` / `tls.X509KeyPair` on hot path
- [x] Distinct from PERF-025 (key **generation**)
- [x] Fixtures + manifest
- [x] Integration green

### C5 — PERF-229 Intermediate string on byte append path

- [x] JSON + registry + `detect_perf_229`
- [x] Itoa/Sprintf → `append(..., s...)` / WriteString
- [x] Fixtures + manifest
- [x] Integration green

### C6 — PERF-230 Pure function re-evaluated in loop with stable args

- [x] JSON + registry + `detect_perf_230`
- [x] Loop-invariant pure-ish helpers (`parse*` / `measure*` / …)
- [x] Fixtures + manifest
- [x] Integration green

### C7 — PERF-232 Crypto scaffold rebuilt per operation

- [x] Decide: **merge into PERF-231**
- [x] Document decision (this checklist)
- [x] N/A ship separate
- [x] Integration green (via 231)

> **Decision:** merged into PERF-231 for v1.

### C8 — PERF-228 Parallel fan-out for tiny workset (optional / low prio)

- [x] Decide: **defer** (precision risk / low value vs noise)
- [x] Note under Phase D
- [ ] Spike / ship later if needed

### Phase C validation

- [x] `cargo test --test go_perf_detector_integration`
- [x] `cargo test --test go_perf_registry_generation`
- [x] `cargo test --test go_perf_ruleset_audit`
- [x] `cargo test --test fixture_manifest_integration_inventory`
- [x] Commit includes Phase C rules + fixtures
- [ ] Phase C PR pushed & merged *(same as above — auth required)*

---

## Phase D — Optional / fold decisions

- [x] PERF-228 final status recorded — **deferred**
- [x] Confirm no need for extra IDs 233+ (Grow/map folded into 215/192)
- [x] Noise spot-check: `clean_go_file.txt` → no slop
- [x] Confirm clone/grow/pool/static findings **without Gin**:
  - PERF-225 (clone), PERF-226 (re-copy), PERF-215 (grow), PERF-027 (pool), PERF-217 (static), PERF-227 (compress) all fire on non-HTTP fixtures

---

## Phase E — Closeout

- [x] All Phase B boxes checked (or explicitly deferred with note)
- [x] Core new rules 225, 226, 227, 229, 230, 231 shipped (232 merged; 228 deferred)
- [x] `cargo test --test go_perf_detector_integration` final green
- [x] `cargo test --test go_perf_ruleset_audit` final green
- [x] Update this folder README status → **Shipped (core)**
- [x] Pointer from `pending-work/02-perf-detectors-remaining.md` → this folder
- [x] CHANGELOG Unreleased note
- [x] Local commit on `feat/enhanced-perf`
- [ ] Push + open PR *(blocked here: no `gh` login / HTTPS credentials)*

---

## Explicitly out of scope (not work items)

- [ ] ~~Compression level policy (BestSpeed)~~ — OOS
- [ ] ~~klauspost / third-party compress library recommendation~~ — OOS
- [ ] ~~GOMAXPROCS / GOMEMLIMIT~~ — OOS
- [ ] ~~Product compliance (PDF/A, signatures required, workload mix)~~ — OOS
- [ ] ~~CWE / BP catalogue changes~~ — OOS
- [ ] ~~Auto-`--fix` for new rules~~ — later / separate plan
- [ ] ~~PERF-228 tiny fan-out~~ — deferred
- [ ] ~~PERF-027 large `make([]byte,n)` optional~~ — deferred

---

## Shipped inventory (quick reference)

| Kind | IDs / items |
|------|-------------|
| Shared helper | `is_hot_path`, `enclosing_function_name`, `function_name_is_hot` |
| Tightened | 018, 027, 032, 054, 109, 192, 215, 217, 218, 219 |
| New rules | **225, 226, 227, 229, 230, 231** |
| Merged | 232 → 231 |
| Deferred | 228; optional large `make([]byte)` in 027 |
| Chunk | `ruleset/golang/chunks/perf-225-232.json` |
| Detectors | `…/stdlib_misuse/copies_and_compress.rs` + tightened existing modules |

---

## Progress snapshot

| Phase | Status |
|-------|--------|
| A Shared helper | [x] |
| B Tighten | [x] |
| C New rules | [x] core (228 deferred) |
| D Optional | [x] |
| E Closeout | [x] code+docs (PR open left to you) |

**Last updated:** 2026-07-09 (checklist synced + Phase D/E closeout)
