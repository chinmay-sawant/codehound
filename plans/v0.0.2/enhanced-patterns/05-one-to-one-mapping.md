# 1:1 Plan Theme → PERF Mapping

> **Parent:** `plans/v0.0.2/enhanced-patterns/`
> **Status:** **Shipped** — parallel Agents A–E complete (2026-07-10)
> **Goal:** Every **static-analyzable** theme from the Zerodha/pprof improvement plan maps to a Codehound PERF rule that fires on real hot-path shapes (project-agnostic).

Source plan (external): `gopdfsuit/guides/cursor/ZERODHA_5000_OPS_IMPROVEMENT_PLAN.md`

---

## Mapping table (living)

| # | Plan theme | Target PERF | Goal status | Owner agent |
|---|------------|-------------|-------------|-------------|
| 1 | Double `slices.Clone` / signed-path clone | PERF-225 | **Yes** (see Agent A) | Agent A |
| 2 | Post-compress `make`+`copy` | PERF-226 | **Yes** (see Agent A) | Agent A |
| 3 | Pre-grow Buffer/Builder | PERF-215 | **Yes** (see Agent B) | Agent B |
| 4 | Map / pdfBuffer pre-size | PERF-192 + 215 | **Yes** (192 already fixed; 215 live) | Agent B |
| 5 | ICC / static recompute (OutputIntent, fonts) | PERF-217 | **Yes** (see Agent B) | Agent B |
| 6 | flate/zlib without pool | PERF-227 | **Yes** | Agent C |
| 7 | BestSpeed vs Default/BestCompression | PERF-233 | **Yes** | Agent C |
| 8 | Tiny parallel fan-out (1-page compress) | PERF-228 | **Yes** (fixtures; gopdfsuit dynamic N) | Agent C |
| 9 | PEM/key parse on sign path | PERF-231 | **Yes** (cache miss still flagged) | Agent D |
| 10 | drawTable props/width cache | PERF-230 + 109 | **Yes** | Agent D |
| 11 | strconv/fmt numeric emit | PERF-015/006/229 | **Already fixed** on draw path | Agent D |
| 12 | Large make([]byte) in loop | PERF-027 | **Partial** (see Agent A) | Agent A |
| 13 | klauspost / GOMAXPROCS / GOMEMLIMIT / compliance | — | **OOS** (documented) | Agent E |
| 14 | `make run` visibility | `run-perf-enhanced` | **Done** | Agent E |

---

## Acceptance (per theme)

- [x] Detector fires on a **gopdfsuit** (or equivalent) real site for that theme, **or** explicit “already fixed / no static smell” note
- [x] Vulnerable + safe fixtures green in `go_perf_detector_integration` (4/4)
- [x] No catastrophic noise on other safe fixtures (suite green)
- [x] Checklist row updated to **Yes** / **Partial** / **OOS** with evidence (file:line)

### How to verify (visibility)

```bash
# Prints enhanced PERF findings (not buried by BP/CWE)
make run-perf-enhanced
# Focused:
make run-perf-enhanced PERF_ENHANCED_ONLY=PERF-225,PERF-226,PERF-227,PERF-233
```

---

## Agent results (filled after parallel run)

### Agent A — copies / ownership

**Date:** 2026-07-10  
**Command verified:**
```
cargo run -q -- /home/chinmay/ChinmayPersonalProjects/gopdfsuit/internal/pdf/generator.go \
  --no-fail --format text --no-context --no-chunks --only PERF-225,PERF-226
```
**Integration:** `cargo test --test go_perf_detector_integration` — green (4/4).

| # | Theme | PERF | Status | Evidence (gopdfsuit) |
|---|--------|------|--------|----------------------|
| 1 | Double `slices.Clone` / signed-path clone | PERF-225 | **Yes** | `internal/pdf/generator.go:1490` — second `slices.Clone(signedPDF)` after `slices.Clone(*finalScr)` at `:1478` in same function |
| 2 | Post-compress `make`+`copy` | PERF-226 | **Yes** | `internal/pdf/generator.go:822` — `cp := make([]byte, compressedBuf.Len()); copy(cp, compressedBuf.Bytes())` after zlib Close; also `internal/pdf/metadata.go:325` (ICC compress path) |
| 12 | Large `make([]byte)` in loop without pool | PERF-027 | **Partial** | Fixtures fire/silence correctly. No remaining classic unpooled literal `make([]byte, N≥4KiB)` **inside a loop** on gopdfsuit — large buffers are already hoisted (e.g. `font/pdfa.go:277` `copyBuf` outside extract loop) or pool-backed (`generator.go` / `image.go` `sync.Pool`). File-level `sync.Pool` presence still short-circuits the detector. |

**Extra notes (PERF-226):**
- Also reports `generator.go:1478` (`slices.Clone` after `pdfBuffer.Bytes()` / pool handoff) — related ownership re-copy, not the compress make+copy theme; double-clone chain is owned by PERF-225 at `:1490`.
- Small fixed makes near unrelated `.Bytes()` (e.g. former hit at `:1131` `make([]byte, 16)`) suppressed by requiring `.Len()`/`len(` on make+copy windows.

**Files changed (Agent A):**
- `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse/copies_and_compress.rs` — path-1 make+Len+copy already present (WIP); tightened `window_has_recopy` so post-producer make+copy requires Len/len (drop crypto-scratch FPs)
- Detectors already in place: PERF-225/226 in `copies_and_compress.rs`; PERF-027 large-make-in-loop in `allocations_and_reuse/buffer_pooling.rs`
- Fixtures: `tests/fixtures/go/perf/PERF-{225,226,027}-{vulnerable,safe}.txt` (unchanged this pass; green)

**Remaining gaps:**
- PERF-027: file-wide `if source has sync.Pool { return }` is coarser than plan (“pool for that type”); no gopdfsuit live hit while pools exist — consider function-scoped suppress + expression sizes (`32*1024`, `1<<20`) if a future codebase still allocates large scratch inside loops alongside unrelated pools.
- PERF-226 may still co-report intentional pool-ownership `slices.Clone` (e.g. `:1478`); acceptable overlap with PERF-225, not the P0.2 compress theme.

### Agent B — grow / static

**Date:** 2026-07-10  
**Command verified:**
```
./target/release/codehound --lang go --only PERF-215,PERF-217,PERF-192 \
  --format json --json-envelope --no-fail --no-context --no-chunks --no-baseline \
  /home/chinmay/ChinmayPersonalProjects/gopdfsuit
```
**Result:** 19 findings — PERF-215 ×15, PERF-217 ×4, PERF-192 ×0 (production maps already sized).  
**Integration:** `cargo test --test go_perf_detector_integration` — green (4/4).

| # | Theme | PERF | Status | Evidence (gopdfsuit) |
|---|--------|------|--------|----------------------|
| 3 | Pre-grow Buffer/Builder | PERF-215 | **Yes** | Multi-write / estimable size without `Grow`: `internal/pdf/metadata.go:76` (`var xmp strings.Builder` many `WriteString` in XMP build); `internal/pdf/generator.go:537`; `internal/pdf/font/registry.go:430`; `internal/pdf/outline.go:317`; path-A known-`len` write: `internal/pdf/draw.go:1965` (`widgetDict.WriteString(widgetFontRef)` with `len(widgetFontRef)` later in same func). Already-correct Grow sites stay silent (e.g. `metadata.go:286` `metaSB.Grow(64 + len(streamContent))`, `pagemanager.go:48` `firstStream.Grow(65536)`). |
| 4 | Map / buffer pre-size | PERF-192 + 215 | **Yes** | **PERF-192 already fixed** on hot paths — size hints present (e.g. `merge.go:77` `make(map[int][]byte, len(objMatches))`, `font/registry.go:42` `make(map[string]*RegisteredFont, 16)`, `font/subset.go:18` `make(map[uint16]bool, len(usedGlyphs)+1)`). Zero live PERF-192 on current tree; fixtures still fire/silence. Buffer half covered by PERF-215 evidence above. |
| 5 | ICC / static recompute | PERF-217 | **Yes** | `internal/pdf/metadata.go:312` `getSRGBICCProfile()` inside `GenerateOutputIntent` (hot `generate*` name; zero-arg ICC builder); `internal/pdf/pdfa.go:355` `GetSRGBICCProfile()` inside `GenerateICCProfileObject` (`GetSRGBICCProfile` → `buildSRGBICCProfile()` rebuilds bytes every call, no process-level cache). Hot path is name/loop/handler — **not** HTTP-only. |

**Hardening this pass:**

| Rule | Change |
|------|--------|
| PERF-215 | **Function-scoped** `Grow` / `len(arg)` / multi-write counts (was file-wide: one `sb.Grow` silenced every `sb` in the file). Path B still requires hot function name + ≥3 writes with size hint (or ≥6 writes). |
| PERF-217 | Drop bare `compress` token noise; suppress **pool accessors** (`Get*Buffer` / `Get*Writer` / bare `Get`/`Put`) and `reset*`/`clear*`; skip **func-literal callees** from `defer func(){…}()` IIFEs (was FP: callee text contained `template`). Keep `generate` / `outputintent` / `icc` / `fontobject` / `truetype` / `metadata` / `xmp` / `build` / `profile`. Hot path via shared `is_hot_path` (loop \| handler window \| hot fname). |
| PERF-192 | Unchanged logic; uses shared `enclosing_function_body` from `common.rs`. Still requires `range` / `len(` in enclosing func before flagging bare `make(map[K]V)`. |

**Files changed (Agent B):**
- `src/lang/go/detectors/perf/common.rs` — `enclosing_function_body` / `enclosing_function_body_range`
- `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse/caching_and_allocation.rs` — PERF-215 / PERF-217 harden
- `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse/maps_and_slices.rs` — PERF-192 uses shared body helper
- Fixtures unchanged; green

**Remaining gaps:**
- PERF-215 path A can fire when `len(arg)` is used for a *different* buffer’s Grow in the same function (e.g. draw widget path) — still a missing Grow on the written builder, mild over-flag.
- PERF-217 also reports stateful zero-arg `Generate*` methods (`generator.go:453` `GenerateSubsets()`, `outline.go:79` `generateOutlineObjects()`) that are not pure ICC/static blobs; heuristic is name+arity, not purity analysis.
- PERF-192 does not flag composite `map[K]V{}` (only `make(map…)`); gopdfsuit residual bare maps are already fixed or test-only.

### Agent C — compress / concurrency

**Theme #6 → PERF-227 (Compress Writer Allocated Without Pool)**

| | |
|--|--|
| **Status** | **Yes** |
| **gopdfsuit evidence** | `internal/pdf/form/xfdf.go:1221` and `:1584` (`zlib.NewWriterLevel` + `BestCompression`, no pool); `internal/pdf/redact/secure.go:233` (`zlib.NewWriter`, no pool) |
| **Negative (must not FP)** | `internal/pdf/font/compression.go` — `ZlibWriterPool` + `GetZlibWriter`/`Reset` → clean |
| **Critical harden** | Old detector used **file-level** `sync.Pool`+`Reset` presence to suppress all `NewWriter*` in the file. That would silence unpooled call sites when a sibling `GetZlibWriter` exists. Now suppress only when: (1) enclosing func is a pool getter (`GetZlibWriter` / `Get*Writer`), or (2) **that function’s body** uses writer `Reset`. Package-level `Pool.New` factories (empty name) stay silent. |
| **Fixtures** | Vulnerable: file-level `GetZlibWriter` pool **plus** unpooled `CompressPage` with `BestSpeed` (pool theme only — no PERF-233). Safe: lazy pool + `Reset` + `BestSpeed`. |
| **Integration** | `go_perf_detector_integration` green |

**Theme #7 → PERF-233 (Slow Compress Level On Hot Encode Path)**

| | |
|--|--|
| **Status** | **Yes** (shipped; was once OOS “policy”, reclassified as static `*Compression` / default `NewWriter` on hot encode) |
| **gopdfsuit evidence** | `xfdf.go:1221` and `:1584` (`BestCompression`); `redact/secure.go:233` (`zlib.NewWriter` ⇒ default level). Multi-site emit (not first-only). |
| **Negative** | `font/compression.go` pool factory uses `BestSpeed` → clean; pooled `GetZlibWriter` call sites never construct a slow level |
| **1:1 vs 227** | Level choice only: flags `DefaultCompression` / `BestCompression` / bare `zlib.NewWriter`/`gzip.NewWriter`. Does **not** require missing pool. Does **not** flag free-form level variables or `BestSpeed`. |
| **Fixtures** | Vulnerable: pooled `Reset` path that still uses `DefaultCompression` (level-only — no PERF-227). Safe: pool + `BestSpeed`. |
| **OOS** | klauspost / alternate compressors / GOMAXPROCS — not implemented (Agent E / plan OOS). |
| **Integration** | green; registry + ruleset audit green |

**Theme #8 → PERF-228 (Parallel Fan-Out For Tiny Workset)**

| | |
|--|--|
| **Status** | **Yes** (detector + fixtures shipped) |
| **gopdfsuit note** | `generator.go` uses `errgroup` over `len(pageManager.ContentStreams)` — **dynamic N**, not a 1–2 element composite. Correctly **no** PERF-228 (would be noise if forced). Theme smell is “errgroup over `[]T{single}` / N≤2 literal”; static shape covered by fixtures. |
| **Detect** | `g.Go` / `go func` / WaitGroup+go inside `for range` of composite with 1–2 elems or named slice assigned from such a literal |
| **Fixtures** | Vulnerable: `pages := []Page{p}` + errgroup. Safe: serial single-item path |
| **Integration** | green |

**Shared detector notes**

- File: `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse/copies_and_compress.rs`
- Rules: `ruleset/golang/chunks/perf-225-232.json` (includes PERF-233)
- Registry: `registry.general_perf.toml` → `detect_perf_227` / `228` / `233`
- Non-hot compress-shaped name tokens shared via `compress_shaped_fname` (includes `xfdf`, `redact`, `fill`, …) so form/redact helpers fire without HTTP handler shape
- Makefile `PERF_ENHANCED_ONLY` already lists 227, 228, 233

### Agent D — crypto / table hot path

**Date:** 2026-07-10  
**Command verified:**
```
cargo run -q -- \
  /home/chinmay/ChinmayPersonalProjects/gopdfsuit/internal/pdf/draw.go \
  /home/chinmay/ChinmayPersonalProjects/gopdfsuit/internal/pdf/signature/signature.go \
  --no-fail --format text --no-context --no-chunks \
  --only PERF-230,PERF-231,PERF-109,PERF-229
```
**Integration:** `cargo test --test go_perf_detector_integration` — green (4/4).

| # | Theme | PERF | Status | Evidence (gopdfsuit) |
|---|--------|------|--------|----------------------|
| 9 | PEM/key parse on sign path | PERF-231 | **Yes** | `internal/pdf/signature/signature.go:133` — `pem.Decode` inside `parseSignerPEMMaterials` (name matches hot `*sign*` token). **Note:** production code already has `signerPEMMaterialCache` (Load at `:128`, store after parse); detector still flags the parse-on-miss path as a hot-path smell (acceptable: “still flag parse-on-hot”). Does **not** fire on package/`init` only paths (fixture safe). |
| 10 | drawTable props/width cache | PERF-230 | **Yes** | `internal/pdf/draw.go` loop body: `:529` `parseProps(cell.Props)`, `:672` `resolveFontName(...)`, plus `getFontReference` / `parseHexColor` (`:481`, `:619`, `:645`, `:657`). Cap 6 findings/file; nearby `:673` `EstimateTextWidth` is the same theme. `utils.go` already memoizes `parseProps` via `propsCache sync.Map` — static re-call shape still reported (cache-per-key opportunity). |
| 10b | expensive map key in loop | PERF-109 | **Yes** (related) | Not on `draw.go` itself (props keys are plain strings). Hits `internal/pdf/font/registry.go:358` — expensive key construction + map index in loop (width/font registry path adjacent to table measure). |
| 11 | strconv/fmt numeric emit | PERF-229 / 015 / 006 | **Already fixed** | `draw.go` scan with `--only PERF-229,PERF-015,PERF-006` → **no slop detected**. Hot path already uses `strconv.AppendInt` (e.g. `:648`, `:1229`, border emit) instead of Itoa→append string. Fixtures still green for intermediate-string smell. |

**PERF-230 hardening (this pass):**
- Strong generic name match for `parseProps` / `EstimateTextWidth` / `GetTextWidth` / `resolveFont*` / `getFont*` / `parseHex*` style helpers (no project-specific type names).
- **Suppress** stdlib/crypto parse packages: `time`, `strconv`, `url`, `json`, `xml`, `pem`, `x509`, `tls`, … so `time.Parse` / `strconv.Parse*` never fire.
- **Suppress** pool/map accessors: bare `Get`/`Load`/`Put`/`Store` and `*pool.Get` — does not fire on `pool.Get`.
- Dropped false positive: former PERF-230 on `signature.go:165` `x509.ParseCertificate` (crypto parse is PERF-231 only).

**Files changed (Agent D):**
- `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse/copies_and_compress.rs` — harden `detect_perf_230` (+ helpers `is_drawtable_class_helper`, `is_excluded_parse_package`, `is_pool_or_map_accessor`)
- `tests/fixtures/go/perf/PERF-230-{vulnerable,safe}.txt` — vulnerable covers `parseProps` + `EstimateTextWidth` + `GetTextWidth` + `resolveFontName`; safe hoists helpers and includes `time.Parse` / `strconv.ParseInt` / `strconv.Atoi` / `sync.Pool.Get` in-loop negatives
- `handler_limits.rs` PERF-109 left as-is (already fires expensive map-key markers); verified live on registry.go

**Remaining gaps:**
- PERF-230 cap of 6 findings/file can hide later `EstimateTextWidth` sites in the same draw loop once earlier `parse*`/`getFont*` filled the budget — theme still covered.
- PERF-231 does not yet distinguish “parse only on cold cache miss with process-lifetime cache” vs “parse every call with no cache”; gopdfsuit is the former — documented as intentional flag.
- PERF-109 on drawTable is indirect (font registry), not `m[fmt.Sprintf(props)]` inside `drawTable` itself.


### Agent E — OOS + UX + checklist closeout

**Scope:** documentation and visibility only — no OOS detectors, no detector weaken/strengthen beyond docs.

#### Theme #13 — permanent non-goals (OOS)

| Theme | PERF? | Status | Rationale |
|-------|-------|--------|-----------|
| klauspost / third-party flate | — | **OOS** | Dependency & license choice; CodeHound stays stdlib/vendor-neutral. Faster compress libs are not a static anti-pattern. |
| GOMAXPROCS | — | **OOS** | Runtime / cgroup / container CPU policy — not recoverable from AST. |
| GOMEMLIMIT | — | **OOS** | Process-wide GC/memory operator knob; same class as GOMAXPROCS. |
| Product compliance (PDF/A, “signatures required”, workload mix) | — | **OOS** | Product/legal/config policy, not performance smell detection. |
| CWE / BP catalogue work | — | **OOS** | Different surface; this track is PERF-only. |
| Auto-`--fix` for new rules | — | **OOS (later plan)** | Correctness of detection first; autofix is a separate engineering effort. |

**Not OOS (reclassified):** BestSpeed vs Default/BestCompression on a hot encode path → **PERF-233** (static level constants / default `NewWriter`). That is a local code shape, not “always use BestSpeed globally.”

#### Theme #14 — `make run-perf-enhanced` visibility

| Item | Location | Status |
|------|----------|--------|
| Target | `makefile` → `run-perf-enhanced` | **Done** |
| Default `--only` | `PERF_ENHANCED_ONLY` = 018, 027, 032, 054, 109, 192, 215, 217–219, 225–231, 233 | **Done** |
| Format | text, `--no-context --no-chunks`, `--no-fail` | **Done** |
| Docs | [README.md](./README.md), [CHECKLIST.md](./CHECKLIST.md) | **Done** |
| CHANGELOG | Unreleased: PERF-233 + `run-perf-enhanced` | **Done** |

#### How to verify 1:1 mapping with the makefile

```bash
# Default SCAN_PATH is the external high-ops tree (override as needed)
make run-perf-enhanced
make run-perf-enhanced SCAN_PATH=/path/to/your/go/project

# Single theme / rule subset
make run-perf-enhanced PERF_ENHANCED_ONLY=PERF-225,PERF-226
make run-perf-enhanced PERF_ENHANCED_ONLY=PERF-233
```

**Acceptance interpretation for agents A–D:**

1. Run `make run-perf-enhanced` (or with `SCAN_PATH` / `PERF_ENHANCED_ONLY` narrowed).
2. For each owned theme in the mapping table, record either:
   - a real **file:line** finding, or
   - **already fixed / no static smell** with a one-line note.
3. Confirm fixtures still green: `cargo test --test go_perf_detector_integration`.
4. Update the mapping table Goal status + this file’s agent section with evidence.

**Checklist closeout (Agent E + post-verify sync 2026-07-10):**

- [x] Status on checklist/README set to **Shipped / 1:1 complete** (not “in progress”)
- [x] Link to this doc from [CHECKLIST.md](./CHECKLIST.md) and [README.md](./README.md)
- [x] Permanent OOS table with rationale (above + checklist)
- [x] `run-perf-enhanced` present and documented
- [x] CHANGELOG Unreleased mentions PERF-233 + makefile target
- [x] Full 1:1 acceptance boxes — Agents A–D evidence filled; suite green
- [x] Plan docs **02 / 03 / 04** updated only after code verification (detector + registry + fixtures + tests)
