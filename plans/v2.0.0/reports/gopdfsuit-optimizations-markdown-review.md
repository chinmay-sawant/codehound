# V2.0.0 — gopdfsuit Optimization Dedupe Checklist

> **Parent:** `plans/v2.0.0/reports/` — external optimization-doc synthesis
> **Status:** Markdown set reviewed in detail and de-duped into implemented, in-progress, and reverted optimization tracks
> **Estimated effort:** 1-2 review passes to keep this synced with new optimization docs

---

## Overview

This file is a de-duplicated checklist of the performance work documented under:

`/home/chinmay/ChinmayPersonalProjects/gopdfsuit/guides/optimizations`

It is based on the markdown reports, checklists, PR summaries, and executive summaries in that folder. It is not a code scan of SlopGuard itself.

The goal is to collapse repeated optimization themes across those docs into one checklist-oriented ledger:

- what was actually implemented
- what was kept as a guardrail
- what is still pending
- what was tried and intentionally reverted

---

## Executive Summary

- [x] The optimization work is real and broad, not one-off tuning. It spans PDF engine internals, tagged-PDF structure writing, HFT row rendering, signing, compression, JSON ingress, Python bindings, benchmark harnesses, validation, and CI.
- [x] The strongest repeated pattern is: reduce allocation churn, replace repeated formatting/building work with direct writes, and keep hot-path reuse local and bounded.
- [x] The docs repeatedly converge on the same winning families:
  - [x] buffer pre-sizing
  - [x] pool/reuse instead of rebuild
  - [x] direct writer paths instead of temporary strings/slices
  - [x] bounded caches instead of unbounded convenience caches
  - [x] profile-guided HFT fast paths
  - [x] compliance-preserving optimizations only
- [x] The docs also repeatedly converge on the same rejected families:
  - [x] unbounded key-based caches
  - [x] benchmark-only shortcuts that hide real work
  - [x] aggressive memory-retention strategies that inflate heap
  - [x] parallel structure-tree work that regresses end-to-end throughput
  - [x] compliance shortcuts on HFT tagged-PDF output

---

## Phase 1: Dedupe of Implemented Performance Improvements

### 1.1 PERF: Final PDF buffers, page buffers, and general pre-sizing

- [x] PERF: Increased pooled final PDF buffer capacity to reduce `bytes.growSlice` pressure during final assembly.
- [x] PERF: Removed extra scratch-slice hops at final PDF assembly so the hot path does less copy work.
- [x] PERF: Switched from `append([]byte(nil), ...)` style copying to more explicit cloning where needed.
- [x] PERF: Pre-sized page content streams using template complexity / workload shape instead of letting them grow blindly.
- [x] PERF: Added PDF buffer pooling and later split pool buckets by capacity class so large HFT buffers do not poison smaller workloads.
- [x] PERF: Introduced HFT-aware output-size estimation so buffer sizing reflects compliant HFT output rather than the old compact/non-compliant shape.
- [x] PERF: Added structure-capacity estimation (`ReserveElementCapacity` / related prealloc work) so tagged-PDF paths start closer to the needed size.

### 1.2 PERF: Compression pipeline and flate reuse

- [x] PERF: Streamed page content directly into zlib/flate instead of building extra intermediate byte slices first.
- [x] PERF: Pooled `compress/flate.Writer` instances per worker to remove repeated writer construction costs.
- [x] PERF: Sharded the page compression cache to reduce contention and improve cache locality.
- [x] PERF: Kept compression fingerprint thresholds and store/uncompressed heuristics where they helped measured throughput.
- [x] PERF: Reworked compression-cache shard bookkeeping to use cheaper hashing and correct count behavior.
- [x] PERF: Preserved compression optimizations only where they held up in end-to-end measurements, not just micro-profiles.

### 1.3 PERF: Tagged-PDF structure-tree serialization and object writing

- [x] PERF: Replaced repeated `fmt.Sprintf` / `strconv.Itoa` style integer formatting in hot writer paths with append-based numeric writes.
- [x] PERF: Used stack scratch buffers plus direct `Write` calls for structure/object emission instead of allocating temporary strings.
- [x] PERF: Replaced page-index maps in `StructureManager` with slices where the index domain was predictable.
- [x] PERF: Added `BeginStructureElementCap` / child-count-aware capacity hints for table and row structure nodes.
- [x] PERF: Moved annotation object IDs onto Link structure elements to avoid reverse scans later.
- [x] PERF: Reworked structure-tree walks from recursive patterns toward iterative loops where that reduced call and allocation pressure.
- [x] PERF: Converted xref offset tracking from a map to a pre-sized slice with sentinel slots.
- [x] PERF: Added fast decimal/object-ref emit paths so hot tagged-PDF writers avoid repeated helper overhead.
- [x] PERF: Reduced escaped text allocation by appending escaped PDF literals into reusable scratch buffers rather than creating fresh strings.

### 1.4 PERF: Struct-element pooling, arena work, and HFT TD/TR path

- [x] PERF: Added struct-element pooling to reduce repeated allocation on tagged-PDF generation paths.
- [x] PERF: Reduced pool reset cost by moving to more selective reset behavior instead of full-object clearing on every reuse.
- [x] PERF: Kept `StructKid` slice pooling for repeated TR/TD children work.
- [x] PERF: Added lazy arena activation so heavier arena machinery is only paid when a PDF actually needs it.
- [x] PERF: Added batch TD allocation / row-arena style work to reduce per-cell/per-row allocation overhead on HFT-heavy tables.
- [x] PERF: Added `tdLeafFast` / related fast paths for HFT-compliant TD emission.
- [x] PERF: Added preallocation of page MCID slots for shared-layout HFT paths.
- [x] PERF: Preserved the compliant `TR -> TD` hierarchy rather than taking a smaller but invalid shortcut.

### 1.5 PERF: Shared-row / HFT row rendering

- [x] PERF: Built and kept the shared-layout row rendering fast path because HFT rows are disproportionately expensive despite being a small workload share.
- [x] PERF: Precomputed row fragments / text prefixes / row text commands for shared-layout rows so repeated HFT row emission does less repeated work.
- [x] PERF: Added `charsPreScanned`-style logic to avoid duplicate font-char scans on repeated shared rows.
- [x] PERF: Reused per-request shared-row assets and buffer fragments without broadening them into unsafe process-lifetime caches.
- [x] PERF: Retained the bounded shared-row cache only in the form that survived k6 validation.

### 1.6 PERF: Bounded caches and memory stability

- [x] PERF: Bounded `subsetCache` instead of leaving font-subset caching unbounded.
- [x] PERF: Bounded `imgCache` instead of allowing decoded-image retention to grow without limit.
- [x] PERF: Bounded `propsCache` instead of keeping parsed props forever.
- [x] PERF: Recovered the shared-row cache after the k6 regression by replacing the unbounded global `sync.Map` behavior with explicit entry/byte caps plus eviction/clear behavior.
- [x] PERF: Copied cached row byte slices on store so pooled buffers could not alias cached state.
- [x] PERF: Used k6 completion and heap shape as release gates, not just in-process throughput.

### 1.7 PERF: Font, ICC, metadata, and PDF/A-related reuse

- [x] PERF: Cached gray and sRGB ICC profile compressed bytes at init time instead of rebuilding/compressing them on every PDF.
- [x] PERF: Changed output-intent generation to reuse cached ICC payloads.
- [x] PERF: Precomputed startup font hints on Zerodha templates.
- [x] PERF: Added static XMP metadata shell logic with only emit-time date/ID patching.
- [x] PERF: Pre-grew XMP builders and metadata-related buffers earlier in the program before the later static-shell cleanup.
- [x] PERF: Kept PDF/A and PDF/UA work in the optimized path; metadata optimizations were done by reuse, not by disabling compliance.

### 1.8 PERF: Signing path cleanup

- [x] PERF: Moved the main signing path to ECDSA P-256 instead of the heavier RSA default.
- [x] PERF: Added PEM / signer caching in the benchmark path to remove repeated setup overhead.
- [x] PERF: Added PKCS#7 marshal buffer pooling.
- [x] PERF: Added direct byte-range marker and hex-encoding helpers instead of more allocation-heavy generic paths.
- [x] PERF: Continued to treat signing as a real production cost in the benchmark, especially because retail is the bulk of the workload.

### 1.9 PERF: `drawTable`, fonts, and repeated content work

- [x] PERF: Added per-cell / per-table font reference caching.
- [x] PERF: Reduced repeated font subset / standard-font work on hot table paths.
- [x] PERF: Added precomputed text-width and repeated-text helpers around `drawTable`.
- [x] PERF: Added uniform-border fast paths so common border shapes emit cheaper drawing commands.
- [x] PERF: Added image dedup / XObject reuse for repeated PNG cell content.
- [x] PERF: Reduced repeated work for HFT `drawTable` stripes and row replays.

### 1.10 PERF: HTTP / Gin JSON ingress and request-path work

- [x] PERF: Switched Gin request decode toward Sonic-based JSON ingress.
- [x] PERF: Added decode pretouch / preallocation / tier-aware decode work.
- [x] PERF: Added HFT split-decode fast paths because HFT payload shape is materially different from retail/active.
- [x] PERF: Added borrowed-buffer response generation (`GenerateTemplatePDFBorrowed` family) to reduce extra copies on the request path.
- [x] PERF: Added fast API / benchmark modes and concurrency alignment around the HTTP path so the request path matched the intended saturation profile.

### 1.11 PERF: Python binding / PyPDFSuit optimizations

- [x] PERF: Root-caused Python overhead to `to_dict()` tree walking plus JSON/FFI boundary cost, rather than blaming the renderer first.
- [x] PERF: Precomputed dataclass field-to-JSON-key mappings so per-field key lookup stopped repeating for every PDF.
- [x] PERF: Added more specialized serializers for the dominant Python objects (`PDFTemplate`, `Table`, `Row`, `Cell`, `Config`).
- [x] PERF: Switched to compact UTF-8 JSON output so HFT payload bytes shrink without changing schema.
- [x] PERF: Removed automatic JSON payload caching from the published benchmark path because it made the benchmark look better without reflecting true full execution.
- [x] PERF: Added benchmark scenario controls and better percentile reporting so weighted, retail-only, active-only, and HFT-only cases are measured explicitly.
- [x] PERF: Reframed the Python benchmark around honest end-to-end throughput rather than cache-only throughput.

### 1.12 PERF: SlopGuard-guided source cleanups that landed

- [x] PERF: Hoisted repeated regex compilation out of hot loops.
- [x] PERF: Replaced many `fmt.Sprintf` / `fmt.Errorf` / `strconv.Itoa` sites with cheaper append/build/static-error paths.
- [x] PERF: Removed repeated `defer` use in hot functions where explicit cleanup was cheaper.
- [x] PERF: Reduced repeated `string` / `[]byte` conversion churn.
- [x] PERF: Added map pre-sizing and `clear()`-based reuse for repeatedly rebuilt maps.
- [x] PERF: Added cheaper guards before `TrimSpace`, `bytes.Equal`, and similar work where a prefix/length check was enough.
- [x] PERF: Switched hot logging/recovery paths toward less blocking or less wasteful behavior.

### 1.13 PERF: Benchmark harness and measurement hygiene

- [x] PERF: Standardized weighted Zerodha measurement around the 80/15/5 mix.
- [x] PERF: Standardized x10 / pprof entrypoints for repeatable measurement.
- [x] PERF: Added seed/concurrency controls (`BENCH_SEED`, worker alignment, `GOMAXPROCS`) so runs are comparable.
- [x] PERF: Distinguished honest full-path numbers from cache/control numbers in the Python benchmark work.
- [x] PERF: Added k6 light/full guardrails so heap shape and service stability are checked before trusting throughput.
- [x] PERF: Used veraPDF / PDF correctness gates after optimization phases so invalid output was not counted as a win.

---

## Phase 2: Dedupe of Guardrails That Shaped the Work

### 2.1 Non-negotiable constraints repeated across the docs

- [x] PERF guardrail: no compliance shortcuts on HFT tagged output.
- [x] PERF guardrail: no new unbounded key-based cross-request caches.
- [x] PERF guardrail: benchmark numbers must represent real work, not bypassed work.
- [x] PERF guardrail: k6 stability and heap behavior matter as much as raw in-process throughput.
- [x] PERF guardrail: output-size and veraPDF acceptance must hold after optimization passes.
- [x] PERF guardrail: optimization wins should be proven under the actual weighted workload, not only on easy retail cases.

---

> **Note:** This checklist documents the **gopdfsuit** project's optimization status (not slopguard). Items below cannot be validated against the slopguard codebase; they remain as documented by the original analysis.

## Phase 3: Dedupe of Work Still Open / Repeatedly Deferred

### 3.1 Still-open engine and HFT items

- [~] PERF: Further reduce `bytes.growSlice` and peak heap on compliant x10 runs. `(deferred → see plans/v3.0.0/)`
- [~] PERF: Continue Phase B / C Zerodha 15K work around pdfBuffer zero-grow, page-stream caps, arena sizing, row-stream direct append, and deeper HFT TD/TR batching. `(deferred → see plans/v3.0.0/)`
- [~] PERF: Keep reducing `drawTable` / shared-layout row replay cost on HFT-heavy paths. `(deferred → see plans/v3.0.0/)`
- [~] PERF: Continue retail signature-path cleanup beyond the buffer-pooling work already landed. `(deferred → see plans/v3.0.0/)`
- [~] PERF: Continue xref / slice / glyph-dedupe / batch-emit work where the 15K checklist still shows open gates. `(deferred → see plans/v3.0.0/)`

### 3.2 Still-open HTTP / Gin items

- [~] PERF: Weighted Gin 1,500 req/s is still open; HFT tail, flate cost, and JSON ingress remain the main ceiling. `(deferred → see plans/v3.0.0/)`
- [~] PERF: Optional codegen / alternate Sonic decode improvements remain documented as possible next steps. `(deferred → see plans/v3.0.0/)`

### 3.3 Still-open Python / API-contract items

- [~] PERF: Large further gains for PyPDFSuit require Go-boundary or API-contract changes, not just more Python serializer cleanup. `(deferred → see plans/v3.0.0/)`
- [~] PERF: Handle/batch/service-mode style APIs are still the main path if Python needs a much higher ceiling than the current honest no-cache band. `(deferred → see plans/v3.0.0/)`
- [~] PERF: HFT-specific Go-side profile harnessing remains relevant if Python-to-Go boundary work becomes allowed. `(deferred → see plans/v3.0.0/)`

---

## Phase 4: Dedupe of Reverted / Rejected Optimizations

### 4.1 Reverted because they hurt end-to-end performance or stability

- [~] PERF revert: parallel structure-tree build (`G3`) regressed end-to-end throughput and was removed. `(deferred → see plans/v3.0.0/)`
- [~] PERF revert: template PDF cache (`G4`) was removed because it made the benchmark misleading and did not represent unique-PDF production work. `(deferred → see plans/v3.0.0/)`
- [~] PERF revert: aggressive Gin Phase 12 experiments such as CRC32 fingerprinting, in-place signature hex work, and store-uncompressed page experiments did not give enough real throughput gain. `(deferred → see plans/v3.0.0/)`
- [~] PERF revert: generic structure-writer abstraction regressed performance versus the concrete hot path. `(deferred → see plans/v3.0.0/)`
- [~] PERF revert: aggressive buffer-retention / large-cap pool experiments increased heap and were not kept. `(deferred → see plans/v3.0.0/)`
- [~] PERF revert: specific compress-cache/store ordering experiments were not stable wins and were not kept. `(deferred → see plans/v3.0.0/)`

### 4.2 Reverted because they violated the intended benchmark semantics or memory budget

- [~] PERF reject: HFT TR->TD collapse produced faster numbers but invalid compliant output, so it was rejected. `(deferred → see plans/v3.0.0/)`
- [~] PERF reject: expanding key-based shared-row caches beyond the bounded safe version was rejected because it caused k6/OOM failure modes. `(deferred → see plans/v3.0.0/)`
- [~] PERF revert: large per-SM struct-element arena slabs created unacceptable live-heap pressure across 48 workers. `(deferred → see plans/v3.0.0/)`
- [~] PERF reject: Python JSON-cache benchmark numbers were removed from the main benchmark surface because they bypassed real per-call serialization. `(deferred → see plans/v3.0.0/)`

---

## Phase 5: Highest-Value Dedupe Summary

### 5.1 Core repeated win pattern

- [x] PERF: Pre-size first.
- [x] PERF: Reuse locally with pools/scratch buffers next.
- [x] PERF: Replace string-building / temporary-object work with direct append/write paths.
- [x] PERF: Keep caches bounded and measurable.
- [x] PERF: Validate with the real weighted benchmark and correctness gates.

### 5.2 Dedupe conclusion

- [x] PERF: The optimization program is mostly a disciplined removal of repeated allocation, repeated formatting, repeated decoding, repeated compression setup, and repeated structure-tree work.
- [x] PERF: The best shipped improvements are the ones that preserve correctness while reducing work per PDF, not the ones that skip work entirely.
- [x] PERF: The docs strongly support one engineering rule: cheap local reuse and precise pre-sizing win; broad lifetime caches and speculative complexity tend to backfire.

---

## Dependencies

- Source folder reviewed: `/home/chinmay/ChinmayPersonalProjects/gopdfsuit/guides/optimizations`
- Output file: `plans/v2.0.0/reports/gopdfsuit-optimizations-markdown-review.md`
- Basis for synthesis: PR summaries, checklists, phase reports, executive summaries, regression analysis, and Python-binding optimization reports
