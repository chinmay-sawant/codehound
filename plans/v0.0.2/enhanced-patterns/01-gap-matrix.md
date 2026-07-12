# Enhanced Patterns — Gap Matrix

> **Parent:** `plans/v0.0.2/enhanced-patterns/README.md`
> **Status:** Plan only
> **Purpose:** Map real hot-path optimization themes to CodeHound PERF coverage. Themes come from profiler-driven work (copies, growth, flate, structure serialization, crypto setup, caching) — **not** product-specific APIs.

Legend:

| Tag | Meaning |
|-----|---------|
| **Covered** | Existing rule can fire on realistic code (or close enough) |
| **Tighten** | Rule exists but detector is fixture-shaped, wrong gate, or too narrow |
| **New** | No rule; propose PERF-225+ |
| **OOS** | Out of scope for static PERF (runtime policy / product compliance) |

---

## 1. Copy & ownership

| Theme (generic) | Example shape | Existing | Verdict | Notes |
|-----------------|---------------|----------|---------|-------|
| Redundant full-buffer clone after ownership already held | `b2 := slices.Clone(b1)` then `b3 := slices.Clone(signed)` | PERF-018 (reslice/append copy — **fixture-only**) | **New** + **Tighten 018** | Need generic `slices.Clone` / `append([]T(nil), …)` of large buffers; 018 rewrite |
| Own-then-copy after producer already returns owned `[]byte` | `cp := make([]byte, n); copy(cp, out)` right after compress/`Bytes()` | PERF-049, PERF-114 | **New** | Neither models “second copy of just-produced buffer” |
| Unnecessary string↔[]byte on write path | `string(buf)` then re-escape / re-append | PERF-032 | **Tighten** | Often loop/request-path only; also fire on tight encode helpers |
| Manual element loop instead of `copy` | for-i assign | PERF-114 | **Tighten** | Draft status; ensure registry + real detection |

---

## 2. Growth & capacity

| Theme | Example shape | Existing | Verdict | Notes |
|-------|---------------|----------|---------|-------|
| `bytes.Buffer` / `strings.Builder` without `Grow` when size estimable | `var b bytes.Buffer; b.Write(…)` with `len(x)` available | PERF-215 | **Tighten** | Today: almost only `WriteString(payload)` + `len(payload)` literals |
| `append` / slice growth without capacity in accumulation loops | `for { out = append(out, …) }` | PERF-037, PERF-045, PERF-003 | **Covered** (partial) | Keep; ensure non-HTTP functions count |
| `make(map)` without size hint when N known | `make(map[K]V)` + known `len(items)` / object count | PERF-192, PERF-004 | **Tighten 192** | Draft; hoist-friendly size-hint detection |
| Pre-size main assembly buffer | `Grow(estimated)` missing on primary builder | PERF-215 | **Tighten** | Same detector; expand beyond toy names |

---

## 3. Compression / encoding writers

| Theme | Example shape | Existing | Verdict | Notes |
|-------|---------------|----------|---------|-------|
| `flate.NewWriter` / `zlib.NewWriter` / `gzip.NewWriter` per call without pool | New writer every page/chunk | PERF-027 (only `bytes.Buffer{}`) | **New** | Module: `compress/*` |
| Writer level left at default on hot encode (informational) | `flate.DefaultCompression` on bulk path | — | **OOS / optional later** | Policy + size tradeoff; don’t hard-fail |
| Drop-in faster flate library | klauspost vs stdlib | — | **OOS** | Dependency choice |
| Parallel compress/errgroup for N≤1..2 units | `errgroup` over single page | PERF-029 (unbounded spawn) | **New (low prio)** | Narrow heuristic: errgroup over range with known small bound |

---

## 4. Pooling & reuse

| Theme | Example shape | Existing | Verdict | Notes |
|-------|---------------|----------|---------|-------|
| Missed pool for short-lived buffers | `bytes.Buffer{}` on hot path | PERF-027 | **Tighten** | Expand to hot non-HTTP; optional large `make([]byte, n)` when n large/literal |
| Pool without cap guard on Put | oversized retain | PERF-219 | **Tighten** | Less fixture-hardcoded (`func Recycle`) |
| Pool backing discarded | `s=nil` then Put | PERF-223 | **Covered** (partial) | Keep + broaden |
| Single pool under high fan-out | global `sync.Pool` + many goroutines | PERF-218 | **Tighten** | Avoid requiring handler file shape only |
| Per-element `strings.Builder` instead of Reset | new Builder each item | PERF-054, PERF-016 | **Tighten** | Fire outside Gin-only paths |

---

## 5. Static recompute & caches

| Theme | Example shape | Existing | Verdict | Notes |
|-------|---------------|----------|---------|-------|
| Deterministic pure function rebuilt every op | zero-arg expensive builder in hot function | PERF-217 | **Tighten** | **Drop HTTP-only gate**; keep examples (ICC/font/metadata) in prose |
| Process-level unbounded cache | package map as cache, no eviction | PERF-213, PERF-106 | **Covered** | Already shipped |
| Cache key volatility | pointer / request-id keys | PERF-214 | **Covered** | Already shipped |
| Compress-once for stable blob (template/static) | zlib of constant bytes in hot path | PERF-217 | **Tighten / New sub-case** | Same detector family |
| Parse/config props re-parsed per cell | pure parse of same string in loop | PERF-109 | **Tighten** | Expression-equivalence lite: same callee + same arg name in loop |

---

## 6. Numeric / text emit on hot paths

| Theme | Example shape | Existing | Verdict | Notes |
|-------|---------------|----------|---------|-------|
| `strconv.Itoa` / `fmt.Sprintf("%d")` in loops | per-cell numbers | PERF-015, PERF-006 | **Covered** | Already strong |
| Prefer append-into-scratch over intermediate string | `AppendInt` vs Itoa→string | PERF-015, PERF-178 | **Tighten 015 / New** | Optional PERF: “format to string then append” chain |
| `time.Format` vs `AppendFormat` | timestamps | PERF-178 | **Tighten** | Ensure implemented for Draft |

---

## 7. Crypto / material setup (not RSA mul itself)

| Theme | Example shape | Existing | Verdict | Notes |
|-------|---------------|----------|---------|-------|
| RSA/ECDSA **key generation** per request | `rsa.GenerateKey` | PERF-025 | **Covered** | Keep |
| PEM / x509 parse of **same** material per op | `pem.Decode` + `ParsePKCS1PrivateKey` in hot fn | — | **New** | Setup reuse, not crypto math |
| Signer / cert-chain scaffolding rebuilt per op | new signer struct + re-marshal DER every call | — | **New** | Heuristic: parse/marshal certs inside hot function without package-level cache |
| Key size policy (2048 vs 4096) | constants | — | **OOS** | Product/security policy |
| “Must keep signatures enabled” | config | — | **OOS** | Product policy |

---

## 8. Concurrency / GC / system

| Theme | Existing | Verdict |
|-------|----------|---------|
| Unbounded goroutine spawn | PERF-029 | **Covered** |
| Manual `runtime.GC` | PERF-052 | **Covered** |
| GOMAXPROCS sweet spot | — | **OOS** |
| GOMEMLIMIT experiment | — | **OOS** |
| Workload mix / large-doc tails | — | **OOS** |

---

## 9. Explicit mapping from prior conversation themes

| Prior plan id (external) | Generic smell | CodeHound action |
|--------------------------|---------------|------------------|
| P0.1 double Clone | redundant large-slice clone | **New PERF-225** |
| P0.2 compress make+copy | post-producer own-then-copy | **New PERF-226** |
| P0.3–P0.4 pre-grow buffers/maps | missing Grow / map hint | **Tighten 215, 192, 037/045** |
| P0.5 ICC / static bytes cache | static recompute | **Tighten 217** |
| P1.1 BestSpeed | compression level policy | **OOS** |
| P1.2 zlib writer pool | compress writer without pool | **New PERF-227** |
| P1.3 klauspost | dependency choice | **OOS** |
| P1.4 compress unique subset once | static/keyed recompute | **Tighten 217** + cache rules |
| P1.5 skip parallel for small N | small-bound errgroup | **New PERF-228 (low)** |
| P2.1–P2.3 struct serialize | Builder growth / map hint | **Tighten 215, 054, 192** |
| P2.4 pool miss cost | pool quality | **Tighten 027, 218, 219** |
| P2.5 intermediate strings | string/byte churn | **Tighten 032** + **New PERF-229** |
| P3.* table micro-opts | parse cache, strconv, width cache | **Tighten 015/006/109**; optional **New PERF-230** pure-call-in-loop cache miss |
| P4.1–P4.3 signer reuse / copies | PEM parse; rebuild; clones | **New PERF-231, 232** + clone rules |
| P4.4–P4.5 key size / policy | — | **OOS** |
| P5 font subset cache | cache + static | **Covered 213/217** after tighten |
| P6.* GOMAXPROCS/GC/mix | — | **OOS** (except alloc rules generally) |

---

## 10. Proposed ID block (preview)

| ID | Name (working) | Primary theme |
|----|----------------|---------------|
| PERF-225 | Redundant Large Slice Clone | copies |
| PERF-226 | Post-Producer Buffer Re-Copy | copies |
| PERF-227 | Compress Writer Allocated Without Pool | compress |
| PERF-228 | Parallel Fan-Out For Tiny Workset | concurrency (low prio) |
| PERF-229 | Intermediate String On Byte Append Path | strings/bytes |
| PERF-230 | Pure Function Re-Evaluated In Loop With Stable Args | cache/loop |
| PERF-231 | PEM Or Key Material Parsed On Hot Path | crypto setup |
| PERF-232 | Signer Or Cert Scaffold Rebuilt Per Operation | crypto setup |
| PERF-233 | bytes.Grow / make Capacity Ignored When Bound Known | growth (if not folded into 215) |
| PERF-234 | Append Chain Via Temporary String | strings (related 229) |
| PERF-235 | Sync.Pool New Allocates On Every Get Miss Path Smell | pool (optional) |
| PERF-236 | Map Resized In Hot Loop Via Missing Hint | maps (if not folded into 192) |

IDs **233–236** are **optional** — prefer folding into tighten work if detection is identical to existing rules. Final numbering locked in `03-new-rules-batch-225.md` after dedup.

---

## 11. Non-goals (reminders)

- No PDF, PDF/A, PDF/UA, signature-validity, or product compliance detectors.
- No “you should use library X” product recommendations.
- No rules that only fire on a single private repo’s type names (`drawTable`, `StructureManager`, …).
- Descriptions **may** keep domain examples (ICC, font objects, page buffers) as prose illustrations.
