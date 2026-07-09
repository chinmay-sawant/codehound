# Enhanced Patterns — New Rules Batch (PERF-225+)

> **Parent:** `plans/v2.0.0/enhanced-patterns/README.md`
> **Status:** Plan only
> **Estimated effort:** ~5–7 days (core 8 rules) + optional tail
> **Numbering:** Next free block after PERF-224 → **PERF-225…**
> **Domain:** Prefer `general_perf` / stdlib; keep **project-agnostic**

---

## Shipping template (each rule)

Same as prior batches:

1. Rule JSON in `ruleset/golang/chunks/perf-225-….json` (or extend `perf-201-224.json` → rename/split if preferred)
2. `build.rs` / chunk loader picks up new file (already globs chunks)
3. Registry entry in `registry.general_perf.toml` (or new domain file if compress-specific)
4. `detect_perf_N` implementation
5. Fixtures: `tests/fixtures/go/perf/PERF-N-vulnerable.txt` + `-safe.txt`
6. `tests/fixtures/manifest.toml` entries
7. `cargo test --test go_perf_detector_integration` green

**Rule JSON fields** (mirror existing):

```json
{
  "PERF-225": {
    "applicable_to": ["golang"],
    "category": "Performance",
    "description": "...",
    "detection_notes": "...",
    "go_relevance": "High",
    "id": 225,
    "name": "...",
    "original_description": "...",
    "status": "Draft",
    "weakness_abstraction": "Base"
  }
}
```

Promote `status` → `Implemented` when detector + fixtures land.

---

## Core batch (must ship)

### PERF-225 — Redundant Large Slice Clone

| | |
|--|--|
| **Severity** | High |
| **Smell** | Full clone of a large `[]byte` / `[]T` when the source is already exclusively owned or was just cloned |
| **Why** | Double `slices.Clone` / `append(nil, …)` shows up as top alloc in buffer-heavy pipelines |
| **Detect** | In one function: ≥2 of (`slices.Clone(x)`, `append([]T(nil), x...)`, `append([]T{}, x...)`) on the same `x` **or** clone of a local that was assigned from `make`+`copy` and never shared |
| **Suppress** | Clone before passing to API that documents mutation; clone across goroutine publish |
| **Vulnerable** | `a := slices.Clone(buf); b := slices.Clone(a)` (or unsigned then signed double clone) |
| **Safe** | Single clone, or mutate in place with clear ownership |
| **Overlaps** | Tighten PERF-018 (related; 225 is the explicit large-buffer clone rule) |

- [ ] JSON + registry + detector
- [ ] Fixtures + manifest
- [ ] Tests green

---

### PERF-226 — Post-Producer Buffer Re-Copy

| | |
|--|--|
| **Severity** | High |
| **Smell** | Immediately after a producer returns/fills a buffer (`Close` of compress writer, `Bytes()`, `ReadAll`), code does `make`+`copy` / `slices.Clone` into a second slice without mutation of the first |
| **Why** | Classic “own the pool buffer then copy again” waste |
| **Detect** | Window: call to `Close`/`Bytes`/`Flush` on flate/zlib/gzip/buffer **then** within N lines `make([]byte, len(…))` + `copy(...)` of that result |
| **Suppress** | Copy required because source is pooled and returned to pool in same function (look for `pool.Put` of source) — still flag if Put happens **after** unnecessary second copy of a non-pooled local |
| **Vulnerable** | `w.Close(); out := buf.Bytes(); cp := make([]byte, len(out)); copy(cp, out); return cp` without pool Put of `out` |
| **Safe** | Return `out` directly, or copy **only** when Put-ing the producer buffer back |

- [ ] JSON + registry + detector
- [ ] Fixtures + manifest
- [ ] Tests green

---

### PERF-227 — Compress Writer Allocated Without Pool

| | |
|--|--|
| **Severity** | High |
| **Smell** | `flate.NewWriter`, `flate.NewWriterDict`, `zlib.NewWriter`, `zlib.NewWriterLevel`, `gzip.NewWriter`, `gzip.NewWriterLevel` inside loops or hot functions without `sync.Pool` / reset reuse |
| **Why** | Writer construction + `newDeflate*` alloc is a known bulk-encode cost |
| **Detect** | Call facts for those callees under loop/hot gate; suppress if same file has pool storing `*flate.Writer` / reset pattern (`Reset(w)`) |
| **Suppress** | One-shot CLI tools (`package main` + single call in `main` only) — optional
| **Vulnerable** | Loop: `zw, _ := zlib.NewWriterLevel(&buf, level); …; zw.Close()` |
| **Safe** | `pool.Get().(*flate.Writer); w.Reset(&buf); …; pool.Put(w)` |
| **Note** | Do **not** flag compression level choice (BestSpeed vs Default) — OOS |

- [ ] JSON + registry + detector
- [ ] Fixtures + manifest
- [ ] Tests green

---

### PERF-229 — Intermediate String On Byte Append Path

| | |
|--|--|
| **Severity** | Medium |
| **Smell** | Build a `string` (Itoa, Sprintf, Builder.String) then immediately convert/`WriteString` into a `[]byte` / `bytes.Buffer` sink on a hot path |
| **Why** | Extra string alloc when `AppendInt` / `Write` of digits would do |
| **Detect** | Pattern chain in one function: `strconv.Itoa`/`FormatInt`/`fmt.Sprintf` assigned to name `s`, then `append(dst, s...)` or `buf.WriteString(s)` or `[]byte(s)` |
| **Suppress** | String needed for map key / interface API |
| **Vulnerable** | `s := strconv.Itoa(n); buf = append(buf, s...)` |
| **Safe** | `buf = strconv.AppendInt(buf, int64(n), 10)` |
| **Overlaps** | PERF-015 (loop strconv) — 229 is the **append-sink** chain even outside tight loops if hot |

- [ ] JSON + registry + detector
- [ ] Fixtures + manifest
- [ ] Tests green

---

### PERF-230 — Pure Function Re-Evaluated In Loop With Stable Args

| | |
|--|--|
| **Severity** | Medium |
| **Smell** | Loop body calls `f(x)` where `x` is loop-invariant (not the range variable / not indexed by `i`) |
| **Why** | Props parse, width measure, config normalize re-run per cell/item |
| **Detect** | Call inside loop; all args are identifiers defined outside the loop (or literals); callee not a method on the range element |
| **Suppress** | Callee name suggests impure (`Rand`, `Now`, `Read`, `Write`, `Next`) |
| **Vulnerable** | `for _, cell := range cells { w := measure(font, size, label) }` where `label` invariant |
| **Safe** | Hoist `w := measure(...)` before loop, or pass per-cell varying text |
| **Overlaps** | PERF-109 lite — 230 is call-based invariant; 109 may stay map-key focused |

- [ ] JSON + registry + detector
- [ ] Fixtures + manifest
- [ ] Tests green

---

### PERF-231 — PEM Or Key Material Parsed On Hot Path

| | |
|--|--|
| **Severity** | High |
| **Smell** | `pem.Decode`, `x509.ParseCertificate`, `x509.ParsePKCS1PrivateKey`, `x509.ParsePKCS8PrivateKey`, `x509.ParseECPrivateKey`, `tls.X509KeyPair` inside hot functions / loops |
| **Why** | Key **generation** is PERF-025; repeated **parse** of the same PEM is a separate production tax |
| **Detect** | Call facts for those callees under hot gate |
| **Suppress** | Inside `init`, `sync.Once`, package `var` init, or function named `Load*` that is clearly startup |
| **Vulnerable** | `Sign(doc []byte)` body calls `pem.Decode(block)` every time |
| **Safe** | Package-level `var privateKey = mustParse(...)` or `sync.Once` |

- [ ] JSON + registry + detector
- [ ] Fixtures + manifest
- [ ] Tests green

---

### PERF-232 — Crypto Scaffold Rebuilt Per Operation

| | |
|--|--|
| **Severity** | Medium |
| **Smell** | Hot path repeatedly constructs signing scaffolding: `rsa.PrivateKey` PEM path already covered by 231; also `x509.CreateCertificate` is rare — focus on **re-marshaling cert DER / rebuilding signer wrapper types** each call |
| **Detect (v1 heuristic)** | Hot function contains **both** PEM/x509 parse (or `tls.LoadX509KeyPair`) **and** PKCS-related marshal/`crypto` signer setup in the same body without package-level cache variables |
| **Simpler v1:** Flag hot functions that call `pem.Decode` **and** `x509.Parse*` in the same function (subset of 231 multi-call) — **merge with 231 if too overlapping** |
| **Decision gate:** If 231+tighten covers 90%, **fold 232 into 231** and free the ID for something else |

- [ ] Decide merge vs separate during implement
- [ ] If separate: fixtures for “new signer struct every request”
- [ ] Tests green

---

### PERF-228 — Parallel Fan-Out For Tiny Workset (low priority)

| | |
|--|--|
| **Severity** | Low |
| **Smell** | `errgroup` / `WaitGroup` + one goroutine per item over a slice with **literal** length ≤ 2 or `for range` of a composite literal with ≤2 elems |
| **Why** | Spawn cost dominates 1-page / 2-chunk work |
| **Detect** | Hard; start with: `g.Go` inside `for range pages` where `pages` is built as `[]T{a}` single-element composite in same function |
| **Risk** | Noise — ship last or drop |
| **Vulnerable** | Construct `items := []Page{p}`; `for _, it := range items { g.Go(...) }` |
| **Safe** | Direct serial call for single item |

- [ ] Spike feasibility 0.5d
- [ ] Ship only if precision ≥ safe fixture silence on clean trees
- [ ] Or mark deferred

---

## Optional / fold-into-tighten (do not allocate IDs until needed)

| Working name | Prefer |
|--------------|--------|
| Grow when bound known on raw `[]byte` | Fold into **PERF-215** or PERF-037/045 |
| Map resize in hot loop | Fold into **PERF-192** |
| Pool New always allocates | PERF-110 already; tighten if needed |

---

## Chunk file plan

**Preferred:**

```
ruleset/golang/chunks/perf-225-236.json   # or perf-225-232.json for core only
```

- [ ] Add chunk file
- [ ] Confirm `build.rs` glob loads it (no code change if already `chunks/*.json`)
- [ ] Update any audit that assumes max PERF id == 224 (`go_perf_ruleset_audit`, registry generation)

Search for hard-coded `224` / `PERF-224` ceilings:

- [ ] `build/gen_perf.rs` / registry generators
- [ ] `tests/go_perf_registry_generation.rs`
- [ ] `tests/go_perf_ruleset_audit.rs`
- [ ] docs that say “224 rules”

---

## Detector placement (suggested)

| IDs | Module path |
|-----|-------------|
| 225, 226 | `general_perf/stdlib_misuse/maps_and_slices.rs` or new `copies_and_ownership.rs` |
| 227 | new `general_perf/stdlib_misuse/compress_writers.rs` |
| 229 | `string_bytes.rs` or `allocations_and_reuse/fmt_and_append.rs` |
| 230 | `loops_and_iteration/` or `caching_and_allocation.rs` |
| 231, 232 | `request_path/crypto_and_keys.rs` (expand beyond GenerateKey) |
| 228 | `concurrency.rs` |

---

## Description example language (allowed)

Descriptions **may** illustrate with domain-neutral or domain-example prose, e.g.:

> “…common when assembling large binary outputs (archives, documents, media containers) where an intermediate buffer is cloned before and after a mutation step…”

Do **not** put private type names or product paths in `detection_notes`.

---

## Validation matrix

| Rule | Vulnerable must fire | Safe must not | Notes |
|------|----------------------|---------------|-------|
| 225 | double Clone | single Clone / needed Clone | |
| 226 | make+copy after Bytes | return Bytes / copy+Put source | |
| 227 | NewWriter in loop | pooled Reset | |
| 229 | Itoa then append string | AppendInt | |
| 230 | invariant call in loop | hoisted call | |
| 231 | pem.Decode in Sign() | Once / package var | |
| 228 | only if shipped | | |

```bash
cargo test --test go_perf_detector_integration
cargo test --test go_perf_ruleset_audit
cargo test --test fixture_manifest_integration_inventory
cargo test --test go_perf_registry_generation
```

---

## Core batch exit criteria

- [ ] PERF-225, 226, 227, 229, 230, 231 shipped (232 merged or shipped)
- [ ] 228 decided (ship / defer)
- [ ] Max PERF id updated in audits
- [ ] README definition-of-done scan criterion met (non-web library path finds clone/grow/pool/static smells via **tighten + new** together)
