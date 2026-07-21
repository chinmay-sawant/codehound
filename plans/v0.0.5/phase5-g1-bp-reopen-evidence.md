# Phase 5 G1 — BP expansion reopen evidence (BP-71 focus)

> **Issue:** [#137](https://github.com/chinmay-sawant/codehound/issues/137) · Relates to epic [#136](https://github.com/chinmay-sawant/codehound/issues/136)  
> **Gate:** [`phase5-gated-work.md`](./phase5-gated-work.md) G1 · disposition [`bp-candidates-disposition.md`](./bp-candidates-disposition.md)  
> **Prior canary:** [`bp-71-canary.md`](./bp-71-canary.md) (#46, wontfix)  
> **Corpus pins:** [`canary-corpus.md`](./canary-corpus.md) · [`canary-corpus-pins.json`](./canary-corpus-pins.json)  
> **Branch:** `chore/phase5-g1-bp-expansion`  
> **Date:** 2026-07-22  
> **CodeHound base:** `9e61e807358a1b9a4f5a03cf3b2abecbe30281a2` (`origin/master`)  
> **Outcome:** **Keep deferred** — no BP detector shipped  
> **Checklist plan:** this file (execution checklist below)

---

## Execution checklist

### Completed (2026-07-22)

- [x] Read G1 reopen criteria in `phase5-gated-work.md`
- [x] Re-read absent BP disposition (`bp-candidates-disposition.md`)
- [x] Identify only **BP-71** as `defer-needs-canary`
- [x] Static-sample five-module corpus (gopdfsuit, monsoon, go-retry, gorl, no-mistakes)
- [x] Classify hits as idiomatic vs actionable correctness bugs
- [x] Decision: **keep deferred** (0 actionable)
- [x] Evidence + PR body under `plans/v0.0.5/`
- [x] Explicit non-action: no bulk BP rules / no pure-fixture detectors
- [x] Cross-link backlog #137 / epic #136

### Remaining to reopen implementation

- [ ] Find non-Write/non-Copy multi-return discard class with real-module signal
- [ ] Overlap analysis vs live BP/CWE/tools
- [ ] Vulnerable + safe fixtures with near-miss negatives
- [ ] Release canary with agreed FP budget
- [ ] New scoped implementable issue (or re-open work under #137 with evidence comment)

---

## Purpose

G1 reopens broad BP-66+ expansion only when a **concrete high-signal pattern** is observed on pinned real modules, with fixtures, overlap analysis, and canary FP budget ([`phase5-gated-work.md`](./phase5-gated-work.md) G1).

This record:

1. Re-reads disposition of **absent** BP candidates (focus: **BP-71**, the only `defer-needs-canary` row).
2. Re-runs **static sampling** on the full decision-quality corpus (gopdfsuit + monsoon + go-retry + gorl + **no-mistakes**).
3. Freezes whether any candidate is ready to implement.

**Explicit non-action:** do **not** bulk-add BP rules or invent detectors from pure fixtures.

---

## Disposition re-read (absent candidates)

Source: [`bp-candidates-disposition.md`](./bp-candidates-disposition.md) (29 absent IDs).

| Disposition | Count | Ready for G1 ship? |
|-------------|------:|--------------------|
| retire-duplicate | 9 | No — owned by CWE/PERF/BP-13/noctx |
| **defer-needs-canary** | **1 (BP-71)** | **Only if this canary shows actionable correctness hits** |
| defer-needs-proof-boundary | 6 | No — needs type/alias/multi-file proof (G4-adjacent) |
| defer-policy | 13 | No — architecture/deploy/auth convention |

### BP-71 proposed shape (reminder)

Flag **discarding the primary multi-return** while keeping/checking the error on a frozen callee allowlist:

- `io.Copy` / `io.CopyN` (`n, err`)
- `fmt.Fscan*` / `fmt.Sscanf` / `fmt.Scanf` (count, err)
- `Write` / `WriteString` byte counts (`n, err`)

Distinct from **BP-1** (discards *error*). Goal: catch cases where ignoring `n`/count hurts correctness.

### Other candidates (not promoted)

No proof-boundary or policy row was reclassified. None showed a new **bounded static shape** with reviewed actionable real-module bugs under tree-sitter-only facts. Prior design notes: [`bp-proof-boundary-notes.md`](./bp-proof-boundary-notes.md).

---

## Canary method

BP-71 is **not implemented** — there is no `--only BP-71` release-binary path. Evidence is **read-only static sampling** (ripgrep) on non-test `.go` files, excluding `vendor/`.

### Commands (reproducible)

```sh
export PATH="/usr/bin:/bin:/usr/local/bin:$PATH"
RG=/usr/bin/rg
CORPUS_ROOT="${CODEHOUND_CORPUS_ROOT:-/home/chinmay/ChinmayPersonalProjects/codehound}/real-repos"
GOPDF="${CODEHOUND_GOPDFSUIT:-/home/chinmay/ChinmayPersonalProjects/gopdfsuit}"

# Per target T ∈ {gopdfsuit, monsoon, go-retry, gorl, no-mistakes}:
# io.Copy primary discard
"$RG" -n --glob '*.go' --glob '!**/vendor/**' --glob '!**/*_test.go' \
  '_\s*,\s*\w+\s*:?=\s*io\.Copy' "$T"

# Write / WriteString primary discard
"$RG" -n --glob '*.go' --glob '!**/vendor/**' --glob '!**/*_test.go' \
  '_\s*,\s*\w+\s*:?=\s*\S*\.Write(String)?\(' "$T"

# Fscan family primary discard
"$RG" -n --glob '*.go' --glob '!**/vendor/**' --glob '!**/*_test.go' \
  '_\s*,\s*\w+\s*:?=\s*fmt\.(Sscanf|Fscan|Fscanf|Scanf|Sscan)' "$T"

# Broader context: any _, err :=  and Seek / non-allowlist multi-return discards
"$RG" -n --glob '*.go' --glob '!**/vendor/**' --glob '!**/*_test.go' \
  '_\s*,\s*err\s*:?=' "$T"
```

Target path resolution (same pins as decision corpus):

| Logical target | Path used | Git revision (verified 2026-07-22) | `.go` files¹ |
|----------------|-----------|-------------------------------------|-------------:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 97 |
| monsoon | `…/codehound/real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 55 |
| go-retry | `…/codehound/real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 10 |
| gorl | `…/codehound/real-repos/gorl` | `ec54aaf15ce4d0f3f8014eac2548986c91d0f001` | 47 |
| no-mistakes | `…/codehound/real-repos/no-mistakes` | `0a2c82f993b9467c5ab84992313dfd13b66830af` | 491 |

¹ `find … -name '*.go' -not -path '*/.git/*' -not -path '*/vendor/*'` (includes tests).

**Note:** Isolated worktree has no local `real-repos/`; scans used the main-checkout absolute paths above (identical revisions to [`canary-corpus-pins.json`](./canary-corpus-pins.json)).

---

## Hit table — allowlist-shaped primary discard (non-test)

Counts are **static pattern hits**, not CodeHound findings. Classification is manual review of whether ignoring the primary value is **actionably wrong**.

| Callee class | gopdfsuit | monsoon | go-retry | gorl | no-mistakes | Correctness reading |
|--------------|----------:|--------:|---------:|-----:|------------:|---------------------|
| `io.Copy` / `CopyN` with `_` primary | **10** | 0 | 0 | 0 | **4** | Idiomatic: err is the contract; byte count unused after successful/failed copy is normal (font download, stream decode, file copy, pipe drain). |
| `*.Write` / `WriteString` with `_` primary | **14** | **2** | 0 | 0 | **13** | Textbook Go: `if _, err := w.Write(...); err != nil`. Near-universal FP if flagged. |
| `fmt.Sscanf` / Fscan with `_` primary | **11** | 0 | 0 | 0 | 0 | Single-verb `%d` parses check `err`; count is redundant. One multi-verb site (`merge.go` `"%d %d"`) relies on Sscanf err semantics; no partial-count bug evidenced. |
| Other multi-return `_` primary (context) | many Seek skips | 1 Seek | 1 DoValue discard | Incr new-value discard; SplitHostPort port discard | Atoi-for-validation; ParseFindings validate-only | Intentional discards; not a unified correctness class. |

### Aggregate allowlist shape (non-test)

| Module | Copy | Write | Fscan | any `_, err :=` (context) |
|--------|-----:|------:|------:|--------------------------:|
| gopdfsuit | 10 | 14 | 11 | 80 |
| monsoon | 0 | 2 | 0 | 4 |
| go-retry | 0 | 0 | 0 | 1 |
| gorl | 0 | 0 | 0 | 2 |
| no-mistakes | 4 | 13 | 0 | 185 |
| **Total** | **14** | **29** | **11** | **272** |

**Actionable correctness hits (reviewed):** **0**

---

## Representative non-bugs (would light up a naive detector)

```text
// gopdfsuit — font download: byte count unused; err + close handled
_, err = io.Copy(tmpFile, limitedReader)

// gopdfsuit — stream write (zlib / content)
if _, err := zlibWriter.Write(iccData); err != nil { ... }

// gopdfsuit — single-verb parse; err gates success
if _, err := fmt.Sscanf(p, "%d", &v); err == nil { ... }

// monsoon — CLI write: only err returned to Cobra
_, err = os.Stdout.Write(buf)

// monsoon — multi-verb range parse CORRECTLY keeps and checks count
n, err := fmt.Sscanf(..., "%de%d\n", &value, &exp)
if err != nil || n != 2 { ... }

// no-mistakes — file copy / HTTP body stream
if _, err := io.Copy(dst, src); err != nil { ... }
_, err = io.Copy(w, resp.Body)

// no-mistakes — binary / config writes
if _, err := tmp.Write(binaryData); err != nil { ... }

// go-retry — Do wrapper intentionally discards DoValue result
_, err := DoValue(ctx, b, func(...) (*struct{}, error) { ... })

// gorl — Incr side effect; new counter value unused
_, err := s.store.Incr(ctx, currKey, s.stateTTL)
```

### Non-Write/non-Copy class (reopen bar from #46)

Prior wontfix reopen condition ([`bp-71-canary.md`](./bp-71-canary.md)): a **non-Write/non-Copy** primary-discard class with documented wrong behavior and ≤3-callee allowlist with FP≈0.

This pass found:

| Pattern | Presence | Verdict |
|---------|----------|---------|
| `Seek` with `_` offset | gopdfsuit ttf skip-bytes; monsoon rewind | Correct — offset return unused when relative skip succeeds |
| `strconv.Atoi` / parse with `_` primary | no-mistakes validation-only | Correct — only err matters for “is this an int?” |
| Multi-verb `Sscanf` with `_` | one gopdfsuit `"%d %d"` | Relies on err; no partial-fill bug shown |
| Multi-verb `Sscanf` keeping `n` | monsoon range parser | **Counter-example of correct use** — not a miss |

No domain-specific “must use `n`” API class emerged with actionable bugs.

---

## Overlap analysis (G1 reopen item 2)

| Owner | Relationship to BP-71 |
|-------|------------------------|
| **BP-1** / errcheck | Discards *error* (`n, _ :=`); opposite of BP-71 |
| **staticcheck / go vet** | No stock rule flags idiomatic `_, err := w.Write` |
| **CWE / PERF** | Not a security/perf domain |
| **BP-154** | Ignored Unmarshal *errors* — different smell |

A naive BP-71 on Write/Copy would **not** retire-duplicate an existing rule; it would **create mass noise** without a unique correctness lesson.

---

## G1 reopen criteria check

| # | Criterion | Status |
|---|-----------|--------|
| 1 | Concrete high-signal pattern on pinned real modules | **Fail** — only idiomatic primary discards |
| 2 | Overlap analysis vs BP/CWE/staticcheck | **Pass** (documented) — no retire-duplicate, but no ship value |
| 3 | Vulnerable + safe fixtures with near-miss negatives | **N/A** — no detector |
| 4 | Release-binary canary with FP budget | **N/A** — no detector; static canary FP would be ~54 allowlist hits alone |
| 5 | Scoped implementable issue after evidence | **This issue (#137)** records **keep deferred** — no implement PR |

**Gate decision:** G1 remains **deferred**. Do not implement BP-71 or bulk BP-66+ rules.

---

## Disposition freeze

| Field | Value |
|-------|--------|
| **BP-71** | **Keep deferred** (still no canary-proven actionable class; reinforces #46 wontfix) |
| **Other absent candidates** | Unchanged vs [`bp-candidates-disposition.md`](./bp-candidates-disposition.md) |
| **Code shipped** | None (no fixtures, registry, detectors, canary table in product) |
| **Broad BP-66+ expansion** | **Not authorized** by this evidence |

### Reopen only if (updated)

A later canary finds **all** of:

1. A **non-Write / non-Copy** primary-discard class with **documented wrong behavior** on a real module (not fixture invent).
2. Frozen allowlist of **≤3 callees** with measured **FP≈0** on the five-module decision corpus.
3. Overlap note showing unique value vs BP-1 / errcheck.
4. Vulnerable + safe fixtures with renamed near-miss negatives.
5. New scoped implement issue under epic #136 (do not reopen this evidence-only close as bulk expansion).

---

## What this PR does / does not do

| Does | Does not |
|------|----------|
| Record G1 canary commands + hit table | Implement BP-71 or any BP-66+ rule |
| Freeze **keep deferred** for BP-71 | Invent detectors from pure fixtures |
| Expand sampling to **no-mistakes** (new vs #46) | Promote proof-boundary / policy candidates |
| Satisfy honest G1 “evidence before expansion” | Change maturity, packs, profiles, or recommended pack |

---

## Sources

- [`phase5-gated-work.md`](./phase5-gated-work.md) G1  
- [`phase5-implementation-backlog.md`](./phase5-implementation-backlog.md) · epic #136 / child #137  
- [`bp-candidates-disposition.md`](./bp-candidates-disposition.md) Group A BP-71  
- [`bp-71-canary.md`](./bp-71-canary.md) (#46)  
- [`bp-proof-boundary-notes.md`](./bp-proof-boundary-notes.md)  
- [`canary-corpus.md`](./canary-corpus.md) · [`canary-corpus-pins.json`](./canary-corpus-pins.json)  
- Research sketch: `plans/v0.0.3/new-bad-practices/01-part-a-core-language.md` § BP-71  
- Live trees under `real-repos/{gorl,monsoon,go-retry,no-mistakes}` and gopdfsuit (2026-07-22 scan)
