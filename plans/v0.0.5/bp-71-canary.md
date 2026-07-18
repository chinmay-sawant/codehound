# BP-71 Canary — Primary multi-return discard

> **Issue:** [#46](https://github.com/chinmay-sawant/codehound/issues/46)  
> **Parent disposition:** `plans/v0.0.5/bp-candidates-disposition.md` (defer-needs-canary)  
> **Research sketch:** `plans/v0.0.3/new-bad-practices/01-part-a-core-language.md` § BP-71  
> **Date:** 2026-07-19  
> **Decision:** **wontfix** as a BP detector (no implementation)

---

## Proposed rule (reminder)

Flag **discarding the primary multi-return value** while keeping/checking the error on a frozen callee allowlist:

- `io.Copy` / `io.CopyN` (`n, err`)
- `fmt.Fscan*` / `fmt.Sscanf` / `fmt.Scanf` (count, err)
- `Write` / `WriteString` byte counts (`n, err`)

Distinct from **BP-1** (discards *error*). Goal: catch cases where ignoring `n`/count hurts correctness.

---

## Canary method

Read-only ripgrep over:

| Module | Path |
|--------|------|
| gorl | `real-repos/gorl` |
| monsoon | `real-repos/monsoon` |
| go-retry | `real-repos/go-retry` |
| gopdfsuit | sibling checkout `gopdfsuit` |

Patterns: `_\s*,\s*\w+\s*:?=` on allowlist callees; also broader `_, err` near Copy/Write/Fscan/Seek/ReadFull for context.

---

## Evidence summary

### Allowlist hits

| Callee class | gorl | monsoon | go-retry | gopdfsuit | Correctness reading |
|--------------|-----:|--------:|---------:|----------:|---------------------|
| `io.Copy` with `_` primary | 0 | 0 | 0 | **~10** production sites | Idiomatic: err is the contract; `n` unused after successful/failed copy is normal (e.g. `fontutils.go:218`, `helpers.go`, `xfdf.go`, `pdfa.go`). |
| `*.Write` / `WriteString` with `_` primary | 0 | 1 (`os.Stdout.Write`) | 0 | **many** (zlib/content streams, handlers) | Textbook Go: `if _, err := w.Write(...); err != nil`. Flagging would be near-universal FP. |
| `fmt.Sscanf` / Fscan with `_` primary | 0 | 0 primary-discard (uses `n, err`) | 0 | **~10** single-/multi-verb parses | Sites check `err == nil` / `err != nil`. For single `%d`, count is redundant with err. Multi-verb cases (e.g. `merge.go` `"%d %d"`) rely on Sscanf error/EOF semantics; no partial-count bug evidenced. |
| Other multi-return `_` primary | few | several | 1 | many | Intentional: `Seek` offset, `os.Stat` FileInfo, `net.SplitHostPort` port, store `Incr` new value, `DoValue` discard in retry `Do` wrapper. |

### Representative non-bugs (would light up a naive detector)

```text
// gopdfsuit — font download: byte count unused; err + close handled
_, err = io.Copy(tmpFile, limitedReader)

// monsoon — CLI write: only err returned to Cobra
_, err = os.Stdout.Write(buf)

// gopdfsuit — stream write
if _, err := zlibWriter.Write(iccData); err != nil { ... }

// monsoon — range parse correctly keeps count
n, err := fmt.Sscanf(..., "%de%d\n", &value, &exp)
```

### What a “ship” bar needed

1. Real-module hits where ignoring primary is **actionably wrong** (e.g. partial `Sscanf` count not checked *and* err nil path continues with unfilled vars — rare with modern check patterns).
2. Frozen callee list that does **not** include idiomatic `Write`/`io.Copy` error checks.
3. FP budget near zero on gopdfsuit-sized codebases.

None of (1)–(3) held on this canary.

---

## Decision

| Field | Value |
|-------|--------|
| **Outcome** | **wontfix** (do not implement BP-71) |
| **Rationale** | Allowlist-shaped hits are overwhelmingly idiomatic Go. A static detector for `_, err := io.Copy` / `Write` would dominate noise and teach the wrong lesson. Remaining Fscan edge cases are API-semantics-thin and did not show bug-class hits in canary modules. |
| **Code shipped** | None |
| **Reopen only if** | A later canary finds a **non-Write/non-Copy** primary-discard class with documented wrong behavior (e.g. domain-specific “must use `n`” APIs) and a ≤3-callee allowlist with measured FP=0 on the same four modules. |

Cross-check: disposition already noted a quick scan found no high-value `n, _ :=` correctness pattern; this pass confirms the dual form (`_, err :=` on allowlist callees) is also non-actionable as a BP.

---

## Sources

- `plans/v0.0.5/bp-candidates-disposition.md` Group A BP-71
- `plans/v0.0.3/new-bad-practices/01-part-a-core-language.md` BP-71
- Live trees under `real-repos/{gorl,monsoon,go-retry}` and gopdfsuit (2026-07-19 scan)
