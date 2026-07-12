# Part A — Core Language (BP-66..BP-85)

> **Parent:** `plans/v3.0.0/new-bad-practices/README.md`
> **IDs:** BP-66 … BP-85 (**20 rules**)
> **Domains:** nil/interface, slice/map correctness, deep error handling, context, time
> **Status:** Plan only
> **Effort:** ~1.5–2 weeks

**Fixtures required for every rule:**  
`tests/fixtures/go/bad_practices/BP-N-vulnerable.txt` + `BP-N-safe.txt` (text snippets only — see README).

---

## A0 — Module / category work

- [ ] Extend `BadPracticeCategory` if needed (`ErrorHandling` reuse OK; consider `CoreLanguage` or keep under existing buckets)
- [ ] Extend `error_handling.rs` + new helpers for slice/nil/time as needed
- [ ] Add SourceIndex needles: `errors.Is`, `errors.As`, `errors.Join`, `time.LoadLocation`, `context.WithValue`, `append(`, `copy(`, `json.Unmarshal`, …
- [ ] JSON placeholders BP-66..BP-85 in `bad-practices.json`
- [ ] Dispatch entries for BP-66..BP-85

---

## Rule catalog

### BP-66 — Error Compared With `==` Instead Of `errors.Is`

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Category** | Error Handling |
| **Smell** | `err == ErrX` / `err != ErrX` on values that may be wrapped |
| **Why unique** | staticcheck does not consistently force `errors.Is` for all sentinel comparisons in application code; CodeHound can flag `==` against known package-level `var Err` / `errors.New` identifiers |
| **Detect** | Binary expr `==`/`!=` where one side is `err`/`error` and other is exported sentinel-like ident or `pkg.Err*` |
| **Suppress** | Comparison against `nil`; same-function fresh `errors.New` never wrapped |
| **Vulnerable snippet theme** | `if err == ErrNotFound` after `fmt.Errorf("%w", ErrNotFound)` path |
| **Safe** | `errors.Is(err, ErrNotFound)` |
| **Fixtures** | **Must add** `BP-66-vulnerable.txt` + `BP-66-safe.txt` |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-67 — `errors.As` Target Not A Pointer To Interface/Type

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Category** | Error Handling |
| **Smell** | `errors.As(err, target)` where target is not `&T` / not pointer |
| **Detect** | Call `errors.As` second arg not address-of |
| **Suppress** | Second arg already `*T` variable passed correctly |
| **Vulnerable** | `var e *MyErr; errors.As(err, e)` or `errors.As(err, MyErr{})` |
| **Safe** | `errors.As(err, &e)` |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-68 — `errors.Join` Result Discarded Or Unchecked

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Category** | Error Handling |
| **Smell** | `errors.Join(err1, err2)` assigned to `_` or not returned |
| **Detect** | Join call with discarded/non-returned result |
| **Safe** | `return errors.Join(...)` or check combined error |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-69 — Returning Data With Non-Nil Error (Unclear Contract)

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Category** | Error Handling |
| **Smell** | `return value, err` where both non-nil-looking on same path (heuristic: `return x, err` after `if err != nil` without zeroing `x`) |
| **Detect** | Same return statement has non-nil literal/ident data + `err` when prior branch set err without clearing data |
| **Suppress** | Documented partial-result APIs (name contains `Partial`) — keep heuristic tight |
| **Safe** | `return nil, err` / zero value + err |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-70 — Logging Error Then Continuing Without Return

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Category** | Error Handling |
| **Smell** | `if err != nil { log...; }` without `return`/`panic`/assign in block |
| **Why unique** | Beyond BP-1/BP-2; catches “log and fall through” |
| **Detect** | err-nil check block ends with log call only |
| **Safe** | log + return err |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-71 — Ignoring Non-Error Multi-Return Values That Affect Correctness

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Category** | Error Handling |
| **Smell** | `_, err := strconv.Atoi` is fine; flag `n, _ := strconv.Atoi` (discard error) already BP-1; this rule flags **discarding primary result** when error is checked but primary is `_` without justification on mutating APIs |
| **Detect** | Tight list: `io.Copy`, `fmt.Fscan*`, `bufio.Writer.Write` with `_` primary when err checked — optional narrow set |
| **Safe** | Use primary byte count / value |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-72 — Typed Nil Interface Return

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Category** | Core / API Design |
| **Smell** | `var p *T = nil; return p` where return type is `error` or interface (typed nil ≠ nil interface) |
| **Detect** | Return of pointer-typed nil assigned to interface return type (classic) |
| **Safe** | `return nil` bare for interface |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-73 — Nil Map Write Without Initialization

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Category** | Core language |
| **Smell** | `var m map[K]V` then `m[k] = v` without `make` |
| **Detect** | Function-local map declared zero-value then index-assign |
| **Suppress** | Map received as param (may be non-nil); make earlier in function |
| **Safe** | `m := make(map[K]V)` |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-74 — Slice Append Alias Unexpected Share

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Category** | Core language |
| **Smell** | `b := a[:]; b = append(b, x)` then read `a` expecting immutability — classic backing-array alias |
| **Detect** | Slice derived via `[:]` / `[i:j]` then append on alias in same function with later use of original |
| **Safe** | `slices.Clone` / `append([]T(nil), a...)` before append |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-75 — `copy` Destination Smaller Without Length Check

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Category** | Core language |
| **Smell** | `copy(dst, src)` when `dst` is empty/nil make of 0 and src non-empty literal/ident |
| **Detect** | `copy` with dest `make([]T, 0)` or nil slice |
| **Safe** | `make([]T, len(src))` then copy |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-76 — Range Over Map With Deterministic-Order Assumption

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Category** | Core language |
| **Smell** | Building ordered output by ranging map and joining without sort |
| **Detect** | `for k := range m` then append to slice used in `strings.Join` / stable serialization without `slices.Sort` |
| **Safe** | Collect keys, sort, then iterate |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-77 — Context Value Used For Optional Parameters (Stringly Keys)

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Category** | API Design / Context |
| **Smell** | `context.WithValue(ctx, "userID", …)` string keys |
| **Detect** | `WithValue` / `ctx.Value` with string/bool/int basic-type keys |
| **Safe** | Unexported key type `type key struct{}` |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-78 — Context Not Propagated To Child Call

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Category** | Context |
| **Smell** | Function accepts `ctx` but calls `http.NewRequest` / `Query` / child without `ctx` overload |
| **Detect** | Param `context.Context` present; body uses `http.NewRequest(` or `db.Query(` instead of `*Context` variants |
| **Overlap** | noctx linter — keep **stdlib multi-API** list aligned; skip pure client.Do cases if too noisy |
| **Safe** | `NewRequestWithContext`, `QueryContext`, … |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-79 — `context.WithCancel` Without `defer cancel()`

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Category** | Context |
| **Smell** | `ctx, cancel := context.WithCancel|WithTimeout|WithDeadline` without `defer cancel()` in function |
| **Detect** | Constructor present; no `cancel(` in function body |
| **Safe** | `defer cancel()` |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-80 — Context TODO In Production Code

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Category** | Context |
| **Smell** | `context.TODO()` outside tests / generated |
| **Detect** | `context.TODO()` in non-`_test.go` |
| **Safe** | Propagate real ctx or Background only in main |
| **Overlap** | Related BP-13 (Background); this is TODO-specific |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-81 — Time Comparisons With `time.Now` Nested In Expressions Repeatedly

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Category** | Time |
| **Smell** | Correctness: `if time.Now().After(deadline) && time.Now().Before(…)` clock skew windows — prefer single `now := time.Now()` |
| **Detect** | ≥2 `time.Now()` in same condition expression |
| **Note** | PERF may cover hot path; this is **correctness/consistency** |
| **Safe** | Single `now` variable |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-82 — Parsing Time Without Location (Ambiguous Local)

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Category** | Time |
| **Smell** | `time.Parse` for timestamps that should be UTC / explicit location |
| **Detect** | `time.Parse(` on RFC3339-ish layouts without `ParseInLocation` / `time.RFC3339` careful use — heuristic: layout without zone + store to DB |
| **Safe** | `time.Parse(time.RFC3339, …)` or `ParseInLocation` with explicit loc |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-83 — Sleeping For Synchronization Outside Tests

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Category** | Concurrency / Core |
| **Smell** | `time.Sleep` in non-test production code used as “wait for ready” |
| **Detect** | `time.Sleep` outside `_test.go` and outside clearly backoff retry with jitter comments/heuristic |
| **Overlap** | BP-16 is test-only; this is production |
| **Safe** | channels, condition, poll with context |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-84 — Integer Division Truncation Used As Percentage Without Comment/Guard

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Category** | Core language |
| **Smell** | `a / b * 100` integer types for percentages |
| **Detect** | Binary `/` on integer idents followed by `* 100` |
| **Safe** | float conversion or explicit rational |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

### BP-85 — Type Assert Without `ok` On Untrusted Interface

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Category** | Core language |
| **Smell** | `x.(T)` single-value assert outside tests (panic risk) |
| **Detect** | Type assertion expression not in `v, ok :=` form |
| **Suppress** | `_test.go`; assert on known sealed unions hard to prove — start strict on public handlers |
| **Safe** | `v, ok := x.(T)` |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs
- [ ] Text fixtures + manifest
- [ ] Tests green

---

## Part A exit criteria

- [ ] All 20 rules implemented or explicitly deferred with reason in CHECKLIST
- [ ] Each implemented rule has **vulnerable + safe `.txt` snippets**
- [ ] `documents/bad-practices.md` section updated
- [ ] Integration tests green for BP-66..BP-85
