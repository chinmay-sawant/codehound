# Part B — Concurrency & Resource Lifecycle (BP-86..BP-100)

> **Parent:** `plans/v0.0.3/new-bad-practices/README.md`
> **IDs:** BP-86 … BP-100 (**15 rules**)
> **Domains:** channels, errgroup, mutex hygiene, goroutine leaks (heuristic), I/O ownership
> **Status:** Plan only
> **Effort:** ~1.5 weeks

**Fixtures required for every rule:**  
`tests/fixtures/go/bad_practices/BP-N-vulnerable.txt` + `BP-N-safe.txt` (text snippets only).

**Overlap guard:** BP-6..15 already cover WaitGroup.Add-in-goroutine, mutex by value, select without timeout, time.After in loop, defer in loop, background ctx, recursive Once, etc. New rules must not restate those.

---

## B0 — Module work

- [ ] Extend `sync.rs` / `loops.rs` for new concurrency rules
- [ ] Consider `resources.rs` for Close/Flush/unlock lifecycle beyond BP-5/BP-49
- [ ] Needles: `errgroup`, `golang.org/x/sync`, `mu.Lock`, `RLock`, `CloseSend`, `http.Response`, `ioutil` (already BP-56)
- [ ] JSON + dispatch BP-86..BP-100

---

## Rule catalog

### BP-86 — Mutex Lock Without Unlock On All Paths

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `mu.Lock()` without `Unlock` / `defer Unlock` in function |
| **Detect** | Lock call; no Unlock for same recv in function |
| **Suppress** | Manual unlock in each branch if all paths covered (hard — start with missing unlock entirely) |
| **Safe** | `defer mu.Unlock()` |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests

---

### BP-87 — `RLock` Held Across Blocking Call

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `RLock` then channel recv / `Sleep` / HTTP / DB without unlock first |
| **Detect** | Between RLock and RUnlock: `<-`, `time.Sleep`, `http.`, `Query` |
| **Safe** | Copy data under lock, unlock, then block |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests

---

### BP-88 — Channel Send/Recv On Nil Channel Accidentally

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `var ch chan T` then send/recv without make (blocks forever) |
| **Detect** | Zero-value chan decl + send/recv in function without make/assign |
| **Safe** | `make(chan T)` or intentional nil-channel select pattern (select-only suppress) |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests

---

### BP-89 — Closing Channel More Than Once / From Receiver Side

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | Multiple `close(ch)` or close in consumer loop without ownership comment |
| **Detect** | ≥2 `close(` on same ident; or `close` inside `for range ch` body |
| **Safe** | Single owner closes once |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests

---

### BP-90 — `range` Over Channel Without Exit Condition In Non-Range Form

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `for { v := <-ch }` without default/timeout/ctx (infinite) |
| **Detect** | Infinite for + bare channel recv, no select escape |
| **Overlap** | BP-9 select; this is non-select recv loop |
| **Safe** | `for v := range ch` or select with ctx |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests

---

### BP-91 — Notification Channel Carrying Data Unnecessarily

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Smell** | `chan bool` / `chan int` used only for signal (`ch <- true`) |
| **Detect** | Send of constant true/1 on chan bool/int with no recv value use |
| **Safe** | `chan struct{}` |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests

---

### BP-92 — `errgroup.Group` Without Context (`WithContext`)

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `var g errgroup.Group` + `g.Go` without `errgroup.WithContext` |
| **Detect** | Import `golang.org/x/sync/errgroup`; Group not from WithContext; Go calls present |
| **Safe** | `g, ctx := errgroup.WithContext(parent)` |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests

---

### BP-93 — `errgroup.Go` Closure Ignoring Returned Error Path

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `g.Go(func() error { do(); return nil })` when `do` returns error discarded |
| **Detect** | Inside Go func: call returning err assigned `_` or unchecked |
| **Safe** | Return error from Go func |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests

---

### BP-94 — Fire-And-Forget Goroutine Writing To Shared Map Without Sync

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `go func(){ m[k]=v }()` on map without mutex/sync.Map |
| **Detect** | Goroutine body map index assign; no Lock/sync.Map in function |
| **Safe** | Mutex or `sync.Map` or channel ownership |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests

---

### BP-95 — `http.Response.Body` Not Closed (Client)

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `http.Get` / `Client.Do` without `defer resp.Body.Close()` |
| **Overlap** | bodyclose — ship only if CodeHound wants zero-dep path; mark as **optional implement if gap confirmed** |
| **Detect** | Assignment from Get/Do; no `.Body.Close` in function |
| **Safe** | `defer resp.Body.Close()` after nil check |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests
- [ ] Confirm vs bodyclose: keep if we want default-on without golangci

---

### BP-96 — `sql.Rows` / `sql.Row` Resource Not Closed

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `rows, err := db.Query` without `defer rows.Close()` |
| **Overlap** | sqlclosecheck — same policy as BP-95 |
| **Safe** | `defer rows.Close()` |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests

---

### BP-97 — Flushable Writer Never Flushed Before Read Side

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `bufio.Writer` / `gzip.Writer` written then underlying read without `Flush`/`Close` |
| **Detect** | Writer created; Write* calls; function returns/uses buffer without Flush/Close |
| **Safe** | `Flush` or `Close` before consume |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests

---

### BP-98 — `os.Open` File Not Closed On Error Path

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | Open succeeds, later error return without close |
| **Detect** | `os.Open`/`OpenFile`; early returns after success without close/defer |
| **Safe** | `defer f.Close()` immediately after successful open |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests

---

### BP-99 — `sync.Cond` Without Locker Discipline

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `cond.Wait` without lock held / Signal without lock patterns |
| **Detect** | `sync.NewCond` / `.Wait()` without surrounding Lock in function (heuristic) |
| **Safe** | Lock → Wait loop → Unlock |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests

---

### BP-100 — Goroutine Per Request Without Bound (Unbounded Fan-Out)

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | Handler/API loops `for _, item := range items { go process(item) }` without semaphore/errgroup limit |
| **Detect** | Loop + `go ` without worker pool / semaphore tokens |
| **Overlap** | Not PERF-228 (tiny fan-out); this is **unbounded** correctness/reliability |
| **Safe** | errgroup + limit, or worker pool |
| **Fixtures** | **Must add** text snippets |

- [ ] Detector + JSON + docs + **txt fixtures** + tests

---

## Part B exit criteria

- [ ] 15 rules shipped or deferred with reason
- [ ] All shipped rules have **vulnerable + safe `.txt` snippets**
- [ ] No pure rehash of BP-6..15
- [ ] Integration green for BP-86..BP-100
