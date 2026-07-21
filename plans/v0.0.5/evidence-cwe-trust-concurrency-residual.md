# Evidence — C3 Concurrency residual trust (shared_state)

> **Issue:** #114 · **Epic:** #105 · **Phase 3 slice:** C3  
> **Branch:** `chore/cwe-trust-concurrency-residual`  
> **Integration base:** `7d912d5be8528f80df0122259d24130c6f394df9`  
> **Owner seam:** `src/lang/go/detectors/cwe/domains/concurrency/`  
> **Selected family file:** `shared_state.rs`  
> **Date:** 2026-07-21

---

## Family inventory and selection

| Leaf | Rules | Approx. lines (pre-edit) | Fixture coverage | Selected? |
|------|-------|--------------------------|------------------|-----------|
| `shared_state.rs` | CWE-366, 368, 421, 820, 821 | ~155 | stdlib + frameworks × vulnerable/safe | **Yes** |
| `toctou.rs` | CWE-367 | ~49 | stdlib + frameworks × vulnerable/safe | Deferred (already disposed §2.8) |

### Why select shared_state

1. **Residual only** — CWE-367 already has call-facts primary + keep Heuristic (audit §2.8).
2. **Local syntactic proof boundary** — unit-local SI museums + Setenv/RLock call sites; no channel/goroutine lifecycle.
3. **Plan ceiling** — §3.3 explicitly forbids channel/goroutine data-flow inference.
4. **Full oracle pairs** — five rules, four fixtures each.
5. **Single-file cohesive slice** — unsynchronized shared-state theme.

### Why defer toctou

| Deferred | Reason |
|----------|--------|
| **CWE-367** | Dated disposition (2026-07-18): call-facts `os.Stat`+`os.ReadFile` shared path; keep Heuristic; one reviewed example-path canary hit. Reopening is not residual work. |

---

## Freeze inventory (selected family)

| Rule | Fixtures | Maturity today | Profile eligibility today | Primary signals (frozen) | Negatives |
|------|----------|----------------|---------------------------|--------------------------|-----------|
| **CWE-366** | 4 files | Heuristic (default) | all / --only; not recommended/security allow-list | SI credit `+=` museums | SI `atomic.AddInt64(` |
| **CWE-368** | 4 files | Heuristic (default) | same | call_facts `os.Setenv` + SI mode flags | SI `sync.Mutex` / `Lock()` |
| **CWE-421** | 4 files | Heuristic (default) | same | SI token + SSE museums | SI mutex / transferMu / wireMu |
| **CWE-820** | 4 files | Heuristic (default) | same | SI visitCounts + TrackVisit | SI visitMu lock |
| **CWE-821** | 4 files | Heuristic (default) | same | call_facts `.RLock` + SI tokenCache write | SI `cacheMu.Lock()` |

**Shared surfaces not edited (worker contract):** `maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`, `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`.

---

## Corpus signal classes

| Class | Examples | Rules |
|-------|----------|-------|
| Exact credit identifiers | `walletCredits += amount`, `referralCredits += 10` | 366 |
| Privilege mode flags | `actingAsRoot = true`, `privilegedMode = true` | 368 |
| Process env write | `os.Setenv` | 368 |
| SSE event formats | `event: status\ndata: …` + transfer tokens | 421 |
| Map counter + helper | `visitCounts[key] = …`, `TrackVisit` | 820 |
| Read-lock + map write | `RLock`, `tokenCache[key] = value` | 821 |
| Sync negatives | `atomic.AddInt64(`, `sync.Mutex`, `Lock()`, `visitMu`, `cacheMu.Lock()` | all |

---

## Analysis ceilings (explicit non-claims)

| Ceiling | Impact |
|---------|--------|
| No channel data-flow | CWE-421 remains SSE string co-presence, not alternate-channel ownership |
| No goroutine lifecycle | CWE-366/820 do not claim concurrent handler reachability |
| No lock-set analysis | CWE-821 is unit-local RLock + map-write co-presence, not critical-section proof |
| No principal-switch analysis | CWE-368 mode flags are corpus identifiers, not policy lattice |

---

## Call-facts primary analysis

| Rule | Can call_facts be complete primary? | Decision |
|------|-------------------------------------|----------|
| CWE-366 | **No.** Compound `+=` is not a callee. Assignment facts on corpus names only re-encode the museum. | Leave SI primary; **fixture-only** |
| CWE-368 | **Partial.** `os.Setenv` is a real sink; emit still needs mode-flag SI. | Call-facts Setenv + SI flags; **fixture-only** |
| CWE-421 | **No.** Frameworks use `Write` with concatenated bytes; stdlib uses `fmt.Fprintf` — no shared callee proof without SSE format museum. | Leave SI primary; **fixture-only** |
| CWE-820 | **No.** Map index write is not a call; TrackVisit is a helper name. | Leave SI primary; **fixture-only** |
| CWE-821 | **Partial.** `.RLock` is a real API; emit still needs `tokenCache[key] = value` SI. | Call-facts RLock + SI map write; **fixture-only** |

---

## Per-rule disposition

| Rule | Disposition | Rationale |
|------|-------------|-----------|
| CWE-366 | **fixture-only** | Credit-identifier museum; concurrent-access proof out of scope |
| CWE-368 | **fixture-only** | Setenv sink real; privilege-flag names corpus |
| CWE-421 | **fixture-only** | SSE + token museum; no channel dataflow |
| CWE-820 | **fixture-only** | visitCounts + TrackVisit museum |
| CWE-821 | **fixture-only** | RLock sink real; tokenCache write museum |

**No Structural promotion.** No Heuristic keep for selected family (all corpus-gated; zero real-module expectation for exact museums).

---

## Detector changes this PR

File: `concurrency/shared_state.rs` only.

- Module + per-rule freeze comments documenting signals, negatives, ceilings, disposition.
- **CWE-368:** call-facts primary for `os.Setenv`; span at Setenv call.
- **CWE-821:** call-facts primary for `RLock` / `*.RLock`; span at RLock call.
- **CWE-366 / 421 / 820:** emit path unchanged (comment freeze only).

No new fixture `.txt` files. No `manifest.toml` edits.

---

## Proposed integrator changes (DO NOT apply on this branch)

### Maturity (`src/rules/maturity.rs`)

- Add `CWE-366`, `CWE-368`, `CWE-421`, `CWE-820`, `CWE-821` to `is_fixture_only`.
- Leave `CWE-367` **not** fixture-only (Heuristic, §2.8).
- Update maturity unit tests accordingly.
- Do **not** add any of these to the structural allow-list.

### NEEDLES labels (`source_index.rs`)

See PR body table. High-priority fixture-literals: credit increments, mode flags, SSE formats, visitCounts shape, tokenCache write, TrackVisit. Negatives: atomic.AddInt64, visitMu locks, cacheMu.Lock. Shared dual-use needles (`sync.Mutex`, `Lock()`) need careful review before labeling.

### Fixture / manifest / findings-oracle

- No new fixtures.
- No manifest wiring.
- Oracle presence checks only; line shifts for 368/821 are acceptable.

---

## Canary record

See PR body for command and per-repo totals (filled after release canary run).

**Reviewed expectation:** zero hits on gopdfsuit / monsoon / go-retry for the five exact-museum rules. Confirms fixture-only quarantine rather than production Heuristic keep.
