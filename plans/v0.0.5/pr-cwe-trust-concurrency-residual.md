# chore(cwe): audit concurrency residual trust (C3)

## Summary

- Inventory both concurrency leaves; **select** `concurrency/shared_state.rs`
  (**CWE-366**, **CWE-368**, **CWE-421**, **CWE-820**, **CWE-821**).
- **Defer** `concurrency/toctou.rs` (**CWE-367**) — already call-facts primary with
  dated **keep Heuristic** disposition in `cwe-catalog-trust-audit.md` §2.8.
- Freeze primary signals, negatives, fixtures, and maturity state for the selected family.
- Oracle-safe rewrites: **CWE-368** (`os.Setenv` call-facts) and **CWE-821** (`.RLock`
  call-facts); **CWE-366 / 421 / 820** comment-only freeze (pure SI museums).
- Propose **fixture-only** for all five selected rules (integrator applies `maturity.rs` /
  SourceIndex NEEDLES labels). No channel/goroutine data-flow inference.
- Focused fixtures + five-rule real-module canary.

---

## Motivation / context

Phase 3 slice **C3** of [`parallel-catalog-program.md`](./parallel-catalog-program.md) §3.3 /
issue [#114](https://github.com/chinmay-sawant/codehound/issues/114). Relates to epic
[#105](https://github.com/chinmay-sawant/codehound/issues/105).

**Integration base SHA:** `7d912d5be8528f80df0122259d24130c6f394df9`  
**Branch:** `chore/cwe-trust-concurrency-residual`  
**Structural bar:** [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §1.3

Owner seam: `src/lang/go/detectors/cwe/domains/concurrency/`

**Selected family:** `shared_state.rs` (366 / 368 / 421 / 820 / 821)

**Deferred sibling:** `toctou.rs` (367) — already disposed Heuristic; not reopened.

---

## Selection inventory

### Candidate A — `shared_state.rs` (**selected**)

| Rule | Approx. shape | Fixture coverage |
|------|---------------|------------------|
| CWE-366 | Non-atomic credit `+=` museum | stdlib + frameworks vulnerable/safe |
| CWE-368 | Privilege flag + `os.Setenv` unsync | stdlib + frameworks vulnerable/safe |
| CWE-421 | SSE alternate channel + transfer token | stdlib + frameworks vulnerable/safe |
| CWE-820 | Map counter write without lock | stdlib + frameworks vulnerable/safe |
| CWE-821 | Map write under `RLock` only | stdlib + frameworks vulnerable/safe |
| **Total** | **5 rules** | **full pair coverage** |

Local syntactic boundaries (no channel/goroutine ownership):

- `os.Setenv` call site (368)
- `.RLock` call site (821)
- Exact SI museums for credit increments, SSE token shapes, visit-counter maps

### Candidate B — `toctou.rs` (**deferred**)

| Rule | Status |
|------|--------|
| CWE-367 | Call-facts primary `os.Stat` + `os.ReadFile` shared path; **keep Heuristic** (audit §2.8, 2026-07-18); one reviewed gopdfsuit example-path canary hit |

Reopening 367 would re-litigate a completed disposition and is not a residual.

### Why select A

1. **Residual only** — 367 already has a dated disposition; shared_state has none.
2. **Local syntactic proof** — Setenv / RLock / SI co-presence are unit-local; no channel or goroutine lifecycle claims.
3. **Plan ceiling** — §3.3 forbids channel/goroutine data-flow inference; shared_state stays inside that ceiling.
4. **Full fixture pairs** — every selected rule has stdlib + frameworks vulnerable/safe.
5. **Cohesive five-rule slice** — one file, one theme (unsynchronized shared state).

---

## Frozen signals (selected family)

Runtime maturity today: all five default to **Heuristic** (`maturity_for` has no explicit
fixture-only / structural entry). Available under `--profile all` / `--only`; not on
recommended/security explicit allow-lists.

### CWE-366 — Race Condition within a Thread

| Field | Value |
|-------|--------|
| File | `shared_state.rs` → `detect_cwe_366` |
| Primary signal | SI `walletCredits += amount` **or** `referralCredits += 10` without `atomic.AddInt64(` |
| Negatives | SI `atomic.AddInt64(` |
| Span | source find of the increment text |
| Fixtures | stdlib + frameworks vulnerable/safe |
| Call-facts? | **No** — `+=` is not a callee; general shared-int mutation needs concurrent-access proof (out of scope) |
| **Proposed disposition** | **fixture-only** |

### CWE-368 — Context Switching Race Condition

| Field | Value |
|-------|--------|
| File | `shared_state.rs` → `detect_cwe_368` |
| Primary signal (after rewrite) | `call_facts` `os.Setenv` + SI privilege flag (`actingAsRoot = true` **or** `privilegedMode = true`) + SI `os.Setenv(` prefilter |
| Negatives | SI `sync.Mutex` **or** `Lock()` |
| Span | `os.Setenv` call site |
| Fixtures | stdlib + frameworks vulnerable/safe |
| Call-facts? | **Yes** for Setenv sink; mode-flag names remain corpus co-signals |
| **Proposed disposition** | **fixture-only** |

### CWE-421 — Race Condition During Access of Alternate Channel

| Field | Value |
|-------|--------|
| File | `shared_state.rs` → `detect_cwe_421` |
| Primary signal | SI shared token assign + SSE event embedding (`transferToken` / `wireTransferCode` museums) |
| Negatives | SI `sync.Mutex` / `transferMu` / `wireMu` |
| Span | source find of token assignment |
| Fixtures | stdlib + frameworks vulnerable/safe |
| Call-facts? | **No** — SSE format + field-name museum; frameworks use `Write` not a shared callee shape |
| **Proposed disposition** | **fixture-only** |

### CWE-820 — Missing Synchronization

| Field | Value |
|-------|--------|
| File | `shared_state.rs` → `detect_cwe_820` |
| Primary signal | SI `visitCounts[key] = visitCounts[key] + 1` + `TrackVisit` without visitMu lock |
| Negatives | SI `visitMu.Lock()` **or** `visitMu sync.Mutex` |
| Span | source find of map-write text |
| Fixtures | stdlib + frameworks vulnerable/safe |
| Call-facts? | **No** — map index write is not a callee; general concurrent-map proof needs lifecycle analysis |
| **Proposed disposition** | **fixture-only** |

### CWE-821 — Incorrect Synchronization

| Field | Value |
|-------|--------|
| File | `shared_state.rs` → `detect_cwe_821` |
| Primary signal (after rewrite) | `call_facts` callee `RLock` or ends with `.RLock` + SI `tokenCache[key] = value` + SI `RLock()` prefilter |
| Negatives | SI `cacheMu.Lock()` |
| Span | RLock call site |
| Fixtures | stdlib + frameworks vulnerable/safe |
| Call-facts? | **Yes** for RLock site; map-write shape remains corpus co-signal |
| **Proposed disposition** | **fixture-only** |

### Disposition table

| Rule | Disposition | Primary signal class | Notes |
|------|-------------|----------------------|-------|
| **CWE-366** | **fixture-only** | SI credit-increment museum | No safe call-facts primary for `+=` |
| **CWE-368** | **fixture-only** | call_facts Setenv + SI mode flags | Sink real; flags corpus |
| **CWE-421** | **fixture-only** | SI SSE + token museum | No channel dataflow |
| **CWE-820** | **fixture-only** | SI map-counter + TrackVisit | No lifecycle proof |
| **CWE-821** | **fixture-only** | call_facts RLock + SI map write | Sink real; map name corpus |
| CWE-367 (deferred) | keep Heuristic (existing) | call_facts Stat+ReadFile | audit §2.8; not reopened |

No deletes. No §1.3 Structural promotion. No channel/goroutine data-flow claims.

---

## Changes

### Code (`shared_state.rs` only)

| Rule | Change |
|------|--------|
| CWE-366 | Freeze comments only; SI museum unchanged |
| CWE-368 | Call-facts primary: `os.Setenv`; SI privilege-flag + Setenv prefilter; SI mutex negative; emit at Setenv call site |
| CWE-421 | Freeze comments only; SI museum unchanged |
| CWE-820 | Freeze comments only; SI museum unchanged |
| CWE-821 | Call-facts primary: `.RLock`; SI map-write + RLock prefilter; SI exclusive-lock negative; emit at RLock call site |

### Explicitly not changed (integrator / out of scope)

- `src/rules/maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`
- `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`
- Sibling C1/C2/C4; `toctou.rs` (CWE-367)
- No new fixture files; no fixture renames
- No channel/goroutine data-flow analysis

---

## Proposed dispositions (integrator)

| Rule | Disposition | Call-facts | Rationale |
|------|-------------|------------|-----------|
| CWE-366 | **fixture-only** quarantine | no | Exact credit identifiers; zero real-module expectation |
| CWE-368 | **fixture-only** quarantine | yes — `os.Setenv` | Sink real; still gated on actingAsRoot/privilegedMode museum |
| CWE-421 | **fixture-only** quarantine | no | SSE + transfer-token museum; no alternate-channel analysis |
| CWE-820 | **fixture-only** quarantine | no | visitCounts + TrackVisit museum |
| CWE-821 | **fixture-only** quarantine | yes — `.RLock` | Sink real; still gated on tokenCache write museum |

Prefer fixture-only over Heuristic keep: all remain corpus-gated on identifiers or exact map shapes. Do **not** structural-promote any rule. Do **not** invent general concurrent-map or shared-int findings.

### Proposed NEEDLES labels (integrator applies in `source_index.rs`)

| Needle | Proposed label |
|--------|----------------|
| `walletCredits += amount` | `fixture-literal` (CWE-366 frameworks) |
| `referralCredits += 10` | `fixture-literal` (CWE-366 stdlib) |
| `atomic.AddInt64(` | `negative-gate` (CWE-366) |
| `actingAsRoot = true` | `fixture-literal` (CWE-368 frameworks) |
| `privilegedMode = true` | `fixture-literal` (CWE-368 stdlib) |
| `os.Setenv(` | prefilter / co-signal (CWE-368; call_facts primary after this PR) |
| `sync.Mutex` | `negative-gate` (shared; CWE-368/421 and neighbors) — label carefully if dual-use |
| `Lock()` | `negative-gate` / co-signal (shared; dual-use) |
| `transferToken =` | `fixture-literal` (CWE-421 frameworks) |
| `wireTransferCode =` | `fixture-literal` (CWE-421 stdlib) |
| `event: status\ndata: " + transferToken` | `fixture-literal` (CWE-421 frameworks SSE) |
| `event: status\ndata: %s\n\n", wireTransferCode` | `fixture-literal` (CWE-421 stdlib SSE) |
| `transferMu` / `wireMu` | `negative-gate` (CWE-421) |
| `visitCounts[key] = visitCounts[key] + 1` | `fixture-literal` (CWE-820) |
| `TrackVisit` | `fixture-literal` (CWE-820 helper) |
| `visitMu.Lock()` / `visitMu sync.Mutex` | `negative-gate` (CWE-820) |
| `RLock()` | prefilter (CWE-821; call_facts primary after this PR) |
| `tokenCache[key] = value` | `fixture-literal` (CWE-821 map write) |
| `tokenCache` | co-signal / optional `fixture-literal` if only used as museum |
| `cacheMu.Lock()` | `negative-gate` (CWE-821 exclusive write path) |

### Proposed maturity.rs (integrator)

```rust
| "CWE-366" // walletCredits/referralCredits += museum
| "CWE-368" // privilege flag + os.Setenv without mutex (call_facts Setenv)
| "CWE-421" // SSE alternate channel + transfer token museum
| "CWE-820" // visitCounts + TrackVisit without lock
| "CWE-821" // tokenCache write under RLock (call_facts RLock)
// leave CWE-367 as default Heuristic (already call_facts Stat+ReadFile; §2.8)
```

Plus matching unit-test asserts in `maturity.rs` tests.

### Fixtures / oracle impact

- No fixture additions or renames.
- Vulnerable fixtures still fire; safe fixtures still silence.
- Emit spans shift to call sites for 368 (Setenv) and 821 (RLock); fixture oracle checks rule presence only, not line.

---

## Canary

Release binary on this branch; integration base `7d912d5be8528f80df0122259d24130c6f394df9`.

```sh
cargo build --release --locked
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry; do
  echo "=== $t ==="
  target/release/codehound "$t" --profile all \
    --only CWE-366,CWE-368,CWE-421,CWE-820,CWE-821 \
    --format json --json-envelope --no-fail --no-cache 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print('findings', len(d.get('findings',[])), 'files', d.get('stats',{}).get('files_scanned'));
from collections import Counter; c=Counter(f.get('rule_id') for f in d.get('findings',[])); print(dict(c) if c else '{}')"
done
```

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | _(filled by canary)_ | _(filled)_ |
| monsoon | `codehound/real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | _(filled)_ | _(filled)_ |
| go-retry | `codehound/real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | _(filled)_ | _(filled)_ |

**Decision (expected / to confirm):** quarantine all five as fixture-only (`--profile all` only). Do not structural-promote. Do not broaden to general concurrent-map / shared-int / alternate-channel analysis. Revisit only with unit-local lock-set or shared-state proof that does not invent goroutine ownership.

---

## Validation

```sh
make lint
cargo test --locked --test go_cwe_detector_fixtures
make test
git diff --check
```

- `go_cwe_detector_fixtures` — 4 passed (oracle preserved)
- remaining filled after full gate run

---

## Integrator handoff

1. Apply `is_fixture_only` for **CWE-366**, **CWE-368**, **CWE-421**, **CWE-820**, **CWE-821** (+ maturity unit tests). Leave **CWE-367** Heuristic (existing §2.8).
2. Label owned NEEDLES as proposed above (do not bulk-relabel shared `sync.Mutex` / `Lock()` without review).
3. Append dated audit section (concurrency shared_state residual) to `cwe-catalog-trust-audit.md` from this evidence; mark C3 residual inventory item.
4. Wire nothing new into `manifest.toml` (no fixture additions).
5. Integration merge order for Phase 3: detector/fixture commits first (this PR), then shared maturity/index/manifest, then audit ledger.
6. Re-run combined Phase 3 `--only` canary after C1–C4 land; this worker canary is evidence, not final integrated proof.
7. No structural promotion for any rule under §1.3. Do not invent channel/goroutine dataflow findings.
8. Deferred: reopening CWE-367 (already disposed); general concurrent-map / shared-int detectors.

### Integration note (epic Phase 3)

- Branch: `chore/cwe-trust-concurrency-residual`
- Integration base: `7d912d5be8528f80df0122259d24130c6f394df9`
- Diff surface: **one file** under `concurrency/shared_state.rs` (+ this PR plan doc + optional evidence doc)
- Sibling conflict risk: low (C1 injection, C2 configuration, C4 input-validation are separate seams)
- Note for integration branch: Phase 3 integrator branch when opened

---

## Impact

| Area | Impact |
|------|--------|
| **Performance** | Neutral/slightly better (SI prefilters retained; call_facts only when 368/821 prefilters pass) |
| **Behavior** | Emit spans on Setenv/RLock call sites for 368/821; same true/false positive shape outside corpus paths |
| **Pack membership** | Unchanged until integrator adds fixture-only maturity for the five rules |
| **Dependencies** | None |

---

## Closes

- Closes [#114](https://github.com/chinmay-sawant/codehound/issues/114)
- Relates to [#105](https://github.com/chinmay-sawant/codehound/issues/105)

---

## Reviewer checklist

- [ ] Only `concurrency/shared_state.rs` (+ plans PR handoff / evidence) edited (no maturity/index/manifest/audit)
- [ ] Fixture oracle preserved for CWE-366/368/421/820/821
- [ ] `toctou.rs` (CWE-367) untouched
- [ ] No channel/goroutine data-flow inference introduced
- [ ] Disposition proposals clear for integrator
- [ ] Canary command and hit totals recorded
- [ ] PR assignee + labels documentation+enhancement
- [ ] Integration base SHA `7d912d5be8528f80df0122259d24130c6f394df9`

## Related issues

- Closes #114
- Relates to #105

