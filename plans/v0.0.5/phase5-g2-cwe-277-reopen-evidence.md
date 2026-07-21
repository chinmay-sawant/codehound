# Phase 5 G2 — CWE-277 Structural reopen evidence

> **Issue:** [#138](https://github.com/chinmay-sawant/codehound/issues/138) · Relates to epic [#136](https://github.com/chinmay-sawant/codehound/issues/136)  
> **Gate:** [`phase5-gated-work.md`](./phase5-gated-work.md) G2 · audit [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §1.3  
> **Prior canary:** [`cwe-file-permissions-canary.md`](./cwe-file-permissions-canary.md) (Phase 3 / #88 — 0/126 on three modules)  
> **Detector:** `detect_cwe_277` in `src/lang/go/detectors/cwe/domains/access_control/file_permissions/file_modes.rs`  
> **Corpus pins:** [`canary-corpus.md`](./canary-corpus.md) · [`canary-corpus-pins.json`](./canary-corpus-pins.json)  
> **Branch:** `chore/phase5-g2-cwe-277`  
> **Date:** 2026-07-22  
> **CodeHound base:** `9e61e807358a1b9a4f5a03cf3b2abecbe30281a2` (`origin/master`)  
> **Outcome:** **Keep Heuristic** — **not** Structural-promoted

---

## Purpose

G2 reopens **Structural** promotion for `CWE-277` only when all reopen criteria in
[`phase5-gated-work.md`](./phase5-gated-work.md) G2 hold — especially a **reviewed
actionable real-module hit** plus mode/scope negatives under audit §1.3.

This record:

1. Re-runs the **release-binary** canary with `--only CWE-277 --profile all` on the
   **expanded** decision-quality corpus (historical trio + **gorl** + **no-mistakes**).
2. Records zeros / hits and corpus API context (manual, non-finding).
3. Freezes whether maturity may flip to Structural and whether oracle-safe mode
   variants (`0o777`) should land.

**Explicit non-action:** do **not** promote without a reviewed real-module hit.
Zero-hit canary alone is not promotion or deletion evidence.

---

## Detector snapshot (unchanged)

| Field | Value |
|-------|--------|
| Function | `detect_cwe_277` |
| Primary signal | `call_facts`: any `syscall.Umask` with first arg exact `"0"` **and** any `os.MkdirAll` with second arg exact `"0777"` |
| Emit span | `os.MkdirAll` call site |
| SourceIndex | None (no SI prefilter) |
| Maturity today | **Heuristic** (`src/rules/maturity.rs`) |
| Mode literals accepted | Decimal `0777` only — **not** `0o777` / alternate umask |

Safe fixtures use `Umask(027)` + `MkdirAll(..., 0750)`. Vulnerable fixtures use
`Umask(0)` + `MkdirAll(..., 0777)` (stdlib + frameworks variants).

---

## Canary method

```sh
cargo build --release --locked --bin codehound

BIN=target/release/codehound
# Paths: gopdfsuit external; real-repos from main checkout (worktree has no local real-repos/)
for t in \
  /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
  /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
  /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry \
  /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/gorl \
  /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/no-mistakes
do
  echo "=== $t ==="
  "$BIN" "$t" --profile all --only CWE-277 \
    --format json --json-envelope --no-fail --no-cache
done
```

Equivalent helper (when `CODEHOUND_CORPUS_ROOT` / `CODEHOUND_GOPDFSUIT` point at the
same trees):

```sh
scripts/canary/run_decision_corpus.sh only --only CWE-277
```

Binary: `codehound 0.1.0` built from this worktree at base SHA above.

---

## Canary table — 2026-07-22

| Repository | Path | Git revision | Files scanned (`stats.files_scanned`) | Files skipped | Findings (CWE-277) |
|---|---|---|---:|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 383 | **0** |
| monsoon | `…/codehound/real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 20 | **0** |
| go-retry | `…/codehound/real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 8 | **0** |
| gorl | `…/codehound/real-repos/gorl` | `ec54aaf15ce4d0f3f8014eac2548986c91d0f001` | 28 | 40 | **0** |
| no-mistakes | `…/codehound/real-repos/no-mistakes` | `0a2c82f993b9467c5ab84992313dfd13b66830af` | 222 | 320 | **0** |
| **Total** | | | **376** | 771 | **0** |

Envelope summary (all five runs): `findingCount=0`, `errorCount=0`, `findings=[]`.

### Findings by rule

| Rule | gopdfsuit | monsoon | go-retry | gorl | no-mistakes | Total | Classification |
|------|----------:|--------:|---------:|-----:|------------:|------:|----------------|
| CWE-277 | 0 | 0 | 0 | 0 | 0 | **0** | — (no hit) |

No actionable / narrower-policy / FP / duplicate classifications — **no findings to review**.

### Comparison to prior Phase 3 canary

| Corpus | Files scanned | CWE-277 findings |
|--------|-------------:|-----------------:|
| Phase 3 trio (2026-07-20) | 126 | 0 |
| Expanded five-module (this pass) | **376** | **0** |

Expanded set adds **gorl** (28) + **no-mistakes** (222). Still silent.

---

## Corpus API context (manual, non-finding)

Ripgrep on non-test `.go` (excluding vendor) shows production-shaped file APIs
**without** the umask-clear + world-writable MkdirAll pair:

| Pattern class | Presence on expanded corpus | Why CWE-277 stays silent |
|---------------|----------------------------|---------------------------|
| `os.MkdirAll(..., 0755)` / `0o755` | gopdfsuit; no-mistakes (many) | Mode is not exact `"0777"`; no co-present `Umask(0)` |
| `os.MkdirAll(..., info.Mode().Perm())` | no-mistakes `common_fs.go` | Mode is not literal `0777` |
| `syscall.Umask` | **no-mistakes only** — `Umask(0o077)` in `internal/ipc/transport_unix.go` | Restrictive mask (`0o077`), **not** clear-to-zero `"0"`; no paired `MkdirAll(..., 0777)` |
| `syscall.Umask(0)` | **absent** on all five modules | Clear-umask half of the pair never forms |
| `MkdirAll(..., 0777)` / `0o777` | **absent** on all five modules | World-writable mkdir half never forms |

This supports **keep Heuristic**, not promote and not delete: the APIs exist in real
code (mkdir, occasional umask), but the production-shaped **pair** that the detector
requires did not appear on the pinned corpus.

---

## Mode-variant widening decision (`0o777`)

Issue #138 allows **optional** oracle-safe acceptance of `0o777` (and similar) **only if**
fixtures still pass and matching fixture coverage is added.

| Option | Applied? | Why |
|--------|----------|-----|
| Accept `0o777` as MkdirAll mode | **No** | No real-module hit to justify wider FN surface; decimal `0777` remains the fixture oracle |
| Accept alternate umask forms (`0o000`, etc.) | **No** | Same; corpus shows `0o077` (restrictive) which must stay negative |
| Add vulnerable fixture with `0o777` only | **No** | Widening without §1.3 real-module bar is out of scope for this evidence pass |

**Remaining gap:** call-facts store raw argument text; Go source often uses `0o777` /
`0o000`. Until a reviewed hit (or deliberate FN-budget decision) lands, mode taxonomy
stays narrow.

---

## G2 reopen criteria check (audit §1.3)

| # | Criterion | Status |
|---|-----------|--------|
| 1 | Reviewed **actionable** real-module hit | **Fail** — 0 findings / 376 files; no hit to classify |
| 2 | Broader mode-variant and scope **negatives** with bounded FP | **Not started** — deferred with mode widening (no hit to design against) |
| 3 | Primary emit meets §1.3 (AST/call facts primary) | **Partial** — already call_facts primary (`Umask`+`MkdirAll`); still exact mode/umask text, not a general permissive-mode classifier |
| 4 | Maturity table + profile eligibility in **same** change as promotion | **N/A** — no promotion |
| 5 | Scoped implementable issue (not wholesale FO reopen) | **This issue (#138)** records **keep Heuristic** — no Structural PR |

**Gate decision:** G2 remains **deferred**. `CWE-277` stays **Heuristic**. Do not edit
`maturity.rs` structural allow-list.

---

## Disposition freeze

| Field | Value |
|-------|--------|
| **CWE-277 maturity** | **Keep Heuristic** (not Structural) |
| **Detector code** | Unchanged |
| **Mode variants** | Unchanged (`0777` / `Umask(0)` only) |
| **Fixture-only siblings** (276/278/279/281/921) | Untouched — out of scope |
| **Code shipped** | Docs only |

### Reopen only if (updated)

A later pass finds **all** of:

1. At least one **reviewed actionable** finding on a pinned real module (or a justified
   new pin with documented review) for `Umask(0)` + world-writable mkdir (or a
   carefully generalized equivalent with FP budget).
2. Mode/scope **negatives** covering intentional shared dirs, restrictive umask
   (`0o077` style), and non-world modes (`0755` / `0o755`).
3. If mode text widens (`0o777`, etc.): matching vulnerable **and** safe fixtures;
   `cargo test --locked --test go_cwe_detector_fixtures` green.
4. Maturity flip to Structural in the **same** change as the evidence PR.
5. New scoped implement issue under epic #136 (do not reopen entire file-permissions
   FO set wholesale).

---

## What this PR does / does not do

| Does | Does not |
|------|----------|
| Record expanded five-module CWE-277 canary (0/376) | Promote CWE-277 to Structural |
| Freeze **keep Heuristic** with §1.3 criteria check | Widen mode/umask matching |
| Link gate trackers to this evidence | Touch FO siblings 276/278/279/281/921 |
| Satisfy honest G2 “evidence before promotion” | Change packs, profiles, or recommended pack |

---

## Validation (this branch)

| Check | Result |
|-------|--------|
| `cargo build --release --locked` | OK |
| Five-target CWE-277 canary | **0 / 376** findings |
| Detector / maturity code edits | None |
| Fixture oracle | Unchanged (no detector edit) |

---

## Sources

- [`phase5-gated-work.md`](./phase5-gated-work.md) G2  
- [`phase5-implementation-backlog.md`](./phase5-implementation-backlog.md) · epic #136 / child #138  
- [`cwe-file-permissions-canary.md`](./cwe-file-permissions-canary.md) · [`cwe-file-permissions-trust.md`](./cwe-file-permissions-trust.md)  
- [`cwe-file-permissions-evidence.md`](./cwe-file-permissions-evidence.md)  
- [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §1.3  
- [`canary-corpus.md`](./canary-corpus.md) · [`canary-corpus-pins.json`](./canary-corpus-pins.json)  
- Detector: `src/lang/go/detectors/cwe/domains/access_control/file_permissions/file_modes.rs`  
- Live trees under `real-repos/{gorl,monsoon,go-retry,no-mistakes}` and gopdfsuit (2026-07-22 scan)
