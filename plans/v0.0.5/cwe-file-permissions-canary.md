# v0.0.5 — CWE File-Permissions Phase 3 Canary and Dispositions

> **Parent plan:** [`cwe-file-permissions-trust.md`](./cwe-file-permissions-trust.md)  
> **Issue:** [#88](https://github.com/chinmay-sawant/codehound/issues/88) (Phase 3 of epic [#85](https://github.com/chinmay-sawant/codehound/issues/85))  
> **Phase 1 evidence:** [`cwe-file-permissions-evidence.md`](./cwe-file-permissions-evidence.md) ([#86](https://github.com/chinmay-sawant/codehound/issues/86))  
> **Parent audit:** [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §1.3 promotion bar; §2.11 sibling inventory  
> **Branch:** `chore/cwe-file-perm-phase3-canary`  
> **Status:** Phase 3 complete — real-module canary recorded; keep/quarantine/narrow/delete **frozen**  
> **Date:** 2026-07-20  
> **CodeHound source revision (this branch tree):** `e9485cb81d303382fd50638252f0c63c1bca0c8e` (`origin/master` detectors; **pre–Phase 2 merge**)

---

## Purpose

Run a release-binary canary of the six access-control file-permission siblings against the
pinned real Go modules and freeze an explicit disposition per rule. Zero useful hits alone is
**not** a delete or promote signal.

**Parallel work note:** Phase 2 (`fix/cwe-file-perm-phase2-detectors`, issue [#87](https://github.com/chinmay-sawant/codehound/issues/87))
may change detectors and maturity on a sibling branch. This canary is frozen on **this branch’s
tree** (master detectors at `e9485cb`). Integration must **re-canary after merge** if detector
emit paths change; maturity quarantine applied in Phase 2 does not alter `--profile all --only`
hit counts.

---

## Method

```sh
cargo build --release --locked

target/release/codehound TARGET --profile all \
  --only CWE-276,CWE-277,CWE-278,CWE-279,CWE-281,CWE-921 \
  --format json --json-envelope --no-fail --no-cache
```

Binary: `codehound 0.1.0` built from this worktree (`target/release/codehound`).

### Target path resolution

| Logical target | Path used | Notes |
|----------------|-----------|--------|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | External sibling checkout (present) |
| monsoon | `/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon` | Main-repo `real-repos/` (present) |
| go-retry | `/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry` | Main-repo `real-repos/` (present) |

**Missing in this worktree:** `real-repos/` is **not** checked out / linked under the isolated
worktree root. Scans used the absolute paths above (same revisions and file counts as prior
CWE trust canaries in `cwe-catalog-trust-audit.md`). No target was blocked.

---

## Canary table — 2026-07-20

| Repository | Path | Git revision | Files scanned (`stats.files_scanned`) | Files skipped | Findings (six-rule) |
|---|---|---|---:|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 383 | **0** |
| monsoon | `/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 20 | **0** |
| go-retry | `/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 8 | **0** |
| **Total** | | | **126** | 411 | **0** |

Envelope summary (all three runs): `findingCount=0`, `errorCount=0`, `findings=[]`.

### Findings by rule

| Rule | gopdfsuit | monsoon | go-retry | Total | Classification |
|------|----------:|--------:|---------:|------:|----------------|
| CWE-276 | 0 | 0 | 0 | 0 | — (no hit) |
| CWE-277 | 0 | 0 | 0 | 0 | — (no hit) |
| CWE-278 | 0 | 0 | 0 | 0 | — (no hit) |
| CWE-279 | 0 | 0 | 0 | 0 | — (no hit) |
| CWE-281 | 0 | 0 | 0 | 0 | — (no hit) |
| CWE-921 | 0 | 0 | 0 | 0 | — (no hit) |

No actionable / narrower-policy / FP / duplicate classifications — **no findings to classify**.

### Owner comparison (taint / PERF / BP / staticcheck)

**Skipped:** owner-duplicate comparison applies only when findings appear. Zero hits ⇒ no
cross-owner review required for this canary.

### Corpus API context (manual, non-finding)

Ripgrep on the three trees shows production-shaped file APIs **without** the museum co-signals
that gate these detectors:

| Pattern class | Presence on canary modules | Why current detectors stay silent |
|---------------|----------------------------|-------------------------------------|
| `os.WriteFile(..., 0644)` / `0o644` | gopdfsuit tests + samples; monsoon recorder | Mode is not exact `"0666"` / `"0777"`; no session / ParseUint museum gates |
| `os.MkdirAll(..., 0755)` / `0o755` | gopdfsuit | Not `"0777"`; no `syscall.Umask(0)` co-presence |
| `os.Create` | gopdfsuit `mem.prof`; monsoon logfile | No exact `io.Copy(out, in)` co-shape |
| `os.OpenFile` | monsoon key log `0o600` | Mode is not `os.FileMode(hdr.Mode)` formula |
| `/tmp/integration.key` | absent | CWE-921 path literal never present |
| `syscall.Umask` | absent on all three | CWE-277 pair never forms |

This context supports **keep / quarantine**, not delete: the APIs exist in real code, but the
emit gates are corpus-tight (or, for CWE-277, a rare umask+0777 pair that did not appear).

---

## Frozen dispositions (Phase 3 gate)

Evidence stack: Phase 1 source review ([`cwe-file-permissions-evidence.md`](./cwe-file-permissions-evidence.md))
+ fixture oracle multiset + this zero-hit canary. Maturity **application** is Phase 2’s code
change; this section freezes the **catalog decision** Phase 3 is authorized to make.

| Rule | Frozen disposition | Maturity intent | Rationale | Revisit condition |
|------|--------------------|-----------------|-----------|-------------------|
| **CWE-276** | **fixture-only quarantine** | FixtureOnly | `WriteFile`+`0666` call-facts still require session co-signals (`sessions` / `session_data` / `X-Session-Data`). Canary 0/126. | General sensitive-artifact path class without session museum names; real-module hit review |
| **CWE-277** | **keep Heuristic** | Heuristic (not Structural) | Fully call-facts `Umask(0)` + `MkdirAll(..., 0777)`; production-shaped; **no** §1.3 real-module hit; zero canary ≠ delete or promote | Real-module actionable hit + mode-variant / scope negatives meeting §1.3 |
| **CWE-278** | **fixture-only quarantine** | FixtureOnly | Exact `os.FileMode(hdr.Mode)` mode-arg formula; no generalized archive-header mode fact. Canary 0/126. | Call-facts / AST for “mode derived from archive header field” without exact identifier text |
| **CWE-279** | **fixture-only quarantine** | FixtureOnly | `ParseUint(` + `WriteFile`+`0777` co-presence only — no parse→mode dataflow. Canary 0/126. | Dataflow from parsed mode to write mode with ignored-user-mode proof |
| **CWE-281** | **fixture-only quarantine** | FixtureOnly | `os.Create` + exact `io.Copy(out, in)` without `info.Mode()`; generic create/copy would mass-FP. Canary 0/126. | Generalized copy callee + permission-preservation negative without fixed `out`/`in` names |
| **CWE-921** | **fixture-only quarantine** | FixtureOnly | Corpus path `/tmp/integration.key` + `0644` (+ WriteFile); no general secret classification. Canary 0/126. | Sensitive-path classifier or taint-backed secret storage proof |

### Explicit non-decisions

| Option | Applied? | Why |
|--------|----------|-----|
| **delete** any rule | **No** | Zero hits are not deletion evidence; fixtures remain regression oracles |
| **narrow** detector further | **No** (this phase) | Current gates already corpus-tight; further narrow only if FP appears post-generalization |
| **promote Structural** | **No** | Even CWE-277 fails §1.3 (no reviewed real-module actionability / broader negatives) |
| **leave undecided** | **No** | Every ID has an explicit disposition + revisit condition |

### Agreement with decision threshold (§3.2)

- **Fixture-only set (276/278/279/281/921):** fixture oracle fires only on museum shapes; source review shows corpus co-signals; canary 0/126. Quarantine is agreed across all three inputs. Preserve fixtures.
- **CWE-277 keep Heuristic:** generalized call-facts; canary does not supply a hit to promote; do not widen modes (`0o777`, alternate umask) without a false-positive budget. Stronger proof deferred.
- Maturity/profile code changes are **accepted as disposition-aligned** when Phase 2 lands the `is_fixture_only` updates that match this freeze; this Phase 3 PR does **not** edit `maturity.rs` or detectors (out of scope).

---

## Artifact / validation

| Check | Result |
|-------|--------|
| `cargo build --release --locked` | OK (this worktree) |
| Three-target six-rule canary | **0 / 126** findings |
| Detector / maturity code edits | None (Phase 3 docs-only) |
| `make lint` | N/A — no Rust touched |

---

## Integration / follow-ups

1. After Phase 2 merges, re-run the same command shape on the integrated tree if emit paths or argument matching changed (Phase 2 kept oracle-safe; hit count expected unchanged under `--profile all --only`).
2. Phase 4 owns audit `§2.12` narrative closure and plan status roll-up (`cwe-catalog-trust-audit.md`).
3. Do not open structural promotion for CWE-277 without a new scoped issue and a real-module hit review.
