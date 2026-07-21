# chore(phase5): G2 CWE-277 structural gate evidence

## Summary

Docs-only G2 gate work for epic #136 / issue #138: re-run release-binary canary for
**CWE-277** with `--profile all --only CWE-277` on the **expanded** decision-quality
corpus (gopdfsuit, monsoon, go-retry, **gorl**, **no-mistakes**), record **0 findings /
376 scanned files**, and freeze **keep Heuristic** (no Structural promotion).
**No detector, maturity, or fixture changes.** Closes #138 · Relates to #136.

---

## Motivation / context

- Gate criteria: [`phase5-gated-work.md`](./phase5-gated-work.md) G2  
- Structural bar: [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §1.3  
- Prior file-permissions canary (#88): [`cwe-file-permissions-canary.md`](./cwe-file-permissions-canary.md) → 0/126 on three modules; CWE-277 kept Heuristic  
- Evidence (this PR): [`phase5-g2-cwe-277-reopen-evidence.md`](./phase5-g2-cwe-277-reopen-evidence.md)  
- Corpus pins: [`canary-corpus.md`](./canary-corpus.md)  
- Base SHA: `9e61e807358a1b9a4f5a03cf3b2abecbe30281a2`  
- Branch: `chore/phase5-g2-cwe-277`

G2 forbids Structural promotion without a reviewed **actionable real-module hit**.
This PR is the honest **evidence-before-promotion** pass on the expanded corpus.
Zero hits ⇒ remain Heuristic; do not invent mode-variant widening without a hit to
design the FP budget against.

---

## Changes

| Path | Role |
|------|------|
| `plans/v0.0.5/phase5-g2-cwe-277-reopen-evidence.md` | Canary table, criteria check, **keep Heuristic** freeze |
| `plans/v0.0.5/pr-phase5-g2-cwe-277.md` | This PR body |
| `plans/v0.0.5/phase5-gated-work.md` | Cross-link G2 evidence note |
| `plans/v0.0.5/phase5-implementation-backlog.md` | Mark #138 evidence recorded |

### Canary outcome (release binary)

```sh
cargo build --release --locked --bin codehound
target/release/codehound TARGET --profile all --only CWE-277 \
  --format json --json-envelope --no-fail --no-cache
```

| Module | Revision | Files scanned | CWE-277 findings |
|--------|----------|-------------:|-----------------:|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | **0** |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | **0** |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | **0** |
| gorl | `ec54aaf15ce4d0f3f8014eac2548986c91d0f001` | 28 | **0** |
| no-mistakes | `0a2c82f993b9467c5ab84992313dfd13b66830af` | 222 | **0** |
| **Total** | | **376** | **0** |

Corpus context: `MkdirAll` appears with `0755`/`0o755`; the only `syscall.Umask` on
the set is no-mistakes `Umask(0o077)` (restrictive). No `Umask(0)` + `MkdirAll(..., 0777)`
pair.

**Promoted to Structural:** no.

**Mode variants (`0o777`) shipped:** no (optional widening deferred with promotion).

---

## Out of scope (explicit)

- Structural promotion of CWE-277 / maturity.rs allow-list edits
- Detector mode/umask widening (`0o777`, alternate umask)
- Reopening fixture-only siblings CWE-276/278/279/281/921
- Bulk FO → Heuristic/Structural flips (G3)
- BP expansion, typed Go, taint ceilings, Python catalog (sibling G-rows)

---

## Integration

This branch is intended for later merge into `chore/epic-136-integration` when other
Phase 5 G-row children land. Prefer reviewing/merging the epic integration PR when
present; child PRs may be superseded.

---

## Impact

| Area | Impact |
|------|--------|
| **Performance** | None |
| **Memory** | None |
| **Behavior / correctness** | None (docs only) |
| **API / CLI** | None |
| **Dependencies** | None |
| **Binary size / build time** | None |
| **Packs / maturity** | Unchanged — CWE-277 remains Heuristic |

---

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| None | — |

---

## Test plan

- [x] Docs-only diff under `plans/v0.0.5/`
- [x] Release-binary canary executed on five pinned modules (see evidence file)
- [x] Hit table + disposition freeze recorded (**keep Heuristic**)
- [x] No source / ruleset / fixture changes → product `make test` not required for correctness of this PR
- [x] `make lint` / `cargo test --locked --test go_cwe_detector_fixtures` — optional regression; no Rust touched
- [ ] Reviewer confirms “keep Heuristic / no Structural without real hit” is unambiguous for agents

### Commands

```sh
cargo build --release --locked --bin codehound
# See plans/v0.0.5/phase5-g2-cwe-277-reopen-evidence.md for full five-target canary.
target/release/codehound /path/to/target --profile all --only CWE-277 \
  --format json --json-envelope --no-fail --no-cache
```

---

## Checklist

- [x] Summary + motivation complete
- [x] Impact table filled
- [x] Out of scope explicit
- [x] Closes #138 · Relates to #136
- [x] No maturity promotion without §1.3 real-module evidence
