# chore(cwe): audit injection residual trust (C1)

## Summary

- Phase 3 slice **C1** — select, freeze, and disposition one non-taint injection
  subfamily under `src/lang/go/detectors/cwe/domains/injection/`.
- **Selected:** `header.rs` (**CWE-93** — CRLF into `Location` header).
- **Deferred sibling:** `resource.rs` (**CWE-619**, **CWE-917**) — pure SourceIndex
  museums; not this worktree.
- Confirmed **no taint-core duplication** (CWE-22/78/79/89/90/91).
- Oracle-safe detector cleanup: single `call_facts` walk (proof + span); freeze
  documentation only. Emit oracle unchanged.
- Propose **keep Structural** for CWE-93 (already allow-listed). Integrator owns
  maturity / NEEDLES / ledger.

---

## Motivation / context

Phase 3 slice **C1** of [`parallel-catalog-program.md`](./parallel-catalog-program.md)
§3.1 / issue [#112](https://github.com/chinmay-sawant/codehound/issues/112).
Relates to epic [#105](https://github.com/chinmay-sawant/codehound/issues/105).
Superseded later by single Phase 3–5 integration branch
`chore/epic-105-phase345-integration` when present.

**Integration base SHA:** `7d912d5be8528f80df0122259d24130c6f394df9`  
**Branch:** `chore/cwe-trust-injection-residual`  
**Structural bar:** [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §1.3

Owner seam: `src/lang/go/detectors/cwe/domains/injection/`

**Selected subfamily:** `header.rs` (CWE-93)

**Deferred sibling:** `resource.rs` (CWE-619, CWE-917)

---

## Subfamily selection rationale

| Candidate | Rules | Why select / defer |
|-----------|-------|--------------------|
| **header** (selected) | CWE-93 | Bounded sink (`c.Header` / `w.Header().Set` + `"Location"`); safe negatives (CR+LF `strings.ReplaceAll`); already call-facts + `input_bindings` primary; stdlib + frameworks fixture pairs; production-shaped non-taint residual |
| resource (deferred) | CWE-619, CWE-917 | Pure SI museums (`rows, err := db.Query(`, `{{.Title}} where ` + `+ expr`); CWE-619 is cursor-lifecycle more than injection; CWE-917 is exact fixture template formula — separate residual disposition later |

### Why header over resource

1. **Plan §3.1** asks for a subfamily with a **bounded sink** and **safe-negative set** — CWE-93 has both as generalized facts, not corpus identifiers.
2. **Non-duplication vs taint-core** is clearest for CRLF header injection (orthogonal to path/command/XSS/SQL/LDAP/XML taint sinks).
3. **Existing Structural allow-list** — audit reaffirms rather than invents maturity.
4. **Oracle-safe cleanup only** — no emit expansion; resource museums need fixture-only quarantine and stay out of this slice.

---

## Non-duplication vs taint-core

| Family | IDs | Ownership |
|--------|-----|-----------|
| Taint-core | CWE-22, 78, 79, 89, 90, 91 | Graph-based path / OS command / XSS / SQL / LDAP / XML injection via `taint/` |
| CWE-93 (this slice) | CWE-93 | Local facts: user-controlled binding → Location header write without CR+LF strip |
| Deferred resource | CWE-619, 917 | SI co-presence museums; not taint-core; not rewritten here |

CWE-93 does **not** consult the taint graph, does **not** share sink classification with taint-core, and does **not** emit under those rule IDs. Header CRLF is intentionally a separate residual boundary.

---

## Evidence freeze

### CWE-93 — Improper Neutralization of CRLF Sequences

| Axis | Frozen state |
|------|----------------|
| Primary | `input_bindings` (`UserControlled`) + `call_facts` `c.Header` \| `w.Header().Set` with arg0 `"Location"` and value using binding |
| Negatives | both `strings.ReplaceAll(binding, "\r", "")` and `… "\n", ""` (scratch_contains) |
| Emit span | Location header call site (`call_facts.start_byte`) |
| SourceIndex | **none** (no SI needles) |
| Fixtures | stdlib + frameworks vulnerable/safe pairs |
| Maturity (current) | **Structural** (`is_structural_cwe`) |
| Pack | Security pack member (`pack.rs`) |

**Corpus vs real sink:** production-shaped Location-header write + request-derived binding. Intentionally **not** all header names (noise control). Safe path requires both CR and LF strip.

### Deferred inventory (`resource.rs`) — not changed

| Rule | Primary (SI) | Negatives | Proposed later |
|------|--------------|-----------|----------------|
| CWE-619 | `rows, err := db.Query(` ∧ `rows.Next()` ∧ ¬`defer rows.Close()` | `defer rows.Close()` | fixture-only (exact `rows` formula) |
| CWE-917 | `template.New("report").Parse(src)` ∧ `{{.Title}} where ` ∧ `+ expr` | `reportTemplate` / `reportTemplatePure` | fixture-only (exact template corpus) |

---

## Changes

### Detector (`header.rs` only)

| Rule | Change |
|------|--------|
| CWE-93 | Freeze doc-comment; collapse double `call_facts` walk (`any` + `find`) into single `find` for proof + emit span. Behavior oracle-preserving. |

### Explicitly not changed (integrator / out of scope)

- `src/rules/maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`
- `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`
- Sibling C2–C4; `resource.rs` (CWE-619 / CWE-917)
- Taint-core rewrites
- No new fixture files; no fixture renames

---

## Proposed disposition (integrator)

| Rule | Current maturity | Proposed disposition | Rationale |
|------|------------------|----------------------|-----------|
| **CWE-93** | Structural | **keep Structural** | Call-facts + UserControlled binding + dual CRLF strip negative; no SI corpus needles; security-pack member; oracle stable. Do **not** broaden to arbitrary headers without FP review. Do **not** move into taint-core. |
| CWE-619 (deferred) | Heuristic default | **fixture-only** (later) | Exact `rows` Query/Next/Close formula |
| CWE-917 (deferred) | Heuristic default | **fixture-only** (later) | Exact `template.New("report")` + `{{.Title}} where ` corpus |

### Integrator proposals

1. **maturity.rs:** no change for CWE-93 (already Structural). Optionally add a unit-test assert `maturity_for("CWE-93") == Structural` if missing. When a later resource residual lands, add `"CWE-619"` / `"CWE-917"` to `is_fixture_only`.
2. **source_index.rs:** no NEEDLES for CWE-93 (does not use SI). Resource needles (later): `rows, err := db.Query(`, `rows.Next()`, `defer rows.Close()`, `template.New("report").Parse(src)`, `{{.Title}} where `, `+ expr`, `reportTemplate`, `reportTemplatePure`.
3. Append dated disposition to `cwe-catalog-trust-audit.md` (e.g. §2.x Injection residual — CWE-93) with canary table below.
4. Check off §3.1 boxes in `parallel-catalog-program.md` only after integration review.
5. Phase 3–5 combined canary should include `CWE-93` in the batch `--only` list.
6. Do **not** create integration yourself — single mega-integration `chore/epic-105-phase345-integration` later.

### Fixtures / oracle impact

- No fixture additions or renames.
- Vulnerable fixtures still fire; safe fixtures still silence.
- Emit span remains the Location header call site (single find vs prior any+find — same site).

---

## Canary (release binary, this worktree)

```sh
cargo build --release --locked
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
  /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
  /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry; do
  echo "=== $t ==="
  target/release/codehound "$t" --profile all \
    --only CWE-93 \
    --format json --json-envelope --no-fail --no-cache 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print('findings', len(d.get('findings',[])), 'files', d.get('stats',{}).get('files_scanned'))"
done
```

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | **0** |
| monsoon | `codehound/real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | **0** |
| go-retry | `codehound/real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | **0** |

**Totals:** 126 scanned files (78+43+5). Per-rule: CWE-93 ×0.

Worktree note: this isolated worktree has no local `real-repos/`; canary uses absolute paths under the main checkouts (same revs as prior catalog canaries).

**Decision:** reaffirm **Structural** for CWE-93. Quiet canary is acceptable — proof boundary is generalized facts (call_facts Location sink + UserControlled binding + dual CRLF strip), not a hit-rate promotion. Do not broaden header names; do not open resource museums in this PR. §1.3 real-module-hit bullet remains thin on this corpus; keep Structural on production-shaped evidence already allow-listed; do not demote solely for zero canary hits.

---

## Validation

```sh
make lint
cargo test --locked --test go_cwe_detector_fixtures
make test
git diff --check
```

- `make lint` — green
- `go_cwe_detector_fixtures` — 4 passed (oracle preserved; CWE-93 pairs fire/silence)
- `make test` — green (see commit / CI)
- `git diff --check` — clean

---

## Impact

- Owned seam only: `injection/header.rs` + this PR body.
- No shared-surface edits; integrator applies maturity/audit/ledger when Phase 3–5 integrate.
- Superseded by `chore/epic-105-phase345-integration` when present.

## Test plan

- [x] `make lint`
- [x] `cargo test --locked --test go_cwe_detector_fixtures`
- [x] `make test` (re-run if needed at commit time)
- [x] `git diff --check`
- [x] Release canary `--only CWE-93` on gopdfsuit, monsoon, go-retry (0/126)
- [x] Confirm CWE-93 vulnerable fixtures fire and safe fixtures silence

## Related issues

- Closes #112
- Relates to #105

