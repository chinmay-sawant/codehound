# Enhanced Patterns — Implementation Order

> **Parent:** `plans/v2.0.0/enhanced-patterns/README.md`
> **Status:** Plan only

---

## Why this order

1. **Tighten first** — existing rule IDs already appear in docs/baselines; better matching pays off immediately without catalogue churn.
2. **High-value new rules next** — clone / re-copy / compress pool / PEM parse.
3. **Loop-invariant & string chains** — good precision, medium impact.
4. **Optional parallel-tiny fan-out last** — precision risk.

---

## Phase A — Shared hot-path helper (0.5 day)

**File:** `src/lang/go/detectors/perf/common.rs` (or adjacent)

- [ ] Centralize `is_hot_function(name|source_window) -> bool` used by tighten + new rules
- [ ] Name heuristics (non-exhaustive): `Handle`, `Serve`, `Write`, `Encode`, `Decode`, `Build`, `Generate`, `Render`, `Compress`, `Sign`, `Marshal`, `Emit`, `Serialize`
- [ ] Loop membership remains primary signal; names are secondary
- [ ] Unit-test the helper if pure

**Exit:** Helper used by at least one tightened detector without behavior regression.

---

## Phase B — Tighten batch (days 1–4)

Order inside phase (dependencies first):

| Step | Item | Ref |
|------|------|-----|
| B1 | PERF-215 pre-size (name-agnostic) | `02` T6 |
| B2 | PERF-217 static recompute (drop HTTP-only) | `02` T7 |
| B3 | PERF-027 pool miss (non-HTTP + Builder) | `02` T2 |
| B4 | PERF-192 map size hint | `02` T5 |
| B5 | PERF-054 Builder reset (general domain) | `02` T4 |
| B6 | PERF-018 + groundwork for 225 | `02` T1 |
| B7 | PERF-032 conversion chains | `02` T3 |
| B8 | PERF-218 / 219 pool quality | `02` T8–T9 |
| B9 | PERF-109 lite | `02` T10 |

**PR shape:** Prefer 2–3 PRs (B1–B3, B4–B6, B7–B9) to keep review small.

**Exit:**

```bash
cargo test --test go_perf_detector_integration
cargo test --test go_perf_ruleset_audit
```

- [ ] Phase B green
- [ ] At least one non-HTTP fixture per tightened rule where applicable

---

## Phase C — New core rules (days 5–10)

| Step | Rule | Depends on |
|------|------|------------|
| C1 | PERF-225 redundant large clone | B6 helpful |
| C2 | PERF-226 post-producer re-copy | C1 patterns reusable |
| C3 | PERF-227 compress writer without pool | B3 hot-path helper |
| C4 | PERF-231 PEM/key parse on hot path | — |
| C5 | PERF-229 intermediate string → append | B7 |
| C6 | PERF-230 pure call loop-invariant | B9 |
| C7 | PERF-232 merge decision / ship | C4 |

**Chunk work at C1 start:**

- [ ] Add `ruleset/golang/chunks/perf-225-232.json` (or similar)
- [ ] Fix any hard-coded max-id == 224 in tests/build

**Exit:**

```bash
cargo test --test go_perf_detector_integration
cargo test --test go_perf_registry_generation
cargo test --test fixture_manifest_integration_inventory
```

- [ ] Core IDs 225–231 (and 232 if kept) green

---

## Phase D — Optional / defer (0.5–1 day)

- [ ] Spike PERF-228 tiny fan-out — ship or document defer in this file
- [ ] Fold-or-drop optional Grow/`[]byte` IDs (233+)
- [ ] Noise scan on a medium Go repo (stdlib-heavy library, not only fixtures)

---

## Phase E — Closeout

- [ ] Update `plans/v2.0.0/enhanced-patterns/README.md` status → **Shipped** / partial
- [ ] Checkboxes in `02` / `03` reflected
- [ ] Optional: one-line pointer from `pending-work/02-perf-detectors-remaining.md` → this folder (residue)
- [ ] Optional: note in CHANGELOG under Unreleased

**Folder-level DoD** (from README):

- [ ] Gap matrix reviewed
- [ ] Tighten fixtures go beyond toy shapes
- [ ] New rules in chunks + registry + detectors + fixtures + manifest
- [ ] Integration + audit tests green
- [ ] Spot-scan non-web buffer-heavy path shows clone/grow/pool/static findings

---

## Risk register

| Risk | Mitigation |
|------|------------|
| Noise from dropping HTTP gate on 217 | Require loop **or** strong hot name; keep Once/package-var suppress |
| 225/226 overlap double-reporting | Prefer one finding per site; 226 windows after compress/Bytes only |
| 227 flags one-shot scripts | Suppress `main`-only single call if noisy |
| 231 flags legitimate per-request mTLS load | Suppress obvious `Load*` startup; document residual |
| Max-id hardcodes break CI | Grep `224` before C1 merge |

---

## Out of scope (do not schedule here)

- Compression level policy (BestSpeed)
- Third-party compress library recommendations
- GOMAXPROCS / GOMEMLIMIT
- Product compliance (PDF/A, signatures required, workload mix)
- CWE / BP catalogue changes
- Auto-`--fix` for new rules (can follow later in `implement-fix.md`)

---

## Suggested commit/PR titles

```
perf(tighten): broaden PERF-215/217/027 hot-path matching
perf(tighten): map hints and builder reset outside HTTP
perf(rules): add PERF-225/226 large-buffer clone and re-copy
perf(rules): add PERF-227 compress writer pool miss
perf(rules): add PERF-231 PEM parse on hot path + PERF-229/230
```

---

## Quick reference — files likely touched

```
ruleset/golang/chunks/perf-*.json
src/lang/go/detectors/perf/common.rs
src/lang/go/detectors/perf/registry/registry.general_perf.toml
src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse/caching_and_allocation.rs
src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse/maps_and_slices.rs
src/lang/go/detectors/perf/domains/general_perf/allocations_and_reuse/buffer_pooling.rs
src/lang/go/detectors/perf/domains/request_path/strings_and_copies.rs
src/lang/go/detectors/perf/domains/request_path/crypto_and_keys.rs
tests/fixtures/go/perf/PERF-*-{safe,vulnerable}.txt
tests/fixtures/manifest.toml
tests/go_perf_ruleset_audit.rs   # if max-id asserted
```
