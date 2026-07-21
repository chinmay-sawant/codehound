# Evidence — R2 sensitive_fields trust (CWE-201 / CWE-213)

> **Issue:** #159 · **Epic:** #151 · **Mega-integration:** epic #151 R1–R4 integration (when present)  
> **Branch:** `chore/cwe-trust-sensitive-fields`  
> **Integration base:** `0ff071f` (origin/master at branch creation)  
> **Owner seam:** `src/lang/go/detectors/cwe/domains/information_exposure/response_leaks/sensitive_fields.rs`  
> **Deferred from:** Phase 2 B2 (`metadata_leaks` only — see `plans/v0.0.5/pr-cwe-trust-response-leaks.md`)  
> **Date:** 2026-07-22

---

## Family inventory and selection

| Leaf | Rules | Approx. lines | Fixture coverage | Selected? |
|------|-------|---------------|------------------|-----------|
| `sensitive_fields.rs` | CWE-201, 213 | ~110 | stdlib + frameworks × vulnerable/safe | **Yes (R2)** |
| `metadata_leaks.rs` | CWE-209, 215, 756, 1230 | ~200 | stdlib + frameworks × vulnerable/safe | B2 sibling (done #108) |

R2 completes disposition for the deferred B2 sibling leaf only. No edits to
`metadata_leaks.rs` or other response-leak leaves.

---

## Generalized sinks vs exact response literals

| Rule | Response sink (call_facts) | Corpus co-signals (SI) | Literal-class? |
|------|---------------------------|------------------------|----------------|
| **CWE-201** | `c.JSON` or `json.NewEncoder(w).Encode` with arg `record` | `APIKey` / `TokenKey`; `type userRecord struct` / `type memberRecord struct` | **No** — production JSON APIs; field/type inventory gates noise |
| **CWE-213** | `c.JSON` or `json.NewEncoder(w).Encode` with arg `profile` | `Salary` / `Comp` | **No** — production JSON APIs; comp-field inventory |

Unlike B2 `metadata_leaks` (exact `fmt.Sprintf("db failure: %v", err)`, `FetchProfile` helper names, `X-Original-Name` header museum), this leaf already matches §2.2’s generalized response-sink shape. Residual trust work is field/type-name inventory and redaction-negative preservation, not sink generalization.

---

## Freeze inventory

| Rule | Fixtures | Maturity today | Profile eligibility today | Primary signals (frozen) | Negatives |
|------|----------|----------------|---------------------------|--------------------------|-----------|
| **CWE-201** | 4 files (frameworks + stdlib vulnerable/safe) | Heuristic (default; not in `is_fixture_only`) | Eligible via Heuristic for non-allow-list packs | **call_facts:** `c.JSON` / `json.NewEncoder(w).Encode` + arg `record`; SI: `APIKey` / `TokenKey` + record type | Safe: encodes `publicUser` / `publicMember` DTO (call-facts arg ≠ `record`) |
| **CWE-213** | 4 files | Heuristic (default) | Same | **call_facts:** `c.JSON` / `json.NewEncoder(w).Encode` + arg `profile`; SI: `Salary` / `Comp` | SI: `guestProfile{` / `directoryEntry{`; safe encodes redacted DTO |

**Source spans:**

| Rule | Span source |
|------|-------------|
| CWE-201 | `call.start_byte` of matching JSON response sink |
| CWE-213 | `call.start_byte` of matching JSON response sink |

**Shared surfaces not edited (worker contract):** `maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`, `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`, sibling detectors.

---

## Corpus signal classes

| Class | Examples | Rules |
|-------|----------|-------|
| Sensitive credential struct fields | `APIKey`, `TokenKey` | 201 |
| Internal record types | `type userRecord struct`, `type memberRecord struct` | 201 |
| Full record JSON response | `c.JSON(..., record)`, `json.NewEncoder(w).Encode(record)` | 201 |
| Redacted public DTO (negative) | `publicUser{`, `publicMember{` | 201 |
| Compensation profile fields | `Salary`, `Comp` | 213 |
| Full profile JSON response | `c.JSON(..., profile)`, `Encode(profile)` | 213 |
| Policy-specific redaction DTO (negative) | `guestProfile{`, `directoryEntry{` | 213 |

---

## Call-facts primary analysis

| Rule | Can call_facts be complete primary? | Decision |
|------|-------------------------------------|----------|
| CWE-201 | **Partially** — JSON sink + `record` arg is production-shaped; SI field/type inventory still required to avoid mass-FP on any struct with `APIKey` serialized under another binding name | **Keep call_facts primary** with SI prefilters; **keep Heuristic** |
| CWE-213 | **Partially** — JSON sink + `profile` arg is production-shaped; `Salary`/`Comp` inventory + redaction DTO negatives control noise | **Keep call_facts primary** with SI prefilters/negatives; **keep Heuristic** |

**No Structural promotion** — §1.3 bar not met (field/type-name co-signals remain required for emit; no reviewed real-module promotion evidence; fixtures use museum type/arg names).

---

## Per-rule disposition

| Rule | Disposition | Rationale |
|------|-------------|-----------|
| CWE-201 | **keep Heuristic** | Production JSON response sink (call_facts primary); field/type inventory co-signals intentional noise control; not fixture-only (no exact response literal museum) |
| CWE-213 | **keep Heuristic** | Production JSON response sink (call_facts primary); comp-field inventory + redaction DTO SI negatives; not structural |

---

## Oracle-safe detector rewrites (this PR)

File: `response_leaks/sensitive_fields.rs` only.

- **CWE-201 / CWE-213:** freeze comments documenting call_facts primary, SI co-signals/negatives, generalized-sink vs literal analysis, disposition; **no emit-path, span, or needle changes** (already emit at `call.start_byte`).

Fixture oracle preserved (vulnerable fire, safe silence). No fixture renames; no new proposed fixture files.

---

## Existing CWE / BP ownership neighbors

| Concern | Owner | Relation to this family |
|---------|-------|-------------------------|
| Error message / header metadata leaks | **metadata_leaks** (B2 / #108) | Sibling: exact error/body/header museum strings |
| Debug log secret material | **CWE-215** (metadata_leaks) | Same response_leaks parent; log sink not JSON |
| Secrets in config files | **secrets_in_config** (R1 / #158) | Out of scope — configuration domain |
| Sensitive fields logged | **BP-146** (`observability_config_pending.rs`) | BP observability, not CWE response leak |

---

## Proposed integrator changes (DO NOT apply on this branch)

### Maturity (`src/rules/maturity.rs`)

- **Do not** add CWE-201 or CWE-213 to `is_fixture_only`.
- **Do not** promote either rule to Structural.
- Leave both as default **Heuristic** (integrator may add inline comments when epic #151 lands).

### NEEDLES labels (`source_index.rs`)

| Needle | Proposed label |
|--------|----------------|
| `APIKey` | co-signal (CWE-201 sensitive field inventory) |
| `TokenKey` | co-signal (CWE-201 sensitive field inventory) |
| `type userRecord struct` | `fixture-literal` (CWE-201 frameworks record type) |
| `type memberRecord struct` | `fixture-literal` (CWE-201 stdlib record type) |
| `Salary` | co-signal (CWE-213 comp field inventory) |
| `Comp` | co-signal (CWE-213 comp field inventory) |
| `guestProfile{` | `negative-gate` (CWE-213 redaction DTO safe path) |
| `directoryEntry{` | `negative-gate` (CWE-213 redaction DTO safe path) |

### Fixture / manifest / findings-oracle

- No new fixtures; no manifest wiring.
- Findings-oracle impact: none expected on existing 8 fixture files.

### Canary command (integrator re-run after batch merge)

```sh
cargo build --release --locked
ONLY="CWE-201,CWE-213"
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/gorl \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/no-mistakes; do
  echo "=== $t ==="
  target/release/codehound "$t" --profile all --only "$ONLY" \
    --format json --json-envelope --no-fail --no-cache 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print('findings', d.get('findingCount')); print('files', d.get('stats',{}).get('files_scanned')); print([(f.get('rule_id'), f.get('file'), f.get('line')) for f in d.get('findings',[])])"
done
```

---

## Canary results (worker pre-integration) — 2026-07-22

| Repository | Revision | Files scanned | Findings |
|---|---|---:|---:|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 0 |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |
| gorl | `ec54aaf15ce4d0f3f8014eac2548986c91d0f001` | 28 | 0 |
| no-mistakes | `0a2c82f993b9467c5ab84992313dfd13b66830af` | 222 | 0 |

**Totals:** 376 files scanned · 0 findings. Per-rule: CWE-201 ×0, CWE-213 ×0.

---

## Handoff checklist for integrator

- [ ] Confirm Heuristic keep for CWE-201 and CWE-213 (no fixture-only quarantine)
- [ ] Optional NEEDLES labels above (non-blocking)
- [ ] Re-run two-rule canary on integrated tree
- [ ] Update audit ledger when epic #151 R1–R4 integration lands
- [ ] No `manifest.toml` / profile allow-list edits expected from this worker
