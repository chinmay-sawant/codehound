# Evidence — R1 secrets_in_config trust (CWE-260 / CWE-455)

> **Issue:** #158 · **Epic:** #151 · **Mega-integration:** epic #151 R1–R4 integration (when present)  
> **Branch:** `chore/cwe-trust-secrets-in-config`  
> **Integration base:** `0ff071f` (origin/master at branch creation)  
> **Owner seam:** `src/lang/go/detectors/cwe/domains/configuration/secrets_in_config.rs`  
> **Deferred from:** Phase 3 C2 (`config_hardcoding` only — see `plans/v0.0.5/evidence-cwe-trust-configuration-residual.md`)  
> **Date:** 2026-07-22

---

## Family inventory and selection

| Leaf | Rules | Approx. lines | Fixture coverage | Selected? |
|------|-------|---------------|------------------|-----------|
| `secrets_in_config.rs` | CWE-260, 455 | ~110 | stdlib + frameworks × vulnerable/safe | **Yes (R1)** |
| `config_hardcoding.rs` | CWE-15, 472, 1051, 1067 | ~195 | stdlib + frameworks × vulnerable/safe | C2 sibling (done #113) |

R1 completes disposition for the deferred C2 sibling leaf only. No edits to
`config_hardcoding.rs` or other configuration leaves.

---

## Env-requiredness vs project-agnostic security contract

| Rule | Contract type | Analysis |
|------|---------------|----------|
| **CWE-260** | **Org/deployment policy** (env-requiredness) | Detects secret struct fields (`Password string` / `Secret   string`) loaded from disk config and used via `cfg.Password` / `cfg.Secret` when the unit lacks `os.Getenv(`. Many production systems legitimately store secrets in config files with proper ACLs, sealed volumes, or external secret injection that does not use `os.Getenv`. Universal “secrets must come from env” is not project-agnostic. |
| **CWE-455** | **Org/deployment policy** (fail-fast) | Detects `tls.LoadX509KeyPair(` failure followed by exact log text `continuing without mTLS` without `log.Fatalf(`. Whether startup must abort vs enter degraded mode is deployment topology / SLO policy, not a correctness sink provable without museum co-signals. |

Neither rule meets the project-agnostic bar that justified keeping CWE-15 as Heuristic in C2. Both are **fixture-only** museums.

---

## Freeze inventory

| Rule | Fixtures | Maturity today | Profile eligibility today | Primary signals (frozen) | Negatives |
|------|----------|----------------|---------------------------|--------------------------|-----------|
| **CWE-260** | 4 files (frameworks + stdlib vulnerable/safe) | Heuristic (default; not in `is_fixture_only`) | Eligible via Heuristic for non-allow-list packs | SI: `Password string` **or** `Secret   string` + (`cfg.Password` **or** `cfg.Secret`) | SI: `os.Getenv(`; safe fixtures also omit secret struct fields |
| **CWE-455** | 4 files | Heuristic (default) | Same | SI: `tls.LoadX509KeyPair(` + `continuing without mTLS` | SI: `log.Fatalf(` |

**Source spans:**

| Rule | Span source |
|------|-------------|
| CWE-260 | `source.find("cfg.Password")` or `source.find("cfg.Secret")` |
| CWE-455 | `source.find("continuing without mTLS")` |

**Shared surfaces not edited (worker contract):** `maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`, `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`, sibling detectors.

---

## Corpus signal classes

| Class | Examples | Rules |
|-------|----------|-------|
| Secret-bearing config struct fields | `Password string`, `Secret   string` | 260 |
| Loaded secret use from config | `cfg.Password`, `cfg.Secret` | 260 |
| Env-based credential load (negative) | `os.Getenv(` | 260 |
| TLS material load | `tls.LoadX509KeyPair(` | 455 |
| Continue-after-failure log (museum) | `continuing without mTLS` | 455 |
| Fatal exit on TLS failure (negative) | `log.Fatalf(` | 455 |

---

## Call-facts primary analysis

| Rule | Can call_facts be complete primary? | Decision |
|------|-------------------------------------|----------|
| CWE-260 | **No** — `os.ReadFile` + yaml/json unmarshal is production-shaped but cannot prove env-requiredness without secret field name corpus; any config secret load would over-fire | Leave SI primary; **fixture-only** |
| CWE-455 | **No** — `tls.LoadX509KeyPair` error handling is production-shaped but cannot prove fail-fast policy without exact log substring; non-Fatal error paths are common | Leave SI primary; **fixture-only** |

**No Structural promotion** — §1.3 bar not met (museum struct field names / exact log text remain required for emit; no reviewed real-module promotion evidence).

---

## Per-rule disposition

| Rule | Disposition | Rationale |
|------|-------------|-----------|
| CWE-260 | **fixture-only** | Environment-requiredness museum; org policy not project-agnostic |
| CWE-455 | **fixture-only** | Fail-fast / degraded-mode museum; deployment policy not project-agnostic |

---

## Oracle-safe detector rewrites (this PR)

File: `configuration/secrets_in_config.rs` only.

- **CWE-260 / CWE-455:** freeze comments documenting SI primary, negatives, env-requiredness vs fail-fast policy analysis, disposition; **no emit-path, span, or needle changes**.

Fixture oracle preserved (vulnerable fire, safe silence). No fixture renames; no new proposed fixture files.

---

## Existing CWE / BP ownership neighbors

| Concern | Owner | Relation to this family |
|---------|-------|-------------------------|
| Hard-coded DSN password in connection string | **CWE-798** (fixture-only, B1) | Neighbor: embedded password in DSN vs config-file struct field |
| External control of configuration (user DSN) | **CWE-15** (Heuristic, C2) | Same configuration domain; project-agnostic contract |
| Cleartext listen / payment fields | **CWE-319** (fixture-only) | Different domain (transport) |
| Sensitive field logging / exposure | **sensitive_fields** (R2 / #159) | Out of scope — different leaf |

---

## Proposed integrator changes (DO NOT apply on this branch)

### Maturity (`src/rules/maturity.rs`)

- Add `CWE-260`, `CWE-455` to `is_fixture_only`.
- Do **not** promote either rule to Structural or Heuristic keep.

### NEEDLES labels (`source_index.rs`)

| Needle | Proposed label |
|--------|----------------|
| `Password string` | `fixture-literal` (CWE-260 frameworks yaml password field) |
| `Secret   string` | `fixture-literal` (CWE-260 stdlib json secret field; note spacing) |
| `cfg.Password` | `fixture-literal` (CWE-260 loaded password use) |
| `cfg.Secret` | `fixture-literal` (CWE-260 loaded secret use) |
| `os.Getenv(` | `negative-gate` (CWE-260 env-requiredness safe path) |
| `tls.LoadX509KeyPair(` | dual-use generic — leave unlabeled or note CWE-455 co-signal only |
| `continuing without mTLS` | `fixture-literal` (CWE-455 continue-after-failure log) |
| `log.Fatalf(` | `negative-gate` (CWE-455 fail-fast safe path) |

### Fixture / manifest / findings-oracle

- No new fixtures; no manifest wiring.
- Findings-oracle impact: none expected on fixtures; real-module canary expected zero for museum rules.

### Canary command (integrator re-run after batch merge)

```sh
cargo build --release --locked
ONLY="CWE-260,CWE-455"
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

**Totals:** 376 files scanned, 0 findings. Per-rule: CWE-260 ×0, CWE-455 ×0.

---

## Handoff checklist for integrator

- [ ] Apply fixture-only maturity for CWE-260 and CWE-455
- [ ] Optional NEEDLES labels above (non-blocking)
- [ ] Re-run two-rule canary on integrated tree
- [ ] Update audit ledger when epic #151 R1–R4 integration lands
- [ ] No `manifest.toml` / profile allow-list edits expected from this worker
