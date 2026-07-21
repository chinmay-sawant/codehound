# Evidence — C2 Configuration residual trust (config_hardcoding)

> **Issue:** #113 · **Epic:** #105 · **Mega-integration:** `chore/epic-105-phase345-integration`  
> **Branch:** `chore/cwe-trust-configuration-residual`  
> **Integration base:** `7d912d5be8528f80df0122259d24130c6f394df9`  
> **Owner seam:** `src/lang/go/detectors/cwe/domains/configuration/`  
> **Selected family file:** `config_hardcoding.rs`  
> **Date:** 2026-07-21

---

## Family inventory and selection

| Leaf | Rules | Approx. lines | Fixture coverage | Selected? |
|------|-------|---------------|------------------|-----------|
| `config_hardcoding.rs` | CWE-15, 472, 1051, 1067 | ~120 | stdlib + frameworks × vulnerable/safe | **Yes** |
| `secrets_in_config.rs` | CWE-260, 455 | ~60 | stdlib + frameworks × vulnerable/safe | **Deferred** |

### Why select config_hardcoding

1. **Project-agnostic correctness/security contract** — CWE-15 (external control of system/configuration settings: request-derived value → database-opening sink) is true independent of organization policy, deployment topology, or env-loading conventions.
2. **Clear sink/API boundary** — `CONFIG_SINKS` (`sql.Open`, fixture `factory`) + `InputKind::UserControlled` bindings; call_facts primary already.
3. **Cohesive single-file family** — four rules under one hardcoding leaf; three siblings are corpus museums that share the same file and need disposition alongside the flagship rule.
4. **Full fixture oracle** — vulnerable/safe × frameworks/stdlib for all four; no new fixtures required.
5. **Plan alignment** — §3.2 requires selecting a family with a project-agnostic contract and deferring env-requiredness / deployment mode / org-policy.

### Why defer secrets_in_config

| Deferred rule | Reason (plan §3.2) |
|---------------|--------------------|
| **CWE-260** | **Environment-requiredness** museum: secret-bearing config fields (`Password string` / `Secret   string`) without `os.Getenv(` + `cfg.Password` / `cfg.Secret` use. Explicitly deferred unless an approved policy profile demands “secrets must come from env.” |
| **CWE-455** | **Fail-fast / deployment-mode policy**: `tls.LoadX509KeyPair(` + exact `continuing without mTLS` log text without `log.Fatalf(`. Whether startup must abort is deployment/org policy, not a universal correctness sink. |

Deferred leaf left **untouched** (same pattern as B1 deferred siblings).

---

## Freeze inventory (selected family)

| Rule | Fixtures | Maturity today | Profile eligibility today | Primary signals (frozen) | Negatives |
|------|----------|----------------|---------------------------|--------------------------|-----------|
| **CWE-15** | 4 files (frameworks + stdlib vulnerable/safe) | Heuristic (default; not in `is_fixture_only`) | Eligible via Heuristic for non-allow-list packs; not on recommended/security explicit allow-lists | **call_facts:** `is_configuration_sink` (`sql.Open` / `factory`) + arg uses `UserControlled` binding | Safe path: DSN from `os.Getenv("APP_DATABASE_URL")` (no user-controlled binding) |
| **CWE-472** | 4 files | Heuristic (default) | Same | SI: `Role    string \`form:"role"\`` **or** `role := r.FormValue("role")` | SI: `SELECT role FROM users` |
| **CWE-1051** | 4 files | Heuristic (default) | Same | SI: (`ChargeCard(` \| `ChargeCardPure(`) + `10.20.30.40:9090` + `http.NewRequest(` + `X-Card-Token` | SI: `os.Getenv("BILLING_API_URL")` |
| **CWE-1067** | 4 files | Heuristic (default) | Same | SI: `fmt.Sprintf("%%%s%%", term)` (or pattern assign) + `LIKE` + (`notes.body` \| `SELECT id, body FROM notes`) | SI: `prefix+"%"` / `pattern := prefix + "%"` |

**Source spans:**

| Rule | Span source |
|------|-------------|
| CWE-15 | `call.start_byte` of matching configuration-sink call |
| CWE-472 | `source.find("role")` |
| CWE-1051 | `source.find("10.20.30.40:9090")` |
| CWE-1067 | `source.find("fmt.Sprintf(\"%%%s%%\", term)")` |

**Shared surfaces not edited (worker contract):** `maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`, `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`, `sinks.rs` / `CONFIG_SINKS`.

---

## Corpus signal classes

| Class | Examples | Rules |
|-------|----------|-------|
| Configuration / DB-open sinks | `sql.Open`, fixture `factory` (CONFIG_SINKS) | 15 |
| User-controlled input bindings | `c.Query("dsn")`, `r.URL.Query().Get("dsn")` | 15 |
| Client role form fields | `Role    string \`form:"role"\``, `role := r.FormValue("role")` | 472 |
| Server-side role resolution (negative) | `SELECT role FROM users` | 472 |
| Fixed private host + billing helpers | `10.20.30.40:9090`, `ChargeCard(`, `ChargeCardPure(`, `X-Card-Token` | 1051 |
| Env-loaded destination (negative) | `os.Getenv("BILLING_API_URL")` | 1051 |
| Leading-wildcard LIKE + notes corpus | `fmt.Sprintf("%%%s%%", term)`, `LIKE`, `notes.body` / `SELECT id, body FROM notes` | 1067 |
| Prefix-only pattern (negative) | `prefix+"%"`, `pattern := prefix + "%"` | 1067 |

---

## Call-facts primary analysis

| Rule | Can call_facts be complete primary? | Decision |
|------|-------------------------------------|----------|
| CWE-15 | **Yes** for the local sink+input-binding boundary (`sql.Open` / `factory` + user-controlled arg). Already implemented. Bare `factory` is fixture-shaped sink name; not §1.3 structural without broader sinks + real-module hits. | **No rewrite**; **keep Heuristic** |
| CWE-472 | **No** without proving role field is used as immutable authz claim; FormValue/bind alone over-fires | Leave SI primary; **fixture-only** |
| CWE-1051 | **No** — hard-coded host is literal corpus + helper names; `http.NewRequest` alone is not config-hardcoding proof | Leave SI primary; **fixture-only** |
| CWE-1067 | **No** — `fmt.Sprintf` alone cannot prove leading-wildcard sequential scan without LIKE + table co-signals | Leave SI primary; **fixture-only** |

---

## Per-rule disposition

| Rule | Disposition | Rationale |
|------|-------------|-----------|
| CWE-15 | **keep Heuristic** | Call_facts primary; project-agnostic external-control contract; not Structural (§1.3: no reviewed real-module bar; `factory` sink is fixture-shaped) |
| CWE-472 | **fixture-only** | Client role form museum; org-policy / assumed-immutable parameter shape |
| CWE-1051 | **fixture-only** | Hard-coded private IP + ChargeCard helpers; deployment-config museum |
| CWE-1067 | **fixture-only** | Leading-wildcard LIKE + notes corpus; performance sequential-scan museum |

**No Structural promotion** for any rule in this family.

---

## Oracle-safe detector rewrites (this PR)

File: `configuration/config_hardcoding.rs` only.

- **CWE-15:** freeze documentation only (call_facts primary already complete; no emit-path change).
- **CWE-472 / 1051 / 1067:** freeze comments documenting SI primary, negatives, disposition; **no emit-path, span, or needle changes**.

Fixture oracle preserved (vulnerable fire, safe silence). No fixture renames; no new proposed fixture files required.

---

## Existing CWE / BP / PERF ownership

| Concern | Owner | Relation to this family |
|---------|-------|-------------------------|
| SQL injection / query taint | **Taint CWE-89** etc. | Different: CWE-15 is *configuration* of the DB open, not query string injection |
| Hard-coded credentials / DSN password | **CWE-798** (fixture-only, B1) | Neighbor: 798 is embedded password in DSN string; 15 is user-controlled DSN at open |
| Hard-coded signing constants | **CWE-547** (fixture-only, B1) | Different sink (const names vs network host) |
| Cleartext listen / payment fields | **CWE-319** (fixture-only) | Different domain (transport) |
| Authz / IDOR / forced browsing | **authorization_and_scoping** (A4 fixture-only) | CWE-472 is form-role assumed-immutable neighbor; not reopened here |
| Secrets-from-config / fail-fast TLS | **secrets_in_config** (deferred C2 sibling) | Explicit §3.2 deferral |
| PERF sequential scan / LIKE | PERF family (if any) | CWE-1067 remains CWE catalog museum; do not fold without separate PERF ownership review |

---

## Proposed integrator changes (DO NOT apply on this branch)

### Maturity (`src/rules/maturity.rs`)

- Add `CWE-472`, `CWE-1051`, `CWE-1067` to `is_fixture_only`.
- Leave `CWE-15` as default **Heuristic** (not structural allow-list).
- Do **not** maturity-change deferred `CWE-260` / `CWE-455` in this batch (no disposition issued).

### NEEDLES labels (`source_index.rs`)

| Needle | Proposed label |
|--------|----------------|
| `Role    string \`form:"role"\`` | `fixture-literal` (CWE-472 frameworks role form) |
| `role := r.FormValue("role")` | `fixture-literal` (CWE-472 stdlib role form) |
| `SELECT role FROM users` | `negative-gate` (CWE-472 server-side role) |
| `ChargeCard(` | `fixture-literal` (CWE-1051 frameworks helper) |
| `ChargeCardPure(` | `fixture-literal` (CWE-1051 stdlib helper) |
| `10.20.30.40:9090` | `fixture-literal` (CWE-1051 hard-coded host; already noted in audit corpus) |
| `http.NewRequest(` | dual-use generic — leave unlabeled or note CWE-1051 co-signal only |
| `X-Card-Token` | `fixture-literal` (CWE-1051 card token header) |
| `os.Getenv("BILLING_API_URL")` | `negative-gate` (CWE-1051 env destination) |
| `fmt.Sprintf("%%%s%%", term)` | `fixture-literal` (CWE-1067 leading wildcard) |
| `pattern := fmt.Sprintf("%%%s%%", term)` | `fixture-literal` (CWE-1067 pattern assign) |
| `notes.body` | `fixture-literal` (CWE-1067 table co-signal) |
| `SELECT id, body FROM notes` | `fixture-literal` (CWE-1067 SQL co-signal) |
| `prefix+"%"` / `pattern := prefix + "%"` | `negative-gate` (CWE-1067 prefix-only safe path) |
| bare `LIKE` | too generic — leave unlabeled |
| CWE-15 needles | none required for emit (call_facts primary); no SI gate |

### Fixture / manifest / findings-oracle

- No new fixtures; no manifest wiring.
- Findings-oracle impact: none expected on fixtures; real-module canary expected zero or low for museum rules; CWE-15 may fire on real `sql.Open` + query DSN patterns if present (record hits).

### Canary command (integrator re-run after batch merge)

```sh
cargo build --release --locked
ONLY="CWE-15,CWE-472,CWE-1051,CWE-1067"
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry; do
  echo "=== $t ==="
  target/release/codehound "$t" --profile all --only "$ONLY" \
    --format json --json-envelope --no-fail --no-cache 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print('findings', d.get('findingCount')); print('files', d.get('stats',{}).get('files_scanned')); print([(f.get('rule_id'), f.get('file'), f.get('line')) for f in d.get('findings',[])])"
done
```

---

## Canary results (worker pre-integration) — 2026-07-21

| Repository | Revision | Files scanned | Findings |
|---|---|---:|---:|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | *(filled after canary)* | *(filled after canary)* |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | *(filled after canary)* | *(filled after canary)* |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | *(filled after canary)* | *(filled after canary)* |

**Totals:** *(filled after canary)*. Per-rule: CWE-15 ×?, CWE-472 ×?, CWE-1051 ×?, CWE-1067 ×?.

---

## Handoff checklist for integrator

- [ ] Apply fixture-only maturity for CWE-472 / 1051 / 1067 only
- [ ] Keep CWE-15 Heuristic (no Structural)
- [ ] Optional NEEDLES labels above (non-blocking)
- [ ] Do not disposition CWE-260 / 455 in this batch without a follow-on issue
- [ ] Re-run four-rule canary on integrated tree
- [ ] Update `cwe-catalog-trust-audit.md` + `parallel-catalog-program.md` §3.2 checkbox only from integrated evidence
- [ ] No `manifest.toml` / profile allow-list edits expected from this worker
