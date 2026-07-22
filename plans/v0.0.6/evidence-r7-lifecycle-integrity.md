# Evidence — R7 lifecycle_and_integrity bounded trust (plugins leaf)

> **Issue:** #164 · **Epic:** #151  
> **Branch:** `chore/cwe-trust-lifecycle-integrity`  
> **Integration base:** `79c9b29799436729699bc8f1a6aa18116fc4b316`  
> **Owner seam:** `src/lang/go/detectors/cwe/domains/general_security/lifecycle_and_integrity/`  
> **Selected family file:** `plugins.rs` (whole leaf)  
> **Date:** 2026-07-22

---

## Family inventory and selection

| Leaf | Rules | Lines (approx) | Fixture coverage | Selected? |
|------|-------|----------------|------------------|-----------|
| `lifecycle.rs` | CWE-765, 778, 826, 1322 | ~122 | stdlib + frameworks each | **No** — topology / ownership |
| **`plugins.rs`** | **CWE-618, 829, 1125** | **~92** | **stdlib + frameworks each** | **Yes** |
| `runtime_state.rs` | CWE-515, 544, 605 | ~100 | stdlib + frameworks each | **No** — cross-request / failure topology |

### Why select `plugins.rs`

1. **Smallest cohesive leaf** — three rules, ~92 lines; no boil-the-ocean.
2. **Clearest local sinks** — `exec.Command` + vendor bridge path (618), `plugin.Open` (829), mount-helper + exact route literals (1125).
3. **Full fixture oracle** — vulnerable + safe for stdlib and frameworks; no new fixtures.
4. **Matches plan preference** — clear sink + safe fixtures; siblings carry the topology/ownership deferral called out in the residual checklist.
5. **Does not reopen** B4 `privilege_escalation/` (already dispositioned).

### Why defer siblings

| Deferred | Reason |
|----------|--------|
| **lifecycle.rs** (CWE-765, 778, 826, 1322) | Double-unlock / premature `db.Close` vs background task / blocking worker sleep are lock-ownership and lifetime proofs — checklist item “Defer topology / whole-program ownership rules.” Missing auth-audit (778) is a logging-policy museum better with a dedicated audit slice. |
| **runtime_state.rs** (CWE-515, 544, 605) | CWE-515 is a cross-request covert global flag; CWE-544 is inconsistent panic-vs-log failure topology. CWE-605 (`SO_REUSEADDR`) has a clear socket sink but the leaf theme is not cohesive enough to ship with 515/544 in one bounded residual. |

---

## Freeze inventory (selected family)

Runtime maturity today: all three default to **Heuristic** (`maturity_for` has no explicit fixture-only / structural entry). Available under `--profile all` / `--only`; not on recommended/security explicit allow-lists.

| Rule | Fixtures | Primary signals (frozen) | Negatives | Source span |
|------|----------|----------------------------|-----------|-------------|
| **CWE-618** | 4 files | SI `/opt/vendor/activex-bridge` + `exec.Command(` + `method` + `args` | SI `allowedPluginMethods` | `source.find("/opt/vendor/activex-bridge")` |
| **CWE-829** | 4 files | SI `plugin.Open(` + `module_path` \| `path := ` | SI `allowedModules` / `moduleRoot` | `source.find("plugin.Open(")` |
| **CWE-1125** | 4 files | SI `MountWideSurface(` \| `MountWideSurfacePure(` + `/debug/pprof`\|`pprof.Index` + `/admin/sql` + `/admin/config` + `/internal/reload` | SI `authRequired()` / `authRequiredPure(` | `source.find("/debug/pprof")` |

**Shared surfaces not edited (worker contract):** `maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`, `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`, `pending-work.md`.

---

## Corpus signal classes

| Class | Examples | Rules |
|-------|----------|-------|
| Exact vendor native-bridge path | `/opt/vendor/activex-bridge` | 618 |
| exec + query param co-signals | `exec.Command(`, `method`, `args` | 618 |
| Plugin load API | `plugin.Open(` | 829 |
| Caller path markers | `module_path`, `path := ` | 829 |
| Allowlist / root negatives | `allowedPluginMethods`, `allowedModules`, `moduleRoot` | 618, 829 |
| Mount helper names | `MountWideSurface(`, `MountWideSurfacePure(` | 1125 |
| Debug/admin/internal route literals | `/debug/pprof`, `/admin/sql`, `/admin/config`, `/internal/reload` | 1125 |
| Auth wrapper negatives | `authRequired()`, `authRequiredPure(` | 1125 |

---

## Runtime / deployment assumptions

| Rule | Assumption | Trust impact |
|------|------------|--------------|
| CWE-618 | Native-bridge exposure inferred from exact vendor path + exec co-presence, not capability analysis of the helper | Unit-local museum → fixture-only |
| CWE-829 | Untrusted inclusion inferred from `plugin.Open` + caller path markers without allowlist/root | Does not prove path sanitization beyond SI negatives → fixture-only |
| CWE-1125 | Oversized surface inferred from mount helper + exact route set co-presence, not routing CFG / middleware graph | Route-set museum → fixture-only |

---

## Existing CWE / BP / PERF ownership

| Concern | Owner | Relation to this family |
|---------|-------|-------------------------|
| Untrusted search path / `plugin.Open` PATH | **CWE-426** (`file_permissions` / path area) | Neighbor: 426 targets PATH/modPath search-order; 829 targets caller-controlled filesystem path without allowlist. |
| Command injection / exec | injection families | Different proof (shell metachar / argv); 618 is vendor-bridge ActiveX method exposure museum. |
| Privilege escalation Setuid/Chown | **privilege_escalation/** (B4 done) | Sibling domain; not reopened. |
| Lock / resource lifetime | **lifecycle.rs** (deferred) | Different leaf. |
| Covert channel / SO_REUSEADDR | **runtime_state.rs** (deferred) | Different leaf. |

---

## Call-facts primary analysis

| Rule | Can call_facts be complete primary? | Decision |
|------|-------------------------------------|----------|
| CWE-618 | **No.** `exec.Command` is common; ActiveX/native-bridge proof requires exact vendor path + method/args museum. | Leave SI primary; **fixture-only** |
| CWE-829 | **No.** `plugin.Open` fires on safe allowlisted loads; defect boundary is path-policy SI. | Leave SI primary; **fixture-only** |
| CWE-1125 | **No.** Route registration APIs alone cannot prove oversized public surface without corpus mount helper + route literals. | Leave SI primary; **fixture-only** |

No oracle-safe call_facts rewrite in this PR — rewrites would not strengthen the proof boundary while preserving oracle.

---

## Per-rule disposition

| Rule | Disposition | Rationale |
|------|-------------|-----------|
| CWE-618 | **fixture-only** (proposed) | Exact vendor bridge path + exec + method/args museum |
| CWE-829 | **fixture-only** (proposed) | `plugin.Open` + caller path markers without allowlist/root |
| CWE-1125 | **fixture-only** (proposed) | MountWideSurface + debug/admin/internal route co-presence museum |

**No Structural promotion.** No Heuristic keep (no generalized production-shaped sink with real-module signal under §1.3).

---

## Detector changes this PR

File: `lifecycle_and_integrity/plugins.rs` only.

- Module + per-rule freeze comments documenting signals, negatives, ownership, and disposition.
- **No emit-path / span / needle changes** — fixture oracle preserved bit-for-bit.

No new fixture `.txt` files. No `manifest.toml` edits. No edits to `lifecycle.rs` or `runtime_state.rs`.

---

## Proposed integrator changes (DO NOT apply on this branch)

### Maturity (`src/rules/maturity.rs`)

Add to `is_fixture_only`:

```text
CWE-618, CWE-829, CWE-1125
```

Unit-test assertions mirroring other fixture-only families.

### NEEDLES labels (`source_index.rs`)

| Needle | Proposed label |
|--------|----------------|
| `/opt/vendor/activex-bridge` | `fixture-literal: CWE-618` |
| `allowedPluginMethods` | `negative-gate: CWE-618` |
| `plugin.Open(` | leave unlabeled or dual-use note (also CWE-426 fixtures) |
| `module_path`, `path := ` (829 context) | `fixture-literal: CWE-829` |
| `allowedModules`, `moduleRoot` | `negative-gate: CWE-829` |
| `MountWideSurface(`, `MountWideSurfacePure(` | `fixture-literal: CWE-1125` |
| `/debug/pprof`, `/admin/sql`, `/admin/config`, `/internal/reload` | `fixture-literal: CWE-1125` |
| `authRequired()`, `authRequiredPure(` | `negative-gate: CWE-1125` |

### Fixture / manifest / findings-oracle

- None (oracle unchanged; no new `.txt` files).

### Exact canary command

```sh
target/release/codehound TARGET --profile all \
  --only CWE-618,CWE-829,CWE-1125 \
  --format json --json-envelope --no-fail --no-cache
```

Re-run on the integrated tree; worker canary is evidence, not final proof.

Per `plans/v0.0.5/canary-corpus.md`, scan gopdfsuit + real-repos (monsoon, go-retry, gorl, no-mistakes).

---

## Canary (worker pre-integration) — 2026-07-22

| Repository | Revision | Files scanned | Findings |
|---|---|---:|---:|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | **0** |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | **0** |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | **0** |
| gorl | `ec54aaf15ce4d0f3f8014eac2548986c91d0f001` | 28 | **0** |
| no-mistakes | `0a2c82f993b9467c5ab84992313dfd13b66830af` | 222 | **0** |

**Totals:** 376 scanned files. Per-rule: all three ×0.

Zero real-module hits confirms museum/fixture-only shapes; no Heuristic-keep signal under §1.3.

```sh
ONLY="CWE-618,CWE-829,CWE-1125"
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/gorl \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/no-mistakes; do
  target/release/codehound "$t" --profile all --only "$ONLY" \
    --format json --json-envelope --no-fail --no-cache > /tmp/ch-r7.json
  python3 -c "import json; d=json.load(open('/tmp/ch-r7.json')); print(d.get('stats',{}).get('files_scanned'), len(d.get('findings') or []))"
done
```

---

## Validation

| Gate | Result |
|------|--------|
| `make lint` | pass |
| `cargo test --locked --test go_cwe_detector_fixtures` | pass (includes all 3×4 fixture pairs) |
| `make test` | pass (459 tests) |
| `git diff --check` | pass |
