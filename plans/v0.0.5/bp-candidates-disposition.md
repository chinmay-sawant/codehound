# v0.0.5 — BP-66..BP-165 Absent Candidates Disposition (Phase 4.1)

> **Parent:** `plans/v0.0.5/pending-work.md` §4.1; research source `plans/v0.0.3/new-bad-practices/`  
> **Issue:** [#40](https://github.com/chinmay-sawant/codehound/issues/40) Phase 4.1  
> **Date:** 2026-07-18  
> **Scope:** Reassess the **29** proposed BP IDs that remain absent from the live ruleset/dispatch. **No new detectors** are implemented here.  
> **Live catalog baseline:** 135 registered BP rules in `ruleset/golang/bad-practices.json` (IDs BP-1..BP-165 with holes at the 29 listed below).  
> **Disposition vocabulary:** `retire-duplicate` | `defer-needs-canary` | `defer-needs-proof-boundary` | `defer-policy`

---

## Method

1. Read research sketches for each candidate in parts A–F (`01-part-a-core-language.md` … `06-part-f-testing-api-hygiene.md`) and the deferred ledger in `CHECKLIST.md` / `IMPLEMENTABLE-DEFERRED-BP-PLAN.md`.
2. Cross-check against:
   - **Live BP pack** (`ruleset/golang/bad-practices.json`)
   - **CWE pack** detectors and fixtures (especially CWE-22, CWE-89, CWE-601, CWE-798)
   - **PERF pack** (especially PERF-030, PERF-067, PERF-079)
   - **Known external tools** named in `00-gap-and-scope.md`: `go vet`, staticcheck, errcheck, bodyclose, sqlclosecheck, **noctx**
3. Apply the admission policy from `00-gap-and-scope.md` and CHECKLIST §2.2:
   - true security vulns → CWE, not BP
   - exact tool duplicates without multi-statement / framework value → drop
   - deployment, auth, namespace, and logging-library preferences → policy defer
   - needs type/SSA/interprocedural/ownership proof beyond tree-sitter → proof-boundary defer
4. Optional static-shape sampling on `real-repos/gorl`, `real-repos/monsoon`, `real-repos/go-retry`, and gopdfsuit (read-only); notes appear in the Evidence column where relevant.

### Disposition meanings

| Disposition | Use when |
|-------------|----------|
| **retire-duplicate** | Already owned by CWE, PERF, another BP, or a stock linter (`go vet` / staticcheck / errcheck / bodyclose / sqlclosecheck / noctx) with no documented additional CodeHound value at current architecture. |
| **defer-needs-canary** | A bounded static subset might be inventable, but there is no real-module canary proving signal vs noise. |
| **defer-needs-proof-boundary** | Pattern needs type facts, alias/data-flow, driver semantics, interprocedural ownership, or multi-file lifecycle proof that the current detector seam cannot claim honestly. |
| **defer-policy** | Signal is architecture, deployment, auth, config-requiredness, or framework convention; not a project-agnostic correctness smell. |

---

## Counts

| Disposition | Count |
|-------------|------:|
| **retire-duplicate** | 9 |
| **defer-needs-canary** | 1 |
| **defer-needs-proof-boundary** | 6 |
| **defer-policy** | 13 |
| **Total** | **29** |

### Clear retire-duplicate list

| Candidate | Duplicate of |
|-----------|--------------|
| **BP-78** | **noctx** (missing `*Context` overloads when `ctx` is in scope) |
| **BP-103** | **CWE-601** open redirect (fixture + detector present) |
| **BP-108** | **BP-13** (`context.Background` outside main/init; CHECKLIST already said “fold into BP-13”) |
| **BP-118** | **CWE-22** path traversal / taint file sinks |
| **BP-124** | **PERF-067** Gin Recovery disabled (+ package-wide “public server” claim is policy, not a second BP) |
| **BP-129** | **CWE-89** SQL injection / `fmt.Sprintf` query hygiene |
| **BP-130** | **PERF-079** unconfigured `SetMaxOpenConns` / pool limits |
| **BP-139** | **CWE-89** GORM `Raw` / string-concat SQL |
| **BP-152** | **CWE-798** hard-coded credentials (CWE domain; BP-161 already covers production DSN markers in tests) |

---

## Group A — Core / context (BP-69, 71, 74, 77, 78)

| Candidate | Theme | Disposition | Evidence |
|-----------|-------|-------------|---------|
| **BP-69** | Returning data with non-nil error (unclear contract) | **defer-needs-proof-boundary** | Research smell is `return x, err` after error path without zeroing `x`. Partial-result APIs are legitimate; distinguishing them needs API contract / naming / docs, not local syntax. No CWE/PERF/tool duplicate. CHECKLIST: “return-value intent is contract-dependent.” |
| **BP-71** | Discarding primary multi-return while keeping error | **defer-needs-canary** | Distinct from BP-1 (discards error). A tight callee list (`io.Copy`, `fmt.Fscan*`, `Write` byte counts) is syntactically possible, but correctness impact is API-specific and unproven on real modules. Sampled gorl/monsoon/go-retry/gopdfsuit: no high-value `n, _ :=` correctness pattern surfaced in a quick scan. Revisit only after a canary shows actionable hits. |
| **BP-74** | Slice append alias / unexpected share | **defer-needs-proof-boundary** | Classic backing-array alias (`b := a[:]; b = append(b, x)` then use `a`). Requires alias + later-use data-flow that tree-sitter heuristics cannot soundly claim without heavy false positives. Not owned by staticcheck as a general rule. Gap doc allows BP only for *correctness* append aliasing — still needs a proof boundary first. |
| **BP-77** | `context.WithValue` / `Value` with stringly keys | **defer-policy** | Unexported key types are style/API-design convention; many codebases use string keys intentionally (middleware, frameworks). Not a security CWE and not a stock linter default. Policy preference, not project-agnostic correctness. |
| **BP-78** | Context not propagated to child call | **retire-duplicate** | Research explicitly maps to **noctx** (`http.NewRequest` vs `NewRequestWithContext`, `Query` vs `QueryContext`, etc.). `00-gap-and-scope.md` lists “Missing context on net/http client \| noctx”. Sample: monsoon `request/request.go` uses `http.NewRequest(...)` — noctx-shaped, not a CodeHound-unique multi-statement lifecycle rule. |

---

## Group B — HTTP / framework (BP-103, 106, 108, 112–115, 118, 121, 123–125)

| Candidate | Theme | Disposition | Evidence |
|-----------|-------|-------------|---------|
| **BP-103** | Redirect from unvalidated external URL | **retire-duplicate** | Research: “Related CWE-601 — if CWE already covers, skip.” **CWE-601** detector + stdlib/framework fixtures exist (`detect_cwe_601`, `tests/fixtures/go/stdlib/CWE-601-*.txt`). Open-redirect belongs in CWE; BP would be a branded copy. (CWE-601 is currently needle-narrow; strengthening belongs under CWE trust work, not a new BP.) |
| **BP-106** | CORS `Allow-Origin` reflects request `Origin` | **defer-policy** | No CWE-942 in catalog. Reflecting Origin is a security misconfiguration; catalog policy moves true vulns to **CWE**, not BP. Also allowlist/config intent is environment-dependent. Sample: gopdfsuit `internal/middleware/cors.go` uses a fixed allow origin (safe for a naive reflect detector). |
| **BP-108** | Handler uses `context.Background` / ignores request context | **retire-duplicate** | Research overlap field: **BP-13**. CHECKLIST Phase 3.2: “Fold into existing BP-13 unless handler-specific evidence is materially better.” Live **BP-13** already flags Background outside main/init. PERF-030 also covers Background in goroutines from request paths. Sample: gopdfsuit `internal/middleware/auth.go` uses `context.Background()` inside Gin middleware — BP-13-shaped, not a new rule. |
| **BP-112** | Gin group on sensitive prefix without auth middleware | **defer-policy** | Path name heuristics (`admin`/`internal`) plus “auth-like” middleware identity are architecture/policy. Whole-package route graph + middleware naming not project-agnostic. |
| **BP-113** | Gin default mode not Release in `main` | **defer-policy** | Deployment/runtime configuration; debug mode is intentional in many services. Sample: gopdfsuit `cmd/gopdfsuit/main.go` already calls `gin.SetMode(gin.ReleaseMode)` — a “missing SetMode” rule would be noise on well-configured services and wrong for libraries/tests. |
| **BP-114** | `ClientIP` without `SetTrustedProxies` | **defer-needs-proof-boundary** | Correctness/security depends on reverse-proxy topology and package-wide/runtime config not visible in a single function. Multi-file config + deployment facts required. |
| **BP-115** | Bind struct missing `binding:"required"` on “critical” fields | **defer-policy** | Field criticality is application intent; empty tags are often intentional (optional DTO fields). Name-heuristic on `password`/`email` is opinionated policy. |
| **BP-118** | Echo path param used in filesystem path without clean | **retire-duplicate** | Research: “Prefer CWE-22 if covered.” **CWE-22** taint detectors + fixtures cover user-controlled path → file sinks. Framework-specific Echo param is a source flavor of the same vuln class, not a BP lifecycle smell. |
| **BP-121** | Fiber `Prefork: true` hardcoded | **defer-policy** | Operational/deploy preference (12-factor, multi-process). Safe when intentionally used; not statically “wrong.” |
| **BP-123** | Chi `URLParam` used without presence check before authz | **defer-policy** | Empty-param risk is real only when the value is used for authorization/ownership; that intent is handler- and product-specific. |
| **BP-124** | Panic recovery middleware missing on public server | **retire-duplicate** | **PERF-067** is “Gin Recovery Middleware Disabled.” Catalog policy: no second correctness BP that only restates PERF recovery. “Public server” exposure cannot be proven statically. Sample: gopdfsuit intentionally uses custom recovery instead of `gin.Recovery()` — a missing-`gin.Recovery` rule would false-positive. |
| **BP-125** | Mixing framework context with stdlib `ResponseWriter` incorrectly | **defer-needs-proof-boundary** | Dual-write / hijack correctness needs framework control-flow and writer ownership proof beyond syntax facts. CHECKLIST: “depends on framework control flow not proven by current syntax facts.” |

---

## Group C — Data (BP-127, 129, 130, 137, 139, 144)

| Candidate | Theme | Disposition | Evidence |
|-----------|-------|-------------|---------|
| **BP-127** | Nested transactions assumed supported | **defer-needs-proof-boundary** | Nested `Begin` semantics are driver/runtime-specific (savepoints vs error). Local `*sql.Tx` param + another `Begin` is not enough to prove misuse without driver facts. Adjacent **BP-126** (tx without commit/rollback) already ships for local lifecycle. |
| **BP-129** | SQL string built with `fmt.Sprintf` | **retire-duplicate** | Research: verify CWE-89 and drop if covered. **CWE-89** taint rule + fixtures use the exact `fmt.Sprintf` → `Query`/`QueryRow` shape (`tests/fixtures/go/stdlib/CWE-89-vulnerable.txt`). No BP value beyond CWE. |
| **BP-130** | `db.SetMaxOpenConns` never configured for service binary | **retire-duplicate** | **PERF-079** (“GORM Connection Pool Exhaustion”) and PERF data-access detectors already target missing `SetMaxOpenConns` / pool tuning. Absence-of-config is package-wide and deployment-intent heavy; PERF owns the reliability angle. |
| **BP-137** | GORM soft-delete vs hard-delete (`Unscoped`) | **defer-policy** | Hard-delete *intent* is application-specific; soft-delete is often correct. Cannot prove “meant to purge” from syntax alone. |
| **BP-139** | GORM Raw SQL with string concatenation | **retire-duplicate** | Research: “Align with CWE-89.” CWE-89 description explicitly includes GORM `Raw()` / string formatting. Security injection → CWE, not BP. |
| **BP-144** | Redis key without namespace prefix on shared instance | **defer-policy** | Shared-instance and prefix conventions are deployment/org policy. Bare keys are valid on dedicated instances. |

---

## Group D — Observability / API (BP-148, 150, 152, 153, 157, 165)

| Candidate | Theme | Disposition | Evidence |
|-----------|-------|-------------|---------|
| **BP-148** | slog handler hardcoded `LevelDebug` in production path | **defer-policy** | “Production” is not source-provable; debug level is legitimate for tools and local mains. Related shipped rules (**BP-146/147/149/151**) already cover sensitive/log-shape hygiene without env intent. |
| **BP-150** | `os.Getenv` without default/empty check for required config | **defer-policy** | Requiredness is application-specific. Sample: monsoon wires Getenv as flag defaults; gopdfsuit uses optional `ENABLE_PROFILING` / font path env — empty is OK. Fail-fast policy is product choice. |
| **BP-152** | Hardcoded localhost / DSN credentials in non-test code | **retire-duplicate** | Research maps to **CWE-798**. CWE-798 detector + fixtures exist (currently fixture-only maturity — still CWE domain). **BP-161** covers production DSN markers in tests. Broadening credential detection belongs under CWE trust (#39), not a parallel BP. |
| **BP-153** | Config `json.Unmarshal` ignoring critical unknown/version fields | **defer-policy** | Forward-compat version fields and “critical unknown” policy are app-specific; research already labeled low priority / drop if noisy. **BP-154** already covers ignored Unmarshal *errors*. |
| **BP-157** | gRPC `NewServer` without unary interceptor for logging/auth | **defer-policy** | Interceptor requirements are service security/ops policy. Not every gRPC binary needs the same chain; auth may live elsewhere. **BP-158** (status/error handling) already ships a bounded gRPC correctness rule. |
| **BP-165** | Exported constructor starts lifecycle without Close/Shutdown contract | **defer-needs-proof-boundary** | Needs multi-file type method-set + ownership: `New*` returns `*T`, starts `go`/Listen, package has no `Close`/`Shutdown`. CHECKLIST deferred gate: “reliable multi-file type, lifecycle, and ownership evidence is unavailable.” Related single-function lifecycle rules (**BP-12/14/79/98/145**) already cover local cases. |

---

## Optional real-module shape notes (not promotion evidence)

| Target | Observation relevant to absent candidates |
|--------|-------------------------------------------|
| **gopdfsuit** | Fixed CORS origin (not BP-106); `gin.SetMode(ReleaseMode)` (BP-113 safe); custom recovery without `gin.Recovery` (BP-124/PERF-067 FP risk); `context.Background()` in auth middleware (BP-108/BP-13); no Fiber/Chi/sqlx SQL Sprintf samples in the quick pass. |
| **real-repos/monsoon** | `http.NewRequest` without context (BP-78/noctx shape); Getenv used as optional flag defaults (BP-150 weak); no open-redirect handler pattern. |
| **real-repos/gorl** | `context.Background` mostly tests/examples; Getenv for optional Redis URL with empty guard; rate-limit header maps, not Redis bare-key product code in the sample. |
| **real-repos/go-retry** | Library + tests; Background only in tests; no HTTP/SQL/framework candidates fire. |

None of these samples justify promoting a deferred candidate without a stronger proof boundary or a dedicated canary issue.

---

## Cross-check summary vs tools and packs

| External / internal owner | Candidates it absorbs or blocks |
|---------------------------|----------------------------------|
| **CWE-22** | BP-118 |
| **CWE-89** | BP-129, BP-139 |
| **CWE-601** | BP-103 |
| **CWE-798** (+ BP-161 test DSN) | BP-152 |
| **BP-13** / PERF-030 | BP-108 |
| **PERF-067** | BP-124 |
| **PERF-079** | BP-130 |
| **noctx** | BP-78 |
| **errcheck / BP-1 / BP-154** | Not re-opened; BP-71 is *primary*-value discard, not error discard — still canary-gated |
| **bodyclose / sqlclosecheck** | No remaining absent candidate is a pure body/rows close duplicate (BP-95/96 already shipped with documented overlap) |
| **go vet / staticcheck defaults** | No absent candidate is an exact SA/vet reimplementation; remaining items are intent, policy, or stronger analysis |

---

## Recommendation

1. **Retire the 9 retire-duplicate IDs** from any future BP implementation queue; if signal is still desired, strengthen the owning CWE/PERF/BP-13/noctx path instead.
2. Keep the **13 defer-policy** IDs out of the BP pack unless product policy explicitly wants opinionated architecture rules (and then only behind non-recommended profiles).
3. Keep the **6 defer-needs-proof-boundary** IDs parked until typed facts, multi-file method sets, or driver/config proof exist (Phase 4.3 / typed Go facts).
4. **BP-71** is the only **defer-needs-canary** candidate: admit only after a real-module canary with a frozen callee allowlist and FP budget. **Follow-up (#46):** dedicated canary recorded in `bp-71-canary.md` → **wontfix** (allowlist hits are idiomatic `_, err` on Copy/Write; no actionable correctness class). **G1 reopen (#137, 2026-07-22):** five-module re-canary including no-mistakes → **keep deferred** ([`phase5-g1-bp-reopen-evidence.md`](./phase5-g1-bp-reopen-evidence.md)); still 0 actionable correctness hits.
5. Do **not** implement detectors under issue #39; any future work needs a separate scoped issue after this disposition is accepted.
6. **Follow-up (#46):** proof-boundary design notes + retire-duplicate confirmation in `bp-proof-boundary-notes.md` (all six IDs wontfix under current seams; nine retire-duplicates confirmed wontfix-as-BP).

---

## Sources

- `plans/v0.0.3/new-bad-practices/00-gap-and-scope.md`
- `plans/v0.0.3/new-bad-practices/01-part-a-core-language.md` … `06-part-f-testing-api-hygiene.md`
- `plans/v0.0.3/new-bad-practices/CHECKLIST.md` §0.1.1 deferred ledger
- `plans/v0.0.3/new-bad-practices/IMPLEMENTABLE-DEFERRED-BP-PLAN.md` “Deferred outside this batch”
- `plans/v0.0.5/pending-work.md` §4.1
- Live `ruleset/golang/bad-practices.json`, CWE/PERF chunk metadata, and detectors under `src/lang/go/detectors/`
