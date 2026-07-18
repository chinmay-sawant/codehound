# BP proof-boundary IDs — design bar or wontfix

> **Issue:** [#46](https://github.com/chinmay-sawant/codehound/issues/46)  
> **Parent disposition:** `plans/v0.0.5/bp-candidates-disposition.md` (`defer-needs-proof-boundary`)  
> **Date:** 2026-07-19  
> **Scope:** One short decision per ID for BP-69, 74, 114, 125, 127, 165. No detectors.  
> **Policy:** Prefer honest wontfix / park until typed or multi-file facts exist over a weak syntactic bar.

---

## BP-69 — Returning data with non-nil error

**Decision: wontfix** as a BP under current seams.

The research smell is `return x, err` on an error path without zeroing `x`. Partial-result APIs (`io.Reader`-style, multi-value decode, best-effort probes) legitimately return both. Distinguishing “unclear contract” from intentional partial results needs API naming, docs, or type-level contracts — not a local AST shape. A name-heuristic suppress list (`Partial*`) is policy noise, not a sound bar. Park until package-level contract facts exist; do not ship a “return non-zero + err” linter.

---

## BP-74 — Slice append alias / unexpected share

**Decision: wontfix** (no safe static bar without alias + later-use proof).

Classic `b := a[:]; b = append(b, x)` then reading `a` expecting immutability requires proving (1) shared backing array capacity path, (2) append reuses storage, (3) later use of the original observes the mutation. Tree-sitter heuristics on “slice then append” without data-flow would false-positive every intentional buffer growth. staticcheck has no general replacement; CodeHound should not claim a general correctness rule here until alias/data-flow infrastructure exists. Local clone/`append(nil, …)` guidance remains documentation-only.

---

## BP-114 — Gin `ClientIP` without `SetTrustedProxies`

**Decision: wontfix** for BP; security/config topology is multi-file + deploy.

Correctness of trusting `c.ClientIP()` depends on reverse-proxy layout and whether `SetTrustedProxies` / platform defaults appear anywhere in the binary (often `main` or init far from the handler). A same-function “ClientIP used, no SetTrustedProxies nearby” rule is both incomplete and wrong for apps that configure proxies elsewhere. Not a local bad-practice smell; if product wants a security check, place it under CWE/config audit with whole-program or config-file scope, not a BP needle.

---

## BP-125 — Mixing framework context with stdlib `ResponseWriter`

**Decision: wontfix** under syntax-only detectors.

Dual-write / hijack bugs need framework control-flow (who owns the writer after `c.Writer` vs raw `http.ResponseWriter`, middleware order, hijack state). Heuristic “two writer APIs in one handler” cannot prove incorrect mixing without ownership proof. Adjacent shipped rules already cover bounded HTTP write-order and framework error-discard cases. Leave parked until framework control-flow facts are first-class.

---

## BP-127 — Nested transactions assumed supported

**Decision: wontfix** as BP; driver semantics required.

Nested `Begin` (or `Begin` while holding `*sql.Tx`) is legal with savepoints on some drivers and an error or no-op on others. Local shape “function has `*sql.Tx` param and calls `Begin`” does not prove misuse. **BP-126** already covers local tx lifecycle (commit/rollback). Nested-tx correctness stays driver/runtime-proof territory (typed DB facts or runtime annotations), not a tree-sitter BP.

---

## BP-165 — Exported constructor starts lifecycle without Close/Shutdown

**Decision: wontfix** until multi-file type/method-set ownership exists.

The smell needs: exported `New*` returns `*T`, starts `go`/Listen/Accept inside the constructor or immediately after, and package method-set for `T` lacks `Close`/`Shutdown`/`Stop`. That is multi-file type resolution plus lifecycle ownership — explicitly deferred in CHECKLIST. Local rules **BP-12/14/79/98/145** already cover single-function resource lifecycle. Do not implement a half-file constructor heuristic that misses methods on other files or flags intentional fire-and-forget tools.

---

## Shared design bar (when reopening any of the six)

A proof-boundary ID may only leave “wontfix / park” if **all** of:

1. A **frozen static subset** is stated (what is in/out of scope).
2. False positives are argued against real modules (gorl, monsoon, go-retry, gopdfsuit or successor canaries), not only fixtures.
3. Required facts (types, alias, multi-file methods, driver/config) are **already** available to the detector seam — no pretending.

Until then these IDs stay out of the BP implementation queue.

---

## Wontfix as BP — retire-duplicate confirmation

The nine IDs below were classified **retire-duplicate** in `bp-candidates-disposition.md`. Confirmed here as **wontfix for a new BP detector**: do not re-implement under the BP pack; strengthen the owning CWE/PERF/BP/tool path if signal is still desired.

| ID | Theme | Owning signal (do not duplicate as BP) |
|----|--------|----------------------------------------|
| **BP-78** | Context not propagated to child call | **noctx** (and gap-doc “missing context on net/http client”) |
| **BP-103** | Redirect from unvalidated external URL | **CWE-601** open redirect |
| **BP-108** | Handler uses `context.Background` / ignores request context | **BP-13** (+ PERF-030 Background-in-goroutine from request paths) |
| **BP-118** | Echo path param → filesystem without clean | **CWE-22** path traversal / taint file sinks |
| **BP-124** | Panic recovery middleware missing on public server | **PERF-067** Gin Recovery disabled; “public” not static |
| **BP-129** | SQL string built with `fmt.Sprintf` | **CWE-89** SQL injection hygiene |
| **BP-130** | `db.SetMaxOpenConns` never configured | **PERF-079** pool limits / GORM pool exhaustion |
| **BP-139** | GORM `Raw` / string-concat SQL | **CWE-89** (GORM Raw called out in CWE domain) |
| **BP-152** | Hardcoded localhost / DSN credentials in non-test code | **CWE-798** (+ **BP-161** for production DSN markers in tests) |

No detector code, catalog rows, or fixtures are added for these IDs under #46.
