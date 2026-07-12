# Part C — HTTP & Web Frameworks (BP-101..BP-125)

> **Parent:** `plans/v0.0.3/new-bad-practices/README.md`
> **IDs:** BP-101 … BP-125 (**25 rules**)
> **Stacks:** net/http (P0), Gin (P0), Echo/Fiber/Chi (P1)
> **Status:** Plan only
> **Effort:** ~2–2.5 weeks

**Fixtures required for every rule:**  
`tests/fixtures/go/bad_practices/BP-N-vulnerable.txt` + `BP-N-safe.txt`  
Use `variant: gin|echo|fiber|chi|stdlib` in the fixture header.  
**Snippets must be `.txt` files** with the framework import in the body.

**PERF overlap ban:** Do **not** re-add Gin logger hot-path, N+1, static cache headers, bind alloc, etc. Those are PERF. This part is **correctness / safety / API misuse**.

---

## C0 — Module work

- [ ] New module `rules/http_frameworks.rs` (or split `http_stdlib.rs` + `http_gin.rs` …)
- [ ] Import gates: `github.com/gin-gonic/gin`, `github.com/labstack/echo`, `github.com/gofiber/fiber`, `github.com/go-chi/chi`, `net/http`
- [ ] New category `HttpFrameworks` (or `ProductionHardening` reuse — prefer new for filtering)
- [ ] JSON + dispatch BP-101..BP-125
- [ ] Needles for `c.JSON`, `c.Bind`, `c.ShouldBind`, `c.Abort`, `fiber.Ctx`, `echo.Context`, `chi.Router`, …

---

## net/http (stdlib) — BP-101..BP-108

### BP-101 — Handler Writes Header After Write Body

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `Write`/`WriteString` then `WriteHeader` |
| **Detect** | Order inversion on `http.ResponseWriter` |
| **Safe** | WriteHeader before body |
| **Fixtures** | **txt snippets required** |

- [ ] Implement + fixtures + tests

### BP-102 — Missing `http.Error` / Status On Failure Path

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | Handler `if err != nil { return }` without writing status |
| **Detect** | Handler-shaped func with early return on err and no WriteHeader/Error |
| **Safe** | `http.Error(w, …, code)` |
| **Fixtures** | **txt snippets required** |

- [ ] Implement + fixtures + tests

### BP-103 — Redirect Using Unvalidated External URL

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `http.Redirect(w, r, r.URL.Query().Get("next"), …)` open redirect practice |
| **Note** | Related CWE-601 — if CWE already covers, **skip implement** and reassign ID; else BP hygiene with allowlist fix guidance |
| **Detect** | Redirect location from query/form without host check |
| **Fixtures** | **txt snippets required** |

- [ ] Confirm CWE gap first
- [ ] Implement + fixtures + tests

### BP-104 — `ServeHTTP` Mux Registered With Method-Insensitive Overlap Ambiguity (Go 1.22+)

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Smell** | Duplicate patterns / methodless registration conflicting with methodful |
| **Detect** | Heuristic on `HandleFunc` patterns in same file |
| **Safe** | Explicit method patterns `"GET /path"` |
| **Fixtures** | **txt snippets required** |

- [ ] Implement + fixtures + tests

### BP-105 — Cookie Set Without `Secure`/`HttpOnly` In Non-Dev

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `&http.Cookie{...}` missing HttpOnly/Secure flags |
| **Detect** | Cookie composite lit without those fields |
| **Safe** | Set HttpOnly + Secure (and SameSite) |
| **Fixtures** | **txt snippets required** |

- [ ] Implement + fixtures + tests

### BP-106 — CORS Allow-Origin Reflects Request Origin Unconditionally

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `Access-Control-Allow-Origin` = `r.Header.Get("Origin")` without allowlist |
| **Detect** | Header set from Origin header directly |
| **Safe** | Allowlist map |
| **Fixtures** | **txt snippets required** |

- [ ] Implement + fixtures + tests

### BP-107 — Middleware Not Calling `next` / `Handler.ServeHTTP`

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | Middleware func that never invokes next handler |
| **Detect** | Func taking `http.Handler` returning `HandlerFunc` without `next.ServeHTTP` |
| **Safe** | Always call next (or explicit terminal) |
| **Fixtures** | **txt snippets required** |

- [ ] Implement + fixtures + tests

### BP-108 — Request Context Ignored After Server Shutdown Pattern

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | Handler starts work with `context.Background()` instead of `r.Context()` |
| **Detect** | In handler: Background/TODO while `*http.Request` in scope |
| **Overlap** | BP-13; this is **handler-specific** |
| **Safe** | `r.Context()` |
| **Fixtures** | **txt snippets required** |

- [ ] Implement + fixtures + tests

---

## Gin — BP-109..BP-115

### BP-109 — Gin Handler Not Aborting After Error Response

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `c.JSON(4xx/5xx, …)` then code continues / still calls `c.JSON` again |
| **Detect** | Error status JSON without `c.Abort()` / `return` |
| **Safe** | `c.AbortWithStatusJSON` or JSON+Abort+return |
| **Fixtures** | **txt + `variant: gin`** |

- [ ] Implement + fixtures + tests

### BP-110 — Gin `c.ShouldBindJSON` Error Ignored

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | bind call with discarded error then use struct |
| **Detect** | `ShouldBind*` / `Bind*` with `_` or no check |
| **Safe** | Check err → 400 |
| **Fixtures** | **txt + gin** |

- [ ] Implement + fixtures + tests

### BP-111 — Gin Goroutine Using `*gin.Context` Without `c.Copy()`

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `go func(){ c.JSON(...) }()` — context not concurrent-safe |
| **Detect** | `go ` body references `c.` without prior `c.Copy()` |
| **Overlap** | PERF-65 is performance-named copy; this is **correctness** (race/panic). Coordinate naming so both don’t double-fire noisily — prefer single high-signal BP; disable PERF overlap or share helper |
| **Safe** | `cp := c.Copy(); go func(){ ... cp ...}` |
| **Fixtures** | **txt + gin** |

- [ ] Implement + fixtures + tests
- [ ] Resolve PERF-65 overlap policy

### BP-112 — Gin Route Group Missing Auth Middleware On Sensitive Prefix

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `/admin` group without middleware auth ident |
| **Detect** | Heuristic: path contains `admin`/`internal`/`settings` and group has no `Use(` auth-like |
| **Safe** | `admin.Use(AuthRequired())` |
| **Fixtures** | **txt + gin** |

- [ ] Implement + fixtures + tests

### BP-113 — Gin Default Mode Not Set To Release In `main`

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Smell** | `gin.Default()` in main without `gin.SetMode(gin.ReleaseMode)` |
| **Detect** | main + Default + no SetMode |
| **Safe** | SetMode from env |
| **Fixtures** | **txt + gin** |

- [ ] Implement + fixtures + tests

### BP-114 — Gin Trusting `ClientIP` Without Trusted Proxies Config

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `c.ClientIP()` used for authz/rate limit without `SetTrustedProxies` |
| **Detect** | ClientIP usage; no SetTrustedProxies in package/main |
| **Safe** | Configure trusted proxies explicitly |
| **Fixtures** | **txt + gin** (may need multi-file project fixture) |

- [ ] Implement + fixtures + tests

### BP-115 — Gin Binding Struct Missing `binding:"required"` On Critical Fields

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Smell** | Public DTO with empty tags on password/email fields (heuristic name list) |
| **Detect** | Struct used in ShouldBindJSON; sensitive field names without binding tag |
| **Safe** | binding tags + validate |
| **Fixtures** | **txt + gin** |

- [ ] Implement + fixtures + tests

---

## Echo — BP-116..BP-118

### BP-116 — Echo Handler Returning `nil` After Writing Error Blindly

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | Writes response then returns raw err causing double response via middleware |
| **Detect** | `c.JSON` + `return err` both present |
| **Safe** | Return err **or** write response, not both inconsistently |
| **Fixtures** | **txt + echo** |

- [ ] Implement + fixtures + tests

### BP-117 — Echo Bind Error Ignored

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `c.Bind(&req)` without err check |
| **Detect** | Same pattern as Gin bind |
| **Fixtures** | **txt + echo** |

- [ ] Implement + fixtures + tests

### BP-118 — Echo Path Param Used In File Path Without Clean

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `c.Param` joined into filesystem path |
| **Note** | Prefer CWE-22 if covered for Echo — verify gap |
| **Fixtures** | **txt + echo** |

- [ ] Confirm CWE gap
- [ ] Implement + fixtures + tests

---

## Fiber — BP-119..BP-121

### BP-119 — Fiber Immutable / `c.Context()` Lifetime Misuse Across Goroutine

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | Capturing `*fiber.Ctx` in goroutine (unsafe) |
| **Detect** | `go ` + `c.` fiber methods without locals copy |
| **Safe** | Copy needed values before goroutine |
| **Fixtures** | **txt + fiber** |

- [ ] Implement + fixtures + tests

### BP-120 — Fiber BodyParser Error Ignored

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `c.BodyParser(&x)` ignore err |
| **Fixtures** | **txt + fiber** |

- [ ] Implement + fixtures + tests

### BP-121 — Fiber Prefork Enabled Without Caution In 12-factor Deploy

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Smell** | `Prefork: true` hardcoded |
| **Detect** | Config lit Prefork true |
| **Safe** | Default false; document when OK |
| **Fixtures** | **txt + fiber** |

- [ ] Implement + fixtures + tests

---

## Chi — BP-122..BP-123

### BP-122 — Chi Middleware Chain Missing `next.ServeHTTP`

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | Same as BP-107 specialized for chi patterns |
| **Fixtures** | **txt + chi** |

- [ ] Implement + fixtures + tests

### BP-123 — Chi URLParam Used Without Presence Check Before Authz

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `chi.URLParam(r, "id")` empty-string risk for authz |
| **Detect** | URLParam used in comparisons without empty check |
| **Safe** | Validate non-empty / parse UUID |
| **Fixtures** | **txt + chi** |

- [ ] Implement + fixtures + tests

---

## Cross-framework — BP-124..BP-125

### BP-124 — Panic Recovery Middleware Disabled / Missing On Public Server

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | Custom engine without Recovery middleware (Gin Recovery, Echo Recover, …) |
| **Overlap** | PERF mentions Recovery disabled — keep BP for **correctness** “missing recover” if PERF is hot-path only |
| **Fixtures** | **txt per framework variant optional; start with gin** |

- [ ] Implement + fixtures + tests

### BP-125 — Mixing Framework Context With stdlib `http.ResponseWriter` Incorrectly

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | Writing to `c.Writer` and `http.ResponseWriter` from hijacked paths inconsistently |
| **Detect** | Heuristic dual-write in same handler |
| **Fixtures** | **txt snippets required** |

- [ ] Implement + fixtures + tests

---

## Part C exit criteria

- [ ] 25 rules specified → implemented or deferred
- [ ] Every shipped rule has **gin/echo/fiber/chi/stdlib `.txt` fixtures** (vulnerable + safe)
- [ ] PERF overlap review documented for BP-111 / BP-124
- [ ] Integration green for BP-101..BP-125
