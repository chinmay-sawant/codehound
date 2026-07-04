# SlopGuard vs Staticcheck: Finding Analysis

**Test codebase:** `gopdfsuit` — a Go PDF generation/manipulation suite  
**Findings:** 321 across 13 chunk files  
**Staticcheck result:** 0 findings

---

## Summary

| Metric | Count |
|--------|------:|
| Total findings | **321** |
| PERF (performance) | 311 (96.9%) |
| CWE (security) | 10 (3.1%) |
| Distinct rules fired | 34 of 275 (12.4%) |
| Most flagged file | `xfdf.go` — 53 findings |

---

## Why Staticcheck Caught Nothing

| Category | % of findings | Staticcheck blind spot |
|----------|:------------:|------------------------|
| **Unique to SlopGuard** | 81% (22/27 rules) | Framework semantics, hot-path awareness, repeated-call tracking, goroutine-scope analysis |
| Staticcheck would catch | 19% (5/27 rules) | PERF-1 (SA6000 regex-in-loop), PERF-7 (gocritic deferInLoop), PERF-36 (govet loopclosure), PERF-42 (S1028 fmt.Errorf with static string), PERF-45 (prealloc) |

### The Four Blind Spots

**1. Framework-specific patterns** — staticcheck has zero knowledge of Gin, Echo, GORM, or sqlx. It sees `gin.Logger()` as any other function call. SlopGuard knows `gin.Logger()` performs synchronous I/O under a mutex on every request.

Examples: PERF-68 (Gin Logger in production), PERF-61 (static handler no cache headers), PERF-57 (heavy work in middleware)

**2. Hot-path / cold-path distinction** — staticcheck treats all function bodies equally. SlopGuard understands whether code runs at startup (once) vs. on the request path (per-request, potentially thousands of times/second).

Examples: PERF-6 (fmt.Sprintf in loop), PERF-32 (string/byte conversion on hot path), PERF-22 (os.ReadFile in handler)

**3. Security-specific vulnerabilities** — staticcheck has no CWE mappings, no taint analysis, no threat-model awareness.

Examples: CWE-22 (path traversal), CWE-497 (system info exposure), CWE-916 (insufficient password hash effort)

**4. Custom domain-specific detectors** — patterns that require cross-cutting analysis beyond single-statement patterns.

Examples: PERF-40 (repeated time.Now calls in one function), PERF-44 (repeated type assertion on same interface), PERF-35 (interface boxing via fmt.Sprintf on hot path)

---

## Top 10 Rules by Frequency

| Rank | Rule | Count | What it detects |
|------|------|------:|-----------------|
| 1 | PERF-6 | 94 | `fmt.Sprintf` / `fmt.Fprintf` inside loop body |
| 2 | PERF-32 | 57 | `string ↔ []byte` conversion on hot path (copies data) |
| 3 | PERF-1 | 38 | `regexp.MustCompile` inside loop body |
| 4 | PERF-35 | 24 | Interface boxing via `fmt.Sprintf`/`fmt.Errorf` on hot path |
| 5 | PERF-31 | 15 | `defer` in a hot handler function |
| 6 | PERF-15 | 15 | `strconv` formatting inside loop body |
| 7 | PERF-46 | 9 | String trimming with allocations on request path |
| 8 | PERF-42 | 9 | `fmt.Errorf` with static string (no format verbs) |
| 9 | PERF-7 | 7 | `defer` placed inside loop body |
| 10 | PERF-40 | 6 | `time.Now` called repeatedly in same function |

---

## Top 10 Most Flagged Files

| File | Findings |
|------|--------:|
| `internal/pdf/form/xfdf.go` | 53 |
| `internal/pdf/outline.go` | 24 |
| `internal/pdf/generator.go` | 23 |
| `internal/pdf/svg/svg.go` | 22 |
| `internal/pdf/font/registry.go` | 21 |
| `internal/pdf/merge.go` | 18 |
| `sampledata/gopdflib/zerodha/main.go` | 14 |
| `internal/pdf/redact/secure.go` | 12 |
| `internal/handlers/handlers.go` | 12 |
| `internal/pdf/signature/signature.go` | 11 |

---

## Security Findings (CWE)

| Rule | Count | Files | gosec catches? |
|------|------:|-------|:---:|
| CWE-497 (System Info Exposure) | 4 | `main.go`, `financial_report/main.go`, `zerodha/main.go`, `benchconfig.go` | No |
| CWE-328 (Weak Hash — MD5) | 3 | `encrypt.go`, `generator.go`, `encryption_inhouse.go` | Yes |
| CWE-916 (Insufficient Password Hash Effort) | 2 | `encrypt.go`, `encryption_inhouse.go` | No |
| CWE-22 (Path Traversal) | 1 | `handlers.go` | Yes |

---

## PERF Rule Classification

| Rule | Title | Unique to SlopGuard? |
|------|-------|:---:|
| PERF-1 | Regular Expression Compilation Inside Loop | No (staticcheck SA6000) |
| PERF-3 | Slice Rebuild Inside Loop | **Yes** |
| PERF-4 | Map Allocation Inside Loop | **Yes** |
| PERF-6 | fmt Formatting Inside Loop | **Yes** |
| PERF-7 | Defer Inside Loop | No (golangci-lint gocritic) |
| PERF-15 | strconv Formatting Inside Loop | **Yes** |
| PERF-22 | os.ReadFile Inside Handler | **Yes** |
| PERF-27 | Missed sync.Pool Reuse Opportunity | **Yes** |
| PERF-30 | context.Background In Goroutine From Request | **Yes** |
| PERF-31 | Defer In Hot Function | **Yes** |
| PERF-32 | String Byte Conversion In Hot Path | **Yes** |
| PERF-35 | Interface Boxing On Hot Path | **Yes** |
| PERF-36 | Loop Variable Capture In Goroutine | No (go vet loopclosure) |
| PERF-40 | time.Now Calls In Hot Path | **Yes** |
| PERF-41 | log Standard Logger In Production Hot Path | **Yes** |
| PERF-42 | fmt.Errorf With No Formatting In Hot Path | No (staticcheck S1028) |
| PERF-43 | Panic Recovery In Hot Path | **Yes** |
| PERF-44 | Repeated Type Assertion On Same Interface | **Yes** |
| PERF-45 | Append Without Capacity Hint In Loop | No (golangci-lint prealloc) |
| PERF-46 | String Trimming With Allocations | **Yes** |
| PERF-47 | strings.Split In Hot Path | **Yes** |
| PERF-48 | bytes.Equal On Long Strings | **Yes** |
| PERF-55 | bufio.Scanner Default Token Size | **Yes** |
| PERF-57 | Gin Middleware Heavy Allocation | **Yes** |
| PERF-61 | Gin Static Handler No Cache Headers | **Yes** |
| PERF-68 | Gin Logger Middleware In Production Hot Path | **Yes** |
| PERF-88 | Echo Static Handler Missing Cache | **Yes** |

**22 of 27 PERF rules (81%) are unique to SlopGuard.**

---

## Most Interesting Finding

**PERF-55** (`ocr_adapter.go:139`) — `bufio.NewScanner` used without explicit `Buffer()` sizing. Lines longer than 64KB silently fail (truncated) with `bufio.ErrTooLong` — no error surfaced, data is just missing. This is a real correctness bug that no standard Go linter catches.

---

## Bottom Line

Staticcheck is a language-level linter. It operates on syntax patterns without understanding framework semantics, request-path context, security threat models, or application architecture. SlopGuard fills the gap between language linters and full SAST tools — detecting application-level performance patterns and security vulnerabilities that require understanding *what* the code does at runtime, not just *how* it's written.
