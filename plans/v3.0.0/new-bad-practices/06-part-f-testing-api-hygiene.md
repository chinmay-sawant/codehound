# Part F — Testing & API/Org Hygiene Tail (BP-161..BP-165) + Stretch Backlog

> **Parent:** `plans/v3.0.0/new-bad-practices/README.md`
> **IDs:** BP-161 … BP-165 (**5 rules** to complete the 100)
> **Plus:** ordered stretch backlog if any core IDs are dropped during gap review
> **Status:** Plan only
> **Effort:** ~3–5 days (core 5) + optional stretch

**Fixtures required for every rule:**  
`tests/fixtures/go/bad_practices/BP-N-vulnerable.txt` + `BP-N-safe.txt` (**text snippets only**).

**Existing testing rules:** BP-16..BP-25. Do not rehash Sleep-in-test, t.Helper, table tests, etc.

---

## F0 — Module work

- [ ] Extend `testing.rs`, `api_design.rs`, `code_organization.rs`
- [ ] JSON + dispatch BP-161..BP-165

---

## Core five (complete BP-66..BP-165 = 100)

### BP-161 — Test Uses Production Database DSN

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Category** | Testing |
| **Smell** | `_test.go` opens DSN pointing at prod hostnames / missing `test` database name |
| **Detect** | sql.Open / gorm.Open in tests with host literals not localhost/container |
| **Safe** | testcontainers / sqlite / explicit TEST_DSN |
| **Fixtures** | **txt required** (file name `*_test.go` in header `file:`) |

- [ ] Implement + fixtures + tests

### BP-162 — `t.Parallel` With Shared Mutable Fixture State

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Category** | Testing |
| **Smell** | `t.Parallel()` while mutating package-level vars / shared struct |
| **Detect** | Parallel + writes to package-level idents |
| **Safe** | Per-test fixtures; no shared mutables |
| **Overlap** | Related BP-21 (missing Parallel); this is **unsafe Parallel** |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-163 — Golden / Snapshot File Written Without `testing.Short` Guard In Update Path

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Category** | Testing |
| **Smell** | `-update` golden writers always on |
| **Detect** | Flag `update` writing files in tests without short/env guard |
| **Safe** | Explicit UPDATE_GOLDEN env |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-164 — Functional Options Mutating Global Defaults

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Category** | API Design |
| **Smell** | `Option` funcs assign to package-level config |
| **Detect** | `func WithX(...) Option` body assigns package vars |
| **Safe** | Options apply to `*Config` receiver only |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-165 — Exported Constructor Missing Context Or Closer Cleanup Contract

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Category** | API Design |
| **Smell** | `NewServer(...) (*Server, error)` starts goroutines/listeners without `Close`/`Shutdown` method on type |
| **Detect** | Exported New* returns pointer type that calls `go ` or `Listen` without Close/Shutdown methods in package |
| **Safe** | Implement `Close`/`Shutdown`; document lifecycle |
| **Fixtures** | **txt required** (may need multi-file package fixture) |

- [ ] Implement + fixtures + tests

---

## Part F exit criteria (core)

- [ ] BP-161..BP-165 shipped
- [ ] **Text fixtures** for each
- [ ] `documents/bad-practices.md` updated
- [ ] Full BP-66..BP-165 integration pass (or per-batch as merged)

---

## Stretch backlog (replacements if a planned rule is OOS)

Use these **only** to replace dropped IDs so the release still ships ~100 net-new rules. Each stretch item still requires **vulnerable + safe `.txt` snippets**.

| Stretch ID | Title | Domain | Notes |
|------------|-------|--------|-------|
| S1 | `embed` of secrets / `.env` files | Config | `//go:embed` matching `.env`/`*.pem` |
| S2 | `init()` registering HTTP routes | Org | Side-effect routing |
| S3 | Comparing protobuf messages with `==` | gRPC | Use proto.Equal |
| S4 | `math/rand` for security tokens | Security hygiene | Prefer CWE if exists |
| S5 | JWT `alg` none accepted | Security | Prefer CWE |
| S6 | Missing `Content-Type` validation on POST JSON | HTTP | |
| S7 | Websocket upgrade without origin check | HTTP | |
| S8 | `os.Args` parsing instead of flag/cobra in large main | CLI | |
| S9 | Test helper starting server without `t.Cleanup` | Testing | |
| S10 | `httptest.ResponseRecorder` assertions only on body ignoring code | Testing | |
| S11 | GORM `Debug()` left enabled | Data | |
| S12 | sql mock not used; live network in unit tests | Testing | |
| S13 | Chi/Gin route panic on nil deps in handler ctor | HTTP | |
| S14 | Context key collisions across packages (exported key type) | Context | |
| S15 | `defer rows.Close()` before err check on Query | SQL | Classic footgun |
| S16 | Using `interface{}` / `any` in exported public API extensively | API | Heuristic count |
| S17 | Build tags inverted (`//go:build ignore`) left in tree | Org | |
| S18 | Mixing `zap.Logger` pointer vs value incorrectly | Logging | |
| S19 | Fiber `c.Body()` multiple read without restore | Fiber | |
| S20 | Echo group trailing-slash inconsistency | Echo | low |

- [ ] When replacing a core rule, update part file + CHECKLIST + keep ID continuity (do not leave holes without note)

---

## Documentation / release wrap (Part F owns the bow)

- [ ] Final pass on `documents/bad-practices.md` for BP-66..BP-165
- [ ] README rule count update (65 → 165)
- [ ] CHANGELOG v3.0.0 section draft
- [ ] Optional makefile: `run-bp-new` with `--only` list or prefix helper
- [ ] Spot-check against staticcheck on fixture corpus (expect CodeHound-only hits)
