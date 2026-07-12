# v0.0.3 — New Go Bad Practices (BP-66..BP-165)

> **Parent:** `plans/v0.0.3/README.md`
> **Status:** Plan only — **not started**
> **Date:** 2026-07-10
> **Target release:** v0.0.3
> **Scope:** **100 new** Go bad-practice rules (`BP-66` … `BP-165`) that fill gaps **not** covered by existing CodeHound BP/CWE/PERF rules **and** not usefully covered by stock `go vet` / `staticcheck` / `golangci-lint` defaults
> **Estimated effort:** ~8–12 weeks across 6 parts (can parallelize after scaffolding)

---

## Purpose

CodeHound already ships **BP-1..BP-65** across seven domains (error handling, concurrency, testing, API design, code organization, production hardening, dependency hygiene). Those rules target high-signal application-level smells.

This plan adds **100 more** common Golang bad practices that:

1. Show up repeatedly in real codebases and “100 Go Mistakes” / style-guide catalogs.
2. Are **not** already detected by BP-1..65, CWE, or PERF catalogs.
3. Are **not** primarily style/format (gofmt, goimports, revive vanity checks).
4. Are **not** pure language-level `go vet` / default `staticcheck` findings (or only weakly covered there with no framework awareness).
5. Prefer **static, AST / pattern / multi-file heuristics** that CodeHound can ship without a full type-checker.

**ID block:** continue sequential numbering after BP-65 → **`BP-66` … `BP-165`**.

---

## Existing coverage (do not re-implement)

| Bucket | IDs / notes |
|--------|-------------|
| BP shipped | BP-1..BP-65 (`ruleset/golang/bad-practices.json`, `documents/bad-practices.md`) |
| CWE | Security / CWE catalog (path traversal, SQLi, XSS, weak crypto, …) |
| PERF | Perf / hot-path catalog (incl. many **Gin / Echo / GORM / sqlx** *performance* rules) |
| Stock linters | `go vet`, `staticcheck` (SA/S/ST/QF), `errcheck`, `ineffassign`, `govet`, bodyclose, noctx, sqlclosecheck, etc. via golangci-lint |

**Critical distinction for frameworks:** PERF already covers *performance* smells (e.g. Gin logger on hot path, GORM N+1). New BP rules must cover **correctness, API misuse, lifecycle, security-adjacent hygiene, and maintainability** — not thrashing PERF territory.

---

## Framework / library priority (widely used)

Sources: JetBrains Go Ecosystem survey trends (Gin ~48%, Gorilla legacy ~17%, Echo ~16%, Fiber ~11%, Chi ~12%), plus ecosystem defaults for data/RPC.

| Priority | Stack | Why include |
|----------|-------|-------------|
| P0 | **net/http** (stdlib) | Still the baseline; Chi/stdlib hybrids dominate mature services |
| P0 | **Gin** | Most-used web framework |
| P0 | **database/sql** + **GORM** + **sqlx** | Dominant persistence stack |
| P1 | **Echo**, **Fiber**, **Chi** | Next web tier by adoption |
| P1 | **google.golang.org/grpc** | Dominant RPC |
| P1 | **log/slog**, **uber-go/zap** (quality rules only) | Dominant logging |
| P2 | **go-redis/redis**, **jackc/pgx** | Common data clients |
| P2 | **cobra** / **flag** | CLI entrypoints |
| OOS | Niche MVC (Beego, Revel), product-only stacks | Low ROI unless demand spikes |

Framework-tagged rules fire only when the import path is present (same pattern as PERF Gin/Echo detectors).

---

## Documents in this folder

| File | Contents |
|------|----------|
| **[CHECKLIST.md](./CHECKLIST.md)** | **Primary tracker** — phases, DoD, per-part progress |
| [00-gap-and-scope.md](./00-gap-and-scope.md) | Gap criteria, linter exclusion list, permanent OOS |
| [01-part-a-core-language.md](./01-part-a-core-language.md) | BP-66..BP-85 — nil, slices/maps, errors, context, time (**20**) |
| [02-part-b-concurrency-resources.md](./02-part-b-concurrency-resources.md) | BP-86..BP-100 — concurrency, channels, I/O lifecycle (**15**) |
| [03-part-c-http-frameworks.md](./03-part-c-http-frameworks.md) | BP-101..BP-125 — net/http + Gin/Echo/Fiber/Chi (**25**) |
| [04-part-d-data-persistence.md](./04-part-d-data-persistence.md) | BP-126..BP-145 — sql / GORM / sqlx / redis / pgx (**20**) |
| [05-part-e-observability-config.md](./05-part-e-observability-config.md) | BP-146..BP-160 — logging, config, JSON, gRPC, CLI (**15**) |
| [06-part-f-testing-api-hygiene.md](./06-part-f-testing-api-hygiene.md) | BP-161..BP-165 — testing + API/org hygiene tail (**5**) + stretch backlog |
| [07-implementation-order.md](./07-implementation-order.md) | Scaffold → batch order, PR titles, risk notes |

**Track completion in [CHECKLIST.md](./CHECKLIST.md).** Rule-level detection sketches live in the part files.

---

## Shipping shape (every rule — non-negotiable)

Mirror existing BP work. For **each** of BP-66..BP-165:

1. **Ruleset JSON** entry in `ruleset/golang/bad-practices.json` (or a future chunk split if the file grows too large).
2. **Build codegen** — `build/gen_bp.rs` / `build.rs` picks up new IDs (existing pipeline).
3. **Detector** in `src/lang/go/detectors/bad_practices/rules/` (extend existing modules or add domain modules; keep `GoBadPracticeScan` single detector).
4. **SourceIndex needles** if pre-filter helps (`source_index.rs`).
5. **Fixtures as text snippets** (required):
   - `tests/fixtures/go/bad_practices/BP-N-vulnerable.txt`
   - `tests/fixtures/go/bad_practices/BP-N-safe.txt`
   - Framework / multi-file cases may use `tests/fixtures/go/bad_practices_projects/` when a single file is insufficient.
6. **`tests/fixtures/manifest.toml`** entries for both variants.
7. **Docs** line in `documents/bad-practices.md` (rationale + canonical fix).
8. **Integration green:** `cargo test --test go_bad_practice_integration` (and project integration where used).

### Snippet / fixture format (mandatory reminder)

Fixtures are **plain `.txt`**, never committed as raw `.go` files under `tests/fixtures/`.

```text
# BP-N positive: short description
lang: go
file: BP-N-vulnerable.go
variant: stdlib   # or gin | echo | fiber | chi | gorm | sqlx | grpc | ...
---
package sample

// minimal compilable-looking Go source that triggers BP-N
```

```text
# BP-N negative: short description
lang: go
file: BP-N-safe.go
variant: stdlib
---
package sample

// near-miss / correct pattern that must NOT fire BP-N
```

See `tests/fixtures/README.md`. Materialization writes to `target/codehound-fixtures/` at test time.

**Every rule in this plan must land with both vulnerable and safe text fixtures.** No detector without snippets.

---

## Domain map (100 rules)

| Part | Domain | IDs | Count |
|------|--------|-----|------:|
| A | Core language (nil, slice/map, errors, context, time) | BP-66..BP-85 | 20 |
| B | Concurrency + resource lifecycle | BP-86..BP-100 | 15 |
| C | HTTP + web frameworks | BP-101..BP-125 | 25 |
| D | Data persistence | BP-126..BP-145 | 20 |
| E | Observability, config, JSON, gRPC, CLI | BP-146..BP-160 | 15 |
| F | Testing + API/org hygiene (tail) | BP-161..BP-165 | 5 |
| | **Total** | **BP-66..BP-165** | **100** |

Extensions of existing BP domains:

| Existing domain (v2) | How v3 extends it |
|----------------------|-------------------|
| Error Handling | Deeper `errors.Is`/`As`, multi-error, partial failure |
| Concurrency | Channel ownership, errgroup, mutex hygiene beyond BP-6..15 |
| Testing | Advanced flaky / cleanup / golden patterns |
| API Design | Generics, options pattern, constructor contracts |
| Code Organization | Internal packages, build tags, file placement |
| Production Hardening | HTTP/middleware correctness, gRPC interceptors |
| Dependency Hygiene | *(mostly done; only high-value additions if needed)* |
| **New** | Framework correctness, DB correctness, logging, config, JSON, time |

---

## Definition of done (folder-level)

- [ ] All 100 rules specified in part files with detect/suppress/fixture sketches
- [ ] Gap review: no pure `gofmt` / default `staticcheck` duplicates without CodeHound-unique value
- [ ] No PERF-only rehashes (framework *correctness* only)
- [ ] No CWE rehashes (use CWE catalog for true vulns)
- [ ] Scaffold: category enum + dispatch + SourceIndex needles ready for new domains
- [ ] BP-66..BP-165 in `bad-practices.json` + detectors + **txt fixtures** + manifest + docs
- [ ] `cargo test --test go_bad_practice_integration` green
- [ ] `documents/bad-practices.md` updated for all new rules
- [ ] Optional: `make run-bp-new` (`--only BP-66,…` or range helper) so findings are not buried by CWE/PERF
- [ ] PR(s) merged *(human step)*

---

## Quick start for implementers

```bash
# After a batch lands, scan only new BPs (once make target exists):
make run-bp-new
# or today:
cargo run -- scan --bp-only --only BP-66,BP-67  # adjust to shipped IDs
```

Read **[00-gap-and-scope.md](./00-gap-and-scope.md)** before implementing any detector.
Read **[CHECKLIST.md](./CHECKLIST.md)** for the live checkbox tracker.
