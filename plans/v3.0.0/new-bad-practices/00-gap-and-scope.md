# 00 — Gap Criteria, Linter Exclusions, Permanent OOS

> **Parent:** `plans/v3.0.0/new-bad-practices/README.md`
> **Status:** Plan only

---

## 1. Inclusion criteria (rule must pass all)

A candidate becomes a BP-66+ rule only if:

1. **Statically analyzable** with CodeHound’s AST / line / multi-file heuristics (no runtime profiling).
2. **High real-world frequency** in Go services (stdlib + top frameworks/ORMs).
3. **Not already shipped** as BP-1..65, CWE-*, or PERF-*.
4. **Not a pure style preference** (gofmt, import order, naming bike-sheds).
5. **Not a default linter duplicate** without added value:
   - If `staticcheck` / `go vet` / `errcheck` already catch the *same* AST shape at high precision, skip.
   - OK to ship a **related but distinct** rule (e.g. framework-aware, multi-statement lifecycle, request-path correctness).
6. **Actionable fix** can be stated in one short “canonical fix” sentence for `documents/bad-practices.md`.
7. **Fixtures exist as `.txt` snippets** (vulnerable + safe) — see README shipping shape.

---

## 2. Linter exclusion reference (do not re-implement as BP)

These are intentionally **out of CodeHound BP v3** because stock tooling owns them well:

| Area | Typical owner | Examples |
|------|---------------|----------|
| Formatting | gofmt / goimports | Brace style, import groups |
| Unused code | staticcheck U1000, unused | Unused funcs/vars/imports |
| Simple printf mistakes | go vet printf | Wrong format verbs |
| Unchecked single-value error (basic) | errcheck | `foo()` ignoring sole `error` return — **BP-1 already covers discard; do not widen blindly** |
| Deprecated stdlib symbols | staticcheck SA1019 | Prefer SA1019; BP-56 already covers known packages |
| Loop variable capture (Go &lt;1.22 only) | go vet loopclosure | Mostly historical post-1.22 |
| Simple nilness / impossible conditions | nilness / staticcheck | Where purely local |
| HTTP body not closed (stdlib client) | bodyclose | Prefer not duplicating unless multi-hop / framework body |
| Missing context on net/http client | noctx | Overlap carefully; CodeHound may add framework-specific ctx rules |
| SQL rows not closed | sqlclosecheck | Prefer distinct multi-statement / GORM session rules |
| Prealloc / append capacity | prealloc / PERF | PERF owns perf; BP only if **correctness** (e.g. append aliasing bugs) |

**When in doubt:** if a rule’s only value is “staticcheck already has SA#### for this exact pattern,” drop it from the 100 and pull from the stretch backlog in part F.

---

## 3. Overlap policy with existing CodeHound catalogs

| Catalog | Policy |
|---------|--------|
| **BP-1..65** | Never re-number. Extend with *new* IDs only. |
| **PERF-*** | No “hot path allocation” rules. Framework rules here must be **correctness / misuse / lifecycle**. |
| **CWE-*** | No full vulnerability detectors (injection, weak crypto primitives as *vulns*). Soft hygiene (e.g. “JWT alg none in config”) → prefer CWE; BP only if it’s an engineering practice without a solid CWE fit. |
| **Taint** | May later refine BP precision; do not block BP heuristics on inter-procedural taint. |

---

## 4. Permanent non-goals (OOS)

- [ ] Auto-fix / codemod engine
- [ ] Full type inference / SSA (beyond tree-sitter + light heuristics)
- [ ] Product- or company-specific rules
- [ ] Enforcing single logging library or single web framework
- [ ] Benchmark / profiler-driven PERF work (belongs in PERF plans)
- [ ] License / legal compliance scanning
- [ ] Replacing golangci-lint as a general-purpose style suite

---

## 5. Severity defaults (plan guidance)

| Severity | Use when |
|----------|----------|
| **high** | Data loss, deadlock, silent corruption, security-adjacent footgun with high exploitability in common patterns |
| **medium** | Production reliability / incorrect API use (default for most BP) |
| **low** | Maintainability / convention with occasional false positives |

Implementers may tune per-rule after fixture noise review; JSON defaults start from the part-file sketches.

---

## 6. Detection architecture notes

Reuse existing BP architecture:

- Single detector: `GoBadPracticeScan`
- Domain modules under `src/lang/go/detectors/bad_practices/rules/`
- Suggested **new or extended modules** for v3:

| Module file | Parts |
|-------------|-------|
| `error_handling.rs` | extend (Part A) |
| `sync.rs` / `loops.rs` / `panics.rs` | extend (Part B) |
| `http_frameworks.rs` (**new**) | Part C |
| `data_persistence.rs` (**new**) | Part D |
| `observability.rs` (**new**) | Part E |
| `config_cli.rs` (**new**) | Part E |
| `testing.rs` / `api_design.rs` / `code_organization.rs` | extend (Part F) |

Dispatch: extend `dispatch.rs` rule table. Metadata: extend `bad-practices.json` + categories if new `BadPracticeCategory` variants are needed (e.g. `HttpFrameworks`, `DataPersistence`, `Observability`).

---

## 7. Snippet requirements (repeat for agents)

**Required for every BP-N in this plan:**

- [ ] `tests/fixtures/go/bad_practices/BP-N-vulnerable.txt` — positive case
- [ ] `tests/fixtures/go/bad_practices/BP-N-safe.txt` — negative / near-miss
- [ ] Optional: extra variants (`BP-N-indirect-*.txt`, project fixtures) for multi-file
- [ ] `manifest.toml` registration
- [ ] Header uses `lang: go`, `file: BP-N-*.go`, optional `variant:`
- [ ] Body is minimal Go source after `---`
- [ ] **Do not** commit `.go` under `tests/fixtures/go/bad_practices/` — **text snippets only**

Framework snippets must `import` the real module path so SourceIndex / import-gated detectors can key off it, e.g.:

```go
import "github.com/gin-gonic/gin"
```

---

## 8. Research sources used for candidate mining

- Go Wiki CommonMistakes, CodeReviewComments
- Effective Go + Go blog footguns
- Uber / Google Go style guides (anti-pattern subsets)
- *100 Go Mistakes and How to Avoid Them* theme list (100go.co) — **inspired, not copied 1:1**
- Existing CodeHound `staticcheck-comparison.md` blind spots
- Framework docs: Gin, Echo, Fiber, Chi, GORM, sqlx, grpc-go

---

## 9. Preflight checklist before coding Part A

- [ ] Confirm highest existing BP id is **65**
- [ ] Grep for hard-coded max BP assumptions in tests/build
- [ ] Read `documents/bad-practices.md` and `ruleset/golang/bad-practices.json`
- [ ] Skim PERF Gin/GORM/Echo names to avoid PERF duplicates
- [ ] Agree category enum extensions (if any) in one PR before mass rules
