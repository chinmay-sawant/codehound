# Plan: Generate Pure-Go (stdlib-only) Test Fixtures for CWE Rules

## Goal

Produce a **second** set of 350 test fixtures (175 CWEs × 2 = vulnerable + safe)
covering the **same** CWE ids in `ruleset/golang/golang.json`, but with bodies
written in **pure Go using only the standard library** — no Gin, no GORM, no
sqlx, no third-party web/ORM framework. These complement, not replace, the
existing Gin/GORM/sqlx fixtures in `tests/fixtures/go/`.

### Why this matters

The existing 350 fixtures all run inside a Gin handler and use `database/sql`
or GORM/sqlx. That exercises the analyzer on the framework code path only. A
vulnerability analysis tool that only flags bugs in Gin handlers is not very
useful: a Go developer using `net/http`, `os/exec`, `path/filepath`,
`crypto/*`, or just plain `package main` CLI tools needs the same coverage.
Pure-stdlib fixtures force the rules to fire on the actual weakness pattern
in the source, independent of the framework wrapper.

---

## Repo facts that shape this plan

- `tests/fixtures/go/` already has 353 `.txt` files (175 × 2 + a few
  stragglers) and `tests/fixtures/manifest.toml` has 352 `[[fixture]]`
  entries. Off-by-one — fix that in the same PR as the new work.
- The materializer (`src/fixture/materialize.rs:25-37`) uses
  `walkdir::WalkDir` and recurses into subdirectories, so a new
  subfolder under `tests/fixtures/go/` is picked up with **no code
  change**.
- The parser (`src/fixture/format.rs:65-91`) only reads `lang:` and
  `file:` from the header. Any other header fields are dropped, so we
  can add a `variant:` discriminator without touching Rust.
- **Filename collision risk:** the materializer writes all Go fixtures
  to `target/slopguard-fixtures/go/` flat, using the `file:` header
  value (or the `.txt` stem as default). A new `CWE-89-vulnerable.txt`
  with default naming would overwrite the existing
  `target/.../CWE-89-vulnerable.go` at test time. Every pure-Go
  fixture **must** declare an explicit `file:` header with a distinct
  filename (`.pure.go` suffix — see below).

---

## Folder and naming convention

```
tests/fixtures/go/stdlib/CWE-<id>-vulnerable.txt   # -> CWE-<id>-vulnerable.pure.go
tests/fixtures/go/stdlib/CWE-<id>-safe.txt         # -> CWE-<id>-safe.pure.go
```

Fixture header (pure Go):

```text
# CWE-<id> positive: <one-line description> (pure stdlib)
lang: go
file: CWE-<id>-vulnerable.pure.go
variant: pure-go
---
package sample

// ... body uses only stdlib ...
```

The `variant: pure-go` field is documentation; the parser drops it, but
humans and any future variant-aware tooling can read it. The existing
fixtures get an analogous `variant: gin-gorm-sqlx` (or similar) in the
**same** PR for consistency, defaulting to that variant when absent.

Why `.pure.go` and not just leaving the default filename: it guarantees
no collision with the framework set at materialization time, and it
makes the two sets trivially distinguishable in
`target/slopguard-fixtures/go/`.

---

## Per-CWE rules for pure Go

### Allowed imports (non-exhaustive)

`net/http`, `database/sql`, `os`, `os/exec`, `path/filepath`, `path`,
`crypto/tls`, `crypto/x509`, `crypto/rand`, `crypto/subtle`, `crypto/hmac`,
`crypto/aes`, `crypto/cipher`, `crypto/sha256`, `encoding/json`,
`encoding/xml`, `encoding/base64`, `encoding/csv`, `encoding/hex`,
`html/template`, `text/template`, `archive/zip`, `archive/tar`,
`compress/gzip`, `net/url`, `net/mail`, `net/smtp`, `net/smtp`,
`bufio`, `io`, `io/ioutil`, `strings`, `strconv`, `time`, `log`,
`log/slog`, `errors`, `fmt`, `sort`, `sync`, `context`, `runtime`,
`runtime/debug`, `unsafe` (rarely, only for CWEs that actually need it),
`math/rand` (only when the CWE is about weak randomness), `math/big`.

### Forbidden imports

Any third-party package, **in particular**:

- `github.com/gin-gonic/gin` and `gin-gonic/contrib/*`
- `gorm.io/gorm` and any `gorm.io/*`
- `github.com/jmoiron/sqlx`
- Any other web framework (`labstack/echo`, `go-chi/chi`, `gofiber/fiber`,
  `valyala/fasthttp`, etc.) — out of scope.

A pre-flight check (`grep -rE '^\s*"(github\.com/[^\"]+|gorm\.io/[^\"]+)"'`
on the new folder) must return zero matches before tests run.

### Body shape per CWE

Same CWE-to-body mapping rule as the framework set, but the **driver**
is stdlib:

| CWE area | Pure-Go driver |
|---|---|
| SQL injection (CWE-89) | `http.HandleFunc` + `database/sql` with `db.Query("... " + r.URL.Query().Get("id"))` |
| Command injection (CWE-78) | `os/exec.Command("sh", "-c", "echo "+input)` or direct `bash -c` |
| Path traversal (CWE-22) | `os.Open(filepath.Join(base, r.URL.Query().Get("name")))` without `Clean` + prefix check |
| SSRF (CWE-918) | `http.Get(r.URL.Query().Get("url"))` with no allowlist |
| XSS (CWE-79) | `fmt.Fprintf(w, "<div>%s</div>", input)` (server-rendered HTML without escaping) |
| Deserialization (CWE-502) | `json.Unmarshal` of untrusted blob into `interface{}` and type-asserted |
| Hardcoded creds (CWE-798) | `const apiKey = "AKIA..."` literal |
| Weak crypto (CWE-327/330) | `des.NewCipher`, `md5.Sum`, `math/rand` for tokens |
| Race (CWE-362) | goroutine + shared map without mutex |
| Integer overflow (CWE-190) | `uint32(x) * uint32(y)` with attacker-controlled values |
| Path equivalence (CWE-41/59) | `os.Open` on a name after `filepath.Clean` that still allows `..` or symlink |
| ...etc | Match the CWE's `name` + `description` in `golang.json` and pick the most natural stdlib expression |

The vulnerable and safe bodies for the same CWE must be the **same
function** with the **minimum change** that fixes the bug — same as the
framework set rule.

---

## Hard rules (same as plan p4, restated for this set)

- No generator scripts. Every fixture is hand-authored from the CWE's
  `name` + `description`.
- No placeholders, no `...`, no copy-paste bodies with the CWE id
  swapped in.
- No body reuse across CWEs. A handler that demonstrates CWE-89 must
  not also appear, lightly edited, as CWE-564 / CWE-943.
- Do not invent CWEs. The 175 ids in `ruleset/golang/golang.json` are
  the universe.
- Bodies compile under `go build` as standalone `package sample`
  files. Imports are listed once, all used, nothing imported that
  isn't in the allowed list.
- Bodies 20–60 lines. The handler name, the data flow, and the
  surrounding code must differ from the framework-set fixture for the
  same CWE — otherwise the two sets become duplicates in spirit.

---

## Execution plan (6 subagents)

1. Verify the 175 CWE ids match the existing set exactly (read
   `ruleset/golang/golang.json`, sort, diff against the framework-set
   file list). If the count is off, stop and report.
2. Sort the ids ascending. Split into 6 contiguous, non-overlapping
   ranges of ~29 ids each. Each subagent receives its exact id range
   in the prompt, **plus the same id range's existing framework-set
   fixture** so it can deliberately write a *different* driver and
   avoid accidental body overlap.
3. Subagent deliverables per id `N`:
   - `tests/fixtures/go/stdlib/CWE-N-vulnerable.txt`
   - `tests/fixtures/go/stdlib/CWE-N-safe.txt`
   - Each declares `file: CWE-N-{vulnerable,safe}.pure.go` in the
     header.
   - Each sets `variant: pure-go`.
   - Append two matching `[[fixture]]` entries to
     `tests/fixtures/manifest.toml`, with `required_rules = ["CWE-N"]`
     for the positive and `required_rules = []` for the negative.
4. Subagents must not touch files outside their id range or outside
   `tests/fixtures/go/stdlib/` + `tests/fixtures/manifest.toml`.
5. After all 6 finish, the orchestrator:
   - Verifies exactly 350 new `.txt` files (175 × 2) under
     `tests/fixtures/go/stdlib/`.
   - Verifies no duplicate CWE ids in the new folder.
   - Verifies the manifest grew by exactly 350 `[[fixture]]` entries
     pointing at the new paths, with the right `required_rules`.
   - **Forbidden-import grep**: `grep -rE 'gin-gonic/gin|gorm\.io/|jmoiron/sqlx|labstack/echo|go-chi/chi|gofiber/fasthttp' tests/fixtures/go/stdlib/` must return zero matches.
   - **Filename-collision check**: every materialized `.pure.go` name
     must be unique under `target/slopguard-fixtures/go/` (no `.pure.go`
     may collide with an existing framework-set materialized name).
   - **Manifest reconciliation**: while we're here, audit the existing
     352-entry manifest vs the 353 files in `tests/fixtures/go/` and
     resolve the off-by-one (likely an extra `.txt` without a
     manifest entry, or a missing manifest entry).
   - Runs `cargo test --test go_integration` and
     `cargo test --test fixture_manifest_integration`. Any fixture
     whose materialized body fails to compile or whose positive
     doesn't trigger / negative does trigger is fixed in the fixture
     body, not in tests.

---

## Deliverables checklist

- [ ] 350 new `.txt` fixtures under `tests/fixtures/go/stdlib/`
- [ ] All new fixtures declare `file: ...pure.go` and `variant: pure-go`
- [ ] 350 new `[[fixture]]` entries in `tests/fixtures/manifest.toml`
- [ ] Forbidden-import grep returns zero matches
- [ ] No filename collisions with the framework set at materialization
- [ ] Pre-existing off-by-one in `tests/fixtures/go/` ↔ manifest resolved
- [ ] `cargo test --test go_integration` passes
- [ ] `cargo test --test fixture_manifest_integration` passes
- [ ] No committed `.go` files (all under `target/slopguard-fixtures/`)
