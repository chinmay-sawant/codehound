# Plan: Generate Positive and Negative Test Fixtures for CWE Rules

## Goal

For every CWE listed in `ruleset/golang/golang.json` (175 entries), produce one
**vulnerable** (positive) and one **safe** (negative) Go test fixture, following
the CodeHound text-fixture convention used by this repo. No heuristics, no
detection logic — fixtures only.

---

## Repo conventions you MUST follow

These are non-negotiable; deviating breaks the integration tests.

1. **Fixtures are `.txt` text files with a header**, not raw source. See
   `tests/fixtures/README.md` and `tests/fixtures/go/sample.txt` for the
   canonical shape:

   ```text
   # optional comment
   lang: go
   file: CWE-89-vulnerable.go      # optional; default = <stem>.<ext>
   ---
   package sample

   // ... full, compilable Go source ...
   ```

   The `---` line is mandatory and separates header from body. The body must
   be a **complete, compilable Go file** (valid `package`, all imports,
   compilable syntax) so that `codehound::fixture::materialize_fixture` can
   write it to `target/codehound-fixtures/go/...` at test time.

2. **Folder layout** — place every fixture under:

   ```
   tests/fixtures/go/CWE-<id>-{vulnerable,safe}.txt
   ```

   (Yes, `go/` — not `golang/`. The Go ruleset lives at
   `ruleset/golang/golang.json` for historical reasons, but the fixture
   directory is `go/`.)

3. **Register every new fixture** in `tests/fixtures/manifest.toml`:

   ```toml
   [[fixture]]
   lang = "go"
   path = "tests/fixtures/go/CWE-89-vulnerable.txt"
   required_rules = ["CWE-89"]
   ```

   The `required_rules` array should contain the CWE id the fixture is
   expected to trigger (for `-vulnerable.txt`) or not trigger (for
   `-safe.txt`). Use the CWE id string verbatim from `golang.json` (e.g.
   `"CWE-89"`, not `"SLOP..."`).

4. **No `.go` files committed.** Source is materialized under
   `target/codehound-fixtures/go/` at test time (gitignored).

---

## Per-CWE fixture requirements

For each CWE id `N` in `ruleset/golang/golang.json`:

### `CWE-N-vulnerable.txt` (positive — must trigger the rule)

- Read the `name` and `description` fields of the entry. The example must
  demonstrate **that exact weakness** — not a generic security bug.
- Use realistic Gin + GORM/sqlx context where natural: an HTTP handler in
  `package sample` that takes a `*gin.Context`, reads a request value, and
  uses it in a way that exhibits the CWE.
- The vulnerable pattern must be obvious and unambiguous (e.g. string-
  concatenated SQL for CWE-89, `os/exec` with user input for CWE-78,
  `c.Query()` used as a file path for CWE-22).
- Add a short comment block at the top of the body that names the CWE and
  the line that exhibits it. This is for human reviewers, not the analyzer.

### `CWE-N-safe.txt` (negative — must NOT trigger the rule)

- **Same shape** as the vulnerable fixture (same handler signature, same
  imports, same control flow) with the mitigation applied. The diff between
  the two files should be the smallest possible change that fixes the bug.
- For DB CWEs use parameterized queries (`?` placeholders with
  `db.Query`/`db.Queryx`/`db.Raw(...).WithContext`, or GORM's typed
  methods). For command/path/CRYPTO/auth/etc. CWEs use the idiomatic Go
  fix: `filepath.Clean` + prefix check, `subprocess` via `exec.Command`
  with a fixed argv, `crypto/subtle`, `bcrypt`, etc.
- Do not add extra unrelated "good practices" that would change which
  rules fire. The negative fixture's job is to show the *minimal* correct
  version.

### Quality bar

- Every fixture's body is **unique**. No copy-paste templates with the
  CWE id swapped in. If two CWEs share a pattern, vary the handler name,
  the data flow, and the surrounding code so the analyzer's context-
  sensitivity is exercised.
- Bodies compile under `go build` as `package sample` standalone files.
  Imports are listed exactly once and used.
- Bodies are small (target 20–60 lines). Verbose is not realistic; tiny
  is unrealistic.
- Comments and string literals inside the body must not accidentally
  mention "TODO", "FIXME", or other CWE names from sibling fixtures.

---

## Hard rules on the generation process

- **Do not write a generator script** (no Python, no Go, no template
  engine, no `for cwe in cwes: ...`). Every fixture is hand-authored from
  the CWE's `name` + `description` in `golang.json`. If a subagent
  produces a script-like output, that output is rejected.
- **No placeholders, no `...`, no `// same as above`.** Every line of Go
  in the body must be present in the file.
- **No reusing bodies across CWEs.** A handler that demonstrates
  CWE-89 must not also appear, lightly edited, as CWE-564 or CWE-943.
- **Do not invent CWEs.** The 175 ids in `ruleset/golang/golang.json`
  are exhaustive; if a subagent thinks of a related CWE not in the file,
  skip it.

---

## Execution plan (6 subagents)

1. First, count entries in `ruleset/golang/golang.json` and sort the CWE
   ids ascending. The total should be 175. If the count differs, stop
   and report — do not fabricate ids.
2. Split the sorted list into **6 contiguous, non-overlapping** ranges of
   ~29 ids each. Subagent *k* (0-indexed) gets ids at indices
   `[k*⌈175/6⌉, (k+1)*⌈175/6⌉)`. Record the exact id range in each
   subagent's prompt so ranges cannot overlap.
3. Each subagent receives:
   - Its exact id range.
   - The ruleset file path (`ruleset/golang/golang.json`).
   - The fixture template (copy of `tests/fixtures/go/sample.txt`).
   - This plan.
   - The manifest snippet to append.
4. Subagent output: writes `CWE-<id>-vulnerable.txt` and
   `CWE-<id>-safe.txt` under `tests/fixtures/go/` for **only** its ids,
   and appends the matching entries to `tests/fixtures/manifest.toml`.
   Subagents must not touch files outside their id range.
5. After all 6 finish, the orchestrator:
   - Verifies exactly 350 `.txt` files exist (175 × 2), all under
     `tests/fixtures/go/`.
   - Verifies no duplicate CWE ids across files.
   - Verifies `tests/fixtures/manifest.toml` has 350 `[[fixture]]`
     entries.
   - Runs the integration test suite (`cargo test --test go_integration`
     and the fixture-manifest integration test) to confirm fixtures
     materialize and the analyzer behaves as expected on positives vs
     negatives. If a fixture fails to materialize (e.g. body doesn't
     compile), fix the body, not the test.

---

## Deliverables checklist

- [x] 350 `.txt` fixtures under `tests/fixtures/go/frameworks/` (352 files incl. go.mod/go.sum)
- [x] 350 `[[fixture]]` entries in `tests/fixtures/manifest.toml`
- [~] `cargo test` passes for `go_integration` and
      `fixture_manifest_integration` (needs review) (deferred → see plans/v3.0.0/)
- [x] No committed `.go` files under `tests/fixtures/` (confirmed: 0 `.go` files)
