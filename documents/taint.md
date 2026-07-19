# Taint Tracking (Experimental)

CodeHound includes an experimental intra-procedural taint-tracking engine for Go
that augments the substring-based CWE detectors (CWE-22, CWE-78, CWE-79,
CWE-89). When enabled, it traces data flow from untrusted sources to
dangerous sinks and suppresses findings where a recognized sanitizer
intercepts the flow.

## Enabling

| Method | How |
|--------|-----|
| CLI flag | `codehound --taint` |
| Config file | `[codehound.taint]\nenabled = true` |
| Disable | `--no-taint` or `[codehound.taint]\nenabled = false` |
| Show paths | `--taint-show-paths` or `[codehound.taint]\nshow_paths = true` |
| Inter-proc depth | `--taint-depth N` (1–4, default **1** = direct caller→callee only) |

Taint is disabled by default. The substring-based heuristic still runs as a
fallback when taint is off.

### Intra-proc precision (Phase 8)

- **Versioned last-write:** each assignment is a versioned node; uses resolve to
  the latest declaration with `decl_byte ≤ use_byte` (overwrite with a constant
  kills live taint).
- **Field keys:** LHS/RHS like `user.Path` are tracked as qualified keys (not
  only the base `user`).
- **Map/slice index:** `m[k] = t` conservatively taints base `m` (low precision;
  no per-key model).

## Model

The engine builds an intra-procedural data-flow graph per file. Each node is
a variable or expression; edges represent assignment, arithmetic, or
function-call return. The graph is searched backward from each sink to find
paths to recognized sources.

### Sources

| Kind | Examples |
|------|----------|
| `UserInput` | `r.URL.Query()`, `r.FormValue()`, `r.PostForm` |
| `Args` | `os.Args`, `flag.Args()`, `flag.String()` |
| `EnvVar` | `os.Getenv()`, `os.LookupEnv()` |
| `File` | `os.ReadFile()`, `ioutil.ReadFile()`, `os.Open()` |
| `Network` | `net.Conn.Read()`, `http.Request.Body` |

### Sinks

| Kind | CWE | Examples |
|------|-----|----------|
| `CommandExec` | CWE-78 | `exec.Command()`, `(*Cmd).Run/Start/Output` |
| `SQLQuery` | CWE-89 | `(*sql.DB).Query/Exec`, `(*sql.Tx).Query/Exec` |
| `FileOpen` | CWE-22 | `os.Create()`, `os.OpenFile()`, `os.WriteFile()` |
| `Template` | CWE-79 | `(*template.Template).Execute()` |
| `HTTPWrite` | CWE-79 | `w.Write()`, `w.WriteHeader()` |
| `Deserialization` | — | `json.Unmarshal()`, `xml.Unmarshal()` |

### Sanitizers

| Kind | Examples |
|------|----------|
| `Path` | `filepath.Base()` only (strips to final component). **`filepath.Clean` / `path.Clean` alone are not path-safe** and are not treated as sanitizers. |
| `HTML` | `html.EscapeString()`, `template.HTMLEscaper()` |
| `URL` | `url.QueryEscape()`, `url.PathEscape()` |
| `SQL` | **Not** bare `.Prepare` (dynamic Prepare is still injectable). Safe paths: (1) **literal** first arg at Query/Exec; (2) same-function same-var literal `Prepare`/`PrepareContext` → `Stmt.Query`/`Exec` (or `*Context` forms). |
| `Validation` | `strconv.Atoi()`, `strconv.ParseInt()`, allowlist-style `sanitize*` / `escape*` / `validate*` helpers |
| `Bounded` | `len` (weak; prefer explicit validation) |

**Path confinement (CWE-22):** findings are suppressed only when a path
variable is confined with `filepath.Abs` / `filepath.EvalSymlinks` **and**
`strings.HasPrefix` on that same binding — not file-level co-presence of
`Clean`.

When a recognized sanitizer is found on every path from the source to the
sink, the finding is suppressed. CWE-78 (command injection) does **not**
accept Path sanitizers.

## Limitations

- **`filepath.Clean` is not a path sanitizer.** Clean-only code should still
  flag CWE-22 (or show low confidence in a future release).
- **CWE-89 is a heuristic, not full SQLi.** Literal-first-arg Query/Exec is
  treated as parameterized/safe; GORM `.Raw` / sqlx helpers with dynamic SQL
  still fire. No claim of complete ORM coverage.
- **CWE-79 is not full XSS.** Template + HTTPWrite sinks only; no DOM model.
- **CWE-90/91** use real LDAP/XML sink classification; quarantine long-tail
  CWE IDs that only match fixture needles (catalog honesty — Phase 1).
- **Bare `.Prepare` is not a sanitizer.** CWE-89 suppresses only when the
  **same function** binds a simple receiver via literal `Prepare`/`PrepareContext`
  and that binding is the latest write before `Stmt.Query`/`Exec` (or `*Context`).
  Dynamic Prepare SQL, rebinding, and cross-function Prepare factories are not
  proven safe. Residual FN: dynamic Prepare with no tainted Query/Exec arg.
- **Inter-procedural tracking is depth-limited and same-package only.**
  Cross-function analysis works for direct chains (A→B→C), return
  propagation, method calls, and recursion within one package (keyed by
  package directory + clause, receiver type, and function name). Unqualified
  callees never resolve into another package; import-path wiring is not
  implemented. Depth is bounded (not a full fixpoint). Mutual recursion and
  deep chains may miss flows.
- **Limited field keys (not full field-sensitive analysis).** Qualified names
  like `user.Path` are tracked as keys; map/slice index writes taint the base
  (`m[k] = t` → `m`). No full field-sensitive / element-precise model.
- **String concatenation via `+` only.** `fmt.Sprintf` is partially handled
  but not all format-string call graphs are resolved.
- **No type-based aliasing.** Two variables of the same type pointing to the
  same allocation are treated as independent.
- **Interface dispatch.** Methods called on interface types are treated as
  opaque — taint flows through arguments but the return value is not tracked
  because the concrete implementation is unknown.
- **Channel/goroutine.** Channel sends and receives are **explicitly
  unsupported**. Extractor records `UnsupportedFlow::{Channel,Goroutine}` sites
  and does **not** create fake assignment edges through channels or `go`
  statements (honest FN). Taint that flows through a `chan` is lost at the
  goroutine boundary.
- **Pointer dereference.** `*p = tainted` and `json.Unmarshal(data, &target)`
  are handled for a small set of known functions (`json.Unmarshal`,
  `xml.Unmarshal`). General pointer tracking requires type inference.
- **Name-string sinks.** Callees are matched by identifier text, not types —
  renamed wrappers and interface methods may FN or FP.
- **No SSA / no Go types.** Intra-proc last-write and call facts are AST-level.
- **Depth.** Inter-procedural summary is bounded (not a full fixpoint). Mutual
  recursion and deep chains may miss flows.
- **Product positioning.** Enable with `--profile security` or `--taint` for
  triage. **Do not use as a sole security gate** — pair with govulncheck,
  code review, and stronger SAST where required.

See also [ADR 0003 — taint model honesty](./adr/0003-taint-model.md).

## Output

With `--taint-show-paths`, findings include a `TaintFlow` evidence block with
the source kind, sink kind, and hop count (plus per-hop details for
inter-procedural findings):

```json
{
  "evidence": {
    "kind": "TaintFlow",
    "source": { "kind": "UserInput", "function": "r.URL.Query", "variable": "host" },
    "sink": {
      "kind": "CommandExec",
      "function": "exec.Command",
      "hop_details": [
        { "function": "runCommand", "kind": "CommandExec",
          "variable": "cmd", "file": "handler.go", "line": 42 }
      ]
    },
    "hops": 1,
    "sanitized": false
  }
}
```

The text reporter shows a summary line:

```
taint flow UserInput.r.URL.Query -> CommandExec.exec.Command across 1 hop
  hop: runCommand(cmd) at handler.go:42
```

## Custom Sanitizers

Taint recognizes sanitizers by function name matching. Any function whose name
matches the regex `^(sanitize|clean|escape|validate|purify)` is treated as a
`Validation` sanitizer. Framework bind methods (`c.ShouldBind`,
`c.ShouldBindJSON`) are treated as `Validation` sanitizers when the Gin or
Echo packages are imported.

To extend the sanitizer set, see the `SanitizerKind` enum in
`src/lang/go/detectors/cwe/taint/model.rs` and the matcher table in
`src/lang/go/detectors/cwe/taint/extract.rs`.
