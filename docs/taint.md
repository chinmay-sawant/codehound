# Taint Tracking (Experimental)

SlopGuard includes an experimental intra-procedural taint-tracking engine for Go
that augments the substring-based CWE detectors (CWE-22, CWE-78, CWE-79,
CWE-89). When enabled, it traces data flow from untrusted sources to
dangerous sinks and suppresses findings where a recognized sanitizer
intercepts the flow.

## Enabling

| Method | How |
|--------|-----|
| CLI flag | `slopguard --taint` |
| Config file | `[slopguard.taint]\nenabled = true` |
| Disable | `--no-taint` or `[slopguard.taint]\nenabled = false` |
| Show paths | `--taint-show-paths` or `[slopguard.taint]\nshow_paths = true` |

Taint is disabled by default. The substring-based heuristic still runs as a
fallback when taint is off.

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
| `Path` | `filepath.Clean()`, `path.Clean()` |
| `HTML` | `html.EscapeString()`, `template.HTMLEscaper()` |
| `URL` | `url.QueryEscape()`, `url.PathEscape()` |
| `SQL` | `(*sql.DB).Prepare()` + `(*sql.Stmt).Query/Exec` |
| `Validation` | `strconv.Atoi()`, `strconv.ParseInt()` |
| `Bounded` | `len(s) < N` then `s[:N]` |

When a sanitizer is found on every path from the source to the sink, the
finding is suppressed.

## Limitations (MVP)

- **Intra-procedural only.** Taint does not cross function boundaries. If
  untrusted data flows through a helper function, the path is lost.
- **No field/array tracking.** `r.URL.Query()["name"][0]` is traced as one
  node; the engine does not track individual struct fields or array elements.
- **String concatenation via `+` only.** `fmt.Sprintf` is partially handled
  but not all format-string call graphs are resolved.
- **No type-based aliasing.** Two variables of the same type pointing to the
  same allocation are treated as independent.

## Output

With `--taint-show-paths`, findings include a `TaintFlow` evidence block with
the source kind, sink kind, and hop count:

```json
{
  "evidence": {
    "kind": "TaintFlow",
    "source": { "kind": "UserInput", "function": "r.URL.Query", "variable": "host" },
    "sink": { "kind": "CommandExec", "function": "exec.Command" },
    "hops": 2,
    "sanitized": false
  }
}
```

The text reporter shows a summary line:

```
taint flow UserInput.r.URL.Query -> CommandExec.exec.Command across 2 hops
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
