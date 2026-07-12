# Part E — Observability, Config, JSON, gRPC, CLI (BP-146..BP-160)

> **Parent:** `plans/v0.0.3/new-bad-practices/README.md`
> **IDs:** BP-146 … BP-160 (**15 rules**)
> **Stacks:** log/slog, zap, encoding/json, grpc-go, flag/cobra, env config
> **Status:** Plan only
> **Effort:** ~1.5 weeks

**Fixtures required for every rule:**  
`tests/fixtures/go/bad_practices/BP-N-vulnerable.txt` + `BP-N-safe.txt` (**text snippets only**).

---

## E0 — Module work

- [ ] New `rules/observability.rs` and/or `rules/config_cli.rs`
- [ ] Categories: `Observability`, `Configuration` (or reuse ProductionHardening)
- [ ] Needles: `slog.`, `zap.`, `json.Unmarshal`, `protojson`, `grpc.`, `os.Getenv`, `flag.`, `cobra.`
- [ ] JSON + dispatch BP-146..BP-160

---

## Logging — BP-146..BP-149

### BP-146 — Logging Sensitive Fields (Password/Token) At Info

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | log keys/args named password, token, secret, authorization |
| **Detect** | slog/zap/log calls with sensitive key names or format verbs near those idents |
| **Safe** | Redact / omit |
| **Note** | Not full CWE data exposure engines; simple key heuristic |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-147 — `log.Printf` Without Structured Logger In Service Code

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Smell** | std `log` in non-main packages when slog/zap also imported (inconsistent) — optional
| **Detect** | Keep **tight**: flag `log.Fatal` in libraries already BP-48; this flags `log.Print*` in `internal/` handlers when slog present |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-148 — slog Handler Misconfigured (Level Always Debug In main Production Path)

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `slog.LevelDebug` hardcoded in main without env switch |
| **Detect** | NewJSONHandler/LevelDebug in main |
| **Safe** | Level from env |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-149 — Error Logged Without `err` Attribute

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `logger.Error("failed")` without passing err |
| **Detect** | Error-level log in `if err != nil` block without err in args |
| **Safe** | `Error("failed", "err", err)` / zap.Error |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

---

## Config / env — BP-150..BP-153

### BP-150 — `os.Getenv` Without Default Or Empty Check For Required Config

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | Required config used raw from Getenv empty |
| **Detect** | Getenv assigned; used in Open/Listen/Dial without empty guard |
| **Safe** | Fail fast if missing |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-151 — Secrets Loaded From Plain Env Logged At Startup

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | Printf/log of env values for SECRET/KEY/TOKEN vars |
| **Detect** | Log of Getenv result for sensitive names |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-152 — Hardcoded Localhost Credentials In Non-Test Code

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | DSN with `password=` literal in non-test |
| **Detect** | Connection string literals with password= |
| **Overlap** | CWE-798 — verify; implement only if BP-level gap remains for DSN shapes |
| **Fixtures** | **txt required** |

- [ ] Confirm CWE-798 coverage
- [ ] Implement + fixtures + tests

### BP-153 — Feature Flag / Config Parsed With `json.Unmarshal` Ignoring Unknown Critical Version Field

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Smell** | Config struct without version; forward-compat risk — optional weak heuristic |
| **Detect** | Unmarshal into config type named `Config` without Version field (low priority) |
| **Fixtures** | **txt required** |

- [ ] Implement or drop if too noisy

---

## JSON / encoding — BP-154..BP-156

### BP-154 — `json.Unmarshal` Error Ignored

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | Unmarshal/Decode err discarded |
| **Detect** | `_ = json.Unmarshal` / missing check |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-155 — JSON `Decoder` Used On Unbounded Request Body Without Limit

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `json.NewDecoder(r.Body).Decode` without `http.MaxBytesReader` |
| **Detect** | Decoder on Body without MaxBytesReader in function |
| **Safe** | MaxBytesReader before decode |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-156 — Relying On `omitempty` For Security-Sensitive Zero Values

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | Exporting structs where false/0 secrets accidentally omitted vs explicit null — documentation-level; detect `json:"password,omitempty"` |
| **Detect** | Sensitive field names with omitempty |
| **Safe** | Explicit DTO without omitempty for secrets; never log |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

---

## gRPC — BP-157..BP-158

### BP-157 — gRPC Server Without Unary Interceptor For Logging/Auth

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `grpc.NewServer()` with zero options in main |
| **Detect** | NewServer() no interceptors; public RPC service registered |
| **Safe** | Chain unary interceptor |
| **Fixtures** | **txt + grpc** |

- [ ] Implement + fixtures + tests

### BP-158 — gRPC Ignoring `status.FromError` / Returning Naked err

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | Handler `return nil, err` raw without status codes |
| **Detect** | gRPC method signature `(ctx, *Req) (*Resp, error)` returns err not via `status.Errorf` |
| **Safe** | `status.Errorf(codes.X, …)` |
| **Fixtures** | **txt + grpc** |

- [ ] Implement + fixtures + tests

---

## CLI — BP-159..BP-160

### BP-159 — `flag.Parse` After Flags Are Used

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | Reading `*port` before `flag.Parse()` |
| **Detect** | Use of flag vars before Parse call order |
| **Safe** | Parse first |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-160 — Cobra `Run` Instead Of `RunE` Swallowing Errors

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `Run: func(...){ err := ...; }` without os.Exit/return err |
| **Detect** | cobra.Command Run field with ignored errs |
| **Safe** | `RunE` returning error |
| **Fixtures** | **txt + cobra** |

- [ ] Implement + fixtures + tests

---

## Part E exit criteria

- [ ] 15 rules shipped or deferred
- [ ] All shipped rules have **vulnerable + safe `.txt` snippets**
- [ ] Integration green for BP-146..BP-160
