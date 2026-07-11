# CodeHound vs staticcheck / golangci-lint / govulncheck

CodeHound is a **complement**, not a replacement. Prefer the specialized tool
when the check is strictly weaker or lower precision in CodeHound.

## When to use what

| Tool | Strength | Use when |
|------|----------|----------|
| **go vet** | Compiler-adjacent correctness | Always in CI |
| **staticcheck** | Deep Go static analysis | Always in CI |
| **errcheck / wrapcheck** | Error handling completeness | Error discipline |
| **govulncheck** | Live dependency CVEs | Security CI |
| **golangci-lint** | Aggregator for the above | Default lint gate |
| **CodeHound** | PERF hot-path, framework footguns, policy BP, light taint | After lint; recommended pack for CI |

## Overlap summary

Full BP overlap matrix: [`docs/bad-practices.md`](./bad-practices.md).

| Area | Prefer | CodeHound role |
|------|--------|----------------|
| Discarded errors, mutex copy, defer in loop | staticcheck / errcheck / vet | BP off in recommended; style pack optional |
| `time.After` in loop, regex compile in loop | — | **PERF** differentiator |
| HTTP timeouts, body close/drain, GORM N+1 | — | **PERF S-tier** |
| Path/SQL/cmd injection triage | CodeQL / dedicated SAST for gates | Experimental **taint** (not security-grade) |
| Dependency CVEs | **govulncheck** | BP-63 reserved snapshot only |

## Recommended CI shape

```bash
# 1) Language linters
golangci-lint run

# 2) CVEs
govulncheck ./...

# 3) CodeHound high-signal pack (fail high)
codehound --profile recommended --format sarif --strict . > codehound.sarif
```

Brownfield: start with `--no-fail` / baseline (`codehound --baseline`, then
`codehound baseline list|diff|update`).
