# CodeHound vs staticcheck / golangci-lint / govulncheck

CodeHound is a **complement**, not a replacement. Prefer the specialized tool
when the check is strictly weaker or lower precision in CodeHound.

**Status:** Go-first production rules. Python is opt-in (`--features python`,
experimental `SLOP101`). No TypeScript plugin — [ADR 0005](./adr/0005-multi-lang-honesty.md).

## When to use what

| Tool | Strength | Use when |
|------|----------|----------|
| **go vet** | Compiler-adjacent correctness | Always in CI |
| **staticcheck** | Deep Go static analysis | Always in CI |
| **errcheck / wrapcheck** | Error handling completeness | Error discipline |
| **gocritic / prealloc** | Style + allocation micro-opts | When you want those classes |
| **govulncheck** | Live dependency CVEs | Security CI |
| **golangci-lint** | Aggregator for the above | Default lint gate |
| **CodeHound** | PERF hot-path, framework footguns, policy BP, light taint | After lint; recommended pack for CI |

## Side-by-side examples

| Smell | Prefer | Why |
|-------|--------|-----|
| `regexp.Compile` / `MatchString` inside a loop | **CodeHound PERF-1 / PERF-50** | Hot-path cost; often missed by default lint sets |
| `http.Server` / client without timeouts | **CodeHound PERF-101 / PERF-190** | Framework / request-path footgun focus |
| Discarded `err`, mutex value copy | **staticcheck / errcheck / vet** | Higher precision language analysis |
| Known CVE in a module | **govulncheck** | Live advisory feed; CodeHound BP-63 is a reserved snapshot only |
| Injection triage | CodeQL / dedicated SAST for hard gates | CodeHound taint is experimental name-string analysis |

## Overlap summary

Full BP overlap matrix: [`bad-practices.md`](./bad-practices.md).  
PERF B/C tier intentionally overlaps staticcheck / prealloc — keep those under
`--profile all`, not CI: [perf-tiers.md](./perf-tiers.md).

| Area | Prefer | CodeHound role |
|------|--------|----------------|
| Discarded errors, mutex copy, defer correctness | staticcheck / errcheck / vet | BP off in recommended; style pack optional |
| `time.After` in loop, regex compile in loop | — | **PERF** differentiator |
| HTTP timeouts, body close/drain, GORM N+1 | — | **PERF S-tier** |
| Path/SQL/cmd/LDAP/XML injection triage | CodeQL / dedicated SAST for gates | Experimental **taint** ([taint.md](./taint.md)) |
| Dependency CVEs | **govulncheck** | BP-63 reserved snapshot only |

### Taint honesty

Enable with `--taint` or `--profile security`. Intra/same-package, depth-limited,
not security-grade whole-program analysis. Do not hard-gate production security
on taint alone.

## Recommended CI shape

```bash
# 1) Language linters
golangci-lint run

# 2) CVEs
govulncheck ./...

# 3) CodeHound high-signal pack
codehound --profile recommended --format sarif . > codehound.sarif
# optional: fail on medium PERF too
# codehound --profile recommended --warnings-as-errors --format sarif . > codehound.sarif
```

Notes:

- Recommended fail policy is **strict** (high+). S-tier PERF is **medium** →
  non-failing unless `--warnings-as-errors`.
- Brownfield: `--no-fail` → `codehound --baseline` → gate on new fingerprints.
- Full workflows: [ci-integration.md](./ci-integration.md).

When CodeHound is weaker, turn the rule off with `skip`, style default-skips,
or fixture-only quarantine under recommended packs.
