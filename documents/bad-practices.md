# Go Bad Practices Rules

This document summarizes the Go bad-practice (`BP-*`) rules shipped by CodeHound. Each rule records the rationale for the heuristic and the canonical fix the detector expects.

## Product policy

| Profile | BP rules | Fail policy |
|---------|----------|-------------|
| `recommended` / `perf` / `security` | **off** | strict (high+) |
| `style` (`--profile style` / `bp`) | **on** (with a few default-off) | **no-fail** (advisory) |
| `all` | full catalog | medium-as-errors |

Default-off under `style` (opt back in with `--only BP-21` / `--only BP-28`):

- `BP-21` — missing `t.Parallel` (policy preference, not correctness)
- `BP-28` — single-method interface (opinionated API style)

Severity discipline when BP is on:

- **medium** — concurrency footguns that still repay attention: `BP-6`, `BP-7`, `BP-8`, `BP-15`
- **low** — most correctness-adjacent heuristics
- **info** — godoc / interface-shape / one-file-dep opinion (`BP-21`, `BP-28`–`31`, `BP-39`–`42`, `BP-45`, `BP-62`)

Godoc-style rules never fail CI under `style` (no-fail + info severity).

`BP-63` is **reserved**: a curated module-advisory *snapshot* (`ruleset/golang/go_module_advisories.csv`), **not** a live [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) feed. It is quarantined from recommended/security packs. Prefer govulncheck in CI for real CVE coverage until a feed is wired.

## Curated tiering policy

- **Trusted correctness:** BP-6, BP-7, BP-8, BP-9, and BP-15; useful concurrency/runtime footguns, but still reviewed as heuristics.
- **Review-required:** most error, lifecycle, testing, and dependency rules; keep them advisory and do not fail ordinary CI by default.
- **Style/opinion:** BP-2, BP-3, BP-21, BP-28–31, BP-39–42, BP-45, and BP-62; report as `info` or keep disabled unless a team explicitly wants the policy.
- **Reserved:** BP-63 remains quarantined until CodeHound has a live advisory feed.

## Overlap matrix vs golangci ecosystem

Classify each rule before treating CodeHound BP as a substitute for `go vet` / staticcheck / errcheck / revive.  
**Policy:** overlaps mean “enable only if you do not already run X” (or want a second signal). CodeHound’s unique value is **style pack policy** + a few concurrency heuristics, not a better staticcheck.

| Outcome | Meaning |
|---------|---------|
| **weaker** | Strictly weaker or redundant vs named tool → prefer the tool; keep off in recommended |
| **fix** | Same idea; detector precision improved (or still heuristic) |
| **unique** | Policy / framework hygiene staticcheck does not own |
| **reserved** | Placeholder or incomplete feed |

| Rule | Class | Overlaps | Notes |
|------|-------|----------|-------|
| BP-1 | weaker / fixed | errcheck, staticcheck | Assignment shapes for discarded `_`; skips non-error builtins; still no types |
| BP-2 | weaker | wrapcheck, errorlint | Naked `return err` |
| BP-3 | weaker | go vet / staticcheck | panic outside main/test |
| BP-4 | unique-ish | — | recover without logging |
| BP-5 | weaker | errcheck | ignored `Close()` |
| BP-6 | fixed | staticcheck SA2000 | WaitGroup.Add inside goroutine (brace-matched body) |
| BP-7 | weaker / medium | go vet `-copylocks` | mutex by value |
| BP-8 | fixed / medium | vet copylocks | defer Unlock **only** with by-value mutex param |
| BP-9 | fixed / unique | — | select without escape (brace-depth body) |
| BP-10 | weaker | staticcheck SA1015, PERF | `time.After` in loop |
| BP-11 | weaker | staticcheck SA2006-ish | defer in loop |
| BP-12 | unique / heuristic | — | multi-sender unbuffered channel |
| BP-13 | unique-ish | — | `context.Background` in library |
| BP-14 | unique / heuristic | — | goroutine without cancellation |
| BP-15 | unique / medium | — | recursive `sync.Once.Do` |
| BP-16–25 | unique / opinion | tparallel, testifylint | test hygiene; **BP-21 default-off** |
| BP-26–35 | mixed | revive, staticcheck | API design; **BP-28 default-off** |
| BP-36–45 | mixed | revive, unused | org/docs; godoc rules are **info** |
| BP-46–55 | unique | — | production hardening (timeouts, signals, rate limits) |
| BP-56–62 | mixed | govulncheck, go mod tidy | dep hygiene heuristics |
| BP-63 | reserved | **govulncheck** | curated snapshot only — not a feed |
| BP-64–65 | unique-ish | — | local `replace`, missing `go.sum` |

If you already run `golangci-lint` with errcheck + staticcheck + revive, prefer `--profile recommended` (PERF + optional taint) and treat `style` as an optional policy pack—not a replacement gate.

## Curated Core Language Rules

- `BP-67` flags `errors.As` targets passed without an address; pass an addressable target to avoid the stdlib runtime panic.
- `BP-72` flags a directly returned typed nil pointer behind an `error` or anonymous interface result; return a bare `nil` interface instead.
- `BP-73` flags a function-local zero-value map that is indexed before `make` initializes it; initialize the map before the first write. The detector intentionally ignores map parameters and cases where initialization is visible earlier in the same function.
- `BP-75` flags a statically zero-length local slice used as the destination of `copy` with a non-empty literal source; allocate the destination to the required length.
- `BP-80` flags exact `context.TODO()` calls outside tests; replace them with an explicit caller-owned or lifecycle-owned context. This remains a low-severity advisory policy signal.
- `BP-79` flags a locally bound context cancellation function with no visible local call or defer. It is review-only because ownership may be transferred to a helper.
- `BP-84` flags the narrow `a / b * 100` percentage shape when the destination or function name indicates a percentage; convert before dividing to avoid integer truncation.
- `BP-68` flags discarded `errors.Join` results; return or assign the combined error.
- `BP-85` flags unchecked `Context.Value` assertions in typed net/http handlers; check the `ok` result.

## Curated HTTP Rules

- `BP-101` flags a `net/http` handler that writes a response body before `WriteHeader`; set the intended status before the first body write.
- `BP-109` flags a Gin error JSON response that is not followed by `Abort` or `return`; terminate the handler after writing the error.
- `BP-116` flags an Echo error JSON response followed by a raw error return; choose one response-handling path.
- `BP-102` flags net/http error paths that return without writing an error response or status.

## Curated Concurrency and Resource Rules

- `BP-88` flags direct send/receive operations on a local zero-value channel outside an intentional `select`; initialize the channel or keep the nil-channel select explicit.
- `BP-98` flags local `os.Open`/`os.OpenFile` results with no same-function close or ownership transfer; close or return the file. This is review-only because the heuristic cannot prove interprocedural ownership.
- `BP-99` flags a locally created `sync.Cond` whose `Wait` has no visible `Lock`/`RLock` on its associated locker; acquire the locker before waiting.

## Curated Data and Configuration Rules

- `BP-131` flags literal DML sent through `database/sql` `Query`/`QueryContext` without `RETURNING`; use `Exec`/`ExecContext`. This is an import- and type-gated advisory heuristic.
- `BP-145` flags a typed `pgxpool.Acquire` result with no visible `Release`/`Close`; release the connection on every path. This remains review-only for same-function ownership limits.
- `BP-159` flags flag-pointer dereferences before `flag.Parse`; parse command-line arguments before reading values.
- `BP-136` flags GORM `AutoMigrate` in request handlers; run migrations during startup or separately.
- `BP-142` flags `sqlx.In` output executed without `Rebind`; rebind for the target driver first.
- `BP-151` flags sensitive `os.Getenv` values passed directly to loggers; redact or log presence only.

## Error Handling

- `BP-1` flags discarded error returns because `_ = err` suppresses failure handling; keep the error, wrap it with context, or return it to the caller.
- `BP-2` flags naked `return err` paths because they lose operation-specific context; wrap the error with the failing action before returning.
- `BP-3` flags `panic` outside `main` or tests because library code should not abort the process; return an error or convert the failure into an explicit contract.
- `BP-4` flags `recover()` without visible reporting because swallowed panics destroy debugging signal; log, report, or re-panic with context.
- `BP-5` flags unchecked `Close()` errors because cleanup can still fail in meaningful ways; check the returned error directly or inside a deferred closure.

## Concurrency

- `BP-6` flags `WaitGroup.Add` inside the goroutine it tracks because the goroutine may run after `Wait`; call `Add` before launching the goroutine.
- `BP-7` flags `sync.Mutex` passed by value because copying a lock corrupts lock state; pass `*sync.Mutex` or move the lock into shared state.
- `BP-8` flags deferred unlock on a copied mutex because the deferred call may operate on the wrong lock instance; avoid copying mutexes and unlock the original value.
- `BP-9` flags `select` without timeout, default, or cancellation because it can block forever; add `ctx.Done()`, a timer, or another escape hatch.
- `BP-10` flags `time.After` inside loops because it allocates a new timer every iteration; reuse a `time.Timer` or `time.Ticker`.
- `BP-11` flags `defer` inside loops because cleanup accumulates until function exit; close or release resources explicitly inside the loop body.
- `BP-12` flags unbuffered channel sends from multiple goroutines without obvious coordinated receivers because senders can deadlock behind each other; add a buffer, a receiver loop, or a different synchronization pattern.
- `BP-13` flags `context.Background()` in library code because it severs caller cancellation and deadlines; accept a `context.Context` parameter and propagate it.
- `BP-14` flags long-running goroutines that ignore `ctx.Done()` because they can outlive the request or job that created them; select on `ctx.Done()` or pass an explicit shutdown channel.
- `BP-15` flags recursive `sync.Once.Do` because the same `Once` can deadlock itself; restructure initialization so the closure does not call back into the same `Once`.

## Testing

- `BP-16` flags `time.Sleep` in tests because fixed delays create flaky and slow tests; use polling, channels, or deterministic synchronization instead.
- `BP-17` flags `t.Error` immediately followed by `t.Fatal` because the first call adds no value; use one failure path and return early.
- `BP-18` flags `t.Error` without an early exit because the test continues after a failed precondition; call `t.FailNow`, `t.Fatal`, or `return`.
- `BP-19` flags test helpers missing `t.Helper()` because failures point to the helper rather than the caller; call `t.Helper()` at the top of the helper.
- `BP-20` flags table-driven tests without `t.Run` because failures are harder to isolate by case; wrap each case in a named subtest.
- `BP-21` flags table-driven subtests missing `t.Parallel()` where the pattern expects isolated cases; call `t.Parallel()` inside the subtest when shared state permits.
- `BP-22` flags `TestMain` without `os.Exit(m.Run())` because the process exit code can be lost; always return the result of `m.Run()` via `os.Exit`.
- `BP-23` flags long tests without `testing.Short()` because they ignore the standard fast-test contract; skip the expensive path when `testing.Short()` is true.
- `BP-24` flags `_test.go` files with no `Test*` functions because the file is dead test surface; add real test entry points or delete the file.
- `BP-25` flags helpers that return `error` only to be converted into `t.Fatal` by callers because the helper can own the failure path; accept `*testing.T` and fail directly.
- `BP-162` flags parallel tests that mutate package-level state; isolate the test state.

## API Design

- `BP-26` flags `context.Context` that is not the first parameter because Go APIs conventionally put cancellation first; move `ctx` to the first non-receiver position.
- `BP-27` flags exported functions returning unexported concrete types because callers depend on implementation details they cannot name clearly; return an exported type or an interface.
- `BP-28` flags single-method interfaces because many of them are simpler as function types; use a function type unless you need interface semantics.
- `BP-29` flags bloated interfaces because large method sets are hard to implement and mock; split the contract into smaller focused interfaces.
- `BP-30` flags exported interfaces with no same-package implementation because the API surface is speculative and hard to validate; ship a concrete implementation or collapse the interface.
- `BP-31` flags constructors returning concrete types when the package already exposes a fitting interface because it leaks implementation details; return the interface boundary.
- `BP-32` flags `type X string` error aliases because string errors are hard to extend with fields and behavior; use a struct-backed error type.
- `BP-33` flags sentinel-style errors without `Is` because callers cannot compare them reliably across wrapping; implement `Is(error) bool` or expose a stable sentinel.
- `BP-34` flags `fmt.Errorf(... %v, err)` because `%v` and `%s` discard wrapping semantics; use `%w` when you are propagating an error.
- `BP-35` flags package names that diverge from directory names because the codebase becomes harder to navigate; align the package name with the directory unless there is a strong conventional reason not to.
- `BP-164` flags exported functional options that mutate package-level defaults; apply options to the supplied instance.

## Code Organization

- `BP-36` flags `init()` with side effects because hidden startup work is hard to control and test; move registration or I/O into explicit setup paths.
- `BP-37` flags package-level mutable globals because shared mutable state creates hidden coupling; move the state into a struct or constructor-owned dependency.
- `BP-38` flags unexported helpers with no internal callers because they are dead code; delete them or wire them into the intended call path.
- `BP-39` flags exported functions without doc comments because public APIs should explain their contract; add a leading doc comment that starts with the symbol name.
- `BP-40` flags unrelated constants in one block because the grouping hides conceptual boundaries; split the block by domain or prefix.
- `BP-41` flags missing package doc comments because packages should explain their purpose at the package boundary; add `// Package <name> ...` to a package anchor file.
- `BP-42` flags one-off import aliases because aliasing without repetition reduces clarity; drop the alias or use it consistently where it pays off.
- `BP-43` flags dot imports outside tests because they erase call-site ownership and harm readability; use qualified imports in production code.
- `BP-44` flags blank imports without standard registration justification because side-effect imports are easy to cargo-cult; keep them only for documented driver or registration cases.
- `BP-45` flags inconsistent receiver names on the same type because method sets should read uniformly; pick one short receiver name and keep it stable.

## Production Hardening

- `BP-46` flags `http.Server` without read and write timeouts because unbounded request lifetimes invite resource exhaustion; set both timeout fields explicitly.
- `BP-47` flags servers without graceful shutdown because in-flight requests are dropped abruptly; add a shutdown path that reacts to termination signals.
- `BP-48` flags `log.Fatal` and `os.Exit` in library code because helpers should not terminate the host process; return errors to the caller instead.
- `BP-49` flags deferred cleanup that drops returned errors because close and flush failures can still matter; wrap the deferred cleanup in a function and check the error.
- `BP-50` flags long-running servers without signal handling because they cannot terminate cleanly under orchestration; wire `SIGTERM` and `SIGINT` into shutdown.
- `BP-51` flags `recover` in library code without re-panicking or converting the panic because it silently changes failure semantics; re-panic or return an explicit error contract.
- `BP-52` flags allocation-size multiplication without overflow guards because large integer products can wrap before `make`; add a bounds check against `math.MaxInt` or use a checked multiplication helper.
- `BP-53` flags `gob.Register` types that do not line up with nearby `Encode` or `Decode` payloads because gob registration should reflect the serialized types; register the actual payload type or adjust the encode/decode path.
- `BP-54` flags public HTTP endpoints without visible rate limiting because unauthenticated traffic can overwhelm the service; add rate-limiter middleware or a request limiter in the handler path.
- `BP-55` flags request logging without request-id propagation because logs become hard to correlate across systems; generate or forward a request id through the handler chain.

## Dependency Hygiene

- `BP-56` flags deprecated packages such as `io/ioutil` because newer standard-library replacements are clearer and better maintained; migrate to the current package path.
- `BP-57` flags stale `go` toolchain versions in `go.mod` because unsupported Go releases miss fixes and ecosystem support; update to a currently supported Go release line.
- `BP-58` flags major or minor only module versions because reproducibility depends on full module versions; pin dependencies to exact versions.
- `BP-59` flags direct requirements not imported by the project because they add maintenance cost without value; remove the dependency or import it intentionally.
- `BP-60` flags dependencies used only by tests in the main module set because production requirements should reflect production code; move test-only needs behind the correct module boundary or tooling.
- `BP-61` flags non-imported requirements missing `// indirect` because the file no longer communicates why the dependency exists; mark it indirect or remove it.
- `BP-62` flags direct dependencies imported by only one non-test file in multi-file projects because the abstraction cost may exceed the value; internalize the code or narrow the module boundary if the dependency is trivial.
- `BP-63` flags module versions that match the curated advisory snapshot because known-vulnerable dependencies should not remain pinned in active code; upgrade, replace, or delete the vulnerable module.
- `BP-64` flags local filesystem `replace` directives because they hide non-reproducible builds behind local paths; replace them with tagged modules or keep them out of committed production manifests.
- `BP-65` flags missing or empty `go.sum` because dependency integrity data is incomplete; regenerate and commit a complete `go.sum`.
