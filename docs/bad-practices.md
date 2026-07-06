# Go Bad Practices Rules

This document summarizes the Go bad-practice (`BP-*`) rules shipped by CodeHound. Each rule records the rationale for the heuristic and the canonical fix the detector expects.

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
