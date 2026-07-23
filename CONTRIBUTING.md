# Contributing to CodeHound

Thanks for helping. This doc is the short path to a good PR.

## Prerequisites

- Rust **1.88+** (`rustup default stable`)
- Optional: Go (for local fixture realism)
- `cargo-nextest` for the default parallel test target:
  `cargo install cargo-nextest --locked`

## Build & test

```sh
# Default = Go-first (no Python)
cargo build --bin codehound
make test

# Optimized edit → scan loop (incremental; not the release benchmark profile)
make run

# Publishable performance measurements: thin-LTO release profile
make run RUN_PROFILE=release

# Cargo-equivalent all-target check (includes benches)
cargo test --all-targets

# Optional experimental Python (SLOP101)
cargo test --features python --test python_integration

cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
bash scripts/check_no_prod_expect.sh
bash scripts/check_no_box_leak.sh
bash scripts/check_module_size.sh
```

Canaries (finding-count budgets):

```sh
cargo build --release --bin codehound
CODEHOUND_BIN=./target/release/codehound bash scripts/canary/run_canaries.sh
```

## Add a Go rule (checklist)

1. Open [`documents/rule-rfc-template.md`](./documents/rule-rfc-template.md) and fill overlap + pack.
2. **PERF:** metadata in `ruleset/golang/chunks/perf-*.json`, registry TOML under
   `src/lang/go/detectors/perf/registry/`, detector under `domains/`.
   See [`documents/perf-detector-development.md`](./documents/perf-detector-development.md).
3. **BP:** `ruleset/golang/bad-practices.json` + detector under
   `src/lang/go/detectors/bad_practices/rules/`.
4. **CWE:** registry TOML + domain module under `detectors/cwe/`.
5. Add **vulnerable** and **safe** fixtures under `tests/fixtures/go/…`.
6. Run the matching integration test crate(s).
7. Update pack docs if the rule joins recommended / security.

## Land a PR

- Keep modules **≤ ~400 lines** (hard 500 except known needle tables).
- Prefer small, reviewable commits on a feature branch.
- Do not force-push shared branches; do not add secrets.
- Link the feedback phase / issue if applicable.

## Product packs (quick)

| Profile | Use |
|---------|-----|
| `recommended` (default) | CI gate: PERF S-tier + taint-core allow-list |
| `security` | Taint on |
| `style` | BP advisory |
| `all` | Full catalog |

## License

Contributions are dual-licensed under MIT OR Apache-2.0, same as the project.
