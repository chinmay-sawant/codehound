# Releasing CodeHound

How version tags produce multi-arch binaries on GitHub Releases and publish the
crate to crates.io.

Workflow source: [`.github/workflows/release.yml`](../.github/workflows/release.yml).

---

## Overview

Pushing a version tag matching `v*` (for example `v0.1.0`) runs the **release**
workflow:

```
tag v* ──► validate ──► build (5 targets) ──┐
                   └──► sbom              ──┴──► GitHub Release (attach assets)
                   └──► crates.io publish
```

| Job | Purpose |
|-----|---------|
| **validate** | Tag/Cargo version match, fmt, clippy, tests, docs, audit, `cargo package`, canaries |
| **build** | Release binaries for Linux, macOS, Windows |
| **sbom** | CycloneDX SBOM (`codehound.cdx.json`) |
| **publish** | Create GitHub Release and attach archives, checksums, SBOM |
| **crates-io** | `cargo publish --locked` to crates.io |

`publish` and `crates-io` both require **validate** to succeed. Binary packaging
also requires **build** and **sbom**. The crates.io job runs in parallel with
build/sbom after validate.

---

## One-time setup (crates.io)

The crates.io job needs a repository secret:

1. Create an API token at [crates.io/settings/tokens](https://crates.io/settings/tokens)
   (publish scope).
2. In the GitHub repo: **Settings → Secrets and variables → Actions → New repository secret**.
3. Name: `CARGO_REGISTRY_TOKEN`  
   Value: the crates.io token.

Without this secret the **crates-io** job fails with a clear error. The GitHub
Release (binaries) can still succeed if validate/build/sbom passed.

GitHub Releases use the built-in `GITHUB_TOKEN` (workflow grants `contents: write`
only on the publish job). No extra secret is required for binary uploads.

---

## Cut a release

### 1. Prepare the tree

On the default branch (after review):

1. Bump `version` in [`Cargo.toml`](../Cargo.toml).
2. Update [`CHANGELOG.md`](../CHANGELOG.md) for the new version.
3. Commit and merge to the default branch as usual.

The git tag **must** match Cargo’s version with a leading `v`:

| `Cargo.toml` | Git tag |
|--------------|---------|
| `0.1.0` | `v0.1.0` |
| `0.2.0` | `v0.2.0` |

A mismatch fails **validate** before any publish step.

crates.io versions are **immutable**. If `0.1.0` is already published, bump to a
new version before tagging again.

### 2. Tag and push

```sh
# From the commit you intend to release (usually default branch tip)
git tag v0.1.0
git push origin v0.1.0
```

Do **not** create the GitHub Release manually first. The workflow creates the
release and attaches assets when the tag is pushed.

### 3. Watch the run

Open **Actions → release** for the tag run. Expected outcomes:

- Green **validate**, **build** (all matrix rows), **sbom**, **publish**, **crates-io**
- A [GitHub Release](https://github.com/chinmay-sawant/codehound/releases) for the tag
- Crate available as `cargo install codehound --locked` (after crates.io indexes)

---

## Binary artifacts

Each target produces an archive plus a SHA-256 file:

| Platform | Target triple | Archive name pattern |
|----------|---------------|----------------------|
| Linux x86_64 | `x86_64-unknown-linux-gnu` | `codehound-<tag>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 | `aarch64-unknown-linux-gnu` | `codehound-<tag>-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Intel | `x86_64-apple-darwin` | `codehound-<tag>-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `aarch64-apple-darwin` | `codehound-<tag>-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `x86_64-pc-windows-msvc` | `codehound-<tag>-x86_64-pc-windows-msvc.zip` |

Also attached:

- `*.sha256` — checksum per archive
- `codehound.cdx.json` — CycloneDX SBOM

Linux aarch64 is built with [`cross`](https://github.com/cross-rs/cross) on
`ubuntu-latest`. Other targets build natively on the matching runner.

### Install a binary from the release

```sh
# Example: Linux x86_64, tag v0.1.0
tar -xzf codehound-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
# binary is under the extracted directory as `codehound`
sudo install -m 755 codehound-v0.1.0-x86_64-unknown-linux-gnu/codehound /usr/local/bin/codehound
codehound --version
```

Verify checksums when available:

```sh
sha256sum -c codehound-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256
```

---

## Install from crates.io

After a successful **crates-io** job:

```sh
cargo install codehound --locked
```

Requires Rust **1.88+** (see `rust-version` in `Cargo.toml`). Prefer GitHub
Release binaries if you do not want a local Rust toolchain.

---

## What validate checks

Before any artifact is published:

1. Tag version equals `package.version` in `Cargo.toml`
2. `cargo fmt --check`
3. `cargo clippy` (all features, `-D warnings`)
4. `cargo test` (all targets + doc tests)
5. `cargo doc` with warnings denied
6. `cargo audit`
7. `cargo package --locked` (crates.io packaging dry-run)
8. Release binary build + canaries (`scripts/canary/run_canaries.sh`)

If validate fails, **build**, **sbom**, **publish**, and **crates-io** do not run.

---

## Package metadata (crates.io)

Relevant fields live in [`Cargo.toml`](../Cargo.toml):

- `repository` / `homepage` — GitHub project URLs
- `license`, `description`, `keywords`, `categories`
- `exclude` — keeps the crates.io tarball lean (plans, frontend site, docs site,
  internal documents, CI config, etc.). Source, tests, benches, and `ruleset/`
  stay included so `cargo package` / install still build.

Local dry-run (optional):

```sh
cargo package --locked
# inspect: target/package/codehound-*.crate
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| validate: tag does not match Cargo.toml | Tag `vX.Y.Z` ≠ `version` in Cargo.toml | Retag the correct version or bump Cargo.toml and retag |
| crates-io: missing token | No `CARGO_REGISTRY_TOKEN` secret | Add the secret (see [One-time setup](#one-time-setup-cratesio)) |
| crates-io: category slugs not supported | Invalid `categories` entry in `Cargo.toml` (e.g. `development-tools::static-analysis` is not a slug) | Use only slugs from https://crates.io/category_slugs (deslop used `command-line-utilities`; parent `development-tools` is fine). Fix on the branch you will publish from, then re-run crates.io only: `gh workflow run crates-io-publish.yml --ref master` |
| crates-io: version already uploaded | Same version published before | Bump version, update changelog, new tag |
| crates-io: package too large | Unintended files in the crate | Extend `exclude` in `Cargo.toml`; re-run `cargo package` |
| crates-io failed after GitHub Release succeeded | Jobs run in parallel after validate | Fix metadata, merge, then **retry crates.io only** via [`.github/workflows/crates-io-publish.yml`](../.github/workflows/crates-io-publish.yml) (`workflow_dispatch`) — do not retag unless you intend a full re-release |
| build fails on one matrix target | Toolchain / cross / Windows packaging | Inspect that job log; fix then delete bad tag if needed and re-push |
| GitHub Release exists without assets | Manual release created, or publish job failed | Prefer tag-only flow; re-run failed jobs or attach assets from a re-run |

Deleting and re-pushing a tag rewrites history for that ref — only do that if
no one has already consumed the tag, and coordinate with maintainers.

---

## Related docs

- [CHANGELOG.md](../CHANGELOG.md) — user-facing release notes
- [ROADMAP.md](../ROADMAP.md) — product direction
- [SECURITY.md](../SECURITY.md) — vulnerability reporting and supported versions
- [CONTRIBUTING.md](../CONTRIBUTING.md) — day-to-day development
- [Linux binary build & usage](../plans/linux-binary-build-and-usage.md) — local Linux build notes (not the CI matrix)
