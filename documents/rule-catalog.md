# Rule catalog index

How to navigate CodeHound’s rule inventory. Live counts come from the binary
registry, not from markdown.

## Inventory (registry-backed)

| Family | Prefix | Count (locked) | Browse |
|--------|--------|----------------|--------|
| PERF | `PERF-*` | 239 | `codehound --list-rules --rule-category performance` |
| CWE | `CWE-*` | 175 | `codehound --list-rules --rule-category security` |
| BP | `BP-*` | 135 | `codehound --list-rules --rule-category bad-practice` |

Counts are enforced by `tests/rule_counts_readme.rs` and the root README.
Canonical CLI IDs are unpadded (`PERF-1`, not `PERF-001`).

```sh
codehound --list-rules
codehound --explain PERF-103
codehound rules --category security
```

## Two different axes (do not conflate)

| Axis | What it is | Where |
|------|------------|--------|
| **PERF tiers** S / A / B / C | Product pack + severity policy for performance rules | [perf-tiers.md](./perf-tiers.md) |
| **Maturity** | Trust / quarantine tags (`heuristic`, `taint-core`, `structural`, `fixture-only`, `reserved`) | `src/rules/maturity.rs`, `--list-rules` `[tag]` |

Fixture-only and reserved rules stay out of recommended/security/perf packs.
They appear under `--profile all` or explicit `--only`.

## Profiles & fail policy (short)

| Profile | What runs | Default fail |
|---------|-----------|--------------|
| `recommended` | S-tier PERF + taint-core CWEs; BP off | high+ only |
| `perf` | S+A PERF | high+ only |
| `security` | Security CWE pack; taint **on** | high+ only |
| `style` | BP only (skips BP-21/28/30) | never |
| `all` | Full catalog | medium+ |

Details: [go-recommended-pack.md](./go-recommended-pack.md), [cli.md](./cli.md).

**Important:** under recommended, S-tier PERF is **medium** → findings print but
do **not** fail the process unless you pass `--warnings-as-errors`.

## Family boundaries

| Concern | Prefer in CI | Style / advisory | Notes |
|---------|--------------|------------------|-------|
| HTTP body not closed | **PERF-103** | BP-95 | PERF is S-tier in recommended |
| Server timeouts | **PERF-101** | BP-46 | PERF is S-tier |
| `defer` in loop | **PERF-7** | BP-11 | PERF is S-tier |
| Injection / path sinks | **CWE-*** + taint | — | Enable `--taint` or `--profile security` |
| Micro-opts / staticcheck overlap | Prefer staticcheck | PERF B/C under `--profile all` | See [perf-tiers.md](./perf-tiers.md) |
| Module CVEs | **govulncheck** | BP-63 reserved | Not a CVE scanner |

Positioning vs ecosystem tools: [go-vs-staticcheck.md](./go-vs-staticcheck.md).

## Deep dives

| Doc | Audience |
|-----|----------|
| [perf-tiers.md](./perf-tiers.md) | CI policy for PERF S/A/B/C |
| [perf-rules.md](./perf-rules.md) | Partial human notes (not full 239 — use CLI for inventory) |
| [bad-practices.md](./bad-practices.md) | BP policy + per-rule rationale |
| [taint.md](./taint.md) | Experimental data-flow model |
| [finding-identity.md](./finding-identity.md) | Fingerprints, ignores, baselines |
| [rule-rfc-template.md](./rule-rfc-template.md) | Propose a new rule |
| [perf-detector-development.md](./perf-detector-development.md) | Implement a PERF detector |

## Proposing a rule

1. Open an issue / fill [rule-rfc-template.md](./rule-rfc-template.md).
2. Follow `CONTRIBUTING.md` for fixtures and tests.
3. Update pack docs if membership or tiers change.
4. Prefer `--explain` + ruleset JSON as the title/source of truth over prose catalogs.
