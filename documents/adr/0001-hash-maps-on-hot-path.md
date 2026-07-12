# ADR 0001 — Hash maps on the analysis hot path

## Status

Accepted (Phase 4)

## Context

Review feedback recommended `hashbrown` + `ahash` / `FxHash` for taint, facts,
and cache session maps instead of `std::HashMap` + SipHash.

## Decision

1. **SourceIndex needle lookup** uses a process-lifetime `std::HashMap<&'static str, usize>`
   built once per static needle table (CWE / PERF / BP). Table size is ~dozen to
   ~700 keys; build cost is amortized across every file. Lookup is O(1) average
   and no longer a linear `position` scan.

2. **General analysis maps** (taint graphs, import maps, cache manifests) keep
   `std::HashMap` for now. SipHash is intentional until profiling shows a
   measurable share of scan time in map ops on realistic monorepos.

3. Revisit with `rustc-hash` / `hashbrown` only if Criterion or `perf` shows
   hashing as a top frame on large scans.

## Consequences

- No new dependency for Phase 4.
- SourceIndex acceptance is covered by unit tests + `source_index_has_lookup` bench.
- Future switch can be a type alias (`type FastMap<K,V> = …`) without API churn.
