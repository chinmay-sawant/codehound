# ADR 0002 — Project path identity

## Status

Accepted (Phase 5)

## Context

Cache manifest keys, dependency lists, and cascade matching must agree.
Mixing absolute vs relative, or `\` vs `/`, caused cascade misses.

## Decision

1. Introduce `engine::path_identity::normalize_project_path` as the single
   normal form for project-relative paths used by:
   - cache manifest keys (`CacheStore::put`)
   - dependency lists written by `extract_dependencies`
   - cascade matching (`invalidate_dependent`, dirty fixpoint)
   - content-hash cache filenames (`cache_key_for_path`)

2. Normalization rules: backslash→slash, strip leading `./`, collapse `//`.
   No `..` resolution (callers already project-relative).

3. A heavier `ProjectPath` newtype is optional later; a free function keeps
   the blast radius small while tests cover equality.

## Consequences

- Cascade edges survive OS separator differences.
- Embedders should store the same normal form if they write cache keys by hand.
