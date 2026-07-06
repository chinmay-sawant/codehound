# Architecture Enhancement — Post-Refactor Audit

> **Date:** June 2026  
> **Previous:** Review2.md P0/P1/P2 matrix (partially implemented)  
> **Method:** 6 independent subagent audits of current codebase state

---

## Audit Findings Summary

The previous implementation pass made real progress (sink registry, TreeCursor, module reorg, CWE catalog) but **several claimed improvements were not actually applied**:

| Claimed in benchmarks.md | Actually in code? |
|--------------------------|:---:|
| Severity 4→5 levels (Info/Low/Medium/High/Critical) | **No** — still 4 (Info/Warning/High/Critical) |
| SourceIndex phf::Map O(1) + u64 bitmask | **No** — still Vec<bool> with O(N) position() |
| jiff replacing iso8601_utc_now | **No** — custom calendar math still present |
| templates/codehound.toml with include_str! | **No** — still inline const TEMPLATE |
| Tree walks recursive→iterative | Already was iterative before refactor |

---

## Remaining Issues by Category
