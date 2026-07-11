# ADR 0003 — Taint model honesty

## Status

Accepted (Phase 7 / 0.1.0)

## Context

Taint analysis is valuable for triage but was historically oversold in copy.

## Decision

1. Taint is **off** under `--profile recommended` unless `--taint` is set.
2. Security profile enables taint and taint-core CWEs.
3. Documented limitations (Clean, fields, channels, name-string sinks, depth)
   live in `documents/taint.md` and must stay accurate.
4. FP/FN policy: prefer honest FNs over pretending channels/interfaces work.

## Consequences

- Marketing and README must say “experimental / triage”, not “security-grade”.
- New taint features land with limitation bullets in the same PR.
