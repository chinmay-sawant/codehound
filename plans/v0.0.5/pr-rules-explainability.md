# feat(cli): rules explainability surface (4.2)

## Summary

Add/extend `codehound rules` explanation surface reporting rule ID, pack eligibility, maturity, quarantine reason, and documentation location using the existing maturity/registry model.

## Changes

- `src/rules/explain.rs` (new) + wire-up in `rule_info` / CLI
- CLI tests for maturity classes
- Docs note: fixture-only means `--profile all`, not production-certified

## Test plan

- [x] `make lint` / focused tests
- [ ] `make test`

## Related issues

- Closes #118
- Relates to #105
