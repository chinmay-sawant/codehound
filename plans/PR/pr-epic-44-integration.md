# chore: integrate epic #44 workstreams for combined validation

## Summary

- Merge the five parallel epic-#44 branches into one integration branch so CWE, BP docs, taint Prepare guard, perf budget, and roadmap gates are validated **together**.
- Full suite green on the integrated tree (`make lint`, `make test` — 411 passed).
- Prefer merging **this** PR into `master` instead of the five child PRs separately (avoids merge-order risk).

## Motivation / context

Child PRs (#50–#54) each target `master` and were tested **in isolation**. Combined validation requires a single branch that contains all commits.

| Child issue | Branch | Standalone PR |
|------------:|--------|---------------|
| #45 | `chore/cwe-trust-longtail-45` | #50 |
| #46 | `chore/bp-candidates-46` | #51 |
| #47 | `chore/taint-prepare-47` | #52 |
| #48 | `chore/perf-budget-48` | #53 |
| #49 | `chore/roadmap-gates-49` | #54 |

Parent epic: #44

## Changes

### Integrated workstreams

| Area | Outcome |
|------|---------|
| CWE long-tail (#45) | CWE-250/252/552 audit; CWE-552 call-facts; canary notes |
| BP candidates (#46) | BP-71 + proof-boundary wontfix (docs) |
| Taint Prepare (#47) | Same-function Prepare→stmt CWE-89 guard + fixtures |
| Perf budget (#48) | Cold scan under ~1s bar; no engine code |
| Roadmap gates (#49) | Typed Go / Python reopen criteria + ROADMAP links |
| Process | `PR_TEMPLATE.md` multi-workstream integration section |

### Integration method

```text
origin/master
  + roadmap-gates-49
  + perf-budget-48
  + bp-candidates-46
  + cwe-trust-longtail-45
  + taint-prepare-47
```

Clean merges (no conflict resolution required).

## Test plan

- [x] `make lint`
- [x] `cargo test --locked --test go_cwe_detector_fixtures` (4)
- [x] `cargo test --locked --test go_taint_integration` (2)
- [x] `make test` — **411 passed** (integrated tree)

### Commands

```sh
git checkout chore/epic-44-integration
make lint
make test
```

## Related issues

- Closes #45
- Closes #46
- Closes #47
- Closes #48
- Closes #49
- Relates to #44

## Integration note for child PRs

Standalone PRs #50–#54 are **superseded** by this integration PR. Merge this one; close the others without merging if GitHub does not auto-close them.

## Follow-ups (out of scope)

- Further CWE residual inventory (~140 undated rules)
- Policy-deferred BP candidates
- Decode/channel taint, typed Go, Python implementation

## PR metadata checklist (author)

- [x] Self-assigned
- [x] Labels applied
- [x] Related issues filled
