# Decision-quality canary corpus

> **Parent:** [`parallel-catalog-program.md`](./parallel-catalog-program.md) §4.1  
> **Issue:** [#117](https://github.com/chinmay-sawant/codehound/issues/117) · Relates to epic [#105](https://github.com/chinmay-sawant/codehound/issues/105)  
> **Status:** Defined (docs + helper). Detector rewrites and pack membership are out of scope.  
> **Hit-rate ledger:** [`canary-hit-rates.md`](./canary-hit-rates.md)  
> **Pin manifest:** [`canary-corpus-pins.json`](./canary-corpus-pins.json)

---

## Purpose

Catalog-trust decisions need a **pinned, diverse, real-module** Go corpus — not only
fixture oracles and not only the three historical canaries (gopdfsuit, monsoon,
go-retry). This document is the single place for:

1. **Which trees** to scan (URL, revision, file counts, role).
2. **How** to run recommended vs family `--only` scans (separately).
3. **How** to review every finding with a fixed rubric.
4. **Where** to record reviewed hit rates by family and date.

Raw finding volume is not a promotion signal. Reviewed disposition rates are.

---

## Corpus layout

Pinned clones live under **`real-repos/`** at the repository root (gitignored —
see `.gitignore`). Worktrees often have no local `real-repos/`; use the main
checkout path or re-pin with the helper script.

| Kind | Path convention | Checked in? |
|------|-----------------|-------------|
| External Go modules | `real-repos/<name>` at pinned SHA | No (gitignored) |
| Local long-running sample | absolute path to gopdfsuit (or successor) | No |
| In-repo smoke canaries | `tests/canary/clean_lib`, `tests/canary/http_service` | Yes |
| Budget spike guards | `scripts/canary/budgets.json` + `run_canaries.sh` | Yes (CI-oriented) |

Decision-quality work uses the **external + gopdfsuit** set below. In-repo
canaries remain regression/smoke targets; they do not replace real-module review.

---

## Pinned corpus (beyond the original three)

### Machine-readable pins

`canary-corpus-pins.json` is the authoritative pin list (revision + clone URL).
Human summary:

| ID | Upstream | Pinned revision | Role / diversity | Go files (non-test / total¹) | Files scanned² |
|----|----------|-----------------|------------------|------------------------------:|---------------:|
| **gopdfsuit** | `chinmay-sawant/gopdfsuit` (local sibling or clone) | `26d71268937136036c3be1770c0f7bdd89f87dc6` | HTTP + PDF service; dense PERF surface | 78 / 97 | **78** |
| **monsoon** | [RedTeamPentesting/monsoon](https://github.com/RedTeamPentesting/monsoon) | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | HTTP enumerator CLI; network-heavy | 43 / 55 | **43** |
| **go-retry** | [sethvargo/go-retry](https://github.com/sethvargo/go-retry) | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | Small focused library; near-clean control | 5 / 10 | **5** |
| **gorl** | [AliRizaAynaci/gorl](https://github.com/AliRizaAynaci/gorl) | `ec54aaf15ce4d0f3f8014eac2548986c91d0f001` | Rate-limiter library; full-catalog noise canary ([`noise-reduce-1.md`](./noise-reduce-1.md)) | 28 / 47 | **28** |
| **no-mistakes** | [kunchenguid/no-mistakes](https://github.com/kunchenguid/no-mistakes) | `0a2c82f993b9467c5ab84992313dfd13b66830af` | Larger git/tooling CLI; scale + update/HTTP paths | 223 / 491 | **222** |

¹ Counted as `find … -name '*.go' -not -path '*/.git/*' -not -path '*/vendor/*'`
(total) and the same excluding `*_test.go` (non-test).  
² From release-binary JSON `stats.files_scanned` on 2026-07-21 (CodeHound skips
non-source and some support files; may differ slightly from non-test `.go` count).

**Expanded set (this issue):** gorl + no-mistakes are **required** members of the
decision-quality corpus in addition to the historical trio. Together they cover
library / CLI / service shapes and small → mid size.

### Default scan roots (examples)

```text
/home/chinmay/ChinmayPersonalProjects/gopdfsuit
/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon
/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry
/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/gorl
/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/no-mistakes
```

Override with `CODEHOUND_CORPUS_ROOT` (parent of `real-repos/`) and
`CODEHOUND_GOPDFSUIT` when paths differ.

---

## Expected commands

Always use a **release** binary built from the commit under review
(`cargo build --release --locked`). Prefer `--no-cache` so counts are
reproducible. Prefer `--format json --json-envelope` for ledgers; text is fine
for interactive review.

### A. Recommended profile (pack trust)

Run **separately** from family canaries. Recommended silence proves only that the
**recommended pack** is quiet on that tree — never that an all-profile or
`--only` rule is correct.

```sh
BIN="${CODEHOUND_BIN:-target/release/codehound}"

for t in \
  "$CODEHOUND_GOPDFSUIT" \
  "$CODEHOUND_CORPUS_ROOT/real-repos/monsoon" \
  "$CODEHOUND_CORPUS_ROOT/real-repos/go-retry" \
  "$CODEHOUND_CORPUS_ROOT/real-repos/gorl" \
  "$CODEHOUND_CORPUS_ROOT/real-repos/no-mistakes"
do
  echo "=== recommended: $t ==="
  "$BIN" "$t" --profile recommended \
    --format json --json-envelope --no-fail --no-cache
done
```

Helper (same defaults):

```sh
scripts/canary/run_decision_corpus.sh recommended
```

### B. Family / changed-rule `--only` (catalog trust)

Run **per changed family** with `--profile all --only <IDs>`. Record IDs
explicitly in the PR / hit-rate row. Do **not** infer family quality from
recommended silence.

```sh
BIN="${CODEHOUND_BIN:-target/release/codehound}"
ONLY="CWE-916"   # example — replace with the family under review

for t in \
  "$CODEHOUND_GOPDFSUIT" \
  "$CODEHOUND_CORPUS_ROOT/real-repos/monsoon" \
  "$CODEHOUND_CORPUS_ROOT/real-repos/go-retry" \
  "$CODEHOUND_CORPUS_ROOT/real-repos/gorl" \
  "$CODEHOUND_CORPUS_ROOT/real-repos/no-mistakes"
do
  echo "=== only $ONLY: $t ==="
  "$BIN" "$t" --profile all --only "$ONLY" \
    --format json --json-envelope --no-fail --no-cache
done
```

Helper:

```sh
scripts/canary/run_decision_corpus.sh only --only CWE-256,CWE-257,CWE-261,CWE-916
```

### C. Full-catalog noise control (optional)

Used for noise-reduction plans (e.g. gorl under [`noise-reduce-1.md`](./noise-reduce-1.md)):

```sh
"$BIN" real-repos/gorl --profile all --no-fail --no-cache --no-snippet --no-color true
```

Full-catalog counts are **not** interchangeable with recommended or family
`--only` results.

### Anti-patterns

| Do not | Why |
|--------|-----|
| Treat recommended 0 findings as proof a quarantined CWE is safe | Pack membership ≠ detector correctness |
| Mix multiple unrelated families in one `--only` without naming them | Hit-rate rows become uninterpretable |
| Bump a pin SHA silently mid-batch | Invalidates prior disposition tables |
| Promote to Structural from fixture-only hits | Structural bar is in [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §1.3 |

---

## Finding-review rubric

Every real-module hit used for keep / narrow / quarantine / promote decisions
gets **one** disposition. Review the source at `file:line`, not only the message.

| Disposition | Code | Use when |
|-------------|------|----------|
| **Actionable** | `actionable` | A maintainer should change the code or config; the report is correct under the rule's stated contract. |
| **Narrower-policy signal** | `narrower` | Shape is real but the rule is too broad for default packs (style, optional micro-opt, project-policy). Keep under `--only` / advisory, or narrow the detector — do not treat as a pure FP delete. |
| **False positive** | `false-positive` | Report is wrong for this source (control flow, defer semantics, setup-once loop, safe API misuse of the signal). Prefer a negative fixture when fixing. |
| **Duplicate** | `duplicate` | Same underlying issue as another finding (same sink / same root cause) or already owned by another rule with a clearer ID. |
| **No hit** | `no-hit` | Family scan produced zero findings on that repository (record as evidence, not as “clean forever”). |

### Review worksheet (copy into PR or hit-rate entry)

```text
Date:
Binary / commit:
Profile: recommended | all --only <ids>
Repository / revision:
Rule ID | file:line | disposition | one-line rationale
---
Reviewed hit rate (family): actionable / (actionable + false-positive + narrower + duplicate)
  (exclude no-hit rows; no-hit is per-repo absence, not a finding disposition)
```

### Using the rubric for catalog decisions

- **Structural promotion** still requires the full §1.3 bar (generalized proof,
  structural negatives, reviewed real-module evidence) — not merely one
  `actionable` row.
- **Fixture-only quarantine** is consistent with repeated `no-hit` across the
  expanded corpus **plus** corpus-shaped primary signals; zero hits alone are
  not a delete signal.
- **False-positive clusters** on recommended → stop-the-line for that family
  ([`parallel-catalog-program.md`](./parallel-catalog-program.md) §4.3).

Historical disposition tables may use extra labels (`optional-style`,
`example-only`, `advisory-microopt`). Map them into this rubric when rolling
forward:

| Historical label | Rubric |
|------------------|--------|
| optional-style / advisory-microopt | `narrower` |
| example-only | `narrower` (or exclude path via `--exclude-examples` and re-review) |
| false-positive | `false-positive` |
| actionable | `actionable` |
| duplicate | `duplicate` |

---

## Hit-rate tracking

**Location:** [`plans/v0.0.5/canary-hit-rates.md`](./canary-hit-rates.md)

Append a dated section per family (or recommended pilot). Do not overwrite prior
dates — promotion/quarantine arguments need history.

Minimum fields per entry: date, binary/commit, profile/command, pin set, per-repo
finding counts, reviewed sample dispositions, reviewed hit rate, disposition
decision (keep / narrow / quarantine / retire / no change).

---

## How to pin or extend the corpus

### Pin existing members

```sh
# From repo root (creates/updates real-repos/<id> at pinned SHA)
scripts/canary/run_decision_corpus.sh pin
```

Manual equivalent:

```sh
mkdir -p real-repos
git clone https://github.com/RedTeamPentesting/monsoon.git real-repos/monsoon
git -C real-repos/monsoon checkout --detach e0f1027cb0c256853b835d8e20d8d206a96e44ed
# …repeat per pin in canary-corpus-pins.json
```

### Add a repository

1. Choose a **public** Go module with a clear role not already covered (e.g.
   another library, web framework sample, or CLI of different scale).
2. Freeze a **commit SHA** (not a moving branch tip).
3. Add an entry to `canary-corpus-pins.json` and a row to the table above.
4. Record baseline recommended counts (and any family pilot) in
   `canary-hit-rates.md` on the same day.
5. Prefer modest modules over monorepos unless scale is the diversity goal
   (no-mistakes already covers mid-size).

Do **not** vendor these trees into git. Do **not** edit third-party sources to
silence findings.

---

## Pilot (2026-07-21) — rubric used end-to-end

**Binary:** existing release `codehound` at main-repo
`/home/chinmay/ChinmayPersonalProjects/codehound/target/release/codehound`
(tree at integration base `7d912d5` era; counts are decision-quality baselines,
not a CI budget gate).

### Recommended profile

| Repository | Revision | Files scanned | Findings | Notes |
|------------|----------|--------------:|---------:|-------|
| gopdfsuit | `26d7126…` | 78 | **38** | PERF-1 ×38 |
| monsoon | `e0f1027…` | 43 | **3** | PERF-1, PERF-7, PERF-190 |
| go-retry | `d3eb50a…` | 5 | **0** | clean control |
| gorl | `ec54aaf…` | 28 | **0** | recommended control (full-catalog is separate) |
| no-mistakes | `0a2c82f…` | 222 | **2** | PERF-189, PERF-7 |
| **Total** | | **376** | **43** | |

### Family `--only` spot-check (CWE-916)

Command: `--profile all --only CWE-916` on all five roots.

| Repository | Findings |
|------------|---------:|
| gopdfsuit | **2** |
| monsoon | 0 (`no-hit`) |
| go-retry | 0 |
| gorl | 0 |
| no-mistakes | 0 |

**Recommended silence on go-retry/gorl does not validate CWE-916** — the family
`--only` run does. Prior evidence: gopdfsuit PDF password MD5 hits remain the
reviewed real-module signal for Heuristic keep (not Structural).

### Reviewed sample (rubric applied)

| # | Repo | Rule | Location | Disposition | Rationale |
|--:|------|------|----------|-------------|-----------|
| 1 | monsoon | PERF-1 | `cmd/fuzz/main.go:91` | `false-positive` | `compileRegexps` compiles each input pattern once during setup, not a hot-path recompile (same as prior pilot). |
| 2 | monsoon | PERF-7 | `reporter/reporter.go:202` | `actionable` | Loop-level defer accumulates until function return. |
| 3 | monsoon | PERF-190 | `response/runner.go:293` | `actionable` | Long-lived `http.Client` without deadline. |
| 4 | no-mistakes | PERF-189 | `internal/telemetry/telemetry.go:305` | `false-positive` | Idiomatic `defer resp.Body.Close()` then `io.Copy(io.Discard, body)` — drain runs before deferred close. |
| 5 | no-mistakes | PERF-7 | `internal/update/archive.go:58` | `false-positive` | `defer rc.Close()` precedes `return` on the matching zip entry; loop does not stack defers across iterations. |
| 6 | gopdfsuit | CWE-916 | `internal/pdf/encryption/encrypt.go:79` | `actionable` | Fast MD5 password path; reviewed keep-Heuristic signal. |
| 7 | gopdfsuit | CWE-916 | `internal/pdf/redact/encryption_inhouse.go:241` | `actionable` | Same family signal on second call site. |

**Sample reviewed hit rate (rows 1–7):**  
`actionable` 4 / (`actionable` 4 + `false-positive` 3) = **57%** on this mixed
sample (recommended noise + one CWE family). This is a **process pilot**, not a
pack gate. Historical recommended-only senior sample on the original three repos
remains 95%+ actionable (see [`pending-work.md`](./pending-work.md) §3.1); new
no-mistakes FPs are candidates for later PERF batches, not this docs issue.

Full ledger entry: [`canary-hit-rates.md`](./canary-hit-rates.md) §2026-07-21.

---

## Related documents

| Doc | Role |
|-----|------|
| [`parallel-catalog-program.md`](./parallel-catalog-program.md) §4.1–4.3 | Program checklist |
| [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §1.3 | Structural promotion bar |
| [`noise-reduce-1.md`](./noise-reduce-1.md) | gorl full-catalog noise plan (closed) |
| [`pending-work.md`](./pending-work.md) §3.1 | Original recommended-pack pilot |
| `scripts/canary/run_canaries.sh` | In-repo budget canaries (not this corpus) |
| `scripts/canary/run_decision_corpus.sh` | Pin + recommended / `--only` helper |

---

## Out of scope (this definition)

- Detector rewrites or maturity/`source_index` edits  
- Changing default pack membership  
- Replacing the structural promotion bar  
- Checking large private monorepos into the pin list without an explicit issue  
