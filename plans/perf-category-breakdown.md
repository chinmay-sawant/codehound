# PERF-101..212 Category Breakdown

> Source: `ruleset/golang/golang.json` entries `PERF-101` through `PERF-212` and current detector coverage in `src/lang/go/detectors/perf/registry.toml`.
> Purpose: close P2.4 Phase 1.1-1.3 planning by making the remaining PERF rollout explicit before adding more detectors.

## Audit Result

- `ruleset/golang/golang.json` contains all 112 expected entries from `PERF-101` through `PERF-212`.
- Current registry coverage: 15 shipped rules.
- Remaining registry gap: 97 rules.
- Difficulty buckets:
  - Category A: 37 remaining simple local heuristics.
  - Category B: 59 context-aware heuristics.
  - Category C: 1 semantic/control-flow detector.

## Domain Mapping

| Domain | Rule range / examples | Suggested module |
|---|---|---|
| HTTP server/client | PERF-101..104, 141..155, 189..190, 197..203 | `stdlib_optimization::http` |
| Runtime / GC / memory | PERF-105..110, 123, 128..140, 150..151, 168..170, 191..192 | `memory_gc` |
| Strings / bytes / formatting | PERF-111..127, 146..147, 156..159, 178..188, 203 | `string_bytes` |
| Concurrency / channels / context | PERF-132, 148, 167, 171..176, 183, 193..195 | `concurrency` |
| Database / ORMs / Redis | PERF-160..166, 204..212 | `stdlib_optimization::database` |
| Framework-specific web | PERF-196..202, 207 | existing framework modules plus `stdlib_optimization::web_frameworks` |

## Already Shipped

- PERF-103 (High): HTTP Response Body Not Closed
- PERF-105 (Medium): runtime.SetFinalizer On Hot Path Object
- PERF-107 (Medium): encoding/binary Write Or Read Inside Loop
- PERF-111 (Medium): Range Over String Produces Rune Allocation
- PERF-112 (Medium): strings.ToLower Before Comparison Instead Of EqualFold
- PERF-115 (Medium): strings.Compare Used For Equality Check
- PERF-116 (Low): strings.Index Used For Contains Check
- PERF-117 (Medium): bytes.Compare Used For Equality Check
- PERF-118 (Low): Unnecessary http.NewRequest For Simple Methods
- PERF-120 (Low): time.Now().Sub Instead Of time.Since
- PERF-122 (Low): HasPrefix Followed By Slice Instead Of TrimPrefix
- PERF-123 (Low): Redundant make Argument With Zero Value
- PERF-124 (Low): strings.Replace With -1 Instead Of ReplaceAll
- PERF-126 (Low): Redundant http.CanonicalHeaderKey Call
- PERF-127 (Medium): Unnecessary fmt.Sprintf In Log Call

## Category A

Simple local heuristics. These should usually need one AST walk or a bounded source-window check, plus vulnerable/safe fixtures.

PERF-101, PERF-106, PERF-110, PERF-113, PERF-114, PERF-119, PERF-121, PERF-125, PERF-128, PERF-130, PERF-131, PERF-132, PERF-135, PERF-140, PERF-145, PERF-146, PERF-147, PERF-149, PERF-156, PERF-157, PERF-158, PERF-159, PERF-165, PERF-166, PERF-168, PERF-171, PERF-173, PERF-177, PERF-181, PERF-182, PERF-190, PERF-192, PERF-198, PERF-204, PERF-208, PERF-209, PERF-211.

## Category B

Context-aware rules. These need function-level checks, request-handler/hot-path recognition, loop checks, variable reuse checks, or same-scope reasoning.

PERF-102, PERF-104, PERF-108, PERF-109, PERF-129, PERF-133, PERF-136, PERF-137, PERF-138, PERF-139, PERF-141, PERF-142, PERF-143, PERF-144, PERF-148, PERF-150, PERF-151, PERF-152, PERF-153, PERF-154, PERF-155, PERF-160, PERF-161, PERF-162, PERF-163, PERF-164, PERF-167, PERF-169, PERF-170, PERF-172, PERF-174, PERF-175, PERF-176, PERF-178, PERF-179, PERF-180, PERF-183, PERF-184, PERF-185, PERF-186, PERF-187, PERF-188, PERF-189, PERF-191, PERF-193, PERF-194, PERF-195, PERF-196, PERF-197, PERF-199, PERF-200, PERF-201, PERF-202, PERF-203, PERF-205, PERF-206, PERF-207, PERF-210, PERF-212.

## Category C

Semantic/control-flow rule requiring more than local syntax and likely a dedicated helper before broad rollout.

- PERF-134 (Medium): Manual io.Read/Write Loop Instead Of io.Copy.

## Recommended Implementation Order

1. Category A, HTTP and string/bytes sub-batches: PERF-101, 113, 114, 119, 125, 146, 147, 156, 157, 190, 198.
2. Category A, memory/concurrency/database sub-batches: PERF-106, 110, 131, 132, 140, 149, 165, 166, 168, 171, 173, 177, 181, 182, 192, 204, 208, 209, 211.
3. Category B HTTP/database rules with function-scope helpers: PERF-102, 104, 141, 142, 144, 160, 161, 162, 164, 189, 212.
4. Remaining Category B framework and hot-path rules after shared helper coverage is stable.
5. Category C only after control-flow utilities exist.

## Open Verification Gates

- Add registry entries and fixtures with each detector batch.
- Keep `cargo test -q --test go_perf_detector_integration --test fixture_manifest_integration` green for every batch.
- Run a real-project smoke test against a non-trivial Go repository before marking P2.4 performance verification complete.
- Verify PERF-126's curated canonical header list against `net/http` / `net/textproto` behavior before treating that detector as final.
