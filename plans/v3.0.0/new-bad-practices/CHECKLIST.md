# New Go Bad Practices — Master Checklist (v3.0.0)

> **Parent:** `plans/v3.0.0/new-bad-practices/README.md`
> **Status:** Plan only — **0 / 100 rules shipped**
> **Date:** 2026-07-10
> **How to use:** Check boxes as work completes. Rule sketches live in `01`–`06`. Order lives in `07`.

---

## Constraints (always)

- [ ] **Golang-only** bad practices (this epic)
- [ ] **Not covered** by stock `go vet` / `staticcheck` / golangci defaults as pure duplicates
- [ ] **Not covered** by existing BP-1..65 / CWE / PERF (framework rules = correctness, not PERF rehash)
- [ ] **Project-agnostic** (no product-only rules)
- [ ] **Static-only** heuristics
- [ ] **Ship shape:** JSON + detector + **`BP-N-vulnerable.txt` + `BP-N-safe.txt` text snippets** + manifest + docs + tests green
- [ ] **Never** commit raw `.go` under `tests/fixtures/go/bad_practices/` — **snippets are `.txt` only**

---

## Phase 0 — Scaffold

- [ ] Read `00-gap-and-scope.md`
- [ ] Confirm highest BP id is 65
- [ ] Grep hard-coded BP max / counts in tests and docs
- [ ] Category enum extensions (if any)
- [ ] New rule modules stubbed (`http_frameworks`, `data_persistence`, `observability`, `config_cli`)
- [ ] Dispatch + SourceIndex extension plan agreed
- [ ] Optional: `make run-bp-new` target sketched

---

## Phase 1 — Part A: Core language (BP-66..BP-85) — 20 rules

Detail: [01-part-a-core-language.md](./01-part-a-core-language.md)

| ID | Title (short) | Det | Vuln.txt | Safe.txt | Manifest | Docs | Tests |
|----|---------------|:---:|:--------:|:--------:|:--------:|:----:|:-----:|
| BP-66 | errors.Is vs == | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-67 | errors.As target pointer | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-68 | errors.Join discarded | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-69 | data + non-nil error return | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-70 | log err then continue | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-71 | ignore multi-return primary | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-72 | typed nil interface | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-73 | nil map write | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-74 | append alias share | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-75 | copy into empty dest | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-76 | map range order assumed | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-77 | context.WithValue string key | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-78 | ctx not propagated to child | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-79 | WithCancel without defer cancel | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-80 | context.TODO in prod | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-81 | repeated time.Now in cond | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-82 | time.Parse location ambiguity | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-83 | time.Sleep sync in prod | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-84 | int division percentage | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-85 | type assert without ok | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |

- [ ] Part A complete (20/20) or deferred list updated

---

## Phase 2 — Part B: Concurrency & resources (BP-86..BP-100) — 15 rules

Detail: [02-part-b-concurrency-resources.md](./02-part-b-concurrency-resources.md)

| ID | Title (short) | Det | Vuln.txt | Safe.txt | Manifest | Docs | Tests |
|----|---------------|:---:|:--------:|:--------:|:--------:|:----:|:-----:|
| BP-86 | Lock without Unlock | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-87 | RLock across blocking call | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-88 | nil channel send/recv | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-89 | double close / close in consumer | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-90 | infinite bare channel recv loop | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-91 | signal chan not struct{} | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-92 | errgroup without WithContext | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-93 | errgroup.Go swallows error | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-94 | goroutine map write unsynced | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-95 | HTTP response body not closed | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-96 | sql.Rows not closed | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-97 | writer never flushed | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-98 | file not closed on err path | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-99 | sync.Cond locker discipline | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| BP-100 | unbounded goroutine fan-out | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |

- [ ] Part B complete (15/15) or deferred list updated

---

## Phase 3 — Part C: HTTP & frameworks (BP-101..BP-125) — 25 rules

Detail: [03-part-c-http-frameworks.md](./03-part-c-http-frameworks.md)

**Framework priority:** net/http + **Gin** (P0) → Echo / Fiber / Chi (P1).

| ID | Title (short) | Stack | Det | Vuln.txt | Safe.txt | Tests |
|----|---------------|-------|:---:|:--------:|:--------:|:-----:|
| BP-101 | header after body | stdlib | [ ] | [ ] | [ ] | [ ] |
| BP-102 | missing status on err | stdlib | [ ] | [ ] | [ ] | [ ] |
| BP-103 | open redirect query | stdlib | [ ] | [ ] | [ ] | [ ] |
| BP-104 | mux method patterns | stdlib | [ ] | [ ] | [ ] | [ ] |
| BP-105 | cookie flags missing | stdlib | [ ] | [ ] | [ ] | [ ] |
| BP-106 | CORS origin reflect | stdlib | [ ] | [ ] | [ ] | [ ] |
| BP-107 | middleware skips next | stdlib | [ ] | [ ] | [ ] | [ ] |
| BP-108 | handler uses Background | stdlib | [ ] | [ ] | [ ] | [ ] |
| BP-109 | Gin no abort after error JSON | gin | [ ] | [ ] | [ ] | [ ] |
| BP-110 | Gin bind err ignored | gin | [ ] | [ ] | [ ] | [ ] |
| BP-111 | Gin goroutine without Copy | gin | [ ] | [ ] | [ ] | [ ] |
| BP-112 | Gin admin group no auth | gin | [ ] | [ ] | [ ] | [ ] |
| BP-113 | Gin mode not release | gin | [ ] | [ ] | [ ] | [ ] |
| BP-114 | Gin ClientIP trust | gin | [ ] | [ ] | [ ] | [ ] |
| BP-115 | Gin binding tags missing | gin | [ ] | [ ] | [ ] | [ ] |
| BP-116 | Echo double response | echo | [ ] | [ ] | [ ] | [ ] |
| BP-117 | Echo bind err ignored | echo | [ ] | [ ] | [ ] | [ ] |
| BP-118 | Echo param path join | echo | [ ] | [ ] | [ ] | [ ] |
| BP-119 | Fiber ctx in goroutine | fiber | [ ] | [ ] | [ ] | [ ] |
| BP-120 | Fiber BodyParser err ignored | fiber | [ ] | [ ] | [ ] | [ ] |
| BP-121 | Fiber Prefork hardcoded | fiber | [ ] | [ ] | [ ] | [ ] |
| BP-122 | Chi middleware skips next | chi | [ ] | [ ] | [ ] | [ ] |
| BP-123 | Chi URLParam empty authz | chi | [ ] | [ ] | [ ] | [ ] |
| BP-124 | missing recover middleware | multi | [ ] | [ ] | [ ] | [ ] |
| BP-125 | mixed writer contexts | multi | [ ] | [ ] | [ ] | [ ] |

- [ ] PERF overlap review done (esp. BP-111)
- [ ] CWE overlap review done (BP-103, BP-118)
- [ ] Part C complete (25/25) or deferred list updated

---

## Phase 4 — Part D: Data persistence (BP-126..BP-145) — 20 rules

Detail: [04-part-d-data-persistence.md](./04-part-d-data-persistence.md)

| ID | Title (short) | Stack | Det | Vuln.txt | Safe.txt | Tests |
|----|---------------|-------|:---:|:--------:|:--------:|:-----:|
| BP-126 | tx without commit/rollback | sql | [ ] | [ ] | [ ] | [ ] |
| BP-127 | nested Begin assumed | sql | [ ] | [ ] | [ ] | [ ] |
| BP-128 | ErrNoRows not handled | sql | [ ] | [ ] | [ ] | [ ] |
| BP-129 | Sprintf SQL | sql | [ ] | [ ] | [ ] | [ ] |
| BP-130 | pool limits unset | sql | [ ] | [ ] | [ ] | [ ] |
| BP-131 | Query used for Exec | sql | [ ] | [ ] | [ ] | [ ] |
| BP-132 | RowsAffected ignored | sql | [ ] | [ ] | [ ] | [ ] |
| BP-133 | GORM Error unchecked | gorm | [ ] | [ ] | [ ] | [ ] |
| BP-134 | GORM RecordNotFound | gorm | [ ] | [ ] | [ ] | [ ] |
| BP-135 | GORM global DB mutate | gorm | [ ] | [ ] | [ ] | [ ] |
| BP-136 | AutoMigrate in handler | gorm | [ ] | [ ] | [ ] | [ ] |
| BP-137 | soft-delete Unscoped | gorm | [ ] | [ ] | [ ] | [ ] |
| BP-138 | hooks with HTTP side effects | gorm | [ ] | [ ] | [ ] | [ ] |
| BP-139 | GORM Raw concat | gorm | [ ] | [ ] | [ ] | [ ] |
| BP-140 | sqlx scan err ignored | sqlx | [ ] | [ ] | [ ] | [ ] |
| BP-141 | sqlx missing db tags | sqlx | [ ] | [ ] | [ ] | [ ] |
| BP-142 | sqlx.In without Rebind | sqlx | [ ] | [ ] | [ ] | [ ] |
| BP-143 | redis err ignored | redis | [ ] | [ ] | [ ] | [ ] |
| BP-144 | redis key no namespace | redis | [ ] | [ ] | [ ] | [ ] |
| BP-145 | pgx conn not released | pgx | [ ] | [ ] | [ ] | [ ] |

- [ ] CWE-89 overlap resolved (BP-129/139)
- [ ] Part D complete (20/20) or deferred list updated

---

## Phase 5 — Part E: Observability / config / JSON / gRPC / CLI (BP-146..BP-160) — 15 rules

Detail: [05-part-e-observability-config.md](./05-part-e-observability-config.md)

| ID | Title (short) | Det | Vuln.txt | Safe.txt | Tests |
|----|---------------|:---:|:--------:|:--------:|:-----:|
| BP-146 | log sensitive fields | [ ] | [ ] | [ ] | [ ] |
| BP-147 | std log vs structured | [ ] | [ ] | [ ] | [ ] |
| BP-148 | slog debug hardcoded | [ ] | [ ] | [ ] | [ ] |
| BP-149 | error log missing err | [ ] | [ ] | [ ] | [ ] |
| BP-150 | Getenv required empty | [ ] | [ ] | [ ] | [ ] |
| BP-151 | secret env logged | [ ] | [ ] | [ ] | [ ] |
| BP-152 | hardcoded DSN password | [ ] | [ ] | [ ] | [ ] |
| BP-153 | config without version | [ ] | [ ] | [ ] | [ ] |
| BP-154 | json.Unmarshal err ignored | [ ] | [ ] | [ ] | [ ] |
| BP-155 | JSON decode unbounded body | [ ] | [ ] | [ ] | [ ] |
| BP-156 | omitempty on secrets | [ ] | [ ] | [ ] | [ ] |
| BP-157 | gRPC no interceptor | [ ] | [ ] | [ ] | [ ] |
| BP-158 | gRPC naked error return | [ ] | [ ] | [ ] | [ ] |
| BP-159 | flag.Parse order | [ ] | [ ] | [ ] | [ ] |
| BP-160 | cobra Run vs RunE | [ ] | [ ] | [ ] | [ ] |

- [ ] Part E complete (15/15) or deferred list updated

---

## Phase 6 — Part F: Testing & API hygiene tail (BP-161..BP-165) — 5 rules

Detail: [06-part-f-testing-api-hygiene.md](./06-part-f-testing-api-hygiene.md)

| ID | Title (short) | Det | Vuln.txt | Safe.txt | Tests |
|----|---------------|:---:|:--------:|:--------:|:-----:|
| BP-161 | test hits prod DSN | [ ] | [ ] | [ ] | [ ] |
| BP-162 | t.Parallel + shared mutable | [ ] | [ ] | [ ] | [ ] |
| BP-163 | golden update ungated | [ ] | [ ] | [ ] | [ ] |
| BP-164 | options mutate globals | [ ] | [ ] | [ ] | [ ] |
| BP-165 | New* without Close contract | [ ] | [ ] | [ ] | [ ] |

- [ ] Part F complete (5/5)
- [ ] Stretch backlog used only for replacements (document swaps below)

### Deferred / replaced log

| Original ID | Reason | Replacement (stretch) |
|-------------|--------|------------------------|
| | | |

---

## Phase 7 — Release polish

- [ ] `documents/bad-practices.md` covers BP-66..BP-165
- [ ] Root README rule count updated (65 → 165)
- [ ] CHANGELOG draft for v3.0.0 BP section
- [ ] `make run-bp-new` (or equivalent) works
- [ ] Spot-check: stock staticcheck clean on a sample of new fixtures; CodeHound fires
- [ ] Epic DoD in README satisfied

---

## Fixture reminder (copy into every PR description)

```
For each BP-N in this PR:
- [ ] tests/fixtures/go/bad_practices/BP-N-vulnerable.txt
- [ ] tests/fixtures/go/bad_practices/BP-N-safe.txt
- [ ] manifest.toml entries
- [ ] NO raw .go files committed under tests/fixtures/
```

---

## Progress counters

| Part | Rules | Done |
|------|------:|-----:|
| A Core language | 20 | 0 |
| B Concurrency/resources | 15 | 0 |
| C HTTP/frameworks | 25 | 0 |
| D Data persistence | 20 | 0 |
| E Observability/config | 15 | 0 |
| F Testing/API tail | 5 | 0 |
| **Total** | **100** | **0** |
