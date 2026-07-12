# Part D — Data Persistence (BP-126..BP-145)

> **Parent:** `plans/v0.0.3/new-bad-practices/README.md`
> **IDs:** BP-126 … BP-145 (**20 rules**)
> **Stacks:** database/sql (P0), GORM (P0), sqlx (P0), pgx / go-redis (P2)
> **Status:** Plan only
> **Effort:** ~2 weeks

**Fixtures required for every rule:**  
`tests/fixtures/go/bad_practices/BP-N-vulnerable.txt` + `BP-N-safe.txt` with appropriate `variant:`.  
**Text snippets only** — include imports like `gorm.io/gorm`, `github.com/jmoiron/sqlx`, etc.

**PERF overlap ban:** GORM N+1, Select *, Create-in-loop, pool exhaustion, sqlx MapScan alloc, etc. are PERF. This part focuses on **correctness, transactions, error handling, migrations, connection setup**.

---

## D0 — Module work

- [ ] New `rules/data_persistence.rs`
- [ ] Category `DataPersistence`
- [ ] Import gates for database/sql, GORM, sqlx, pgx, go-redis
- [ ] JSON + dispatch BP-126..BP-145

---

## database/sql — BP-126..BP-132

### BP-126 — Transaction Without Commit/Rollback Handling

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `db.Begin` without `Commit`/`Rollback` defer pattern |
| **Detect** | Begin without rollback defer or commit |
| **Safe** | `defer func(){ if err != nil { tx.Rollback() } }()` + Commit |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-127 — Nested Transactions Assumed Supported

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `Begin` inside function that already has `*sql.Tx` param without savepoint |
| **Detect** | Tx method calling `db.Begin` again |
| **Safe** | Pass tx; use savepoints intentionally |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-128 — `QueryRow` Scan Error Not Distinguished From `ErrNoRows`

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | Treat all Scan errs as 500; never check `sql.ErrNoRows` |
| **Detect** | QueryRow+Scan; err check without `errors.Is(..., sql.ErrNoRows)` |
| **Safe** | Branch NotFound vs real error |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-129 — SQL String Built With `fmt.Sprintf` (Correctness/Injection Hygiene)

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | Query text via Sprintf with variables |
| **Note** | CWE-89 may cover — **verify**; if CWE fires, make BP a thin style alias or drop |
| **Safe** | Placeholders `$1` / `?` |
| **Fixtures** | **txt required** |

- [ ] Confirm CWE-89 coverage for stdlib
- [ ] Implement only if gap

### BP-130 — `db.SetMaxOpenConns` Never Configured For Service Binary

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `sql.Open` in main/service without pool tuning |
| **Detect** | Open without SetMaxOpenConns/SetMaxIdleConns in same function/package init path |
| **Safe** | Set pool limits + ConnMaxLifetime |
| **Note** | Quality/reliability not pure PERF pool exhaustion |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-131 — Using `db.Query` For Exec-Only Statement

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | INSERT/UPDATE/DELETE via Query without reading rows (leaks connections) |
| **Detect** | Query string starts with INSERT/UPDATE/DELETE; call is Query not Exec |
| **Safe** | `Exec` / `ExecContext` |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

### BP-132 — Ignoring `RowsAffected` When Required For Correctness

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Smell** | Optimistic lock UPDATE without checking RowsAffected == 0 |
| **Detect** | Exec + no RowsAffected when SQL contains `version`/`WHERE id` update heuristic |
| **Safe** | Check RowsAffected |
| **Fixtures** | **txt required** |

- [ ] Implement + fixtures + tests

---

## GORM — BP-133..BP-139

### BP-133 — GORM Error Not Checked After Chain

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `db.Where(...).Find(&xs)` without `.Error` check |
| **Detect** | Chain ending Find/First/Save/Create/Delete without Error handling |
| **Safe** | `if err := db....Error; err != nil` |
| **Fixtures** | **txt + gorm** |

- [ ] Implement + fixtures + tests

### BP-134 — GORM `First` Without `ErrRecordNotFound` Handling

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | First/Take error treated uniformly |
| **Detect** | First + err check without errors.Is RecordNotFound |
| **Safe** | Map to 404 |
| **Fixtures** | **txt + gorm** |

- [ ] Implement + fixtures + tests

### BP-135 — GORM Global `DB` Mutable Without Session

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | Package-level `var DB *gorm.DB` then `DB.Where` chain mutating statement in concurrent handlers |
| **Detect** | Package-level gorm.DB + chain Where without `Session`/`WithContext` |
| **Safe** | `DB.WithContext(ctx).Session(&gorm.Session{})` per request |
| **Fixtures** | **txt + gorm** |

- [ ] Implement + fixtures + tests

### BP-136 — GORM `AutoMigrate` In Request Path

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | AutoMigrate inside handler |
| **Detect** | AutoMigrate call in handler-shaped function |
| **Safe** | Migrate at startup / separate command |
| **Fixtures** | **txt + gorm** |

- [ ] Implement + fixtures + tests

### BP-137 — GORM Soft-Delete Confusion (`Unscoped` Missing On Hard Delete Intent)

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | Model has `DeletedAt`; code expects hard delete but uses Delete without Unscoped |
| **Detect** | Heuristic hard (optional); start with Delete on model type embedding gorm.DeletedAt without Unscoped when comment/name says purge |
| **Safe** | Explicit Unscoped for hard delete |
| **Fixtures** | **txt + gorm** |

- [ ] Implement + fixtures + tests

### BP-138 — GORM Callbacks / Hooks With Side-Effect External Calls

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Smell** | `BeforeCreate` calling HTTP/email (heuristic: http. / smtp in hook methods) |
| **Detect** | Method named Before*/After* with net/http calls |
| **Safe** | Domain service after commit |
| **Fixtures** | **txt + gorm** |

- [ ] Implement + fixtures + tests

### BP-139 — GORM Raw SQL With String Concatenation

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `db.Raw("…"+userInput)` / Sprintf into Raw |
| **Note** | Align with CWE-89 |
| **Fixtures** | **txt + gorm** |

- [ ] Confirm CWE gap for GORM Raw
- [ ] Implement + fixtures + tests

---

## sqlx — BP-140..BP-142

### BP-140 — sqlx `StructScan` / `Get` Error Ignored

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | Get/Select/StructScan discard err |
| **Fixtures** | **txt + sqlx** |

- [ ] Implement + fixtures + tests

### BP-141 — sqlx Named Query Struct Missing `db` Tags

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | NamedExec with struct fields without `db:` tags |
| **Detect** | Struct type used in Named* lacking tags |
| **Fixtures** | **txt + sqlx** |

- [ ] Implement + fixtures + tests

### BP-142 — sqlx `In` Helper Result Not Rebinded

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `sqlx.In` without `db.Rebind` / `Select` using expanded query incorrectly |
| **Detect** | In() call; no Rebind before Query/Select |
| **Safe** | `query, args, err := sqlx.In(...); query = db.Rebind(query)` |
| **Fixtures** | **txt + sqlx** |

- [ ] Implement + fixtures + tests

---

## Redis / pgx — BP-143..BP-145

### BP-143 — Redis Command Error Ignored

| Field | Value |
|-------|--------|
| **Severity** | medium |
| **Smell** | `rdb.Get(...).Result()` err discarded |
| **Detect** | go-redis Result/Err discarded |
| **Fixtures** | **txt + redis** |

- [ ] Implement + fixtures + tests

### BP-144 — Redis Key Without Namespace Prefix In Shared Instance

| Field | Value |
|-------|--------|
| **Severity** | low |
| **Smell** | Bare keys like `Set("user", …)` without service prefix |
| **Detect** | Heuristic literal keys without `:` namespace (optional, low severity) |
| **Fixtures** | **txt + redis** |

- [ ] Implement + fixtures + tests

### BP-145 — pgx / database Conn From Pool Not Released

| Field | Value |
|-------|--------|
| **Severity** | high |
| **Smell** | `pool.Acquire` without `Release` / `conn.Close` |
| **Detect** | Acquire without Release in function |
| **Fixtures** | **txt + pgx** |

- [ ] Implement + fixtures + tests

---

## Part D exit criteria

- [ ] 20 rules shipped or deferred
- [ ] All shipped rules have **vulnerable + safe `.txt` snippets** with correct imports
- [ ] CWE-89 overlap resolved for BP-129/BP-139
- [ ] Integration green for BP-126..BP-145
