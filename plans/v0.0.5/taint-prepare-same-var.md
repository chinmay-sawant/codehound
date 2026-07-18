# CWE-89 — Same-function Prepare same-variable parameterization

> **Issue:** [#47](https://github.com/chinmay-sawant/codehound/issues/47)  
> **Parent epic:** [#44](https://github.com/chinmay-sawant/codehound/issues/44)  
> **Decision:** `plans/v0.0.5/taint-capability-decision.md` §1 (design-approved)  
> **Status:** Implementation contract (same-function AST only)

---

## Goal

Reduce CWE-89 false positives on the common safe pattern:

```go
stmt, err := db.Prepare("SELECT id FROM users WHERE name = ?")
// …
rows, err := stmt.Query(userInput) // or Exec / *Context variants
```

without treating bare `.Prepare` as a global SQL sanitizer (dynamic Prepare
remains injectable).

Product bar: **honest FN over silent support** (ADR 0003). This is a narrow
sink-side guard, not whole-program prepared-statement analysis.

---

## Safe pattern (suppress CWE-89)

All of the following must hold:

| # | Condition |
|---|-----------|
| 1 | Sink is a method call on a **simple identifier** receiver: `recv.Query`, `recv.Exec`, `recv.QueryRow`, or the `*Context` forms. |
| 2 | The **latest assignment** to `recv` in the **same function** that appears **before** the sink byte range is a `Prepare` / `PrepareContext` call. |
| 3 | The SQL argument of that Prepare is a **string literal** (`"..."` or `` `...` ``). For `Prepare` that is arg 0; for `PrepareContext` that is arg 1. |
| 4 | No requirement that the Query/Exec **arguments** be untainted — bound parameters are the point of prepared statements. |

When these hold, the sink is treated like a parameterized query for CWE-89
(same suppress path as literal-first-arg `db.Query("…", args…)`).

### Supported call shapes

```go
// Prepare
stmt, err := db.Prepare("SELECT … WHERE id = ?")
rows, err := stmt.Query(id)
_, err = stmt.Exec(id)
row := stmt.QueryRow(id)

// PrepareContext
stmt, err := db.PrepareContext(ctx, "SELECT … WHERE id = ?")
rows, err := stmt.QueryContext(ctx, id)
_, err = stmt.ExecContext(ctx, id)
row := stmt.QueryRowContext(ctx, id)
```

Receiver names are arbitrary (`stmt`, `ps`, …). DB/tx receiver of Prepare may
be any simple selector (`db.Prepare`, `tx.Prepare`, …).

---

## Unsafe / must still fire (no suppress)

| Case | Behavior |
|------|----------|
| String-concat / dynamic first arg on `db.Query` / `db.Exec` | Still fires (existing heuristic). |
| Latest binding of `recv` is **not** Prepare (opaque factory, other var, etc.) | Still fires when taint reaches Query/Exec. |
| `recv` **reassigned** after a literal Prepare to a non-literal-Prepare RHS | Still fires (latest-write rule). |
| `Prepare` / `PrepareContext` with **non-literal** SQL (`fmt.Sprintf`, concat, variable) | Do **not** suppress Stmt.Query/Exec on that binding. |
| Cross-function Prepare factories (`stmt := makeStmt(db)`) | Out of scope — honest FN for “safe” factories; taint still fires if args reach Query. |
| Bare `.Prepare` on a taint path as a sanitizer | **Never** — `classify_sanitizer` must not add Prepare. |
| Inter-function same-var / typed `*sql.Stmt` proof | Out of scope. |

### Dynamic Prepare residual FN

```go
q := "SELECT … WHERE n = '" + name + "'"
stmt, _ := db.Prepare(q)
_ = stmt.Query() // no tainted arg at Query
```

Prepare is **not** an SQL sink today. If taint never reaches Query/Exec args,
CWE-89 may not fire — **explicit residual FN**, not fixed by this contract.
String-concat at `db.Query(q)` continues to fire.

---

## Non-goals (out of scope for #47)

- Decoder output pointers (`(*Decoder).Decode`)
- External-package / cross-package stmt propagation
- Channel / goroutine handoffs
- Typed Go / `go/packages` / SSA
- Treating bare `.Prepare` as `SanitizerKind::SQL`
- Inter-procedural Prepare→return→Query summaries

---

## Implementation sketch

1. **Do not** extend `classify_sanitizer` with `.Prepare`.
2. **Sink-side guard** in `detect_cwe_89_taint` (beside `is_parameterized_query`):
   - Parse simple receiver from sink function text.
   - Among `facts.taint.assignments`, pick the latest `lhs == receiver` with
     `assign.byte < sink.byte` inside the enclosing `function_ranges` span.
   - Accept only if RHS is Prepare/PrepareContext with literal SQL arg.
3. Keep literal-first-arg `is_parameterized_query` unchanged.

---

## Fixtures

| Fixture | Expect |
|---------|--------|
| `tests/fixtures/go/taint/CWE-89-vulnerable.txt` (base) | Fires (keep) |
| `tests/fixtures/go/taint/CWE-89-safe.txt` (base) | Silent (keep) |
| `CWE-89-prepare-same-var-safe.txt` | Silent — literal Prepare + Stmt.Query |
| `CWE-89-prepare-same-var-vulnerable.txt` | Fires — string-concat Query |
| Unit cases | Rebind / dynamic Prepare SQL do not suppress |

Register new fixtures in `tests/fixtures/manifest.toml` with `taint = true`.

---

## Tests / validation

- Unit: prepare same-var silent; string-concat fires; rebind fires; dynamic
  Prepare SQL does not suppress.
- Integration: `go_cwe_detector_fixtures` taint bases; evidence/oracle for named
  variants; `go_taint_integration` still green.
- `make lint` + targeted `cargo test --locked`.

---

## Docs

Update `documents/taint.md`:

- Sanitizer SQL row: mention same-function same-var Prepare→Stmt.Query guard.
- Limitations: remove “Same-stmt Prepare→Stmt.Query proof is not implemented”;
  state the tight same-function rule and residual FNs.

---

## Explicit non-claims

- Not security-grade whole-program taint.
- Not a guarantee that every prepared-statement style is recognized.
- Not a claim that dynamic Prepare injection is fully covered.
