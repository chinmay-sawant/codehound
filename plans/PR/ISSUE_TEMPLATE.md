# CodeHound — GitHub Issue Creation Template

Use this when opening a **process-gated** implementation issue (same discipline as `PR_TEMPLATE.md`). Fill the body sections, then create the issue with the CLI so **assignee**, **labels**, and **title** are set correctly.

---

## How to use

1. **Pick a title** — short, imperative or noun phrase; include the work area (`CWE catalog trust…`, `BP noise…`).
2. **Fill the body** below (Context, Scope, Out of scope, Success criteria, Plan, References).
3. **Save a record** (optional but recommended) under `plans/v0.0.x/issue-<slug>.md` or keep the filled body in the checklist plan’s Overview.
4. **Create the issue** with the `gh` command in [Open the issue](#open-the-issue-gh--required-metadata).
5. **Open a local branch** after the issue exists, named after the work (e.g. `chore/cwe-trust-tranche5`).
6. When shipping: open the PR with `PR_TEMPLATE.md` and `Closes #N` / `Relates to #N`.

---

## Open the issue (`gh`) — required metadata

```sh
gh issue create \
  --title "<short title>" \
  --assignee "@me" \
  --label documentation \
  --label enhancement \
  --body-file plans/PR/issue-<short-slug>-body.md
```

| Flag | Rule |
|------|------|
| `--assignee "@me"` | **Required.** Self-assign the author (use a login only when opening for someone else with their OK). |
| `--label …` | **Required.** At least one. Prefer `documentation` + `enhancement` for plan/trust work; use `bug` for defect-driven issues. |
| `--body-file` or `--body` | **Required.** Full body with Context / Scope / Success criteria. |
| `--title` | Specific enough to find later; include domain (CWE, BP, engine). |

If the issue already exists without metadata:

```sh
gh issue edit <NUMBER> --add-assignee "@me"
gh issue edit <NUMBER> --add-label documentation --add-label enhancement
```

List labels:

```sh
gh label list
```

---

## Self-assign

- Every issue the author opens for **their** implementation batch **must** list them as assignee.
- Do not leave assignees empty for “anyone can pick this up” on process-gated work — use `help wanted` / `good first issue` only for true community issues.

---

## Labels

| Label | Use when |
|-------|----------|
| `enhancement` | Product/detector/trust work, new capability |
| `documentation` | Plans, audits, decision records, ledger |
| `bug` | Incorrect behavior / regression |
| `duplicate` / `wontfix` / `invalid` | Triage only |
| `good first issue` / `help wanted` | Community contribution issues |

Mixed plan + code batches: **`documentation` + `enhancement`**.

---

## Ticket references

| In the body | Purpose |
|-------------|---------|
| Link closed parents (`#39`) | Continuity |
| Link merged PRs (`#38`, `#41`) | Evidence |
| Link plan paths | Single source of checklist |
| Link ROADMAP / ADRs | Policy boundaries |

When the work ships, the PR must use:

- `Closes #N` if this issue is fully done
- `Relates to #N` for partial / parent / prior work

See `PR_TEMPLATE.md` → Ticket linking.

---

## Issue body structure

Copy from the line below into `--body` / body file. Delete HTML comments before submit.

---

## Context

<!-- Why this issue exists now. Link closed issues / merged PRs / plan status. -->

-

## Scope (in)

<!-- Concrete, domain-sized. Checklist-friendly bullets. -->

1.
2.

## Out of scope

<!-- Explicit non-goals (decision-gated items, other domains). -->

-

## Success criteria

- [ ]
- [ ]

## Plan

- Checklist: `plans/v0.0.x/<plan>.md`
- Parent: `plans/...`

## References

- Relates to #N / Continues from #N
- PRs: #N
- Docs: `plans/...`

---

## Author checklist before create

- [ ] Self-assigned (`--assignee @me`)
- [ ] Labels applied (at least one)
- [ ] Scope is one issue-sized batch (not “certify entire catalog”)
- [ ] Checklist plan path named in body
- [ ] Out of scope listed
- [ ] Local branch name chosen (create after issue number exists)

---

## Example

```sh
gh issue create \
  --title "CWE catalog trust tranche 5+: file/path, TOCTOU, permissions, call-facts" \
  --assignee "@me" \
  --label documentation \
  --label enhancement \
  --body-file plans/v0.0.5/cwe-catalog-trust-next.md
```

(Prefer a dedicated issue body file, or paste the Context/Scope sections from the checklist plan Overview.)
