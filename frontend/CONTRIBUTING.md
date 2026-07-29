# Frontend contributing guide

How to change the CodeHound marketing site and in-app docs. Quickstart and
Pages deploy: [README.md](./README.md).

---

## Content authoring

| Surface | Where to edit |
|---------|----------------|
| Home page (hero, signal strip, why, workflow, install, docs grid) | `src/App.tsx` |
| Hero rotation lines | `src/components/HeroTitle.tsx` → `HERO_LINES` |
| Story page (`#story`) | `StoryView` inside `src/App.tsx` |
| In-app product docs | Data in `src/data/docs.ts`; UI in `src/components/DocsView.tsx` |
| Links to deep repo docs | `externalDocLinks` + `githubDocsUrl` in `docs.ts` |

**Do not** assume `src/data/sections.ts` drives the live site. That file and
the section-scroller components are **orphaned** unless rewired.

Product honesty: marketing claims should match real capability. Prefer
“see `codehound --list-rules`” over hard-coding stale rule counts. Registry
counts (PERF 239 / CWE 175 / BP 135) are locked by Rust tests on the README.

---

## How to add an in-app docs page

1. Extend `DocPageId` in `src/data/docs.ts`.
2. Add an entry to `docPages` with `hash: '#docs/<slug>'`.
3. Update the `known` list in `docPageFromHash` (or derive from `docPages`).
4. Add a page component / branch in `DocsView.tsx` and export it from the switch.
5. Optionally surface a card on the home docs grid (`inAppDocs` filters out
   `overview` automatically).
6. Verify: `npm run dev` → `#docs/<slug>`; after build, check under `/codehound/`.

---

## Design tokens

CSS variables in `src/styles/global.css` (`:root` / `.dark`):

| Token | Role |
|-------|------|
| `--paper` | Page background |
| `--ink` / `--ink-soft` | Text |
| `--line` | Borders |
| `--accent` / `--accent-dark` | Emphasis / CTA |
| `--pine` | Signal strip / brand green |
| `--card` | Surfaces |
| `--serif` / `--sans` / `--mono` | Font stacks |

Prefer semantic tokens over hard-coded hex in new CSS. Tailwind v4 is available
via `@import "tailwindcss"`; most layout still uses custom classes.

---

## Component map

### Live

| Module | Role |
|--------|------|
| `App.tsx` | Shell, hash routing, home + story |
| `HeroTitle.tsx` | Animated hero |
| `DocsView.tsx` | Docs layout + pages |
| `useTheme` / `useGithubStars` | Theme toggle; star badge |
| `global.css` | Visual system |

### Scaffold / unused

| Path | Notes |
|------|-------|
| `TopNav`, `Section`, `sections.ts`, `section-nav`, `render-inline`, `useReveal` | Old section scroller |
| Diagrams + `AgentLogos` | Old marketing |
| `ui/button.tsx` | shadcn scaffold; unused |

---

## Theme & a11y

- Default theme bootstrapped in `index.html` (localStorage key `codehound-theme`;
  legacy `slopguard-theme` accepted).
- Toggle applies `.dark` on `<html>` via `useTheme`.
- `prefers-reduced-motion` is honored in hero animation and CSS.
- Patterns: `aria-label` / `aria-current` / `aria-labelledby` on nav and
  sections; decorative marks `aria-hidden`.
- No automated a11y tests yet — manual keyboard / contrast check before large UI
  changes.

---

## Testing

None today (no vitest/playwright). Manual checklist:

1. `npm run lint`
2. `npm run build`
3. Spot-check `../docs/index.html` asset paths include `/codehound/`
4. `npm run preview` — open home, `#story`, `#docs/cli`, `#docs/features`
5. Theme toggle persists across reload

---

## Common pitfalls

| Pitfall | Detail |
|---------|--------|
| **base path** | Prod assets under `/codehound/`. Absolute `/foo` breaks on Pages. Dev uses `/`. |
| **emptyOutDir** | `npm run build` **wipes** repo-root `docs/`. Do not hand-edit only `docs/`. |
| **Commit built site** | Branch deploy needs committed `docs/` (or switch to Actions later). |
| **Hash routing** | Not React Router. Unknown `#docs/foo` falls back to overview. `#docs` is a **view**; `#docs-home` is a **home anchor**. |
| **preview** | Use `npm run preview` after build to catch base-path issues. |
| **Authoring in sections.ts** | Changes will not appear until that stack is remounted. |
| **OG / canonical** | Hardcoded Pages URL in `index.html`; forks need updates. |

---

## Deploy checklist

1. Edit source under `frontend/src` (and `public/`).
2. `npm run lint && npm run build`.
3. Spot-check `../docs/index.html` asset paths include `/codehound/`.
4. `npm run preview`.
5. Commit `frontend/` + `docs/` together.
6. Confirm Pages source folder is `/docs`.
7. Smoke: `/codehound/`, `#story`, `#docs/cli`, `#docs/features`.
