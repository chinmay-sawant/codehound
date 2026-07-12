# CodeHound — frontend

Marketing site for [CodeHound](https://github.com/chinmay-sawant/codehound): a Rust
static analyzer for Go performance hot-path regressions, framework footguns,
and curated CWE heuristics.

## Stack

- React 19 · TypeScript 6 · Vite 8
- Tailwind CSS v4 · shadcn/ui (Button)
- lucide-react icons
- **Geist Mono** + JetBrains Mono (computer type, mono-first)

## Design

Flat terminal aesthetic. No gradients. Phosphor accent on near-black (dark)
or ink on paper (light). Everything is monospace. Content lives in
`src/data/sections.ts` — add a section, the nav and layout follow.

## Development

```sh
npm run dev    # Vite dev server
npm run build  # production build → ../docs/
npm run lint   # oxlint
```

## Production build

`npm run build` typechecks, then runs Vite with output aimed at the **repo-root**
`docs/` directory (one level up from `frontend/`).

- If `docs/` already exists (previous `assets/`, `index.html`, fonts, etc.), Vite
  **empties it first** (`emptyOutDir: true`), then writes only the latest build.
- Result: `docs/` always reflects the most recent production build — no stale
  hashed assets left behind.
- Production `base` is `/codehound/` so assets resolve on GitHub Pages project
  site: `https://chinmay-sawant.github.io/codehound/`.
- Section deep links use hash URLs (works on Pages without SPA rewrites), e.g.
  `…/codehound/#audience` → “Who this is built for”.

Configured in `vite.config.ts` (`base` + `build.outDir` → `../docs`).

### GitHub Pages

1. Repo **Settings → Pages → Build and deployment**
2. Source: **Deploy from a branch**
3. Branch: your default branch, folder **`/docs`**
4. After deploy, open `https://chinmay-sawant.github.io/codehound/#audience`
   (or any section id from `src/data/sections.ts`).

## Structure

| Path | What |
|---|---|
| `src/App.tsx` | Full-width hero grid, sections, footer |
| `src/data/sections.ts` | All marketing content as data |
| `src/components/TopNav.tsx` | Sticky top nav + scroll-spy |
| `src/components/Section.tsx` | Section with left rail + split layout |
| `src/styles/global.css` | Flat mono, full-width, no sidebar |

## Positioning

CodeHound leads with **PERF scanning + framework footguns** (Gin/Echo/GORM
blind spots) and positions as a **complement** to golangci-lint, staticcheck,
and govulncheck — not a replacement.
