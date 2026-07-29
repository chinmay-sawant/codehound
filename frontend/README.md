# CodeHound — frontend

Marketing site + in-app product docs for [CodeHound](https://github.com/chinmay-sawant/codehound):
a Rust static analyzer for Go performance hot-path regressions, framework
footguns, and curated CWE heuristics.

Static SPA — no backend. Hash-routed views: **home**, **story** (`#story`), and
**docs** (`#docs…`).

## Stack

- React 19 · TypeScript 6 · Vite 8
- Tailwind CSS v4
- lucide-react icons
- Fonts: **Newsreader** (display) · **Geist** (UI) · **Geist Mono** (code chrome)

Scaffold still present but unused in the live tree: shadcn `Button`, JetBrains
Mono, Phosphor. Prefer lucide + CSS tokens when adding UI.

## Design

Editorial layout on warm paper/ink tokens (light) or near-black with accent
(dark). Monospace is for chrome and code, not the entire page. Tokens live as
CSS variables in `src/styles/global.css`.

## Development

```sh
npm install
npm run dev      # Vite dev server (base: /)
npm run build    # typecheck + production build → ../docs/
npm run preview  # local prod-like server (catches base-path issues)
npm run lint     # oxlint
```

No `VITE_*` env files are required. Only `NODE_ENV` changes the asset `base`.

## Production build

`npm run build` typechecks, then runs Vite with output aimed at the **repo-root**
`docs/` directory (one level up from `frontend/`).

- If `docs/` already exists, Vite **empties it first** (`emptyOutDir: true`), then
  writes only the latest build — no stale hashed assets left behind.
- Production `base` is `/codehound/` so assets resolve on GitHub Pages project
  site: `https://chinmay-sawant.github.io/codehound/`.
- Routing is **hash-based** (works on Pages without SPA rewrites).

Configured in `vite.config.ts` (`base` + `build.outDir` → `../docs`).

### Live hashes

| Hash | View |
|------|------|
| `#top` / empty | Home |
| `#story` | Story |
| `#docs`, `#docs/features`, `#docs/cli`, `#docs/sarif`, `#docs/export` | In-app docs |
| Home anchors | `#why`, `#workflow`, `#install`, `#docs-home` |

### GitHub Pages

1. Repo **Settings → Pages → Build and deployment**
2. Source: **Deploy from a branch**
3. Branch: your default branch, folder **`/docs`**
4. After deploy, open `https://chinmay-sawant.github.io/codehound/#docs`

Commit `frontend/` and the built `docs/` together when using branch deploy.

## Structure (live)

| Path | What |
|------|------|
| `src/App.tsx` | Shell, hash view switch, home + story content |
| `src/components/HeroTitle.tsx` | Rotating hero lines |
| `src/components/DocsView.tsx` | In-app documentation pages |
| `src/data/docs.ts` | Docs catalog, CLI/SARIF/export content |
| `src/hooks/useTheme.ts` | Dark/light toggle |
| `src/hooks/useGithubStars.ts` | GitHub star badge |
| `src/styles/global.css` | Design tokens + layout |
| `public/` | favicon, OG image, logos |

### Legacy / orphan (not mounted by `App.tsx`)

`src/data/sections.ts`, `TopNav.tsx`, `Section.tsx`, diagram components, and
related helpers are leftover from an older section-scroller layout. **Do not
author new marketing content there** unless you rewire `App.tsx` to mount them.
`sections.ts` may still hold copy used as a reference; keep rule counts in sync
with the README when you edit it.

## Positioning

CodeHound leads with **PERF scanning + framework footguns** (Gin/Echo/GORM
blind spots) and positions as a **complement** to golangci-lint, staticcheck,
and govulncheck — not a replacement.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for content authoring, adding a docs
page, design tokens, pitfalls, and the deploy checklist.
