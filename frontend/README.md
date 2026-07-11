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
npm run build  # production build → dist/
npm run lint   # oxlint
```

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
