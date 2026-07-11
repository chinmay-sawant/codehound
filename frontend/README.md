# CodeHound — frontend

Marketing site for [CodeHound](https://github.com/anomalyco/codehound): a Rust
static analyzer for Go performance hot-path regressions, framework footguns,
and curated CWE heuristics.

## Stack

- React 19 · TypeScript 6 · Vite 8
- Tailwind CSS v4 · shadcn/ui (Button)
- lucide-react icons · Inter + JetBrains Mono fonts

## Development

```sh
npm run dev    # Vite dev server
npm run build  # production build → dist/
npm run lint   # oxlint
```

## Structure

| Path | What |
|---|---|
| `src/App.tsx` | Hero section, stat bar, section renderer, footer |
| `src/data/sections.ts` | All marketing content — 11 sections as data |
| `src/components/Sidebar.tsx` | Scroll-spy sidebar nav |
| `src/components/Section.tsx` | Generic section renderer |
| `src/styles/global.css` | Dark-first, amber-accented theme, layout |

## Positioning

CodeHound leads with **PERF scanning + framework footguns** (Gin/Echo/GORM
blind spots) and positions as a **complement** to golangci-lint, staticcheck,
and govulncheck — not a replacement.
