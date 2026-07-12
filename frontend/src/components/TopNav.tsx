import { Moon, Star, Sun } from 'lucide-react'
import { sections } from '../data/sections'
import { useTheme } from '../hooks/useTheme'
import { formatStarCount, useGithubStars } from '../hooks/useGithubStars'

type TopNavProps = {
  active: string
  onNavigate: (id: string) => void
}

export function TopNav({ active, onNavigate }: TopNavProps) {
  const { theme, toggle } = useTheme()
  const { stars } = useGithubStars()

  return (
    <header className="topnav">
      <div className="topnav-inner">
        <a
          className="brand"
          href="#top"
          onClick={(e) => {
            e.preventDefault()
            onNavigate('top')
          }}
        >
          <span className="brand-prompt" aria-hidden="true">
            $
          </span>
          <span className="brand-name">codehound</span>
          <span className="brand-cursor" aria-hidden="true" />
        </a>

        <nav className="topnav-links" aria-label="Sections">
          {sections.map((s, i) => (
            <a
              key={s.id}
              href={`#${s.id}`}
              className={active === s.id ? 'topnav-link active' : 'topnav-link'}
              onClick={(e) => {
                e.preventDefault()
                onNavigate(s.id)
              }}
              aria-current={active === s.id ? 'true' : undefined}
            >
              <span className="topnav-idx">{String(i + 1).padStart(2, '0')}</span>
              <span className="topnav-label">{s.nav}</span>
            </a>
          ))}
        </nav>

        <div className="topnav-end">
          <a
            className="topnav-gh"
            href="https://github.com/chinmay-sawant/codehound"
            target="_blank"
            rel="noreferrer"
          >
            <span>github</span>
            {stars !== null && (
              <span className="topnav-stars" title={`${stars.toLocaleString()} GitHub stars`}>
                <Star size={11} strokeWidth={1.75} aria-hidden="true" />
                <span>{formatStarCount(stars)}</span>
              </span>
            )}
          </a>
          <button
            type="button"
            className="theme-toggle"
            onClick={toggle}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          >
            {theme === 'dark' ? (
              <Sun size={13} strokeWidth={1.75} />
            ) : (
              <Moon size={13} strokeWidth={1.75} />
            )}
          </button>
        </div>
      </div>
    </header>
  )
}
