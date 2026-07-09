import { Moon, Sun } from 'lucide-react'
import { sections } from '../data/sections'
import { useTheme } from '../hooks/useTheme'

type SidebarProps = {
  active: string
  onNavigate: (id: string) => void
}

export function Sidebar({ active, onNavigate }: SidebarProps) {
  const { theme, toggle } = useTheme()

  return (
    <nav className="sidebar" aria-label="Primary">
      <a
        className="brand"
        href="#impact"
        onClick={(e) => {
          e.preventDefault()
          onNavigate('impact')
        }}
      >
        <span className="brand-mark" aria-hidden="true">
          ◆
        </span>
        <span className="brand-name">codehound</span>
      </a>

      <div className="tag">sections</div>
      <ol className="nav-list">
        {sections.map((s, i) => {
          const Icon = s.icon
          const idx = String(i + 1).padStart(2, '0')
          return (
            <li key={s.id}>
              <a
                href={`#${s.id}`}
                className={active === s.id ? 'nav-link active' : 'nav-link'}
                onClick={(e) => {
                  e.preventDefault()
                  onNavigate(s.id)
                }}
                title={s.title}
                aria-current={active === s.id ? 'true' : undefined}
              >
                <span className="nav-idx">{idx}</span>
                <span className="nav-icon" aria-hidden="true">
                  <Icon size={13} strokeWidth={1.75} />
                </span>
                <span className="nav-label">{s.nav}</span>
              </a>
            </li>
          )
        })}
      </ol>

      <div className="nav-foot">
        <div className="foot-line">
          <strong>// static, not stochastic</strong>
          <br />
          Go PERF scanner · single binary · no service
        </div>
        <div className="theme-row">
          <button
            type="button"
            className="theme-toggle"
            onClick={toggle}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          >
            {theme === 'dark' ? (
              <Sun size={14} strokeWidth={1.75} />
            ) : (
              <Moon size={14} strokeWidth={1.75} />
            )}
          </button>
          <span>{theme === 'dark' ? 'dark' : 'light'}</span>
        </div>
      </div>
    </nav>
  )
}
