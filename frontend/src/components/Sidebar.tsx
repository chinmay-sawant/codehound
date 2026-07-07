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
    <nav className="sidebar">
      <a className="brand" href="#how-it-works" onClick={(e) => { e.preventDefault(); onNavigate('how-it-works') }}>
        <span className="brand-mark">$</span>
        <span className="brand-name">codehound</span>
      </a>
      <div className="tag">sections</div>
      <ol className="nav-list">
        {sections.map((s) => {
          const Icon = s.icon
          return (
            <li key={s.id}>
              <a
                href={`#${s.id}`}
                className={active === s.id ? 'nav-link active' : 'nav-link'}
                onClick={(e) => { e.preventDefault(); onNavigate(s.id) }}
                title={s.title}
              >
                <span className="nav-icon"><Icon size={13} strokeWidth={1.75} /></span>
                <span className="nav-label">{s.nav}</span>
              </a>
            </li>
          )
        })}
      </ol>
      <div className="nav-foot">
        <div className="foot-line">
          <strong>// static, not stochastic</strong><br />
          rust · single binary · no service
        </div>
        <div className="theme-row">
          <button
            className="theme-toggle"
            onClick={toggle}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          >
            {theme === 'dark' ? <Sun size={14} strokeWidth={1.75} /> : <Moon size={14} strokeWidth={1.75} />}
          </button>
          <span>{theme === 'dark' ? 'dark' : 'light'}</span>
        </div>
      </div>
    </nav>
  )
}