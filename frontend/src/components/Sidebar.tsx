import { sections } from '../data/sections'

type SidebarProps = {
  active: string
  onNavigate: (id: string) => void
}

export function Sidebar({ active, onNavigate }: SidebarProps) {
  return (
    <nav className="sidebar">
      <a className="brand" href="#why" onClick={(e) => { e.preventDefault(); onNavigate('why') }}>
        <span className="brand-mark">$</span>
        <span className="brand-name">slopguard</span>
      </a>
      <div className="tag">sections</div>
      <ol className="nav-list">
        {sections.map((s, i) => (
          <li key={s.id}>
            <a
              href={`#${s.id}`}
              className={active === s.id ? 'nav-link active' : 'nav-link'}
              onClick={(e) => { e.preventDefault(); onNavigate(s.id) }}
            >
              <span className="nav-idx">{String(i + 1).padStart(2, '0')}</span>
              <span className="nav-label">{s.nav}</span>
            </a>
          </li>
        ))}
      </ol>
      <div className="nav-foot">
        <strong>// static, not stochastic</strong><br />
        rust · single binary · no service
      </div>
    </nav>
  )
}