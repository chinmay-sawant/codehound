import { useEffect, useRef, useState } from 'react'
import { sections } from './data/sections'
import { Sidebar } from './components/Sidebar'
import { SectionView } from './components/Section'
import './styles/global.css'

const HERO_STATS = [
  { value: '~2.7k', label: 'ops/sec', sub: 'after CodeHound fixes' },
  { value: '+35%', label: 'throughput', sub: 'from ~2,000 ops/sec' },
  { value: '$0', label: 'to scan', sub: 'offline · deterministic' },
  { value: '$3.85', label: 'Grok 4.5 batch', sub: 'vs ~$19 skills ×5' },
] as const

export default function App() {
  const [active, setActive] = useState(sections[0].id)
  const mainRef = useRef<HTMLElement>(null)

  // scroll-spy: pick the section whose top has crossed the read line; pin last at bottom
  useEffect(() => {
    const root = mainRef.current
    if (!root) return

    let ticking = false
    const updateActive = () => {
      const lastId = sections[sections.length - 1].id
      const atBottom = root.scrollHeight - root.scrollTop - root.clientHeight < 4

      if (atBottom) {
        setActive(lastId)
        return
      }

      const marker = root.getBoundingClientRect().top + root.clientHeight * 0.32
      let current = sections[0].id
      for (const s of sections) {
        const el = document.getElementById(s.id)
        if (el && el.getBoundingClientRect().top <= marker) current = s.id
      }
      setActive(current)
    }

    const onScroll = () => {
      if (ticking) return
      ticking = true
      requestAnimationFrame(() => {
        ticking = false
        updateActive()
      })
    }

    updateActive()
    root.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onScroll)
    return () => {
      root.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', onScroll)
    }
  }, [])

  const handleNavigate = (id: string) => {
    const el = document.getElementById(id)
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="layout">
      <Sidebar active={active} onNavigate={handleNavigate} />
      <main ref={mainRef} className="main">
        <div className="main-inner">
          <header className="hero">
            <div className="hero-eyebrow">
              <span className="hero-tag">static analyzer</span>
              <span className="hero-dot" aria-hidden="true" />
              <span className="hero-tag-muted">deterministic · offline · agent-ready</span>
            </div>
            <h1 className="hero-title">
              Find the bugs.<br />
              <span className="hero-title-accent">Skip the token bill.</span>
            </h1>
            <p className="hero-sub">
              CodeHound is deterministic static analysis for Go — PERF, bad
              practices, and CWE without a prompt. On gopdfsuit, fixing its
              findings lifted throughput from ~2,000 to ~2,700 ops/sec. Scan
              free, then triage with Grok 4.5 for $3.85 — or DeepSeek for $0.25.
            </p>

            <div className="hero-stats" role="list">
              {HERO_STATS.map((s) => (
                <div className="hero-stat" key={s.label} role="listitem">
                  <div className="hero-stat-value">{s.value}</div>
                  <div className="hero-stat-label">{s.label}</div>
                  <div className="hero-stat-sub">{s.sub}</div>
                </div>
              ))}
            </div>

            <div className="hero-cta-row">
              <a
                className="hero-cta hero-cta-primary"
                href="#impact"
                onClick={(e) => {
                  e.preventDefault()
                  handleNavigate('impact')
                }}
              >
                See the impact
              </a>
              <a
                className="hero-cta hero-cta-ghost"
                href="#cost"
                onClick={(e) => {
                  e.preventDefault()
                  handleNavigate('cost')
                }}
              >
                Grok 4.5 cost math
              </a>
              <a
                className="hero-cta hero-cta-ghost"
                href="#how-it-works"
                onClick={(e) => {
                  e.preventDefault()
                  handleNavigate('how-it-works')
                }}
              >
                How it works
              </a>
            </div>

            <div className="hero-line">
              <span>1,042 findings · $0 scan</span>
              <span aria-hidden="true">·</span>
              <span>175+ CWE · 224 PERF · 65 BP</span>
              <span aria-hidden="true">·</span>
              <span>~15× cheaper bulk triage vs Grok 4.5</span>
            </div>
          </header>

          {sections.map((s) => (
            <SectionView key={s.id} section={s} />
          ))}

          <footer className="footer">
            <span>codehound // static analysis</span>
            <span>deterministic · offline · extendable</span>
          </footer>
        </div>
      </main>
    </div>
  )
}
