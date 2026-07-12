import { useCallback, useEffect, useState } from 'react'
import { sections } from './data/sections'
import { TopNav } from './components/TopNav'
import { SectionView } from './components/Section'
import {
  currentHashId,
  scrollToSection,
  sectionIdFromHash,
  setSectionHash,
} from './lib/section-nav'
import './styles/global.css'

const HERO_STATS = [
  { value: '~2.7k', label: 'ops/sec', sub: 'after CodeHound fixes' },
  { value: '+35%', label: 'throughput', sub: 'from ~2,000 ops/sec' },
  { value: '$0', label: 'to scan', sub: 'offline · deterministic' },
  { value: '$3.85', label: 'Grok 4.5 batch', sub: 'vs ~$19 skills ×5' },
] as const

export default function App() {
  const [active, setActive] = useState(
    () => currentHashId() ?? sections[0].id,
  )

  // Deep link on first paint + browser back/forward / external hash changes.
  useEffect(() => {
    const applyHash = (behavior: ScrollBehavior) => {
      const id = currentHashId()
      if (id) {
        setActive(id)
        // Wait a frame so layout (fonts, sticky nav) is ready.
        requestAnimationFrame(() => scrollToSection(id, behavior))
      } else {
        setActive(sections[0].id)
      }
    }

    applyHash('auto')

    const onHashChange = () => applyHash('smooth')
    const onPopState = () => applyHash('smooth')
    window.addEventListener('hashchange', onHashChange)
    window.addEventListener('popstate', onPopState)
    return () => {
      window.removeEventListener('hashchange', onHashChange)
      window.removeEventListener('popstate', onPopState)
    }
  }, [])

  // Scroll-spy: highlight nav + keep URL hash in sync for copy/share.
  useEffect(() => {
    let ticking = false
    const updateActive = () => {
      const lastId = sections[sections.length - 1].id
      const doc = document.documentElement
      const atBottom =
        doc.scrollHeight - window.scrollY - window.innerHeight < 48

      let current = sections[0].id
      if (atBottom) {
        current = lastId
      } else {
        const marker = window.innerHeight * 0.28
        for (const s of sections) {
          const el = document.getElementById(s.id)
          if (el && el.getBoundingClientRect().top <= marker) current = s.id
        }
      }

      setActive((prev) => (prev === current ? prev : current))
      // replaceState so shared URLs match the visible section without history spam.
      setSectionHash(current, 'replace')
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
    window.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onScroll)
    return () => {
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', onScroll)
    }
  }, [])

  const handleNavigate = useCallback((id: string) => {
    // Brand link uses `top`; everything else is a section id from data/sections.
    const target = id === 'top' ? null : sectionIdFromHash(`#${id}`)
    if (id !== 'top' && !target) return
    setSectionHash(target, 'push')
    setActive(target ?? sections[0].id)
    scrollToSection(target, 'smooth')
  }, [])

  return (
    <div className="layout" id="top">
      <TopNav active={active} onNavigate={handleNavigate} />

      <main className="main">
        <header className="hero">
          <div className="hero-grid">
            <div className="hero-copy">
              <div className="hero-eyebrow">
                <span className="hero-tag">static analyzer</span>
                <span className="hero-dot" aria-hidden="true" />
                <span className="hero-tag-muted">go · offline · deterministic</span>
              </div>
              <h1 className="hero-title">
                Find the bugs.
                <br />
                <span className="hero-title-accent">Skip the token bill.</span>
              </h1>
              <p className="hero-sub">
                CodeHound is a Rust-built static analyzer for Go. It finds
                performance hot-path regressions, framework footguns
                (Gin / Echo / GORM / sqlx), bad practices, and curated CWE
                heuristics — the stuff golangci-lint and staticcheck often miss.
                On gopdfsuit, fixing its findings lifted throughput from ~2,000
                to ~2,700 ops/sec. Scan free. Triage with Grok 4.5 for $3.85, or
                DeepSeek for $0.25.
              </p>

              <div className="hero-cta-row">
                <a
                  className="hero-cta hero-cta-primary"
                  href="#impact"
                  onClick={(e) => {
                    e.preventDefault()
                    handleNavigate('impact')
                  }}
                >
                  see the impact
                </a>
                <a
                  className="hero-cta hero-cta-ghost"
                  href="#cost"
                  onClick={(e) => {
                    e.preventDefault()
                    handleNavigate('cost')
                  }}
                >
                  cost math
                </a>
                <a
                  className="hero-cta hero-cta-ghost"
                  href="#how-it-works"
                  onClick={(e) => {
                    e.preventDefault()
                    handleNavigate('how-it-works')
                  }}
                >
                  how it works
                </a>
                <a
                  className="hero-cta hero-cta-ghost"
                  href="#install"
                  onClick={(e) => {
                    e.preventDefault()
                    handleNavigate('install')
                  }}
                >
                  install
                </a>
              </div>

              <div className="hero-line">
                <span>224 PERF · 175+ CWE · 65 BP</span>
                <span aria-hidden="true">·</span>
                <span>single binary · no service</span>
                <span aria-hidden="true">·</span>
                <span>complements golangci-lint</span>
              </div>
            </div>

            <div className="hero-side">
              <div className="hero-terminal" aria-label="Install and scan">
                <div className="hero-terminal-bar">
                  <div className="hero-terminal-dots" aria-hidden="true">
                    <span />
                    <span />
                    <span />
                  </div>
                  <span>shell · install + scan</span>
                </div>
                <div className="hero-terminal-body">
                  <div>
                    <span className="prompt">$ </span>
                    <span className="cmd">cargo install --path .</span>
                  </div>
                  <div>
                    <span className="prompt">$ </span>
                    <span className="cmd">codehound .</span>
                  </div>
                  <span className="out">
                    {`// recommended pack · S-tier PERF + taint-core
// 1,042 findings → scripts/findings + chunks
// $0 API · same answer every run`}
                  </span>
                </div>
              </div>

              <div className="hero-meta-grid" aria-hidden="true">
                <div className="hero-meta-cell">
                  <span className="hero-meta-k">lang</span>
                  <span className="hero-meta-v">go-first</span>
                </div>
                <div className="hero-meta-cell">
                  <span className="hero-meta-k">mode</span>
                  <span className="hero-meta-v">offline</span>
                </div>
                <div className="hero-meta-cell">
                  <span className="hero-meta-k">output</span>
                  <span className="hero-meta-v">text · json · sarif</span>
                </div>
                <div className="hero-meta-cell">
                  <span className="hero-meta-k">agent</span>
                  <span className="hero-meta-v">bounded triage</span>
                </div>
              </div>
            </div>
          </div>

          <div className="hero-stats" role="list">
            {HERO_STATS.map((s) => (
              <div className="hero-stat" key={s.label} role="listitem">
                <div className="hero-stat-value">{s.value}</div>
                <div className="hero-stat-label">{s.label}</div>
                <div className="hero-stat-sub">{s.sub}</div>
              </div>
            ))}
          </div>
        </header>

        <div className="sections">
          {sections.map((s, i) => (
            <SectionView key={s.id} section={s} index={i + 1} />
          ))}
        </div>

        <footer className="footer">
          <div className="footer-inner">
            <span>codehound // static analysis</span>
            <a
              href="https://github.com/chinmay-sawant/codehound"
              target="_blank"
              rel="noreferrer"
            >
              github.com/chinmay-sawant/codehound
            </a>
            <span className="footer-credit">
              made with{' '}
              <span className="footer-heart" aria-label="love">
                ❤️
              </span>{' '}
              by chinmay sawant
            </span>
          </div>
        </footer>
      </main>
    </div>
  )
}
