import { useCallback, useEffect, useState } from 'react'
import { sections } from './data/sections'
import { TopNav } from './components/TopNav'
import { SectionView } from './components/Section'
import {
  beginProgrammaticNav,
  currentHashId,
  isNavLocked,
  releaseNavLockIfSettled,
  scrollToSection,
  sectionIdFromHash,
  setSectionHash,
} from './lib/section-nav'
import './styles/global.css'

/** Viewport fraction where a section becomes "active" for scroll-spy. */
const SPY_MARKER = 0.28

export default function App() {
  // Empty active = hero / top of page (no section hash).
  const [active, setActive] = useState(() => currentHashId() ?? '')

  // Deep link on first paint + browser back/forward / external hash changes.
  useEffect(() => {
    const applyHash = (behavior: ScrollBehavior) => {
      const id = currentHashId()
      if (id) {
        // Lock before any scroll so spy cannot overwrite mid-animation.
        if (behavior === 'smooth') beginProgrammaticNav(id)
        setActive(id)
        // Wait a frame so layout (fonts, sticky nav) is ready.
        requestAnimationFrame(() => scrollToSection(id, behavior))
      } else {
        if (behavior === 'smooth') beginProgrammaticNav(null)
        setActive('')
        // Only jump to top when hash was explicitly cleared (e.g. brand link),
        // not on first paint with an empty URL.
        if (behavior === 'smooth') {
          requestAnimationFrame(() => scrollToSection(null, behavior))
        }
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
  // While the hero is still primary, keep hash empty (`/` or `/codehound/`).
  useEffect(() => {
    let ticking = false
    const updateActive = () => {
      // While a click/hash nav is scrolling, never rewrite the hash. Only unlock
      // once the target is actually in place (not on a premature scrollend).
      if (isNavLocked()) {
        releaseNavLockIfSettled()
        if (isNavLocked()) return
      }

      const first = document.getElementById(sections[0].id)
      const markerY = window.innerHeight * SPY_MARKER

      // Hero zone: first section has not reached the spy marker yet.
      if (first && first.getBoundingClientRect().top > markerY) {
        setActive((prev) => (prev === '' ? prev : ''))
        setSectionHash(null, 'replace')
        return
      }

      const lastId = sections[sections.length - 1].id
      const doc = document.documentElement
      const atBottom =
        doc.scrollHeight - window.scrollY - window.innerHeight < 48

      let current = sections[0].id
      if (atBottom) {
        current = lastId
      } else {
        for (const s of sections) {
          const el = document.getElementById(s.id)
          if (el && el.getBoundingClientRect().top <= markerY) current = s.id
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
    // Lock *before* the hash write so a pending spy frame cannot flip it back.
    beginProgrammaticNav(target)
    setSectionHash(target, 'push')
    setActive(target ?? '')
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
                Rust-built static analyzer for Go. Catches PERF hot-path
                regressions, framework footguns (Gin / Echo / GORM / sqlx),
                bad practices, and curated CWE heuristics — the gaps
                golangci-lint and staticcheck often leave. Offline, free to
                scan, same answer every run.
              </p>

              <div className="hero-cta-row">
                <a
                  className="hero-cta hero-cta-primary"
                  href="#install"
                  onClick={(e) => {
                    e.preventDefault()
                    handleNavigate('install')
                  }}
                >
                  install
                </a>
                <a
                  className="hero-cta hero-cta-ghost"
                  href="#impact"
                  onClick={(e) => {
                    e.preventDefault()
                    handleNavigate('impact')
                  }}
                >
                  impact
                </a>
                <a
                  className="hero-cta hero-cta-ghost"
                  href="#cost"
                  onClick={(e) => {
                    e.preventDefault()
                    handleNavigate('cost')
                  }}
                >
                  cost
                </a>
              </div>

              <div className="hero-line">
                <span>224 PERF · 175+ CWE · 65 BP</span>
                <span aria-hidden="true">·</span>
                <span>single binary</span>
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

              <div className="hero-meta-grid" aria-label="Key numbers">
                <div className="hero-meta-cell">
                  <span className="hero-meta-k">gopdfsuit</span>
                  <span className="hero-meta-v">~2k → 2.7k ops/sec</span>
                </div>
                <div className="hero-meta-cell">
                  <span className="hero-meta-k">lift</span>
                  <span className="hero-meta-v">+35% throughput</span>
                </div>
                <div className="hero-meta-cell">
                  <span className="hero-meta-k">scan</span>
                  <span className="hero-meta-v">$0 · offline</span>
                </div>
                <div className="hero-meta-cell">
                  <span className="hero-meta-k">triage</span>
                  <span className="hero-meta-v">from $0.25</span>
                </div>
              </div>
            </div>
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
