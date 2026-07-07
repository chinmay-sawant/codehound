import { useEffect, useRef, useState } from 'react'
import { sections } from './data/sections'
import { Sidebar } from './components/Sidebar'
import { SectionView } from './components/Section'
import './styles/global.css'

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
      // ponytail: pin last section only at true bottom. A loose threshold (120px)
      // fires while the second-to-last (e.g. cost) should still be active, because
      // the content below it is short - skipping it in the sidebar.
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
            <div className="hero-tag">static analyzer</div>
            <h1 className="hero-title">codehound</h1>
            <p className="hero-sub">
              Deterministic static analysis for Go — PERF, bad practices, and CWE
              without a prompt. Export 1,042 findings to disk, triage with
              DeepSeek for $0.25, or let Opus spend $14.75 doing it the hard way.
            </p>
            <div className="hero-line">
              <span>1,042 findings · $0 scan</span>
              <span>·</span>
              <span>$0.25 LLM triage</span>
              <span>·</span>
              <span>59× cheaper than Opus</span>
              <span>·</span>
              <span>175+ CWE · 224 PERF · 65 BP</span>
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