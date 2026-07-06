import { useEffect, useRef, useState } from 'react'
import { sections } from './data/sections'
import { Sidebar } from './components/Sidebar'
import { SectionView } from './components/Section'
import './styles/global.css'

export default function App() {
  const [active, setActive] = useState(sections[0].id)
  const mainRef = useRef<HTMLElement>(null)

  // scroll-spy: highlight the nav entry for the section in view
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)
        if (visible[0]) setActive(visible[0].target.id)
      },
      { root: mainRef.current, threshold: [0.15, 0.5, 1], rootMargin: '-10% 0px -60% 0px' },
    )
    sections.forEach((s) => {
      const el = document.getElementById(s.id)
      if (el) observer.observe(el)
    })
    return () => observer.disconnect()
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
            <div className="hero-tag">static analyzer // codename: codehound</div>
            <h1 className="hero-title">slopguard<span className="dot">_</span></h1>
            <p className="hero-sub">
              The static reviewer for the cheap-model era. Deterministic when the
              smart models go away, and cheaper than the smart models ever were.
            </p>
            <div className="hero-line">
              <span>226 findings → 218 fixed</span>
              <span>·</span>
              <span>+13% table throughput</span>
              <span>·</span>
              <span>175+ CWE rules</span>
              <span>·</span>
              <span>224 PERF detectors</span>
            </div>
          </header>
          {sections.map((s) => (
            <SectionView key={s.id} section={s} />
          ))}
          <footer className="footer">
            <span>slopguard // static analysis</span>
            <span>codename: codehound</span>
          </footer>
        </div>
      </main>
    </div>
  )
}