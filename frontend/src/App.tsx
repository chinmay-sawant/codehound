import {
  ArrowRight,
  ArrowUpRight,
  Braces,
  Check,
  ChevronRight,
  CircleAlert,
  FileSearch,
  GitBranch,
  Moon,
  ScanSearch,
  Sparkles,
  Star,
  Sun,
  Terminal,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { formatStarCount, useGithubStars } from './hooks/useGithubStars'
import { useTheme } from './hooks/useTheme'
import './styles/global.css'

const githubUrl = 'https://github.com/chinmay-sawant/codehound'
const docsUrl = `${githubUrl}/blob/master/documents`
const gocorePdfEngineUrl = 'https://github.com/chinmay-sawant/gocorepdfengine'
const gopdfSuitUrl = 'https://github.com/chinmay-sawant/gopdfsuit'
const benchmarkPulls = [
  ['Base build', 'https://github.com/chinmay-sawant/gocorepdfengine/pull/5'],
  ['Go linters only', 'https://github.com/chinmay-sawant/gocorepdfengine/pull/6'],
  ['After CodeHound', 'https://github.com/chinmay-sawant/gocorepdfengine/pull/4'],
] as const
const documentation = [
  ['Recommended pack', 'The high-signal starting point for everyday Go projects.', 'go-recommended-pack.md'],
  ['How it compares', 'Where CodeHound fits beside golangci-lint and staticcheck.', 'go-vs-staticcheck.md'],
  ['Rule catalogue', 'Every performance rule, maturity level, and rationale.', 'perf-rules.md'],
  ['Configuration', 'Profiles, baselines, ignores, and codehound.toml.', 'configuration.md'],
  ['Output formats', 'Text, JSON, and SARIF output for people and CI.', 'output-formats.md'],
  ['Taint tracking', 'The experimental Go data-flow model and its boundaries.', 'taint.md'],
  ['Bad practices', 'The advisory Go BP catalogue and its profile policy.', 'bad-practices.md'],
  ['Incremental cache', 'How repeat scans stay quick without changing findings.', 'incremental-cache.md'],
  ['Add a language', 'The plugin path for adding a real language implementation.', 'adding-a-language.md'],
  ['Architecture & performance', 'The engine choices that preserve fast, predictable scans.', 'architecture-performance.md'],
  ['Performance tiers', 'How performance rules are scoped and prioritized.', 'perf-tiers.md'],
  ['Build a detector', 'A practical guide to extending the performance catalogue.', 'perf-detector-development.md'],
] as const

function Mark() {
  return <span className="mark" aria-hidden="true">C.</span>
}

function StoryView() {
  return (
    <main id="top" className="story-view">
      <section className="story-section story-detail story-page" aria-labelledby="story-title">
        <header className="story-header">
          <div>
            <span className="story-kicker">Our story</span>
            <h1 id="story-title">Turn a long performance<br />loop into a better<br /><em>starting point.</em></h1>
          </div>
          <p>CodeHound came from building GoPDFSuit, then asking how much of that painful optimization loop could become a repeatable check for the next Go project.</p>
        </header>
        <ol className="story-points">
          <li><span>01</span><div><h2>Vision</h2><p>Help Go projects find predictable performance issues early, so the first serious performance pass starts from a stronger baseline.</p></div></li>
          <li><span>02</span><div><h2>Origin</h2><p>Six months on GoPDFSuit and another one to two months of optimization exposed the same costly loop: review, validate, profile, repeat.</p></div></li>
          <li><span>03</span><div><h2>Approach</h2><p>Translate proven performance lessons and checklist items into deterministic rules with file, line, and context—not an open-ended agent prompt.</p></div></li>
          <li><span>04</span><div><h2>Guardrail</h2><p>This is not a case for premature optimization. Add or confirm functionality and unit tests first, then validate every remediation and benchmark.</p></div></li>
          <li><span>05</span><div><h2>Why Rust</h2><p>Rust gives the analyzer a strong Cargo-based development loop and predictable runtime model, while Go remains the language it serves.</p></div></li>
          <li><span>06</span><div><h2>Proof and next</h2><p>The comparison engine moved from 1,140.59 to 2,349.29 ops/s. Next: lower roughly 5% domain-specific false positives, validate high-value Go framework coverage, and carefully expand toward Python.</p></div></li>
        </ol>
        <a className="underlined-link" href={gopdfSuitUrl} target="_blank" rel="noreferrer">Read the GoPDFSuit project <ArrowUpRight size={16} /></a>
      </section>

      <section className="proof-section is-visible" aria-label="Measured gocorepdfengine impact">
        <div className="proof-copy">
          <h2>The results are<br /><em>measurable.</em></h2>
          <p>On a PDF/A-4 and PDF/UA-2 capable Go PDF engine built from scratch, standard Go linters moved throughput from 1,140.59 to 1,171.68 ops/s. The CodeHound remediation pass reached 2,349.29 ops/s.</p>
          <a className="text-link" href={gocorePdfEngineUrl} target="_blank" rel="noreferrer">Explore gocorepdfengine <ArrowUpRight size={15} /></a>
        </div>
        <div className="metric-panel">
          <div className="metric-main"><strong>+106%</strong><span>throughput lift from base</span></div>
          <div className="metric-chart" aria-hidden="true"><i /><i /><i /><i /><i /><i /><i /></div>
          <div className="metric-footer"><span>1,140.59 ops/s</span><span>2,349.29 ops/s</span><span>same project benchmark</span></div>
        </div>
      </section>

      <section className="workflow-section story-references" aria-labelledby="references-title">
        <div className="workflow-heading">
          <h2 id="references-title">Reproduce the<br /><em>comparison.</em></h2>
          <p>The project, source engine, and benchmark pull requests are public. The numbers above are a benchmark result, not a promise for every workload.</p>
        </div>
        <ol className="steps">
          <li><span className="step-number">01</span><div><Braces size={21} /><h3>CodeHound</h3><p>The performance linter and static-analysis tool.</p></div><a className="text-link" href={githubUrl} target="_blank" rel="noreferrer">Repository <ArrowUpRight size={15} /></a></li>
          <li><span className="step-number">02</span><div><FileSearch size={21} /><h3>gocorepdfengine</h3><p>The PDF/A-4 and PDF/UA-2 engine used for the comparison.</p></div><a className="text-link" href={gocorePdfEngineUrl} target="_blank" rel="noreferrer">Repository <ArrowUpRight size={15} /></a></li>
          <li><span className="step-number">03</span><div><GitBranch size={21} /><h3>Benchmark pull requests</h3><p>{benchmarkPulls.map(([label, url], index) => <a key={url} href={url} target="_blank" rel="noreferrer">{label}{index < benchmarkPulls.length - 1 ? ' · ' : ''}</a>)}</p></div><a className="text-link" href={gopdfSuitUrl} target="_blank" rel="noreferrer">GoPDFSuit <ArrowUpRight size={15} /></a></li>
        </ol>
      </section>
    </main>
  )
}

export default function App() {
  const { theme, toggle } = useTheme()
  const { stars } = useGithubStars()
  const [showStory, setShowStory] = useState(() => window.location.hash === '#story')

  useEffect(() => {
    const syncView = () => {
      const story = window.location.hash === '#story'
      setShowStory(story)
      if (!story && window.location.hash) {
        window.requestAnimationFrame(() => document.querySelector(window.location.hash)?.scrollIntoView())
      }
    }

    window.addEventListener('hashchange', syncView)
    syncView()
    return () => window.removeEventListener('hashchange', syncView)
  }, [])

  return (
    <div className="site-shell">
      <header className="site-header">
        <a className="wordmark" href="#top" aria-label="CodeHound home">
          <Mark />
          <span>codehound</span>
        </a>

        <nav className="site-nav" aria-label="Primary navigation">
          <a href="#top">Home</a>
          <a href="#story" aria-current={showStory ? 'page' : undefined}>The story</a>
          <a href="#docs">Documentation</a>
        </nav>

        <div className="header-actions">
          <button
            className="icon-button"
            type="button"
            onClick={toggle}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          >
            {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          </button>
          <a
            className="nav-github"
            href={githubUrl}
            target="_blank"
            rel="noreferrer"
            aria-label={stars !== null ? `View CodeHound on GitHub (${stars.toLocaleString()} stars)` : 'View CodeHound on GitHub'}
          >
            <Star size={15} aria-hidden="true" />
            <span>GitHub</span>
            {stars !== null && <strong className="nav-stars">{formatStarCount(stars)}</strong>}
          </a>
        </div>
      </header>

      {showStory ? <StoryView /> : <main id="top">
        <section className="hero-section" aria-labelledby="hero-title">
          <div className="hero-copy">
            <h1 id="hero-title">Push Go performance<br /><em>earlier.</em></h1>
            <p className="hero-intro">
              CodeHound is a performance linter and static-analysis tool that complements golangci-lint. It turns repeat profiling lessons into deterministic findings before the expensive optimization loop begins.
            </p>
            <div className="hero-actions">
              <a className="button button-dark" href="#install">Start scanning <ArrowRight size={16} /></a>
              <a className="text-link" href="#story">See the story <ArrowUpRight size={15} /></a>
            </div>
            <div className="hero-note">
              <span>Built in Rust</span><i /> <span>Go-first</span><i /> <span>Deterministic</span>
            </div>
          </div>

          <div className="hero-visual" aria-label="Example CodeHound scan results">
            <div className="visual-orbit orbit-one" />
            <div className="visual-orbit orbit-two" />
            <div className="scan-window">
              <div className="scan-topbar">
                <span className="window-label"><ScanSearch size={15} /> codehound / scan</span>
                <span className="live-status"><b /> ANALYSIS COMPLETE</span>
              </div>
              <div className="scan-content">
                <div className="scan-command"><span>$</span> ./codehound .  --profile all --export-chunks --no-cache</div>
                <div className="scan-rule" />
                <div className="finding-line"><CircleAlert size={15} /><b>PERF-007</b><span>defer in a hot path</span></div>
                <div className="finding-path">internal/pdf/writer.go:184</div>
                <div className="code-sample"><span className="line-no">184</span><code><strong>defer</strong> writer.Close()</code></div>
                <div className="finding-line soft"><CircleAlert size={15} /><b>PERF-006</b><span>fmt in a loop</span></div>
                <div className="finding-path">internal/pdf/tables.go:91</div>
                <div className="scan-summary">
                  <span><b>218</b> perf fixes guided</span>
                  <span>deterministic output</span>
                </div>
              </div>
            </div>
            <div className="floating-tag tag-one"><Sparkles size={14} /> predictable</div>
            <div className="floating-tag tag-two"><Check size={14} /> no cloud needed</div>
          </div>
        </section>

        <section className="signal-strip" aria-label="CodeHound capabilities">
          <p>Built from a real Go performance loop</p>
          <div><span>GO-FIRST</span><span>PERFORMANCE</span><span>OFFLINE</span><span>AGENT-READY</span></div>
        </section>

        <section className="story-section" id="why" aria-labelledby="why-title">
          <div className="story-grid">
            <h2 id="why-title">Your linter catches syntax.<br />Your agent reads everything.<br /><em>There is a better middle.</em></h2>
            <div className="story-body">
              <p>
                CodeHound turns patterns that quietly drain a Go codebase into a focused, file-and-line checklist. It complements your usual linter instead of pretending to replace it.
              </p>
              <a className="underlined-link" href="#workflow">See the workflow <ChevronRight size={16} /></a>
            </div>
          </div>
          <div className="benefit-grid">
            <article>
              <span className="benefit-icon"><Terminal size={20} /></span>
              <h3>Run it anywhere</h3>
              <p>One local binary. No token meter, uploaded repository, or surprise API bill.</p>
            </article>
            <article>
              <span className="benefit-icon"><FileSearch size={20} /></span>
              <h3>Find the expensive stuff</h3>
              <p>Hot-path allocations, regex churn, loop formatting, and framework mistakes with real impact.</p>
            </article>
            <article>
              <span className="benefit-icon"><GitBranch size={20} /></span>
              <h3>Keep review focused</h3>
              <p>Export bounded context for an agent when you want it. You decide what gets fixed.</p>
            </article>
          </div>
        </section>

        <section className="workflow-section" id="workflow" aria-labelledby="workflow-title">
          <div className="workflow-heading">
            <h2 id="workflow-title">Tests first. <em>Then a clear queue.</em></h2>
            <p>AI makes implementation faster, not automatically better. Use static rules to find the predictable work, and keep tests and human review as the guardrails.</p>
          </div>
          <ol className="steps">
            <li><span className="step-number">01</span><div><Braces size={21} /><h3>Protect behavior</h3><p>Add or confirm functionality and unit tests before changing code. Performance work must preserve the contract.</p></div><code>go test ./...</code></li>
            <li><span className="step-number">02</span><div><FileSearch size={21} /><h3>Scan the project</h3><p>Run one deterministic pass against your Go module. Findings include stable rule IDs, files, lines, and useful context.</p></div><code>codehound .</code></li>
            <li><span className="step-number">03</span><div><Sparkles size={21} /><h3>Fix, validate, repeat</h3><p>Delegate bounded findings if useful, then review every change and rerun the tests and benchmark that matter.</p></div><code>scripts/chunks/</code></li>
          </ol>
        </section>

        <section className="install-section" id="install" aria-labelledby="install-title">
          <div>
            <h2 id="install-title">Build the test.<br />Then push the ceiling.</h2>
          </div>
          <div className="install-card">
            <div className="install-card-head"><span>terminal</span><span>zsh</span></div>
            <pre><code><span>$</span> cargo install --path .{`\n`}<span>$</span> codehound .</code></pre>
            <p>Offline analysis. No account required. Use it beside the Go linters you already trust.</p>
            <a className="button button-light" href={githubUrl} target="_blank" rel="noreferrer">Get CodeHound <ArrowUpRight size={16} /></a>
          </div>
        </section>

        <section className="docs-section" id="docs" aria-labelledby="docs-title">
          <div className="docs-head"><h2 id="docs-title">The details, without<br />the documentation maze.</h2><div className="docs-intro"><p>The original documentation remains available in full. Start with the guide that meets you where you are.</p><a className="underlined-link" href={`${githubUrl}/tree/master/documents`} target="_blank" rel="noreferrer">View all documentation <ArrowUpRight size={15} /></a></div></div>
          <div className="docs-grid">
            {documentation.map(([title, description, path], index) => (
              <a key={path} href={`${docsUrl}/${path}`} target="_blank" rel="noreferrer">
                <span>{String(index + 1).padStart(2, '0')}</span>
                <h3>{title}</h3>
                <p>{description}</p>
                <ArrowUpRight size={18} />
              </a>
            ))}
          </div>
        </section>
      </main>}

      <footer className="site-footer">
        <a className="wordmark" href="#top"><Mark /><span>codehound</span></a>
        <p>Static analysis for developers who care about the details.</p>
        <a href={githubUrl} target="_blank" rel="noreferrer">github.com/chinmay-sawant/codehound <ArrowUpRight size={14} /></a>
      </footer>
    </div>
  )
}
