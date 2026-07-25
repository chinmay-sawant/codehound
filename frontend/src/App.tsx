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
  Sun,
  Terminal,
} from 'lucide-react'
import { useTheme } from './hooks/useTheme'
import './styles/global.css'

const githubUrl = 'https://github.com/chinmay-sawant/codehound'
const docsUrl = `${githubUrl}/blob/master/documents`

function Mark() {
  return <span className="mark" aria-hidden="true">C.</span>
}

export default function App() {
  const { theme, toggle } = useTheme()

  return (
    <div className="site-shell">
      <header className="site-header">
        <a className="wordmark" href="#top" aria-label="CodeHound home">
          <Mark />
          <span>codehound</span>
        </a>

        <nav className="site-nav" aria-label="Primary navigation">
          <a href="#why">Why CodeHound</a>
          <a href="#workflow">How it works</a>
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
          <a className="nav-github" href={githubUrl} target="_blank" rel="noreferrer">
            <GitBranch size={15} />
            <span>GitHub</span>
          </a>
        </div>
      </header>

      <main id="top">
        <section className="hero-section" aria-labelledby="hero-title">
          <div className="hero-copy">
            <p className="eyebrow"><span /> A calmer way to ship Go</p>
            <h1 id="hero-title">Know what matters<br /><em>before</em> your code ships.</h1>
            <p className="hero-intro">
              CodeHound is a fast, offline static analyzer for the performance
              traps, framework footguns, curated CWE heuristics, and bad practices ordinary linters leave behind.
            </p>
            <div className="hero-actions">
              <a className="button button-dark" href="#install">Start scanning <ArrowRight size={16} /></a>
              <a className="text-link" href="#why">See what it finds <ArrowUpRight size={15} /></a>
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
                <div className="scan-command"><span>$</span> codehound ./internal/pdf</div>
                <div className="scan-rule" />
                <div className="finding-line"><CircleAlert size={15} /><b>PERF-007</b><span>defer in a hot path</span></div>
                <div className="finding-path">internal/pdf/writer.go:184</div>
                <div className="code-sample"><span className="line-no">184</span><code><strong>defer</strong> writer.Close()</code></div>
                <div className="finding-line soft"><CircleAlert size={15} /><b>PERF-006</b><span>fmt in a loop</span></div>
                <div className="finding-path">internal/pdf/tables.go:91</div>
                <div className="scan-summary">
                  <span><b>18</b> signals found</span>
                  <span>~240ms cold scan</span>
                </div>
              </div>
            </div>
            <div className="floating-tag tag-one"><Sparkles size={14} /> predictable</div>
            <div className="floating-tag tag-two"><Check size={14} /> no cloud needed</div>
          </div>
        </section>

        <section className="signal-strip" aria-label="CodeHound capabilities">
          <p>Built for the work that deserves your attention</p>
          <div><span>PERFORMANCE</span><span>SECURITY</span><span>FRAMEWORKS</span><span>MAINTAINABILITY</span></div>
        </section>

        <section className="story-section" id="why" aria-labelledby="why-title">
          <div className="section-label"><span>01</span> Why CodeHound</div>
          <div className="story-grid">
            <h2 id="why-title">Your linter catches syntax.<br />Your agent reads everything.<br /><em>There is a better middle.</em></h2>
            <div className="story-body">
              <p>
                CodeHound turns the patterns that quietly drain a Go codebase into a focused, file-and-line checklist. It complements your usual linter instead of pretending to replace it.
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

        <section className="proof-section" aria-label="Measured CodeHound impact">
          <div className="proof-copy">
            <p className="eyebrow"><span /> Real work, measured</p>
            <h2>A small signal can move<br />a whole system.</h2>
            <p>On gopdfsuit, a focused CodeHound pass helped take throughput from about 2,000 to 2,700 operations per second on the same hardware.</p>
            <a className="text-link" href={githubUrl} target="_blank" rel="noreferrer">Explore the repository <ArrowUpRight size={15} /></a>
          </div>
          <div className="metric-panel">
            <div className="metric-main"><strong>+35%</strong><span>throughput lift</span></div>
            <div className="metric-chart" aria-hidden="true"><i /><i /><i /><i /><i /><i /><i /></div>
            <div className="metric-footer"><span>2k ops/s</span><span>2.7k ops/s</span><span>same harness · same machine</span></div>
          </div>
        </section>

        <section className="workflow-section" id="workflow" aria-labelledby="workflow-title">
          <div className="section-label"><span>02</span> The workflow</div>
          <div className="workflow-heading">
            <h2 id="workflow-title">Three steps. <em>One clear queue.</em></h2>
            <p>CodeHound does the repetitive sorting, so your review time goes to decisions—not rediscovering the codebase.</p>
          </div>
          <ol className="steps">
            <li><span className="step-number">01</span><div><Braces size={21} /><h3>Scan the project</h3><p>Run a single command against your Go module. Get the same result every time.</p></div><code>codehound .</code></li>
            <li><span className="step-number">02</span><div><FileSearch size={21} /><h3>Read a useful queue</h3><p>Findings arrive with stable rule IDs, a file, a line, and the code that needs attention.</p></div><code>PERF-007</code></li>
            <li><span className="step-number">03</span><div><Sparkles size={21} /><h3>Fix or delegate</h3><p>Work through the list yourself or hand its bounded context to the agent you already use.</p></div><code>scripts/chunks/</code></li>
          </ol>
        </section>

        <section className="install-section" id="install" aria-labelledby="install-title">
          <div>
            <p className="eyebrow"><span /> Start in under a minute</p>
            <h2 id="install-title">Give your next PR<br />a second pair of eyes.</h2>
          </div>
          <div className="install-card">
            <div className="install-card-head"><span>terminal</span><span>zsh</span></div>
            <pre><code><span>$</span> cargo install --path .{`\n`}<span>$</span> codehound .</code></pre>
            <p>Offline analysis. No account required.</p>
            <a className="button button-light" href={githubUrl} target="_blank" rel="noreferrer">Get CodeHound <ArrowUpRight size={16} /></a>
          </div>
        </section>

        <section className="docs-section" id="docs" aria-labelledby="docs-title">
          <div className="section-label"><span>03</span> Documentation</div>
          <div className="docs-head"><h2 id="docs-title">The details, without<br />the documentation maze.</h2><p>Start with the guide that meets you where you are.</p></div>
          <div className="docs-grid">
            <a href={`${docsUrl}/go-recommended-pack.md`} target="_blank" rel="noreferrer"><span>01</span><h3>Recommended pack</h3><p>The high-signal starting point for everyday Go projects.</p><ArrowUpRight size={18} /></a>
            <a href={`${docsUrl}/go-vs-staticcheck.md`} target="_blank" rel="noreferrer"><span>02</span><h3>How it compares</h3><p>Where CodeHound fits beside golangci-lint and staticcheck.</p><ArrowUpRight size={18} /></a>
            <a href={`${docsUrl}/perf-rules.md`} target="_blank" rel="noreferrer"><span>03</span><h3>Rule catalogue</h3><p>Every rule, maturity level, and the reasoning behind it.</p><ArrowUpRight size={18} /></a>
          </div>
        </section>
      </main>

      <footer className="site-footer">
        <a className="wordmark" href="#top"><Mark /><span>codehound</span></a>
        <p>Static analysis for developers who care about the details.</p>
        <a href={githubUrl} target="_blank" rel="noreferrer">github.com/chinmay-sawant/codehound <ArrowUpRight size={14} /></a>
      </footer>
    </div>
  )
}
