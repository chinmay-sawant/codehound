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
import { useLayoutEffect, useState } from 'react'
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
      <article className="project-story" aria-labelledby="story-title">
        <header className="project-story-header">
          <span className="story-kicker">A project story</span>
          <h1 id="story-title">From a long feedback loop<br />to a better <em>starting point.</em></h1>
          <p>CodeHound is the performance linter and static-analysis tool I wanted while building a Go PDF engine: a repeatable way to catch known costs before the profiling loop starts again.</p>
        </header>

        <div className="story-chapters">
          <section className="story-chapter"><span>01</span><div><p className="chapter-label">The problem</p><h2>Performance work kept starting too late.</h2><p>After six months building and working on GoPDFSuit, a native template-based PDF engine, I spent another one to two months reviewing, validating, profiling, and iterating. Existing linters helped, but they did not turn the recurring performance issues into an actionable queue.</p></div></section>
          <section className="story-chapter"><span>02</span><div><p className="chapter-label">The idea</p><h2>Make the repeatable parts deterministic.</h2><p>The goal is not premature optimization. Start with functionality and unit tests, then use rules to surface predictable traps before pprof, caching, and workload-specific tuning. An agent can remediate a bounded finding list; the developer still reviews every change and owns the architecture.</p></div></section>
          <section className="story-chapter"><span>03</span><div><p className="chapter-label">Why rules still matter</p><h2>Subagents are powerful. Known checks should not require an open-ended review.</h2><p>I used an agent-driven feedback loop on GoPDFSuit to reach nearly 5,000 ops/s, and that kind of review can uncover system-level approaches beyond straightforward code changes. But repeatedly asking an agent to rediscover the same repository costs time and model budget. When we already know what to detect and how to frame a safe fix, a deterministic rule can find it locally; a lower-cost model such as DeepSeek V4 Flash can then triage the bounded findings instead of re-reading the whole codebase.</p></div></section>
          <section className="story-chapter"><span>04</span><div><p className="chapter-label">The build</p><h2>Use real lessons, not generic AI guesses.</h2><p>An earlier static-analysis attempt taught me to begin with real problems. I converted GoPDFSuit optimization checklists—complete with code examples and rationale—into rules with Codex and Grok, instead of targeting arbitrary AI-generated code patterns.</p></div></section>
          <section className="story-chapter"><span>05</span><div><p className="chapter-label">The toolchain</p><h2>Rust for the analyzer, Go for the target.</h2><p>I chose Rust primarily for Cargo, compiler feedback, and the development experience. AI made a one-person build faster, but it also made strong guardrails essential: architecture, linting, benchmarks, and review. The scanner itself benefited from the same discipline through cheaper walks and earlier short-circuits.</p></div></section>
          <section className="story-chapter"><span>06</span><div><p className="chapter-label">The proof</p><h2>The benchmark moved, not just the conversation.</h2><p>On a PDF/A-4 and PDF/UA-2 capable Go engine built from scratch, standard Go linters moved throughput from 1,140.59 to 1,171.68 ops/s. After the CodeHound remediation pass, it reached 2,349.29 ops/s.</p></div></section>
          <section className="story-chapter"><span>07</span><div><p className="chapter-label">What is next</p><h2>Make the signal sharper, then broaden carefully.</h2><p>Next up: lower the roughly 5% domain-specific false-positive rate, validate high-value Go framework coverage, and carefully expand the approach toward Python.</p></div></section>
          <section className="story-chapter"><span>08</span><div><p className="chapter-label">Use with judgment</p><h2>Findings are a starting point, not a performance guarantee.</h2><p>CodeHound can surface application-level performance opportunities, bad practices, and CWE heuristics. You still need to understand the findings, test each remediation, and profile the system bottlenecks that remain. Some workloads need caching, architectural changes, or a different approach entirely.</p></div></section>
        </div>

        <section className="story-evidence" aria-label="Benchmark comparison">
          <div><span className="story-kicker">Measured result</span><h2>No vibes. A reproducible comparison.</h2><p>The numbers are a project benchmark, not a promise for every workload. The public repositories and pull requests below provide the evidence trail.</p></div>
          <dl>
            <div><dt>Base</dt><dd>1,140.59 ops/s</dd></div>
            <div><dt>Go linters</dt><dd>1,171.68 ops/s <small>+2.7%</small></dd></div>
            <div><dt>CodeHound</dt><dd>2,349.29 ops/s <small>+106.0%</small></dd></div>
          </dl>
        </section>

        <footer className="story-sources">
          <span>Sources</span>
          <a href={githubUrl} target="_blank" rel="noreferrer">CodeHound <ArrowUpRight size={14} /></a>
          <a href={gopdfSuitUrl} target="_blank" rel="noreferrer">GoPDFSuit <ArrowUpRight size={14} /></a>
          <a href={gocorePdfEngineUrl} target="_blank" rel="noreferrer">gocorepdfengine <ArrowUpRight size={14} /></a>
          {benchmarkPulls.map(([label, url]) => <a key={url} href={url} target="_blank" rel="noreferrer">{label} <ArrowUpRight size={14} /></a>)}
        </footer>
      </article>
    </main>
  )
}

export default function App() {
  const { theme, toggle } = useTheme()
  const { stars } = useGithubStars()
  const [showStory, setShowStory] = useState(() => window.location.hash === '#story')

  useLayoutEffect(() => {
    const syncView = () => {
      const story = window.location.hash === '#story'
      setShowStory(story)
      if (!story && window.location.hash) {
        window.requestAnimationFrame(() => window.requestAnimationFrame(() => {
          const target = document.querySelector(window.location.hash)
          if (target) window.scrollTo(0, target.getBoundingClientRect().top + window.scrollY)
        }))
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
                <div className="scan-command"><span>$</span><code>./codehound . --profile all --export-chunks --no-cache</code></div>
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
          <section className="docs-quickstart" aria-labelledby="quickstart-title">
            <div><span className="story-kicker">Quick start</span><h3 id="quickstart-title">Install once. Scan once.<br /><em>Start delegating.</em></h3></div>
            <ol>
              <li><span>01</span><div><h4>Get CodeHound</h4><p>Download a release from GitHub, or install from a source checkout with Cargo.</p><div className="quickstart-options"><a href={`${githubUrl}/releases`} target="_blank" rel="noreferrer">Download from GitHub <ArrowUpRight size={14} /></a><code>cargo install --path .</code></div></div></li>
              <li><span>02</span><div><h4>Scan and delegate</h4><p>Export the full finding set, then hand the generated chunks to the agent you already use.</p><code className="quickstart-command">./codehound . --profile all --export-chunks --no-cache</code></div></li>
            </ol>
          </section>
          <div className="docs-grid">
            {documentation.map(([title, description, path]) => (
              <a key={path} href={`${docsUrl}/${path}`} target="_blank" rel="noreferrer">
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
