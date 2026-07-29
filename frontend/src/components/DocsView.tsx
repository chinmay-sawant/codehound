import { ArrowLeft, ArrowUpRight, ChevronRight, Terminal } from 'lucide-react'
import type { ReactNode } from 'react'
import {
  actionInputs,
  chunkExample,
  cliEnvVars,
  cliExamples,
  cliFlagGroups,
  cliSubcommands,
  docPages,
  exitCodes,
  exportWorkflow,
  externalDocLinks,
  featureCards,
  functionExample,
  githubDocsUrl,
  githubWorkflowExample,
  perfTierRows,
  profiles,
  recommendedCweRules,
  recommendedPerfRules,
  sarifExample,
  sarifFieldTable,
  toolchainRows,
  type DocPageId,
} from '../data/docs'

type DocsViewProps = {
  page: DocPageId
}

function DocShell({
  page,
  children,
}: {
  page: DocPageId
  children: ReactNode
}) {
  const meta = docPages.find((p) => p.id === page) ?? docPages[0]

  return (
    <main id="docs" className="docs-view">
      <div className="docs-layout">
        <aside className="docs-sidebar" aria-label="Documentation sections">
          <a className="docs-back" href="#top">
            <ArrowLeft size={14} />
            Home
          </a>
          <nav className="docs-side-nav">
            {docPages.map((item) => (
              <a
                key={item.id}
                href={item.hash}
                className={item.id === page ? 'is-active' : undefined}
                aria-current={item.id === page ? 'page' : undefined}
              >
                {item.nav}
              </a>
            ))}
          </nav>
          <a
            className="docs-sidebar-link"
            href={`${githubDocsUrl}`}
            target="_blank"
            rel="noreferrer"
          >
            documents/ on GitHub <ArrowUpRight size={13} />
          </a>
        </aside>

        <article className="docs-article" aria-labelledby="docs-page-title">
          <header className="docs-article-header">
            <h1 id="docs-page-title">{meta.title}</h1>
            <p>{meta.lead}</p>
          </header>
          {children}
        </article>
      </div>
    </main>
  )
}

function CodeBlock({ label, children }: { label?: string; children: string }) {
  return (
    <div className="docs-code">
      {label && (
        <div className="docs-code-head">
          <Terminal size={13} />
          <span>{label}</span>
        </div>
      )}
      <pre>
        <code>{children}</code>
      </pre>
    </div>
  )
}

function OverviewPage() {
  return (
    <>
      <section className="docs-section-block">
        <h2>Start here</h2>
        <p>
          Install the binary, run a recommended scan, then either gate CI with SARIF or export
          chunks for agent triage. Deep reference stays in the repo under{' '}
          <code>documents/</code>; the pages here explain the product surface you use day to day.
        </p>
        <CodeBlock label="quick start">{`# From source (Go-first default)
cargo install --path .

# Optional experimental Python (SLOP101 only)
# cargo install --path . --features python

# Or download a release binary from GitHub Releases

codehound .
codehound --format sarif . > codehound.sarif
codehound --profile all --export-context --export-chunks .`}</CodeBlock>
      </section>

      <section className="docs-section-block">
        <h2>Default pack in one screen</h2>
        <p>
          <code>--profile recommended</code> is the default: S-tier PERF + taint-core CWE IDs, BP
          off, fail on <strong>high+</strong> only. S-tier PERF findings are medium severity — they
          print but do not fail CI unless you pass <code>--warnings-as-errors</code>. Taint stays
          off until <code>--taint</code> or <code>--profile security</code>.
        </p>
        <CodeBlock label="CI in 30 seconds">{`# After golangci-lint + govulncheck
codehound --profile recommended --format sarif . > codehound.sarif`}</CodeBlock>
      </section>

      <section className="docs-section-block">
        <h2>Day-2 paths</h2>
        <ul className="docs-bullets">
          <li>
            <strong>Brownfield</strong> — start with <code>--no-fail</code>, then{' '}
            <code>codehound --baseline .</code> so only new fingerprints fail.
          </li>
          <li>
            <strong>Config</strong> — <code>codehound init</code> writes a commented{' '}
            <code>codehound.toml</code>; full schema lives under <code>documents/</code>.
          </li>
          <li>
            <strong>Cache</strong> — warm scans under <code>.codehound-cache/</code> (on by
            default).
          </li>
          <li>
            <strong>Agent export</strong> — opt-in <code>--export-context</code> /{' '}
            <code>--export-chunks</code> for bounded LLM triage.
          </li>
        </ul>
      </section>

      <section className="docs-section-block">
        <h2>In-app guides</h2>
        <div className="docs-card-grid">
          {docPages
            .filter((p) => p.id !== 'overview')
            .map((p) => (
              <a key={p.id} className="docs-card" href={p.hash}>
                <h3>{p.nav}</h3>
                <p>{p.lead}</p>
                <span>
                  Open <ChevronRight size={14} />
                </span>
              </a>
            ))}
        </div>
      </section>

      <section className="docs-section-block">
        <h2>Full markdown library</h2>
        <p>These open the canonical docs on GitHub for long-form reference.</p>
        <ul className="docs-link-list">
          {externalDocLinks.map(([title, description, path]) => (
            <li key={path}>
              <a href={`${githubDocsUrl}/${path}`} target="_blank" rel="noreferrer">
                <strong>{title}</strong>
                <span>{description}</span>
                <ArrowUpRight size={14} />
              </a>
            </li>
          ))}
        </ul>
      </section>
    </>
  )
}

function FeaturesPage() {
  return (
    <>
      <section className="docs-section-block">
        <h2>Capability map</h2>
        <div className="docs-card-grid">
          {featureCards.map((card) => (
            <div key={card.title} className="docs-card static">
              <h3>{card.title}</h3>
              <p>{card.body}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="docs-section-block">
        <h2>Product packs</h2>
        <p>
          Profiles select which rule allow-lists run and what the default fail policy is. Override
          anytime with <code>--only</code>, <code>--skip</code>, <code>--taint</code>, or{' '}
          <code>--no-bp</code>.
        </p>
        <div className="docs-table-wrap">
          <table className="docs-table">
            <thead>
              <tr>
                <th>Profile</th>
                <th>What you get</th>
              </tr>
            </thead>
            <tbody>
              {profiles.map((p) => (
                <tr key={p.name}>
                  <td>
                    <code>--profile {p.name}</code>
                  </td>
                  <td>{p.blurb}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="docs-section-block">
        <h2>Recommended pack (exact)</h2>
        <p>
          Default profile membership. S-tier PERF is <strong>medium</strong> severity — visible
          under recommended, but the process only fails on high/critical unless you pass{' '}
          <code>--warnings-as-errors</code>. Taint-core CWE IDs stay allow-listed; the taint engine
          is off until <code>--taint</code>.
        </p>
        <h3>S-tier PERF</h3>
        <div className="docs-table-wrap">
          <table className="docs-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Why</th>
              </tr>
            </thead>
            <tbody>
              {recommendedPerfRules.map(([id, why]) => (
                <tr key={id}>
                  <td>
                    <code>{id}</code>
                  </td>
                  <td>{why}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <h3>Taint-core CWEs (allow-list)</h3>
        <div className="docs-table-wrap">
          <table className="docs-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Why</th>
              </tr>
            </thead>
            <tbody>
              {recommendedCweRules.map(([id, why]) => (
                <tr key={id}>
                  <td>
                    <code>{id}</code>
                  </td>
                  <td>{why}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="docs-section-block">
        <h2>PERF tiers</h2>
        <p>
          Tiers control pack membership and PERF severity. They are not the same as maturity tags
          (<code>heuristic</code>, <code>fixture-only</code>, …) shown by{' '}
          <code>--list-rules</code>.
        </p>
        <div className="docs-table-wrap">
          <table className="docs-table">
            <thead>
              <tr>
                <th>Tier</th>
                <th>Severity</th>
                <th>Profile</th>
                <th>Meaning</th>
              </tr>
            </thead>
            <tbody>
              {perfTierRows.map(([tier, sev, profile, meaning]) => (
                <tr key={tier}>
                  <td>
                    <strong>{tier}</strong>
                  </td>
                  <td>{sev}</td>
                  <td>{profile}</td>
                  <td>{meaning}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="docs-section-block">
        <h2>Where it sits in the toolchain</h2>
        <div className="docs-table-wrap">
          <table className="docs-table">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Use for</th>
              </tr>
            </thead>
            <tbody>
              {toolchainRows.map(([tool, use]) => (
                <tr key={tool}>
                  <td>
                    <strong>{tool}</strong>
                  </td>
                  <td>{use}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="docs-section-block">
        <h2>Workflow features</h2>
        <ul className="docs-bullets">
          <li>
            <strong>Incremental cache</strong> — content-hash warm scans under{' '}
            <code>.codehound-cache/</code> (on by default).
          </li>
          <li>
            <strong>Baselines</strong> — accept known debt with{' '}
            <code>.codehound-baseline.json</code>; next scan only reports new or regressed hits.
          </li>
          <li>
            <strong>Inline ignores</strong> — <code>codehound-ignore</code> comments (Go{' '}
            <code>//</code>, Python <code>#</code>). Not <code>//nolint</code>.
          </li>
          <li>
            <strong>Stable fingerprints</strong> — same identity in text, JSON, SARIF, and baseline
            matching.
          </li>
          <li>
            <strong>Agent export</strong> — opt-in <code>--export-context</code> and{' '}
            <code>--export-chunks</code> for bounded LLM review.
          </li>
          <li>
            <strong>Fixture-only quarantine</strong> — museum CWEs stay under{' '}
            <code>--profile all</code> / explicit <code>--only</code>, not default CI packs.
          </li>
        </ul>
      </section>

      <section className="docs-section-block">
        <h2>Honest non-goals</h2>
        <p>
          CodeHound does not replace golangci-lint, staticcheck, govulncheck, or CodeQL. It is not a
          CVE scanner, not default-on full bad-practice CI, and experimental taint is for triage —
          not hard security gates. <code>filepath.Clean</code> alone is not treated as a path
          sanitizer.
        </p>
      </section>
    </>
  )
}

function CliPage() {
  return (
    <>
      <section className="docs-section-block">
        <h2>Invocation model</h2>
        <p>
          Global flags apply to scans. Bare paths mean “scan.” Subcommands handle config, rules
          browsing, cache maintenance, and baselines.
        </p>
        <CodeBlock label="usage">{`codehound [OPTIONS] [PATH]... [COMMAND]

Commands:
  init       Write a starter codehound.toml
  rules      List rules or explain a rule id
  cache      Incremental cache operations
  baseline   Baseline management
  scan       Explicit scan (same as bare paths)
  help       Print this message`}</CodeBlock>
      </section>

      <section className="docs-section-block">
        <h2>Subcommands</h2>
        <div className="docs-table-wrap">
          <table className="docs-table">
            <thead>
              <tr>
                <th>Command</th>
                <th>Purpose</th>
              </tr>
            </thead>
            <tbody>
              {cliSubcommands.map((row) => (
                <tr key={row.cmd}>
                  <td>
                    <code>{row.cmd}</code>
                  </td>
                  <td>{row.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {cliFlagGroups.map((group) => (
        <section key={group.title} className="docs-section-block">
          <h2>{group.title}</h2>
          <div className="docs-table-wrap">
            <table className="docs-table">
              <thead>
                <tr>
                  <th>Flag</th>
                  <th>Notes</th>
                </tr>
              </thead>
              <tbody>
                {group.rows.map(([flag, notes]) => (
                  <tr key={flag}>
                    <td>
                      <code>{flag}</code>
                    </td>
                    <td>{notes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}

      <section className="docs-section-block">
        <h2>Environment variables</h2>
        <div className="docs-table-wrap">
          <table className="docs-table">
            <thead>
              <tr>
                <th>Variable</th>
                <th>Equivalent</th>
              </tr>
            </thead>
            <tbody>
              {cliEnvVars.map(([env, equiv]) => (
                <tr key={env}>
                  <td>
                    <code>{env}</code>
                  </td>
                  <td>{equiv}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="docs-section-block">
        <h2>Exit codes</h2>
        <div className="docs-table-wrap">
          <table className="docs-table">
            <thead>
              <tr>
                <th>Code</th>
                <th>Meaning</th>
              </tr>
            </thead>
            <tbody>
              {exitCodes.map(([code, meaning]) => (
                <tr key={code}>
                  <td>
                    <code>{code}</code>
                  </td>
                  <td>{meaning}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="docs-section-block">
        <h2>Common recipes</h2>
        <CodeBlock label="shell">{cliExamples}</CodeBlock>
      </section>
    </>
  )
}

function SarifPage() {
  return (
    <>
      <section className="docs-section-block">
        <h2>Three reporters</h2>
        <ul className="docs-bullets">
          <li>
            <strong>Text</strong> (default) — color severity, snippets, fix hints, summary footer.
          </li>
          <li>
            <strong>JSON</strong> — NDJSON stream (one finding per line), or{' '}
            <code>--json-envelope</code> for a single object with counts.
          </li>
          <li>
            <strong>SARIF 2.1.0</strong> — GitHub Code Scanning–ready; use{' '}
            <code>--sarif-compact</code> for one-line output.
          </li>
        </ul>
        <CodeBlock label="emit SARIF">{`# Pretty (default)
codehound --profile recommended --format sarif --strict . > codehound.sarif

# Compact for machines
codehound --format sarif --sarif-compact . > codehound.sarif

# Security pack + taint
codehound --profile security --format sarif . > codehound.sarif`}</CodeBlock>
      </section>

      <section className="docs-section-block">
        <h2>SARIF field map</h2>
        <p>
          CodeHound only <em>emits</em> SARIF — it does not consume SARIF as input. Fingerprints and
          security-severity values are stable enough for Code Scanning dedupe and severity filters.
        </p>
        <div className="docs-table-wrap">
          <table className="docs-table">
            <thead>
              <tr>
                <th>Field</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              {sarifFieldTable.map(([field, value]) => (
                <tr key={field}>
                  <td>
                    <code>{field}</code>
                  </td>
                  <td>{value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="docs-section-block">
        <h2>Example result shape</h2>
        <p>
          Simplified single-finding run. Live output also includes invocations, scan stats when
          diagnostics are enabled, and full rule catalogs when those rules fired.
        </p>
        <CodeBlock label="out.sarif (excerpt)">{sarifExample}</CodeBlock>
      </section>

      <section className="docs-section-block">
        <h2>GitHub Code Scanning</h2>
        <p>
          The repo ships a composite action and sample workflow that build CodeHound, run the
          recommended pack with <code>--format sarif</code>, and upload via{' '}
          <code>github/codeql-action/upload-sarif</code>. The action always attempts SARIF upload
          first, then propagates the scan exit code (upload-then-fail).
        </p>
        <p>
          Severity note: under recommended, S-tier PERF is medium and does not fail the job unless
          you pass <code>--warnings-as-errors</code> (via <code>args</code>). Fail policy is
          independent of reporter format.
        </p>
        <CodeBlock label="minimal workflow">{githubWorkflowExample}</CodeBlock>
        <h3>Composite action inputs</h3>
        <div className="docs-table-wrap">
          <table className="docs-table">
            <thead>
              <tr>
                <th>Input</th>
                <th>Default</th>
                <th>Purpose</th>
              </tr>
            </thead>
            <tbody>
              {actionInputs.map(([name, def, purpose]) => (
                <tr key={name}>
                  <td>
                    <code>{name}</code>
                  </td>
                  <td>
                    <code>{def}</code>
                  </td>
                  <td>{purpose}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p>
          Full field-level reference:{' '}
          <a href={`${githubDocsUrl}/output-formats.md`} target="_blank" rel="noreferrer">
            documents/output-formats.md <ArrowUpRight size={13} />
          </a>
          {' · '}
          <a href={`${githubDocsUrl}/ci-integration.md`} target="_blank" rel="noreferrer">
            documents/ci-integration.md <ArrowUpRight size={13} />
          </a>
        </p>
      </section>
    </>
  )
}

function ExportPage() {
  return (
    <>
      <section className="docs-section-block">
        <h2>Why two folders?</h2>
        <p>
          Export is <strong>off by default</strong> so CI stays clean. When you want agent help,
          opt in. Both formats use the same finding block formatter — chunks are simply the combined
          version of consecutive function files.
        </p>
        <div className="docs-table-wrap">
          <table className="docs-table">
            <thead>
              <tr>
                <th></th>
                <th>functions</th>
                <th>chunks</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Flag</td>
                <td>
                  <code>--export-context</code>
                </td>
                <td>
                  <code>--export-chunks</code>
                </td>
              </tr>
              <tr>
                <td>Default directory</td>
                <td>
                  <code>scripts/findings/functions</code>
                </td>
                <td>
                  <code>scripts/chunks</code>
                </td>
              </tr>
              <tr>
                <td>Files</td>
                <td>
                  <code>1.txt</code>, <code>2.txt</code>, … <code>N.txt</code>
                </td>
                <td>
                  <code>Chunk_1_25.txt</code>, <code>Chunk_26_50.txt</code>, …
                </td>
              </tr>
              <tr>
                <td>Grouping</td>
                <td>One finding per file</td>
                <td>
                  Up to <code>--chunk-size</code> findings (default 25)
                </td>
              </tr>
              <tr>
                <td>When to use</td>
                <td>Deep dive, single fix, precise review</td>
                <td>Batch triage — fix everything with a fixed token budget</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="docs-section-block">
        <h2>Fix-everything playbook</h2>
        <ol className="docs-steps">
          {exportWorkflow.map((item) => (
            <li key={item.step}>
              <span className="docs-step-num">{item.step}</span>
              <div>
                <h3>{item.title}</h3>
                <p>{item.body}</p>
                <code className="docs-inline-cmd">{item.code}</code>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section className="docs-section-block">
        <h2>Function file (one finding)</h2>
        <p>
          Real export shape from <code>scripts/findings/functions/4.txt</code> — PERF-32 with
          enclosing function context and a local fix hint.
        </p>
        <CodeBlock label="scripts/findings/functions/4.txt">{functionExample}</CodeBlock>
      </section>

      <section className="docs-section-block">
        <h2>Chunk file (combined functions)</h2>
        <p>
          <code>scripts/chunks/Chunk_1_25.txt</code> starts with a range header, then concatenates
          the same blocks as findings 1–25, separated by <code>====</code> lines. Finding 4 inside
          the chunk is identical to <code>4.txt</code>.
        </p>
        <CodeBlock label="scripts/chunks/Chunk_1_25.txt">{chunkExample}</CodeBlock>
      </section>

      <section className="docs-section-block">
        <h2>Delegate to chunks</h2>
        <p>
          Point your agent at <code>scripts/chunks/</code> (and optionally{' '}
          <code>scripts/findings/functions/</code> for drill-down). The repo includes{' '}
          <code>CHUNK_VALIDATOR.md</code> as a strict true/false-positive evaluation prompt if you
          want a validation pass before mass remediation.
        </p>
        <ul className="docs-bullets">
          <li>
            Scan once offline — <strong>$0 tokens</strong> for detection.
          </li>
          <li>
            Review in chunk units so context windows and API cost stay <strong>bounded</strong>.
          </li>
          <li>
            Track fixes by finding number and fingerprint; regenerate export after a remediation
            pass.
          </li>
          <li>
            When 60 of 100 are fixed and 40 remain acceptable debt, run <code>--baseline</code> so
            the next scan only reports regressions and new hits.
          </li>
          <li>
            Gate production CI with SARIF, not with writing export dirs into the workspace.
          </li>
        </ul>
        <CodeBlock label="full export recipe">{`# Full catalog + both export modes
codehound --profile all \\
  --export-context --export-chunks \\
  --chunk-size 25 \\
  --context-output-dir scripts/findings/functions \\
  --chunks-output-dir scripts/chunks \\
  --no-cache \\
  .

# Then hand every Chunk_*.txt to your agent / model of choice
# Re-scan, baseline leftovers, or upload SARIF in CI`}</CodeBlock>
      </section>
    </>
  )
}

export function DocsView({ page }: DocsViewProps) {
  let body: ReactNode
  switch (page) {
    case 'features':
      body = <FeaturesPage />
      break
    case 'cli':
      body = <CliPage />
      break
    case 'sarif':
      body = <SarifPage />
      break
    case 'export':
      body = <ExportPage />
      break
    default:
      body = <OverviewPage />
  }

  return <DocShell page={page}>{body}</DocShell>
}
