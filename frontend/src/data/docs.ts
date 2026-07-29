/** In-app documentation catalog and content for the marketing site. */

export type DocPageId = 'overview' | 'features' | 'cli' | 'sarif' | 'export'

export type DocNavItem = {
  id: DocPageId
  hash: string
  nav: string
  title: string
  lead: string
}

export const docPages: DocNavItem[] = [
  {
    id: 'overview',
    hash: '#docs',
    nav: 'Overview',
    title: 'Documentation',
    lead: 'CodeHound is a Go-first static analyzer: performance hot paths, framework footguns, curated CWE heuristics, and optional agent-ready exports.',
  },
  {
    id: 'features',
    hash: '#docs/features',
    nav: 'Features',
    title: 'What CodeHound does',
    lead: 'Deterministic offline scans that complement golangci-lint — not a cloud service, not an unbounded agent loop.',
  },
  {
    id: 'cli',
    hash: '#docs/cli',
    nav: 'CLI',
    title: 'Command-line reference',
    lead: 'One binary. Scan by default, or use subcommands for rules, cache, baseline, and init.',
  },
  {
    id: 'sarif',
    hash: '#docs/sarif',
    nav: 'SARIF & formats',
    title: 'Text, JSON, and SARIF',
    lead: 'Machine-readable output for CI and GitHub Code Scanning, plus human text for the terminal.',
  },
  {
    id: 'export',
    hash: '#docs/export',
    nav: 'Agent export',
    title: 'Functions, chunks, and fix-everything',
    lead: 'Per-finding context files and batched chunks so you can hand a bounded checklist to any agent.',
  },
]

export function docPageFromHash(hash: string): DocPageId | null {
  const raw = hash.replace(/^#/, '')
  if (raw === 'docs' || raw === 'docs/') return 'overview'
  if (!raw.startsWith('docs')) return null
  const rest = raw.slice('docs'.length).replace(/^\//, '')
  if (!rest) return 'overview'
  const known: DocPageId[] = ['overview', 'features', 'cli', 'sarif', 'export']
  return known.includes(rest as DocPageId) ? (rest as DocPageId) : 'overview'
}

export const githubDocsUrl = 'https://github.com/chinmay-sawant/codehound/blob/master/documents'

/** Repo markdown still linked from the docs hub (deep reference, not rendered here). */
export const externalDocLinks = [
  ['CLI reference', 'Full flag and subcommand encyclopedia.', 'cli.md'],
  ['Recommended pack', 'High-signal default CI pack and fail policy.', 'go-recommended-pack.md'],
  ['CI integration', 'GitHub Actions, SARIF upload, brownfield adoption.', 'ci-integration.md'],
  ['Rule catalog index', 'How to navigate PERF / BP / CWE inventory.', 'rule-catalog.md'],
  ['PERF tiers', 'S/A/B/C pack policy and hot-path rules.', 'perf-tiers.md'],
  ['How it compares', 'Beside golangci-lint, staticcheck, and govulncheck.', 'go-vs-staticcheck.md'],
  ['Rule notes (PERF)', 'Partial human notes — use --list-rules for full inventory.', 'perf-rules.md'],
  ['Configuration', 'codehound.toml, profiles, fails, cache, taint.', 'configuration.md'],
  ['Finding identity', 'Fingerprints, ignores, baseline workflow.', 'finding-identity.md'],
  ['Taint tracking', 'Experimental data-flow model and limits.', 'taint.md'],
  ['Bad practices', 'BP catalogue and style pack policy.', 'bad-practices.md'],
  ['Incremental cache', 'Warm scans without changing findings.', 'incremental-cache.md'],
  ['Output formats', 'Full SARIF field mapping and exit codes.', 'output-formats.md'],
] as const

export const profiles = [
  {
    name: 'recommended',
    blurb: 'Default CI pack: S-tier PERF + taint-core CWEs. BP off. Fail on high+ only. Taint off until --taint.',
  },
  {
    name: 'perf',
    blurb: 'S+A PERF (framework + hot-path). BP off. Fail on high+.',
  },
  {
    name: 'security',
    blurb: 'Security CWE pack (22/41/59/78/79/89/90/91/93). Experimental taint on. BP off.',
  },
  {
    name: 'style',
    blurb: 'BP-* only (skips BP-21/28/30). Advisory — no fail by default.',
  },
  {
    name: 'all',
    blurb: 'Full catalog: PERF + CWE + BP. Fail on medium+. Best for agent export.',
  },
] as const

/** Exact recommended-pack membership for the Features page. */
export const recommendedPerfRules = [
  ['PERF-1', 'Regex compilation inside a loop'],
  ['PERF-7', 'defer inside a loop'],
  ['PERF-50', 'regexp.MatchString inside a loop'],
  ['PERF-58', 'Gin request body not closed'],
  ['PERF-71', 'GORM N+1 query pattern'],
  ['PERF-101', 'http.Server missing timeouts'],
  ['PERF-103', 'HTTP response body not closed'],
  ['PERF-189', 'Response body not drained before close'],
  ['PERF-190', 'HTTP client missing timeout'],
] as const

export const recommendedCweRules = [
  ['CWE-22', 'Path traversal (taint)'],
  ['CWE-78', 'OS command injection (taint)'],
  ['CWE-79', 'XSS / template + HTTP write (taint)'],
  ['CWE-89', 'SQL injection heuristic (taint)'],
  ['CWE-90', 'LDAP injection (taint)'],
  ['CWE-91', 'XML injection (taint)'],
] as const

export const perfTierRows = [
  ['S', 'Medium', 'recommended + perf', 'CI surface — timeouts, body close, regex/defer in loop, N+1'],
  ['A', 'Medium', 'perf', 'Framework / hot-path (sqlx, caches, MaxBytesReader, …)'],
  ['B', 'Info', 'all only', 'Micro-opts (time.Since, TrimPrefix, …)'],
  ['C', 'Info', 'all only', 'staticcheck / prealloc overlap — prefer those tools in CI'],
] as const

export const toolchainRows = [
  ['go vet / staticcheck', 'Language correctness and deep static analysis'],
  ['errcheck / wrapcheck', 'Error-handling completeness'],
  ['govulncheck', 'Live module CVEs'],
  ['golangci-lint', 'Aggregator for the above'],
  ['CodeHound', 'PERF hot paths, framework footguns, optional taint + BP'],
] as const

export const featureCards = [
  {
    title: 'PERF rules',
    body: 'Hundreds of Go performance heuristics: regex-in-loops, fmt.Sprintf on hot paths, defer in tight loops, request-path allocation thrash, and more.',
  },
  {
    title: 'Framework footguns',
    body: 'net/http, Gin, Echo, Chi, Fiber, GORM, and sqlx awareness — unclosed bodies, unbounded rows, missing timeouts, context leaks.',
  },
  {
    title: 'CWE heuristics',
    body: 'Fixture-backed entries for path traversal, injection sinks, and related patterns. Use for triage; not a CodeQL replacement.',
  },
  {
    title: 'Bad practices',
    body: 'BP-* rules across errors, concurrency, testing, API design, and prod hardening. Off in the recommended pack.',
  },
  {
    title: 'Taint (experimental)',
    body: 'Intra/same-package tracking for CWE-22 / 78 / 79 / 89 / 90 / 91. Enable with --taint or --profile security. Not security-grade whole-program analysis.',
  },
  {
    title: 'Offline & agent-ready',
    body: 'Single static binary. Optional export of finding context and review chunks so LLM triage has a fixed token budget.',
  },
] as const

export const cliSubcommands = [
  { cmd: 'codehound [PATH…]', desc: 'Scan paths (default: .). Same as codehound scan.' },
  { cmd: 'codehound scan [PATH…]', desc: 'Explicit scan with the same defaults as bare invocation.' },
  { cmd: 'codehound init', desc: 'Write a starter codehound.toml in the current directory.' },
  { cmd: 'codehound rules', desc: 'List rules; filter with --category; explain with --explain RULE.' },
  { cmd: 'codehound cache prune', desc: 'Drop stale incremental-cache entries, then exit.' },
  {
    cmd: 'codehound baseline list|save|update|prune|diff',
    desc: 'Brownfield baseline management (list, save, merge, prune stale, diff). Optional --path.',
  },
] as const

export const cliEnvVars = [
  ['CODEHOUND_PROFILE', '--profile'],
  ['CODEHOUND_CONFIG', '--config'],
  ['CODEHOUND_ONLY', '--only'],
  ['CODEHOUND_SKIP', '--skip'],
  ['CODEHOUND_GO', 'go binary for --typed'],
  ['NO_COLOR', '--no-color (truthy)'],
  ['RUST_LOG', 'Tracing verbosity (not a product flag)'],
] as const

export const cliFlagGroups = [
  {
    title: 'Output',
    rows: [
      ['--format text|json|sarif', 'Reporter format (default: text).'],
      ['--sarif-compact', 'Single-line SARIF (no pretty indent).'],
      ['--json-envelope', 'JSON as one object instead of NDJSON.'],
      ['--no-snippet', 'Hide source snippets in text output.'],
      ['--quiet / --no-terminal', 'Suppress non-error or stdout findings.'],
      ['--verbose / --show-fingerprint', 'Extra detector detail or fingerprints.'],
      ['--no-color', 'Disable color (also honors NO_COLOR).'],
    ],
  },
  {
    title: 'Profiles & rules',
    rows: [
      ['--profile recommended|perf|security|style|all', 'Product pack (default: recommended). Aliases: ci, sec, bp, full.'],
      ['--only / --skip', 'Comma-separated rule IDs or globs like BP-* (env: CODEHOUND_ONLY / SKIP).'],
      ['--bp-only / --no-bp', 'Only bad-practice rules, or disable them.'],
      ['--list-rules / --rule-category …', 'Browse rules; filter security|performance|bad-practice|general.'],
      ['--explain RULE', 'Deep-dive pack eligibility, maturity, quarantine.'],
      ['--config PATH', 'Override codehound.toml discovery (env: CODEHOUND_CONFIG).'],
    ],
  },
  {
    title: 'Taint & typed Go',
    rows: [
      ['--taint / --no-taint', 'Toggle experimental taint engine.'],
      ['--taint-show-paths', 'Emit taint-path evidence in all formats.'],
      ['--taint-depth N', 'Inter-procedural hops (1–4, default 1).'],
      ['--typed / --no-typed', 'Optional go list package facts (G4). Needs Go toolchain.'],
    ],
  },
  {
    title: 'Exit policy',
    rows: [
      ['(profile default)', 'recommended / perf / security: high+. style: never. all: medium+.'],
      ['--strict', 'Fail only on high-severity findings (CLI-explicit).'],
      ['--warnings-as-errors', 'Fail on medium+ (CLI-explicit; use to gate PERF).'],
      ['--no-fail', 'Always exit 0 for findings.'],
    ],
  },
  {
    title: 'Cache, baseline, discovery',
    rows: [
      ['--lang auto|go|python', 'Language filter (Python needs --features python).'],
      ['--no-cache / --rebuild-cache / --prune-cache', 'Control incremental analysis cache.'],
      ['--cache-dir DIR', 'Override cache directory.'],
      ['--baseline / --no-baseline / --baseline-file', 'Save or ignore baselines.'],
      ['--show-baselined / --show-ignored', 'Emit baselined or codehound-ignore suppressions.'],
      ['--include-tests', 'Include *_test.* (excluded by default).'],
      ['--exclude-examples', 'Skip examples / samples paths.'],
    ],
  },
  {
    title: 'Agent export (opt-in)',
    rows: [
      ['--export-context', 'Write one file per finding (default dir: scripts/findings/functions).'],
      ['--export-chunks', 'Write batched chunk files (default dir: scripts/chunks).'],
      ['--chunk-size N', 'Findings per chunk (default: 25).'],
      ['--context-output-dir / --chunks-output-dir', 'Override export directories.'],
    ],
  },
  {
    title: 'Diagnostics',
    rows: [
      ['--diagnostics-summary', 'Compact stderr summary (files, cache, time).'],
      ['--diagnostics FILE', 'Machine-readable diagnostics JSON.'],
      ['--debug-timing', 'Per-detector timing after findings.'],
    ],
  },
] as const

export const cliExamples = `# Default recommended pack
codehound .

# Product wedge — request-path / timeouts
codehound --profile recommended --only PERF-101 .

# Fail on medium PERF too (recommended defaults to high+ only)
codehound --warnings-as-errors .

# Security pack (enables taint) or full catalog
codehound --profile security .
codehound --profile all .

# Machine-readable for CI
codehound --format json ./...
codehound --format sarif ./... > codehound.sarif
codehound --format sarif --sarif-compact . > codehound.sarif

# Export for agent triage (off by default; keep off pure CI gates)
codehound --profile all --export-context --export-chunks --no-cache .

# Rule browser
codehound --list-rules --rule-category performance
codehound rules --explain PERF-101
codehound --explain CWE-334

# Brownfield baseline
codehound --no-fail .
codehound --baseline .
codehound baseline diff .
codehound baseline prune .
codehound --show-baselined .

# Cache
codehound --rebuild-cache .
codehound cache prune

# Starter config
codehound init`

/** Illustrative SARIF shape (stable fields; values simplified for the docs). */
export const sarifExample = `{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "codehound",
        "informationUri": "https://github.com/chinmay-sawant/codehound",
        "version": "1.0.0",
        "rules": [{
          "id": "PERF-32",
          "shortDescription": { "text": "String Byte Conversion In Hot Path" }
        }]
      }
    },
    "results": [{
      "ruleId": "PERF-32",
      "level": "warning",
      "message": {
        "text": "string <-> []byte conversion copies the underlying data on a hot path"
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "bindings/python/cgo/exports.go" },
          "region": { "startLine": 39, "startColumn": 27 }
        }
      }],
      "partialFingerprints": {
        "codehound/v1": "codehound:2:PERF-32:bindings/python/cgo/exports.go:10aba91bf5ec71ef"
      },
      "properties": {
        "security-severity": "5.0",
        "tags": ["performance", "perf-32"]
      }
    }]
  }]
}`

export const sarifFieldTable = [
  ['$schema / version', 'SARIF 2.1.0 schema URI and version string'],
  ['tool.driver.name', 'Always codehound'],
  ['tool.driver.rules[]', 'Rule metadata sorted by id'],
  ['results[].ruleId', 'Stable rule id (PERF-*, CWE-*, BP-*)'],
  ['results[].level', 'note (info) · warning (low/medium) · error (high/critical)'],
  ['results[].locations', 'File URI + 1-indexed startLine / startColumn'],
  ['partialFingerprints["codehound/v1"]', 'Stable fingerprint across text/JSON/SARIF/baseline'],
  ['properties.security-severity', 'info 0.0 · low 2.0 · medium 5.0 · high 7.5 · critical 9.5'],
  ['properties.tags', 'Category and rule tags for Code Scanning filters'],
  ['properties.remediation / codehoundEvidence', 'Optional longer fix guidance and structured evidence'],
] as const

export const functionExample = `Finding 4/915
Source: bindings/python/cgo/exports.go:39:27
Rule: PERF-32
Fingerprint: codehound:2:PERF-32:bindings/python/cgo/exports.go:10aba91bf5ec71ef
Rule title: String Byte Conversion In Hot Path
Severity: medium
Message: string <-> []byte conversion copies the underlying data on a hot path
Fix: Use unsafe conversions only in measured hot paths, or hoist the conversion
     outside the loop with a pooled buffer.
Enclosing function: lines 34–56
Context:
         34: func GeneratePDF(jsonTemplate *C.char) C.ByteResult {
         35:     var result C.ByteResult
         ...
    >    39:     if err := json.Unmarshal([]byte(goTemplate), &template); err != nil {
         40:         result.error = C.CString(err.Error())
         ...
         56: }`

export const chunkExample = `Findings 1-25 of 915

Finding 1/915
Source: bindings/python/cgo/exports.go:1:1
Rule: BP-57
...
====================================================================================================

Finding 2/915
Source: bindings/python/cgo/exports.go:1:1
Rule: BP-60
...
====================================================================================================

Finding 4/915
Source: bindings/python/cgo/exports.go:39:27
Rule: PERF-32
Fingerprint: codehound:2:PERF-32:bindings/python/cgo/exports.go:10aba91bf5ec71ef
Rule title: String Byte Conversion In Hot Path
Severity: medium
Message: string <-> []byte conversion copies the underlying data on a hot path
...
====================================================================================================

… findings 5–25 follow in the same file …`

export const exportWorkflow = [
  {
    step: '01',
    title: 'Scan once',
    body: 'Run a deterministic offline pass. Prefer --profile all when you want the full checklist for remediation.',
    code: 'codehound --profile all --export-context --export-chunks .',
  },
  {
    step: '02',
    title: 'Functions = one finding each',
    body: 'scripts/findings/functions/1.txt … N.txt hold a single finding with snippet, fix hint, and fingerprint. Use these when you need a precise deep dive.',
    code: 'scripts/findings/functions/4.txt',
  },
  {
    step: '03',
    title: 'Chunks = combined batches',
    body: 'scripts/chunks/Chunk_1_25.txt is literally findings 1–25 concatenated with the same blocks as the function files (default size 25). Point your agent at chunks to fix everything with a fixed token budget.',
    code: 'scripts/chunks/Chunk_1_25.txt',
  },
  {
    step: '04',
    title: 'Delegate, then re-scan',
    body: 'Hand each Chunk_*.txt to the model you already use. Fix by finding number / fingerprint. Re-run CodeHound, baseline remaining noise, or gate CI with SARIF.',
    code: 'codehound --format sarif . > codehound.sarif',
  },
] as const

export const exitCodes = [
  ['0', 'Clean — no failing findings, no scan errors'],
  ['1', 'Findings exceeded the fail policy'],
  ['2', 'Configuration / CLI error'],
  ['3', 'Internal, I/O, encoding, or aborted engine error'],
  ['4', 'Per-file parse error (tree-sitter)'],
  ['5', 'Per-file detector/engine error'],
  ['101', 'Rust panic in a worker thread'],
] as const

export const githubWorkflowExample = `name: codehound
on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/codehound-scan
        with:
          profile: recommended
          paths: .
          upload-sarif: "true"`

export const actionInputs = [
  ['profile', 'recommended', 'Scan pack'],
  ['paths', '.', 'Paths to scan'],
  ['args', '(empty)', 'Extra CLI args'],
  ['sarif-file', 'codehound.sarif', 'Output path'],
  ['upload-sarif', 'true', 'Upload to GitHub Code Scanning'],
  ['strict', 'true', 'Pass --strict'],
] as const

