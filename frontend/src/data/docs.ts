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
  ['Recommended pack', 'High-signal default CI pack and fail policy.', 'go-recommended-pack.md'],
  ['How it compares', 'Beside golangci-lint, staticcheck, and govulncheck.', 'go-vs-staticcheck.md'],
  ['Rule catalogue', 'Performance rules, maturity, and rationale.', 'perf-rules.md'],
  ['Configuration', 'codehound.toml, profiles, ignores, baselines.', 'configuration.md'],
  ['Taint tracking', 'Experimental data-flow model and limits.', 'taint.md'],
  ['Bad practices', 'BP catalogue and style pack policy.', 'bad-practices.md'],
  ['Incremental cache', 'Warm scans without changing findings.', 'incremental-cache.md'],
  ['Output formats', 'Full SARIF field mapping and exit codes.', 'output-formats.md'],
] as const

export const profiles = [
  {
    name: 'recommended',
    blurb: 'Default CI pack: S-tier PERF + taint-core CWEs. BP off. Fail on high+.',
  },
  {
    name: 'perf',
    blurb: 'Broader framework and hot-path PERF pack. BP off.',
  },
  {
    name: 'security',
    blurb: 'Taint-core CWEs with experimental taint enabled. BP off.',
  },
  {
    name: 'style',
    blurb: 'Bad practices only (advisory). No fail by default.',
  },
  {
    name: 'all',
    blurb: 'Full catalog: PERF + CWE + BP. Use when you want everything exported.',
  },
] as const

export const featureCards = [
  {
    title: 'PERF rules',
    body: 'Hundreds of Go performance heuristics: regex-in-loops, fmt.Sprintf on hot paths, defer in tight loops, request-path allocation thrash, and more.',
  },
  {
    title: 'Framework footguns',
    body: 'Gin, Echo, GORM, and sqlx awareness — unclosed bodies, unbounded rows, missing timeouts, context leaks.',
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
    body: 'Intra-procedural tracking for CWE-22 / 78 / 79 / 89. Enable with --taint or --profile security. Not security-grade whole-program analysis.',
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
  { cmd: 'codehound baseline list|save|update|prune|diff', desc: 'Brownfield baseline management for accepted debt.' },
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
    ],
  },
  {
    title: 'Profiles & rules',
    rows: [
      ['--profile recommended|perf|security|style|all', 'Product pack (default: recommended).'],
      ['--only / --skip', 'Comma-separated rule IDs (env: CODEHOUND_ONLY / SKIP).'],
      ['--bp-only / --no-bp', 'Only bad-practice rules, or disable them.'],
      ['--list-rules / --explain RULE', 'Browse or deep-dive a single rule.'],
      ['--config PATH', 'Override codehound.toml discovery.'],
    ],
  },
  {
    title: 'Taint & typed Go',
    rows: [
      ['--taint / --no-taint', 'Toggle experimental taint engine.'],
      ['--taint-show-paths', 'Emit taint-path evidence in all formats.'],
      ['--taint-depth N', 'Inter-procedural hops (1–4, default 1).'],
      ['--typed / --no-typed', 'Optional go list package facts (G4).'],
    ],
  },
  {
    title: 'Exit policy',
    rows: [
      ['(profile default)', 'recommended / security fail on high+.'],
      ['--strict', 'Fail only on high-severity findings.'],
      ['--warnings-as-errors', 'Fail on medium+ (CLI-explicit).'],
      ['--no-fail', 'Always exit 0 for findings.'],
    ],
  },
  {
    title: 'Cache, baseline, discovery',
    rows: [
      ['--no-cache / --rebuild-cache / --prune-cache', 'Control incremental analysis cache.'],
      ['--cache-dir DIR', 'Override cache directory.'],
      ['--baseline / --no-baseline / --baseline-file', 'Save or ignore baselines.'],
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

# Security pack (enables taint) or full catalog
codehound --profile security .
codehound --profile all .

# Machine-readable for CI
codehound --format json ./...
codehound --format sarif ./... > codehound.sarif
codehound --format sarif --sarif-compact . > codehound.sarif

# Export for agent triage (off by default)
codehound --profile all --export-context --export-chunks --no-cache .

# Rule browser
codehound --list-rules
codehound rules --explain PERF-101
codehound --explain CWE-334

# Brownfield baseline
codehound --baseline .
codehound baseline diff .
codehound baseline prune .

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
  ['3', 'Internal, I/O, or engine error'],
  ['101', 'Rust panic in a worker thread'],
] as const

