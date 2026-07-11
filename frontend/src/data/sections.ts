import type { LucideIcon } from 'lucide-react'
import {
  HelpCircle, BarChart3, Sparkles, GitCompare, ShieldAlert,
  FileOutput, Coins, Blocks, Route, Gauge, Users, Scale, Package,
} from 'lucide-react'

export type Stat = { value: string; label: string; sub?: string }
export type Fact = { k: string; v: string }
export type CodeBlock = { label: string; lang: string; before?: string; after?: string; body?: string }
export type DataTable = {
  caption: string
  headers: string[]
  rows: string[][]
  /** Row index to highlight (e.g. recommended tier). */
  highlightRow?: number
}

export type Section = {
  id: string
  nav: string
  title: string
  lead: string
  icon: LucideIcon
  callout?: string
  body?: string[]
  stats?: Stat[]
  facts?: Fact[]
  tables?: DataTable[]
  code?: CodeBlock
}

/**
 * Grok 4.5 pricing (xAI API, per 1M tokens):
 *   Input $2.00 · Cached input $0.50 · Output $6.00
 *
 * Workload estimates (same as prior cost model):
 *   Batch triage: 1.55M input + 125K output
 *   Per-finding:  2.33M input + 125K output
 *
 * Grok 4.5 batch:  1.55×2 + 0.125×6 = $3.10 + $0.75 = $3.85
 * Grok 4.5 per-f:  2.33×2 + 0.125×6 = $4.66 + $0.75 = $5.41
 * Skills ×5 passes (unbounded re-reads ≈ 5× batch): ~$19.25
 */

export const sections: Section[] = [
  {
    id: 'impact',
    nav: 'Impact',
    icon: Gauge,
    title: 'Real results, not vibes',
    lead:
      'On gopdfsuit, fixing CodeHound findings moved throughput from ~2,000 ops/sec to ~2,700 ops/sec — about +35% on the same hardware, before later optimization phases stacked on top.',
    callout:
      '**Not a benchmark theater.** Same machines, same harness, same library. The lift came from deterministic PERF findings — regex hoists, fmt→strconv, defer off hot paths — not from guessing with an agent.',
    stats: [
      { value: '~2k→2.7k', label: 'ops/sec after fixes', sub: 'gopdfsuit · CodeHound pass' },
      { value: '+35%', label: 'throughput lift', sub: 'same machines · same harness' },
      { value: '218', label: 'PERF findings fixed', sub: '226 exported · 8 CWE deferred' },
      { value: '$0', label: 'scan cost', sub: 'offline · no API key' },
    ],
    facts: [
      { k: 'What changed', v: 'Regex hoists, fmt→strconv/AppendInt, defer off hot paths, non-blocking logging' },
      { k: 'Heavy workloads', v: 'table_180_rows +13% · text_240_lines +9% · table_900_rows +4.6%' },
      { k: 'Infra angle', v: '~26% less capacity for the same load (2,000/2,700) — or 35% more work on the fleet you already run' },
      { k: 'Later phases', v: 'CodeHound discipline became the playbook; downstream Zerodha path later reached multi-k ops/sec gains' },
    ],
    body: [
      'CodeHound does not "suggest" that a loop is slow. It pins **PERF-*** rules to file, line, and snippet — the same findings you fix in a PR. On gopdfsuit that was **218** actionable performance hits, all fixed.',
      'The ~**2,000 → ~2,700 ops/sec** jump is the immediate payoff of that pass. Capacity you would have bought with more boxes or more Grok time, you get from a **$0** static scan plus targeted edits.',
      'This is the product wedge: hot-path PERF you can measure, not a wall of unused security noise. Run it after golangci-lint. Fix what moves the needle. Baseline the rest.',
    ],
  },
  {
    id: 'cost',
    nav: 'Cost',
    icon: Coins,
    title: 'Scan free. Review bounded.',
    lead:
      'Detection is $0. Review is optional and sized to exported chunks — so Grok 4.5 (and every other model) has a fixed token budget instead of re-reading the repo forever.',
    callout:
      '**The math is the product.** Skills re-walk the tree every pass. CodeHound writes findings once; you pay only for the models you choose to point at `scripts/chunks/`.',
    stats: [
      { value: '$0', label: 'CodeHound scan', sub: '1,042 findings · offline' },
      { value: '$3.85', label: 'Grok 4.5 batch', sub: '1.55M in · 125K out' },
      { value: '$0.25', label: 'DeepSeek triage', sub: 'same 42 chunks' },
      { value: '~$19', label: 'skills ×5 on Grok', sub: 'unbounded re-reads' },
    ],
    facts: [
      { k: 'Grok 4.5 price', v: '$2.00 / 1M input · $0.50 cached · $6.00 / 1M output (xAI API)' },
      { k: 'Batch math', v: '1.55M×$2 + 0.125M×$6 = $3.10 + $0.75 = $3.85 for full triage' },
      { k: 'vs skills alone', v: '4–5 agent passes re-read the tree; ~5× batch ≈ $19+ on Grok 4.5 with no fixed checklist' },
      { k: 'vs DeepSeek', v: 'Same chunk layout for $0.25 — ~15× cheaper bulk triage; reserve Grok for hard CWE' },
      { k: 'Per-finding Grok', v: '2.33M in + 125K out ≈ $5.41 — still far below open-ended multi-day agent loops' },
    ],
    tables: [
      {
        caption: 'LLM review cost for 1,042 findings (42 chunk batch)',
        headers: ['Model', 'Input $/M', 'Output $/M', 'Total cost', 'Notes'],
        rows: [
          ['DeepSeek V4-Flash', '$0.14', '$0.28', '$0.25', 'Best default for bulk triage'],
          ['DeepSeek V4-Pro', '$0.44', '$0.87', '$0.78', 'Stronger reasoning, still cheap'],
          ['Qwen 2.5 Coder 32B', '$0.18', '$0.18', '$0.30', 'Open-weight via DeepInfra / Together'],
          ['GLM-5', '$0.60', '$1.92', '$1.17', 'Z.ai · strong coding tier'],
          ['Kimi K2.7 Code', '$0.95', '$4.00', '$1.97', 'Moonshot · 256K context'],
          ['GPT-5', '$0.63', '$5.00', '$1.59', 'Mid-tier frontier'],
          ['Grok 4.5', '$2.00', '$6.00', '$3.85', 'xAI flagship · 500k context'],
          ['Claude Haiku 4.5', '$1.00', '$5.00', '$2.18', 'Fast Anthropic tier'],
          ['Claude Sonnet 5', '$2.00', '$10.00', '$4.35', 'Intro pricing thru Aug 2026'],
          ['Claude Opus 4.8', '$5.00', '$25.00', '$10.88', 'Frontier — high CWE only'],
          ['GPT-5.5', '$5.00', '$30.00', '$11.51', 'Frontier — 1M context'],
        ],
        highlightRow: 6,
      },
      {
        caption: 'Grok 4.5 cost paths (same 1,042 findings)',
        headers: ['Path', 'Tokens (approx)', 'Cost', 'What you get'],
        rows: [
          ['CodeHound scan only', '0 API tokens', '$0', '1,042 deterministic findings on disk'],
          ['Grok 4.5 · batch chunks', '1.55M in + 125K out', '$3.85', 'Full triage, fixed budget'],
          ['Grok 4.5 · per-finding', '2.33M in + 125K out', '$5.41', '1,042 separate calls'],
          ['Skills alone · 5 passes', '~5× open-ended reads', '~$19+', 'Drift, duplicates, days'],
          ['DeepSeek Flash · batch', '1.55M in + 125K out', '$0.25', 'Same checklist · 15× vs Grok batch'],
        ],
        highlightRow: 0,
      },
      {
        caption: 'Per-finding review (1,042 separate API calls — not recommended)',
        headers: ['Model', 'Input tokens', 'Output tokens', 'Total cost'],
        rows: [
          ['DeepSeek V4-Flash', '2.33M', '125K', '$0.36'],
          ['DeepSeek V4-Pro', '2.33M', '125K', '$1.12'],
          ['Grok 4.5', '2.33M', '125K', '$5.41'],
          ['Kimi K2.7 Code', '2.33M', '125K', '$2.96'],
          ['Claude Sonnet 5', '2.33M', '125K', '$5.90'],
          ['Claude Opus 4.8', '2.33M', '125K', '$14.75'],
          ['GPT-5.5', '2.33M', '125K', '$15.38'],
        ],
      },
      {
        caption: 'Tiered pipeline (practical — export once, escalate smart)',
        headers: ['Step', 'Model', 'Scope', 'Cost'],
        rows: [
          ['1 · Triage', 'DeepSeek V4-Flash', 'All 42 chunks · 1,042 findings', '$0.25'],
          ['2 · Escalate', 'Grok 4.5', '~104 ambiguous (10%)', '~$0.39'],
          ['3 · Deep CWE', 'Claude Opus 4.8', '202 high-severity CWE', '$2.69'],
          ['Total', '—', 'Full smart review', '~$3.33'],
        ],
        highlightRow: 3,
      },
    ],
    body: [
      '**Grok 4.5** is excellent at coding — and priced like a flagship ($2 / $6 per M). CodeHound keeps that spend **bounded**: export once, review chunks, never re-walk the tree for free every agent pass.',
      'Skills-only review on gopdfsuit needed **4–5** iterations over days. At Grok rates that is roughly **$19+** of open-ended reads with no stable rule IDs. One scan plus a **$0.25** DeepSeek pass (or a **$3.85** Grok batch) finishes the same checklist in minutes.',
      'Pair the **+35%** ops/sec capacity win with the token math: fewer boxes *and* fewer dollars for review.',
    ],
  },
  {
    id: 'audience',
    nav: 'Who for',
    icon: Users,
    title: 'Who this is built for',
    lead:
      'Hobby and small-scale Go projects that want less slop, clearer architecture, and real bad-practice coverage — after your normal linters, not instead of them.',
    callout:
      '**Cloud AI is subsidized.** That will not last forever. Even while it does, unbounded agent review still burns days and dollars. CodeHound is the offline checklist you run first.',
    facts: [
      { k: 'Built for', v: 'Hobby projects, side services, small Go codebases under a real delivery deadline' },
      { k: 'Run after', v: 'golangci-lint, staticcheck, govulncheck — CodeHound is a complement, never a replacement' },
      { k: 'Language (now)', v: 'Go-first production rules; Python opt-in experimental; no TypeScript plugin' },
      { k: 'Instead of skills', v: 'Deterministic PERF, BP, and footgun checks — same answer every run' },
      { k: 'Not for', v: 'Full CodeQL / org-wide SRE platforms — use the tools built for that scale' },
    ],
    body: [
      'We all know the current ChatGPT / cloud subscription model is heavily **subsidized**. That will not last forever — and even while it does, unbounded agent review still burns days and dollars.',
      '**Who this is built for:** hobby projects and **small-scale** work where you do not need enterprise-grade optimization, but you still want *some* PERF discipline, cleaner architecture, and less **slop** in the tree — under a real delivery deadline. It was built for personal use under those constraints.',
      '**When to run it:** after your existing Go CI and linters (**golangci-lint**, staticcheck, govulncheck, and whatever else you already trust). CodeHound targets hot-path PERF, framework footguns, and **bad practices** those tools often miss — it does not replace them.',
      'Anyone who wants less agent-shaped mess, proper architecture habits, or a concrete **bad-practices** catalog can use this instead of (or before) open-ended skills: rules with IDs, files, and lines — not a vibe that drifts every pass. Optional agent triage stays bounded; the checklist does not.',
      'If you need full CodeQL / org-wide security platform coverage, use those tools. If you want a fast, deterministic pass for a side project or small Go service — with optional cheap-model triage — this is for you.',
    ],
  },
  {
    id: 'how-it-works',
    nav: 'How it works',
    icon: Route,
    title: 'How it works',
    lead:
      'One binary, two output folders, you stay in control. CodeHound finds the issues — your agent helps triage and fix them.',
    callout:
      '**You own the architecture.** Findings are automatic. What ships is your call — fix, defer, baseline, or ignore. Agents propose; you decide.',
    body: [
      'By default CodeHound writes numbered context files to **./scripts/findings/functions/** and batched review chunks to **./scripts/chunks/**. Point your agent at those paths — it can classify false positives, propose fixes, and follow a checklist you write.',
      'You keep full control: which findings are real, which are noise, which get fixed now. When **60** of **100** are resolved and **40** remain, run with **--baseline** so those **40** become accepted debt. The next scan only reports regressions and new hits.',
      'Add a **make codehound** target beside your other linters. The agent handles remediation from the exported chunks; you only step in for the review calls you actually want.',
    ],
  },
  {
    id: 'your-call',
    nav: 'Your call',
    icon: Scale,
    title: 'Findings are automatic. Architecture is yours.',
    lead:
      'CodeHound reports what the rules match. You decide what ships — including whether a fix is safe, wrong, or a breaking change.',
    facts: [
      { k: 'Analysis owns', v: 'Finding the issue — rule ID, file, line, snippet' },
      { k: 'You own', v: 'Architectural decisions: fix, defer, redesign, or ignore' },
      { k: 'Before you apply', v: 'Read the surrounding code; do not rubber-stamp agent patches' },
      { k: 'Safety net', v: 'Solid tests — remediations can break behavior on purpose or by accident' },
    ],
    body: [
      'The analyzer does the **code findings**. The **final architectural decision** is yours alone. A PERF hit or CWE heuristic is a signal, not a mandate to merge whatever an agent proposes next.',
      'You need to **understand the code** before changing it. Agents (and fix hints) can suggest refactors that are correct for the rule and wrong for your system — public API breaks, subtle behavior shifts, or "optimizations" that trade correctness for speed.',
      '**Proper tests are non-negotiable.** There is a real chance remediation breaks something, or that an agent asks for a breaking change. Tests, review, and your judgment are how you catch that. CodeHound will not run your suite or sign off on design.',
      'Use the exported reports as a checklist. Ship only what you have read, understood, and covered — not everything the scan (or the model) printed.',
    ],
  },
  {
    id: 'why',
    nav: 'Why this exists',
    title: 'Why this exists',
    icon: HelpCircle,
    lead:
      'Inference is priced per token and priced again on every run. A compiled rule is priced once. As frontier models get expensive, you still need a checklist that does not drift.',
    body: [
      'CodeHound is a static analyzer. One `make run` exports 1,042 findings to disk — PERF, CWE, bad practices — for $0. No API key, no context window, no "I forgot to check file 847." The expensive part becomes optional: point a cheap model (or Grok 4.5) at `scripts/chunks/` with a known token budget.',
      'A passing agent is not a passing build. A flattered review is not a real review. Skills are prompts — they miss things, catch them differently every run, and on gopdfsuit needed four to five iterations over days. CodeHound is a program: run it twice, get the same answers. When it says CWE-79, that is a rule ID with a file, line, and snippet — not a vibe.',
      'It grew out of a real performance crisis, not a marketing exercise. A high-volume Go PDF library, weeks of low-hanging fruit already picked, profiling showing regex-in-loops and fmt.Sprintf on paths that run thousands of times per second. We needed something surgical. So we built one — and wired the export path so tomorrow\'s model has something deterministic to lean on.',
    ],
  },
  {
    id: 'numbers',
    nav: 'Numbers',
    icon: BarChart3,
    title: 'Benchmarks & latest scan',
    lead:
      'Criterion.rs on release builds for engine throughput, plus a real export run — 1,042 findings, 42 review chunks, zero inference.',
    stats: [
      { value: '1,042', label: 'findings exported', sub: 'scripts/findings/functions' },
      { value: '42', label: 'review chunks', sub: 'scripts/chunks · ~25 each' },
      { value: '39.5ms', label: 'full fixture scan', sub: '900 Go files · 275 rules' },
      { value: '+35%', label: 'gopdfsuit ops/s', sub: '~2,000 → ~2,700 after fixes' },
    ],
    facts: [
      { k: 'Severity mix', v: '202 high · 533 medium · 307 low' },
      { k: 'Top rules', v: 'CWE-79 ×192 · BP-1 ×164 · PERF-6 ×96 · PERF-192 ×80 · PERF-32 ×43' },
      { k: 'Categories', v: '533 PERF · 202 CWE · 307 bad practices' },
      { k: 'Export tokens', v: '~1.52M input tokens across 42 chunks (avg ~36K/chunk)' },
    ],
    tables: [
      {
        caption: 'Engine benchmarks (Criterion.rs, release profile)',
        headers: ['Benchmark', 'Time', 'Notes'],
        rows: [
          ['scan_materialized_fixtures', '39.5 ms', '275 detectors · 900 Go fixture files'],
          ['collect_entries_materialized', '1.0 ms', 'File discovery + language classification'],
          ['incremental warm vs cold', '≥5× faster', 'CI gate on cache-hit replay'],
          ['gopdfsuit remediation', '218 PERF fixed', '~2k → ~2.7k ops/sec after CodeHound pass'],
        ],
      },
    ],
    body: [
      'The static pass still flags the essentials — regexes compiled inside loops, fmt.Sprintf boxing on hot paths, defer frames in tight loops — but the export path now batches context for agents: one file per finding, chunked for batch triage.',
      'Four outlier chunks (findings 451–550) carry ~50% of export tokens because enclosing functions are huge. Trim context before LLM review if you want triage cost to stay flat.',
    ],
  },
  {
    id: 'skills',
    nav: 'Skills',
    icon: Sparkles,
    title: 'Skills are no better',
    lead:
      'A "skill" is a prompt. A prompt is not a guarantee. 4–5 iterations to get the essentials flagged — days you did not have.',
    body: [
      'We run AI skills internally too — Apollo best-practices, anti-pattern sweeps, ECC patterns. They catch things. They also miss things, and miss them differently every run.',
      'On the gopdfsuit remediation we iterated the skill output four to five times. Each pass surfaced duplicates the last one missed. Each pass cost a day that a single scan would have cost minutes — and at Grok 4.5 rates, roughly **$19+** of unbounded re-reads.',
      'A static rule is a program. Run it twice and you get the same answer, because the rule IS the check, not a hope about the check. When a skill says "this looks fine" that is a guess; when CodeHound says CWE-22, that is a path-taint trace from source to sink.',
      'Skills drift. Rules do not. That is the whole point.',
    ],
  },
  {
    id: 'evidence',
    nav: 'Evidence',
    icon: GitCompare,
    title: 'A finding, before and after',
    lead:
      'PERF-140: regexp compiled inside a hot loop. Fix hoisted above the loop. Table rendering flows through this path thousands of times per second.',
    code: {
      label: 'internal/pdf/form/xfdf.go — 11+ sites fixed the same way',
      lang: 'go',
      before: `for i := range members {
    nameRe := regexp.MustCompile(\`/T\\s*(?:\\(([^)]*)\\)|<([0-9A-Fa-f\\s]+)>)\`)
    if m := nameRe.FindSubmatch(obj); m != nil {
        // ...
    }
}`,
      after: `var nameRe = regexp.MustCompile(\`/T\\s*(?:\\(([^)]*)\\)|<([0-9A-Fa-f\\s]+)>)\`)

for i := range members {
    if m := nameRe.FindSubmatch(obj); m != nil {
        // ...
    }
}`,
    },
    body: [
      'This is the shape of a CodeHound finding: **rule ID**, file, line, snippet, and a fix that is usually local. Multiply by hundreds of hot-path sites and you get the +35% throughput story — not a single heroic refactor.',
    ],
  },
  {
    id: 'rules',
    nav: 'Rules',
    icon: ShieldAlert,
    title: 'What it flags',
    lead:
      'Three catalogs, one AST walk. Rules are data — ship a rule, ship a finding. Go-first; production bar is 0.1.0.',
    callout:
      '**Complements, does not replace.** Run after golangci-lint + govulncheck for app-level PERF, framework footguns, and curated CWE heuristics.',
    facts: [
      { k: 'PERF rules', v: '224 across 60+ detectors — regex-in-loops, fmt.Sprintf on hot paths, defer in hot funcs, request-path allocation thrash' },
      { k: 'CWE heuristics', v: '175+ fixture-backed entries for file I/O, SQL injection, command injection; auto-generated from sink registry' },
      { k: 'Bad practices', v: '65 across 7 categories: errors, concurrency, testing, API design, prod hardening' },
      { k: 'Framework footguns', v: 'Gin / Echo / GORM / sqlx aware — unclosed bodies, unbounded rows, missing timeouts, context leaks' },
      { k: 'Taint (experimental)', v: 'intra-procedural, name-string sinks; CWE-22/78/79/89 — use for triage, not hard gates' },
      { k: 'Languages', v: 'Go (production); Python opt-in (1 experimental rule, SLOP101)' },
    ],
    body: [
      'Default profile is the **recommended pack**: S-tier PERF + taint-core CWEs, BP off, fail on high. Switch packs with `--profile security` or `--profile all`. List everything with `codehound --list-rules`; deep-dive one rule with `codehound --explain PERF-101`.',
      'Non-goals, stated plainly: not a golangci-lint / staticcheck / govulncheck / CodeQL replacement; not a CVE scanner; not default-on full BP in CI.',
    ],
  },
  {
    id: 'outputs',
    nav: 'Outputs',
    icon: FileOutput,
    title: 'Three formats, fits the CI you already have',
    lead:
      'Text for the terminal, NDJSON for jq, SARIF 2.1.0 for GitHub Code Scanning. One binary, no service.',
    facts: [
      { k: 'Text', v: 'color-coded severity, per-finding snippet, fix hint, summary footer' },
      { k: 'JSON', v: 'NDJSON stream, stable fingerprint (codehound:2:rule:file:msghash), jq-able' },
      { k: 'SARIF', v: '2.1.0, security-severity mapped, partialFingerprints, runs in GitHub Code Scanning' },
      { k: 'Cache', v: 'per-file content-hash, ~27× speedup on repeat scans, enabled by default' },
      { k: 'Agent export', v: 'scripts/findings/functions + scripts/chunks — fixed context for batch triage' },
    ],
    body: [
      'Wire it into CI the same way you wire any linter: `codehound --format sarif ./... > out.sarif`, or keep text for humans and JSON for scripts. Incremental cache is on by default; force rebuild with `--rebuild-cache` when you need a cold pass.',
    ],
  },
  {
    id: 'install',
    nav: 'Install',
    icon: Package,
    title: 'Install & common commands',
    lead:
      'Single static binary. No toolchain required at scan time. Go-first default build; Python is an optional Cargo feature.',
    code: {
      label: 'quick start',
      lang: 'sh',
      body: `# install
cargo install --path .

# optional experimental Python (SLOP101 only)
cargo install --path . --features python

# default = recommended pack (S-tier PERF + taint-core CWEs)
codehound .

# product wedge — request-path / timeouts
codehound --profile recommended --only PERF-101 .

# security pack or full catalog
codehound --profile security .
codehound --profile all .

# machine-readable
codehound --format json ./...
codehound --format sarif ./... > out.sarif

# test files excluded by default
codehound --include-tests .

# rule browser
codehound --list-rules
codehound --explain PERF-101

# starter config
codehound init`,
    },
    facts: [
      { k: 'Profiles', v: 'recommended · security · all — see docs/go-recommended-pack.md' },
      { k: 'Cache', v: '--rebuild-cache · --prune-cache · --no-cache' },
      { k: 'Baseline', v: 'accept known debt; next scan only reports new / regressed findings' },
      { k: 'CI sample', v: '.github/workflows/codehound.yml in the repo' },
    ],
  },
  {
    id: 'extend',
    nav: 'Extend',
    icon: Blocks,
    title: 'Built to extend',
    lead:
      'The catalog is data. The CWE list is auto-generated from a sink registry. This website is the same idea — the nav is data, the page is a renderer.',
    body: [
      'New analyzer? Add one entry to the sink registry. The CWE catalog (175+) regenerates.',
      'New language? Ship a real plugin — Go is production; Python is opt-in (one rule); no TypeScript stub.',
      'New section on this page? Add one entry to src/data/sections.ts. The nav, the scroll target, the layout all follow — no special cases.',
    ],
  },
]
