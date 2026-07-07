import type { LucideIcon } from 'lucide-react'
import {
  HelpCircle, BarChart3, Sparkles, GitCompare, ShieldAlert,
  FileOutput, Coins, Blocks, Route, Monitor, Download, FolderGit2,
  FolderOutput, Bot, ListChecks, ClipboardList, Hash, Bookmark,
  RefreshCw, Terminal,
} from 'lucide-react'
import type { FlowDiagram } from '../components/WorkflowDiagram'

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
  body?: string[]
  stats?: Stat[]
  facts?: Fact[]
  tables?: DataTable[]
  code?: CodeBlock
  flows?: FlowDiagram[]
}

export const sections: Section[] = [
  {
    id: 'how-it-works',
    nav: 'How it works',
    icon: Route,
    title: 'How it works',
    lead:
      'One binary, two output folders, you stay in control. CodeHound finds the issues - your agent helps triage and fix them.',
    flows: [
      {
        caption: 'Setup → scan → export',
        rows: [
          {
            segments: [
              { kind: 'node', step: { label: 'Your machine', hint: 'Win · Linux · macOS', icon: Monitor } },
              {
                kind: 'fork',
                left: { label: 'Download binary', cmd: 'codehound .', icon: Download },
                right: { label: 'Clone repo', cmd: 'make run', icon: FolderGit2 },
              },
              {
                kind: 'node',
                step: {
                  label: 'Artifacts on disk',
                  hint: 'scripts/chunks · scripts/findings',
                  icon: FolderOutput,
                },
              },
            ],
          },
        ],
      },
      {
        caption: 'Agent review → baseline → loop',
        rows: [
          {
            segments: [
              { kind: 'node', step: { label: 'Feed to agent', hint: 'OpenCode · Claude Code', icon: Bot } },
              { kind: 'node', step: { label: 'Triage findings', hint: 'FP · fix · defer', icon: ListChecks } },
              { kind: 'node', step: { label: 'Guide with checklist', hint: 'you pick what ships', icon: ClipboardList } },
            ],
          },
          {
            segments: [
              { kind: 'node', step: { label: '100 findings', hint: '60 fixed · 40 remain', icon: Hash } },
              { kind: 'node', step: { label: 'Set baseline', cmd: 'codehound . --baseline', icon: Bookmark } },
              { kind: 'node', step: { label: 'Re-scan', cmd: 'codehound .', icon: RefreshCw } },
            ],
          },
          {
            segments: [
              { kind: 'node', step: { label: 'Makefile target', cmd: 'make codehound', hint: 'like any linter', icon: Terminal } },
            ],
          },
        ],
        loop: { label: 'repeat until clean or baseline is stable', target: '↩ back to scan' },
      },
    ],
    body: [
      'By default CodeHound writes numbered context files to **./scripts/findings/functions/** and batched review chunks to **./scripts/chunks/**. Point your agent at those paths — it can classify false positives, propose fixes, and follow a checklist you write.',
      'You keep full control: which findings are real, which are noise, which get fixed now. When **60** of **100** are resolved and **40** remain, run with **--baseline** so those **40** become accepted debt. The next scan only reports regressions and new hits.',
      'Add a **make codehound** target beside your other linters. The agent handles remediation from the exported chunks; you only step in for the review calls you actually want.',
    ],
  },
  {
    id: 'why',
    nav: 'Why this exists',
    title: 'Why this exists',
    icon: HelpCircle,
    lead:
      'Inference is priced per token and priced again on every run. A compiled rule is priced once. As frontier models get expensive, you still need a checklist that does not drift — something a DeepSeek or Kimi pass can triage for cents, not an Opus pass for fifteen dollars.',
    body: [
      'CodeHound is a static analyzer. One `make run` exports 1,042 findings to disk — PERF, CWE, bad practices — for $0. No API key, no context window, no "I forgot to check file 847." The expensive part becomes optional: point a cheap model at `scripts/chunks/` and let it classify false positives.',
      'A passing agent is not a passing build. A flattered review is not a real review. Skills are prompts — they miss things, catch them differently every run, and on gopdfsuit needed four to five iterations over days. CodeHound is a program: run it twice, get the same 1,042 answers. When it says CWE-79, that is a rule ID with a file, line, and snippet — not a vibe.',
      'It grew out of a real performance crisis, not a marketing exercise. A high-volume Go PDF library, weeks of low-hanging fruit already picked, profiling showing regex-in-loops and fmt.Sprintf on paths that run thousands of times per second. We needed something surgical. So we built one — and wired the export path so tomorrow\'s cheaper model has something deterministic to lean on.',
    ],
  },
  {
    id: 'numbers',
    nav: 'Numbers',
    icon: BarChart3,
    title: 'Benchmarks & latest scan',
    lead:
      'Criterion.rs on release builds for engine throughput, plus a real export run over the current tree — 1,042 findings, 42 review chunks, zero inference.',
    stats: [
      { value: '1,042', label: 'findings exported', sub: 'scripts/findings/functions' },
      { value: '42', label: 'review chunks', sub: 'scripts/chunks · ~25 each' },
      { value: '39.5ms', label: 'full fixture scan', sub: '900 Go files · 275 rules' },
      { value: '3.4×', label: 'downstream ops/s', sub: 'gopdfsuit · 573 → 9,594' },
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
          ['gopdfsuit remediation', '226 → 218 fixed', '+13% table throughput after one pass'],
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
      'A "skill" is a prompt. A prompt is not a guarantee. 4–5 iterations to get the essentials flagged - days you did not have.',
    body: [
      'We run AI skills internally too - Apollo best-practices, anti-pattern sweeps, ECC patterns. They catch things. They also miss things, and miss them differently every run.',
      'On the gopdfsuit remediation we iterated the skill output four to five times. Each pass surfaced duplicates the last one missed. Each pass cost a day that a single scan would have cost minutes.',
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
      label: 'internal/pdf/form/xfdf.go - 11+ sites fixed the same way',
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
  },
  {
    id: 'rules',
    nav: 'Rules',
    icon: ShieldAlert,
    title: 'What it flags',
    lead:
      'Three catalogs, one AST walk. Rules are data - ship a rule, ship a finding.',
    facts: [
      { k: 'CWE rules', v: '175+ auto-generated from a central sink registry, mapped to MITRE' },
      { k: 'PERF rules', v: '224 across 60+ detectors - regex-in-loops, fmt.Sprintf on hot paths, defer in hot funcs' },
      { k: 'Bad practices', v: '65 across 7 categories: errors, concurrency, testing, API design, prod hardening' },
      { k: 'Taint', v: 'intra-procedural, 5 sources → 6 sinks, 6 sanitizer families; CWE-22/78/79/89 live' },
      { k: 'Languages', v: 'Go (production), Python (default-on), TypeScript (gated)' },
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
      { k: 'JSON', v: 'NDJSON stream, stable fingerprint (codehound:1:rule:file:line:col), jq-able' },
      { k: 'SARIF', v: '2.1.0, security-severity mapped, partialFingerprints, runs in GitHub Code Scanning' },
      { k: 'Cache', v: 'per-file content-hash, ~27× speedup on repeat scans, enabled by default' },
    ],
  },
  {
    id: 'cost',
    nav: 'Cost',
    icon: Coins,
    title: 'Scan free. Review cheap.',
    lead:
      'CodeHound detection costs $0 — one `make run`, ~1.5M tokens of exported context. LLM triage is optional; open-weight models make it cents, not dollars.',
    stats: [
      { value: '$0', label: 'CodeHound scan', sub: '1,042 findings · offline' },
      { value: '$0.25', label: 'DeepSeek triage', sub: '42 chunk batch' },
      { value: '$4.90', label: 'smart pipeline', sub: 'Flash → Sonnet → Opus' },
      { value: '$14.75', label: 'Opus per-finding', sub: '1,042 separate calls' },
    ],
    facts: [
      { k: 'Review workload', v: '1.55M input + 125K output tokens (42 chunk batch, 120 tok verdict each)' },
      { k: 'Recommended path', v: 'DeepSeek V4-Flash triage all chunks → Sonnet on ~10% ambiguous → Opus on 202 high CWE' },
      { k: 'Savings vs frontier', v: '~3× cheaper than Opus batch · ~59× cheaper than Opus per-finding' },
      { k: 'Skills alone', v: 'No fixed token budget — re-reads the repo every pass; 4–5 iterations × days on gopdfsuit' },
    ],
    tables: [
      {
        caption: 'LLM review cost for 1,042 findings (42 chunk batch — recommended)',
        headers: ['Model', 'Input $/M', 'Output $/M', 'Total cost', 'Notes'],
        rows: [
          ['DeepSeek V4-Flash', '$0.14', '$0.28', '$0.25', 'Best default for bulk triage'],
          ['DeepSeek V4-Pro', '$0.44', '$0.87', '$0.78', 'Stronger reasoning, still cheap'],
          ['Qwen 2.5 Coder 32B', '$0.18', '$0.18', '$0.30', 'Open-weight via DeepInfra / Together'],
          ['GLM-5', '$0.60', '$1.92', '$1.17', 'Z.ai · strong coding tier'],
          ['Kimi K2.7 Code', '$0.95', '$4.00', '$1.97', 'Moonshot · 256K context'],
          ['GPT-5', '$0.63', '$5.00', '$1.59', 'Mid-tier frontier'],
          ['Claude Haiku 4.5', '$1.00', '$5.00', '$2.18', 'Fast Anthropic tier'],
          ['Claude Sonnet 5', '$2.00', '$10.00', '$4.35', 'Intro pricing thru Aug 2026'],
          ['Claude Opus 4.8', '$5.00', '$25.00', '$10.88', 'Frontier — use for high CWE only'],
          ['GPT-5.5', '$5.00', '$30.00', '$11.51', 'Frontier — 1M context'],
        ],
        highlightRow: 0,
      },
      {
        caption: 'Per-finding review (1,042 separate API calls — not recommended)',
        headers: ['Model', 'Input tokens', 'Output tokens', 'Total cost'],
        rows: [
          ['DeepSeek V4-Flash', '2.33M', '125K', '$0.36'],
          ['DeepSeek V4-Pro', '2.33M', '125K', '$1.12'],
          ['Kimi K2.7 Code', '2.33M', '125K', '$2.96'],
          ['Claude Sonnet 5', '2.33M', '125K', '$5.90'],
          ['Claude Opus 4.8', '2.33M', '125K', '$14.75'],
          ['GPT-5.5', '2.33M', '125K', '$15.38'],
        ],
      },
      {
        caption: 'Tiered pipeline (practical — matches exported chunk layout)',
        headers: ['Step', 'Model', 'Scope', 'Cost'],
        rows: [
          ['1 · Triage', 'DeepSeek V4-Flash', 'All 42 chunks · 1,042 findings', '$0.25'],
          ['2 · Escalate', 'Claude Sonnet 5', '~104 ambiguous (10%)', '$1.96'],
          ['3 · Deep CWE', 'Claude Opus 4.8', '202 high-severity CWE', '$2.69'],
          ['Total', '—', 'Full smart review', '$4.90'],
        ],
        highlightRow: 3,
      },
    ],
    body: [
      'CodeHound never bills per token — you pay compute once per build. The exported chunks turn agent review into a bounded workload: ~1.5M input tokens, not an open-ended repo read.',
      'Open-weight models (DeepSeek Flash, Qwen Coder, GLM-5, Kimi K2.7 Code) cover bulk triage for under $2. Reserve Opus and GPT-5.5 for the ~200 high CWE hits where exploit reasoning matters.',
      'Compared to skills-only review: same gopdfsuit run needed 4–5 agent iterations over days. One CodeHound scan plus a $0.25 DeepSeek pass gets the same checklist in minutes.',
    ],
  },
  {
    id: 'extend',
    nav: 'Extend',
    icon: Blocks,
    title: 'Built to extend',
    lead:
      'The catalog is data. The CWE list is auto-generated from a sink registry. This website is the same idea - the nav is data, the page is a renderer.',
    body: [
      'New analyzer? Add one entry to the sink registry. The CWE catalog (175+) regenerates.',
      'New language? Ship a plugin - Python is already live behind a feature flag, TypeScript is gated.',
      'New section on this page? Add one entry to src/data/sections.ts. The sidebar, the scroll target, the layout all follow - no special cases.',
    ],
  },
]