import type { LucideIcon } from 'lucide-react'
import {
  HelpCircle, BarChart3, Sparkles, GitCompare, ShieldAlert,
  FileOutput, Coins, Blocks,
} from 'lucide-react'

export type Stat = { value: string; label: string; sub?: string }
export type Fact = { k: string; v: string }
export type CodeBlock = { label: string; lang: string; before?: string; after?: string; body?: string }

export type Section = {
  id: string
  nav: string
  title: string
  lead: string
  icon: LucideIcon
  body?: string[]
  stats?: Stat[]
  facts?: Fact[]
  code?: CodeBlock
}

export const sections: Section[] = [
  {
    id: 'why',
    nav: 'Why',
    title: 'Why does this exist?',
    icon: HelpCircle,
    lead:
      'AI models are cheap today because they are subsidized. They will not stay cheap. Tomorrow you run a cheaper, less expert model — and it needs something deterministic to lean on.',
    body: [
      'SlopGuard is a static analyzer. It reads your code and tells you what is wrong, deterministically, offline, at the cost of one build — not one inference call.',
      'A passing agent is not a passing build. A flattered review is not a real review. The honest reviewer is a program you can re-run and that answers the same way every time.',
      'It grew out of a real performance crisis, not a marketing exercise: a high-volume Go PDF library, weeks of low-hanging fruit already picked, "we needed something more surgical." So we built one.',
    ],
  },
  {
    id: 'numbers',
    nav: 'Numbers',
    icon: BarChart3,
    title: 'What one scan turned into',
    lead:
      'One pass over a real Go codebase. Sourced — not projected, not modeled.',
    stats: [
      { value: '226', label: 'findings exported', sub: 'one AST scan' },
      { value: '218', label: 'real, all fixed', sub: '8 CWE filtered' },
      { value: '+13%', label: 'table throughput', sub: 'table_180_rows' },
      { value: '3.4×', label: 'downstream ops/s', sub: '573 → 9,594' },
    ],
    body: [
      'The static pass flagged the essentials — regexes compiled inside loops, fmt.Sprintf boxing args on hot paths, defer frames allocated millions of times per hour.',
      'Fixed in one deterministic pass. The heaviest CPU workloads jumped +4.6% to +13%. That foundation later carried the end-to-end benchmark to 3.4× its original throughput.',
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
      'On the gopdfsuit remediation we iterated the skill output four to five times. Each pass surfaced duplicates the last one missed. Each pass cost a day that a single scan would have cost minutes.',
      'A static rule is a program. Run it twice and you get the same answer, because the rule IS the check, not a hope about the check. When a skill says "this looks fine" that is a guess; when SlopGuard says CWE-22, that is a path-taint trace from source to sink.',
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
  },
  {
    id: 'rules',
    nav: 'Rules',
    icon: ShieldAlert,
    title: 'What it flags',
    lead:
      'Three catalogs, one AST walk. Rules are data — ship a rule, ship a finding.',
    facts: [
      { k: 'CWE rules', v: '175+ auto-generated from a central sink registry, mapped to MITRE' },
      { k: 'PERF rules', v: '224 across 60+ detectors — regex-in-loops, fmt.Sprintf on hot paths, defer in hot funcs' },
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
    title: 'Billed once, not per run',
    lead:
      'A model call is billed per token, per run, forever. A compiled rule is billed once — the hour you wrote it.',
    body: [
      'No LLM in the loop. No API budget. No rate limits. No "context too long".',
      'On a CI box that is the difference between cents and dollars, every push — and as the cheap-model era ends, that delta only widens.',
      'You pay compute for a build, not inference for a review. The review becomes infrastructure; it stops being a sentence you have to buy',
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
      'New language? Ship a plugin — Python is already live behind a feature flag, TypeScript is gated.',
      'New section on this page? Add one entry to src/data/sections.ts. The sidebar, the scroll target, the layout all follow — no special cases.',
    ],
  },
]