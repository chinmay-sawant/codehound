import { useEffect, useMemo, useState } from 'react'

/** Two-line hero lines: plain lead + accented second line. */
export type HeroLine = {
  lead: string
  accent: string
}

export const HERO_LINES: readonly HeroLine[] = [
  { lead: 'Catch Go costs', accent: 'before they ship.' },
  { lead: 'Find Go bottlenecks', accent: 'before pprof.' },
  { lead: 'Known Go traps,', accent: 'found offline.' },
  { lead: 'A checklist for Go', accent: 'before the agent.' },
  { lead: 'Go performance,', accent: 'file and line.' },
  { lead: 'Stop rediscovering', accent: 'the same Go costs.' },
] as const

type Phase = 'typing' | 'holding' | 'sliding-out'

const TYPE_MS = 38
const HOLD_MS = 2600
const SLIDE_MS = 340

function prefersReducedMotion(): boolean {
  return (
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  )
}

/**
 * Full text is always in the layout (final wrap). Characters not yet typed
 * stay invisible but still occupy space, so words never jump to the next line
 * mid-type.
 */
function TypedLine({
  text,
  visibleCount,
  showCaret,
  asEm = false,
}: {
  text: string
  visibleCount: number
  showCaret: boolean
  asEm?: boolean
}) {
  const chars = Array.from(text)
  const content = chars.map((ch, i) => {
    const typed = i < visibleCount
    const caretHere = showCaret && i === Math.max(0, visibleCount - 1) && visibleCount > 0
    return (
      <span key={`${i}-${ch}`} className={typed ? 'is-typed' : 'is-pending'}>
        {ch}
        {caretHere && <span className="hero-caret" aria-hidden="true" />}
      </span>
    )
  })

  return (
    <span className="hero-title-line" aria-hidden="true">
      {asEm ? <em className="hero-title-typed-em">{content}</em> : content}
      {showCaret && visibleCount === 0 && <span className="hero-caret" aria-hidden="true" />}
      {showCaret && visibleCount >= text.length && text.length > 0 && (
        /* caret already on last char when fully typed; nothing extra */
        null
      )}
    </span>
  )
}

/**
 * Cycles hero headlines with a typewriter + short vertical slide.
 * Slot height is locked to the tallest full phrase so the page layout never jumps.
 */
export function HeroTitle({ lines = HERO_LINES }: { lines?: readonly HeroLine[] }) {
  const [index, setIndex] = useState(0)
  const [phase, setPhase] = useState<Phase>('typing')
  const [leadLen, setLeadLen] = useState(0)
  const [accentLen, setAccentLen] = useState(0)
  const [reduced, setReduced] = useState(false)

  const current = lines[index % lines.length]!
  const fullLabel = useMemo(
    () => lines.map((l) => `${l.lead} ${l.accent}`).join('. '),
    [lines],
  )

  useEffect(() => {
    if (!prefersReducedMotion()) return
    setReduced(true)
    setLeadLen(lines[0]!.lead.length)
    setAccentLen(lines[0]!.accent.length)
    setPhase('holding')
  }, [lines])

  useEffect(() => {
    if (reduced) return

    let timer: ReturnType<typeof setTimeout>

    if (phase === 'typing') {
      if (leadLen < current.lead.length) {
        timer = setTimeout(() => setLeadLen((n) => n + 1), TYPE_MS)
      } else if (accentLen < current.accent.length) {
        timer = setTimeout(() => setAccentLen((n) => n + 1), TYPE_MS)
      } else {
        setPhase('holding')
      }
    } else if (phase === 'holding') {
      timer = setTimeout(() => setPhase('sliding-out'), HOLD_MS)
    } else if (phase === 'sliding-out') {
      timer = setTimeout(() => {
        setIndex((i) => (i + 1) % lines.length)
        setLeadLen(0)
        setAccentLen(0)
        setPhase('typing')
      }, SLIDE_MS)
    }

    return () => clearTimeout(timer)
  }, [
    reduced,
    phase,
    leadLen,
    accentLen,
    current.lead,
    current.accent,
    lines.length,
  ])

  const typing = !reduced && phase === 'typing'
  const caretOnLead = typing && leadLen < current.lead.length
  const caretOnAccent =
    typing && leadLen >= current.lead.length && accentLen <= current.accent.length

  // During hold, show full text; during slide-out keep full text visible until swap.
  const leadVisible =
    phase === 'holding' || phase === 'sliding-out' || reduced
      ? current.lead.length
      : leadLen
  const accentVisible =
    phase === 'holding' || phase === 'sliding-out' || reduced
      ? current.accent.length
      : accentLen

  return (
    <div className="hero-title-slot">
      {/*
        Invisible full phrases share one grid cell with the live title.
        The slot’s height becomes the max of every complete line, so typing /
        clearing never resizes the hero or the signal strip below it.
      */}
      {lines.map((line) => (
        <div key={`${line.lead}-${line.accent}`} className="hero-title-sizer" aria-hidden="true">
          <span className="hero-title-line">{line.lead}</span>
          <span className="hero-title-line hero-title-accent">
            <em>{line.accent}</em>
          </span>
        </div>
      ))}
      <h1
        id="hero-title"
        className={`hero-title${phase === 'sliding-out' ? ' is-slide-out' : ''}${
          phase === 'typing' && leadLen === 0 && accentLen === 0 ? ' is-slide-in' : ''
        }`}
        aria-label={fullLabel}
      >
        <TypedLine text={current.lead} visibleCount={leadVisible} showCaret={caretOnLead} />
        <TypedLine
          text={current.accent}
          visibleCount={accentVisible}
          showCaret={Boolean(caretOnAccent && phase === 'typing')}
          asEm
        />
      </h1>
    </div>
  )
}
