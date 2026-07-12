import { sections } from '../data/sections'

const SECTION_IDS = new Set(sections.map((s) => s.id))

/** Extra gap below the fixed nav when scrolling a section into view. */
const NAV_GAP_PX = 12

/** Fallback if --nav-h is missing from CSS. */
const NAV_H_FALLBACK = 52

/**
 * How long to keep scroll-spy from rewriting the hash after a click.
 * Must outlast a long smooth scroll; release early once the target is settled.
 */
const NAV_LOCK_MAX_MS = 2500

/** px tolerance when deciding "we've arrived" at a section pin. */
const SETTLE_TOLERANCE_PX = 64

/**
 * Target of the in-flight programmatic navigation.
 * - `undefined` → unlocked (scroll-spy owns the hash)
 * - `null` → scrolling to hero / top
 * - `string` → scrolling to that section id
 */
let lockedTarget: string | null | undefined = undefined
let lockTimer: ReturnType<typeof setTimeout> | null = null

/** Parse a location hash into a known section id, or null. */
export function sectionIdFromHash(hash: string): string | null {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash
  if (!raw || raw === 'top') return null
  return SECTION_IDS.has(raw) ? raw : null
}

/** Current hash without the leading `#`. */
export function currentHashId(): string | null {
  return sectionIdFromHash(window.location.hash)
}

/**
 * True while a programmatic nav scroll is in flight.
 * Scroll-spy must not rewrite the hash during this window.
 */
export function isNavLocked(): boolean {
  return lockedTarget !== undefined
}

/** The section (or top) the user asked to go to, if a nav is in flight. */
export function getLockedNavTarget(): string | null | undefined {
  return lockedTarget
}

function clearLockTimer(): void {
  if (lockTimer !== null) {
    clearTimeout(lockTimer)
    lockTimer = null
  }
}

function releaseNavLock(): void {
  lockedTarget = undefined
  clearLockTimer()
}

/**
 * Pin the URL/active state to `target` until the scroll settles on it.
 * Call this *before* changing the hash so spy cannot race the first frame.
 */
export function beginProgrammaticNav(target: string | null): void {
  lockedTarget = target
  clearLockTimer()
  // Safety net if settle detection never fires (tab backgrounded, etc.).
  lockTimer = setTimeout(() => {
    releaseNavLock()
  }, NAV_LOCK_MAX_MS)
}

/** Pixels the fixed top nav occupies, plus a small breathing gap. */
export function navScrollOffset(): number {
  const raw = getComputedStyle(document.documentElement)
    .getPropertyValue('--nav-h')
    .trim()
  const navH = parseFloat(raw)
  return (Number.isFinite(navH) ? navH : NAV_H_FALLBACK) + NAV_GAP_PX
}

function isSettledOn(target: string | null): boolean {
  if (target === null) {
    return window.scrollY <= SETTLE_TOLERANCE_PX
  }
  const el = document.getElementById(target)
  if (!el) return true

  const top = el.getBoundingClientRect().top
  const goal = navScrollOffset()
  // Close to the pin, or the section header has reached/passed it (overshoot).
  return Math.abs(top - goal) <= SETTLE_TOLERANCE_PX || top <= goal + 8
}

/**
 * If a programmatic nav is in flight and the viewport has reached its target,
 * unlock scroll-spy. Call from the scroll handler.
 */
export function releaseNavLockIfSettled(): void {
  if (lockedTarget === undefined) return
  if (isSettledOn(lockedTarget)) releaseNavLock()
}

/**
 * Update the URL hash without a full navigation.
 * - `push` for explicit nav clicks (back/forward works)
 * - `replace` for scroll-spy so copy-URL stays current without history spam
 */
export function setSectionHash(
  id: string | null,
  mode: 'push' | 'replace' = 'replace',
): void {
  // Scroll-spy uses replace. While a click-nav is in flight, ignore any
  // attempt to point the URL at a different section (the mid-scroll flicker).
  if (mode === 'replace' && lockedTarget !== undefined && id !== lockedTarget) {
    return
  }

  const nextHash = id ? `#${id}` : ''
  const { pathname, search, hash } = window.location
  if (hash === nextHash || (!hash && !nextHash)) return

  const url = `${pathname}${search}${nextHash}`
  if (mode === 'push') {
    window.history.pushState(null, '', url)
  } else {
    window.history.replaceState(null, '', url)
  }
}

/**
 * Scroll a section (or top) into view with a single explicit nav offset.
 * Does not manage the nav lock — callers that change the URL should
 * `beginProgrammaticNav` first so spy cannot clobber the hash mid-scroll.
 */
export function scrollToSection(
  id: string | null,
  behavior: ScrollBehavior = 'smooth',
): void {
  if (!id) {
    window.scrollTo({ top: 0, behavior })
    return
  }

  const el = document.getElementById(id)
  if (!el) return

  const top = Math.max(
    0,
    window.scrollY + el.getBoundingClientRect().top - navScrollOffset(),
  )
  window.scrollTo({ top, behavior })
}
