import { sections } from '../data/sections'

const SECTION_IDS = new Set(sections.map((s) => s.id))

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
 * Update the URL hash without a full navigation.
 * - `push` for explicit nav clicks (back/forward works)
 * - `replace` for scroll-spy so copy-URL stays current without history spam
 */
export function setSectionHash(
  id: string | null,
  mode: 'push' | 'replace' = 'replace',
): void {
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

/** Scroll a section (or top) into view. */
export function scrollToSection(
  id: string | null,
  behavior: ScrollBehavior = 'smooth',
): void {
  if (!id) {
    window.scrollTo({ top: 0, behavior })
    return
  }
  const el = document.getElementById(id)
  if (el) el.scrollIntoView({ behavior, block: 'start' })
}
