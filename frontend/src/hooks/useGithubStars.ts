import { useCallback, useEffect, useState } from 'react'

const REPO = 'chinmay-sawant/codehound'
const CACHE_KEY = 'codehound-gh-stars'
const TTL_MS = 5 * 60 * 1000

type CachePayload = {
  stars: number
  fetchedAt: number
}

function readCache(): CachePayload | null {
  try {
    const raw = localStorage.getItem(CACHE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as CachePayload
    if (typeof parsed.stars !== 'number' || typeof parsed.fetchedAt !== 'number') {
      return null
    }
    return parsed
  } catch {
    return null
  }
}

function writeCache(stars: number) {
  const payload: CachePayload = { stars, fetchedAt: Date.now() }
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify(payload))
  } catch {
    /* ignore quota / private mode */
  }
}

function isHardReload(): boolean {
  try {
    const nav = performance.getEntriesByType('navigation')[0] as
      | PerformanceNavigationTiming
      | undefined
    return nav?.type === 'reload'
  } catch {
    return false
  }
}

function isFresh(cache: CachePayload): boolean {
  return Date.now() - cache.fetchedAt < TTL_MS
}

async function fetchStars(): Promise<number> {
  const res = await fetch(`https://api.github.com/repos/${REPO}`, {
    headers: { Accept: 'application/vnd.github+json' },
  })
  if (!res.ok) throw new Error(`GitHub API ${res.status}`)
  const data = (await res.json()) as { stargazers_count?: number }
  if (typeof data.stargazers_count !== 'number') {
    throw new Error('missing stargazers_count')
  }
  return data.stargazers_count
}

/**
 * GitHub star count with localStorage cache (5 min TTL).
 * - Uses cache when fresh
 * - Hard reload forces a network fetch
 * - Background refresh every 5 minutes while the page is open
 */
export function useGithubStars() {
  const [stars, setStars] = useState<number | null>(() => {
    const cache = readCache()
    return cache ? cache.stars : null
  })
  const [loading, setLoading] = useState(false)

  const refresh = useCallback(async (force: boolean) => {
    const cache = readCache()
    if (!force && cache && isFresh(cache)) {
      setStars(cache.stars)
      return
    }

    setLoading(true)
    try {
      const count = await fetchStars()
      writeCache(count)
      setStars(count)
    } catch {
      // keep last known cache on failure
      if (cache) setStars(cache.stars)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    const force = isHardReload()
    void refresh(force)

    const id = window.setInterval(() => {
      void refresh(true)
    }, TTL_MS)

    return () => window.clearInterval(id)
  }, [refresh])

  return { stars, loading }
}

export function formatStarCount(n: number): string {
  if (n >= 1000) {
    const k = n / 1000
    return k >= 10 ? `${Math.round(k)}k` : `${k.toFixed(1).replace(/\.0$/, '')}k`
  }
  return String(n)
}
