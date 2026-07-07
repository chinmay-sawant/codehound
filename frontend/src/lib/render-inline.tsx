import type { ReactNode } from 'react'

/** Renders `**bold**` spans inside section body copy. */
export function renderInlineMarkup(text: string): ReactNode[] {
  const parts = text.split(/\*\*(.+?)\*\*/g)
  return parts.map((part, i) =>
    i % 2 === 1 ? <strong key={i}>{part}</strong> : part,
  )
}