/**
 * FraudTrace AI — XSS-Safe Markdown Renderer
 * Renders a bounded subset of Markdown (headings, paragraphs, bold, inline code,
 * unordered/ordered lists, and blockquotes) purely into React elements without
 * `dangerouslySetInnerHTML` or raw HTML evaluation.
 */

import { Fragment } from 'react'
import type { ReactNode } from 'react'

function renderInlineTokens(text: string, keyPrefix: string): ReactNode[] {
  const tokenPattern = /(\*\*[^*]+\*\*|`[^`]+`)/g
  const parts = text.split(tokenPattern)
  return parts.map((part, idx) => {
    const key = `${keyPrefix}-tok-${idx}`
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
      return (
        <strong key={key} className="font-semibold text-white">
          {part.slice(2, -2)}
        </strong>
      )
    }
    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
      return (
        <code
          key={key}
          className="rounded border border-slate-700/80 bg-slate-900/90 px-1.5 py-0.5 font-mono text-[11px] text-sky-300"
        >
          {part.slice(1, -1)}
        </code>
      )
    }
    return <Fragment key={key}>{part}</Fragment>
  })
}

export interface SafeMarkdownProps {
  content: string
}

export function SafeMarkdown({ content }: SafeMarkdownProps) {
  const normalized = content.replace(/\r\n/g, '\n').trim()
  if (!normalized) {
    return null
  }

  const lines = normalized.split('\n')
  const blocks: ReactNode[] = []
  let i = 0

  while (i < lines.length) {
    const rawLine = lines[i]
    const trimmed = rawLine.trim()

    if (!trimmed) {
      i += 1
      continue
    }

    // Headings (#, ##, ###)
    const headingMatch = trimmed.match(/^(#{1,3})\s+(.+)$/)
    if (headingMatch) {
      const level = headingMatch[1].length
      const headingText = headingMatch[2]
      const key = `md-h-${i}`
      if (level === 1) {
        blocks.push(
          <h3 key={key} className="text-sm font-semibold text-white">
            {renderInlineTokens(headingText, key)}
          </h3>,
        )
      } else if (level === 2) {
        blocks.push(
          <h4 key={key} className="text-xs font-semibold uppercase tracking-wide text-sky-300">
            {renderInlineTokens(headingText, key)}
          </h4>,
        )
      } else {
        blocks.push(
          <h5 key={key} className="text-xs font-semibold text-slate-200">
            {renderInlineTokens(headingText, key)}
          </h5>,
        )
      }
      i += 1
      continue
    }

    // Blockquote (> ...)
    if (trimmed.startsWith('>')) {
      const quoteLines: string[] = []
      const start = i
      while (i < lines.length && lines[i].trim().startsWith('>')) {
        quoteLines.push(lines[i].trim().replace(/^>\s?/, ''))
        i += 1
      }
      blocks.push(
        <blockquote
          key={`md-bq-${start}`}
          className="border-l-2 border-sky-500/60 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-300"
        >
          {renderInlineTokens(quoteLines.join(' '), `md-bq-${start}`)}
        </blockquote>,
      )
      continue
    }

    // Unordered list (- or *)
    if (/^[-*]\s+/.test(trimmed)) {
      const items: string[] = []
      const start = i
      while (i < lines.length && /^[-*]\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^[-*]\s+/, ''))
        i += 1
      }
      blocks.push(
        <ul key={`md-ul-${start}`} className="list-disc space-y-1 pl-5 text-xs text-slate-200">
          {items.map((item, idx) => (
            <li key={`md-ul-${start}-${idx}`} className="leading-relaxed">
              {renderInlineTokens(item, `md-ul-${start}-${idx}`)}
            </li>
          ))}
        </ul>,
      )
      continue
    }

    // Ordered list (1. ...)
    if (/^\d+\.\s+/.test(trimmed)) {
      const items: string[] = []
      const start = i
      while (i < lines.length && /^\d+\.\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^\d+\.\s+/, ''))
        i += 1
      }
      blocks.push(
        <ol key={`md-ol-${start}`} className="list-decimal space-y-1 pl-5 text-xs text-slate-200">
          {items.map((item, idx) => (
            <li key={`md-ol-${start}-${idx}`} className="leading-relaxed">
              {renderInlineTokens(item, `md-ol-${start}-${idx}`)}
            </li>
          ))}
        </ol>,
      )
      continue
    }

    // Paragraph (gather contiguous regular lines)
    const paraLines: string[] = []
    const start = i
    while (
      i < lines.length &&
      lines[i].trim() !== '' &&
      !/^(#{1,3})\s+/.test(lines[i].trim()) &&
      !lines[i].trim().startsWith('>') &&
      !/^[-*]\s+/.test(lines[i].trim()) &&
      !/^\d+\.\s+/.test(lines[i].trim())
    ) {
      paraLines.push(lines[i].trim())
      i += 1
    }
    blocks.push(
      <p key={`md-p-${start}`} className="text-xs leading-relaxed text-slate-200 break-words">
        {renderInlineTokens(paraLines.join(' '), `md-p-${start}`)}
      </p>,
    )
  }

  return <div className="space-y-2.5">{blocks}</div>
}
