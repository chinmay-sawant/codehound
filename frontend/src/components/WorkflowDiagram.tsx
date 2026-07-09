import type { LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'

export type FlowStep = {
  label: string
  hint?: string
  cmd?: string
  icon?: LucideIcon
}

export type FlowSegment =
  | { kind: 'node'; step: FlowStep }
  | { kind: 'fork'; left: FlowStep; right: FlowStep }

export type FlowRow = {
  segments: FlowSegment[]
}

export type FlowDiagram = {
  caption: string
  rows: FlowRow[]
  loop?: { label: string; target: string }
}

function FlowNode({ step }: { step: FlowStep }) {
  const Icon = step.icon
  return (
    <div className="flow-node">
      {Icon && (
        <span className="flow-node-icon" aria-hidden="true">
          <Icon size={12} strokeWidth={1.75} />
        </span>
      )}
      <div className="flow-node-body">
        <div className="flow-node-label">{step.label}</div>
        {step.hint && <div className="flow-node-hint">{step.hint}</div>}
        {step.cmd && (
          <pre className="flow-node-cmd">
            <code>{step.cmd}</code>
          </pre>
        )}
      </div>
    </div>
  )
}

function FlowArrowH() {
  return <div className="flow-arrow-h" aria-hidden="true" />
}

function FlowSegmentView({ segment }: { segment: FlowSegment }) {
  if (segment.kind === 'fork') {
    return (
      <div className="flow-fork-inline">
        <FlowNode step={segment.left} />
        <span className="flow-fork-mid">or</span>
        <FlowNode step={segment.right} />
      </div>
    )
  }
  return <FlowNode step={segment.step} />
}

function FlowRowView({ row }: { row: FlowRow }) {
  const items: ReactNode[] = []
  row.segments.forEach((segment, i) => {
    if (i > 0) items.push(<FlowArrowH key={`arr-${i}`} />)
    items.push(<FlowSegmentView key={`seg-${i}`} segment={segment} />)
  })
  return <div className="flow-row">{items}</div>
}

export function WorkflowDiagram({ diagram }: { diagram: FlowDiagram }) {
  const { caption, rows, loop } = diagram
  return (
    <figure className="flow-diagram">
      <figcaption className="flow-caption">{caption}</figcaption>
      <div className="flow-rows">
        {rows.map((row, i) => (
          <FlowRowView key={i} row={row} />
        ))}
        {loop && (
          <div className="flow-loop">
            <span className="flow-loop-label">{loop.label}</span>
            <span className="flow-loop-target">{loop.target}</span>
          </div>
        )}
      </div>
    </figure>
  )
}