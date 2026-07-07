import type { Section } from '../data/sections'
import { WorkflowDiagram } from './WorkflowDiagram'
import { useReveal } from '../hooks/useReveal'

export function SectionView({ section }: { section: Section }) {
  const s = section
  const { ref, visible } = useReveal<HTMLElement>()
  return (
    <section
      id={s.id}
      ref={ref}
      className={`section reveal${visible ? ' is-visible' : ''}`}
    >
      <header className="section-head">
        <span className="section-prompt">{`>${s.id}`}</span>
        <h2 className="section-title">{s.title}</h2>
      </header>
      <p className={`section-lead${s.flows ? ' section-lead-wide' : ''}`}>{s.lead}</p>

      {s.stats && (
        <div className="stats">
          {s.stats.map((st) => (
            <div className="stat" key={st.label}>
              <div className="stat-value">{st.value}</div>
              <div className="stat-label">{st.label}</div>
              {st.sub && <div className="stat-sub">{st.sub}</div>}
            </div>
          ))}
        </div>
      )}

      {s.facts && (
        <dl className="facts">
          {s.facts.map((f) => (
            <div className="fact" key={f.k}>
              <dt className="fact-k">{f.k}</dt>
              <dd className="fact-v">{f.v}</dd>
            </div>
          ))}
        </dl>
      )}

      {s.code && (
        <div className="code">
          <div className="code-label">{s.code.label}</div>
          {s.code.before && (
            <pre className="code-block code-before">
              <code>{s.code.before}</code>
            </pre>
          )}
          {s.code.after && (
            <pre className="code-block code-after">
              <code>{s.code.after}</code>
            </pre>
          )}
          {s.code.body && (
            <pre className="code-block">
              <code>{s.code.body}</code>
            </pre>
          )}
        </div>
      )}

      {s.flows && (
        <div className="flow-grid">
          {s.flows.map((flow) => (
            <WorkflowDiagram key={flow.caption} diagram={flow} />
          ))}
        </div>
      )}

      {s.body && (
        <div className="section-body">
          {s.body.map((p, i) => (
            <p key={i} className="section-para">{p}</p>
          ))}
        </div>
      )}
    </section>
  )
}