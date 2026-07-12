import type { Section } from '../data/sections'
import { renderInlineMarkup } from '../lib/render-inline'
import { ExtendDiagram } from './ExtendDiagram'
import { HowItWorksDiagram } from './HowItWorksDiagram'
import { WhyExistsDiagram } from './WhyExistsDiagram'
import { SkillsDiagram } from './SkillsDiagram'
import { useReveal } from '../hooks/useReveal'

export function SectionView({
  section,
  index,
}: {
  section: Section
  index: number
}) {
  const s = section
  const { ref, visible } = useReveal<HTMLElement>()
  const Icon = s.icon
  const idx = String(index).padStart(2, '0')

  const hasFacts = Boolean(s.facts?.length)
  const hasWide =
    Boolean(s.tables?.length) ||
    Boolean(s.code) ||
    s.id === 'how-it-works' ||
    s.id === 'extend' ||
    s.id === 'why' ||
    s.id === 'skills'

  return (
    <section
      id={s.id}
      ref={ref}
      className={`section reveal${visible ? ' is-visible' : ''}${hasWide ? ' section-wide' : ''}`}
    >
      <div className="section-rail" aria-hidden="true">
        <span className="section-rail-idx">{idx}</span>
        <span className="section-rail-line" />
        <span className="section-rail-id">{s.id}</span>
      </div>

      <div className="section-main">
        {/*
          Body stays in the primary column so it sits directly under the lead
          (and any media), aligned with the facts card — not pushed below a
          tall facts sidebar.
        */}
        <div className={hasFacts ? 'section-split' : undefined}>
          <div className="section-primary">
            <header className="section-head">
              <div className="section-meta">
                <span className="section-icon" aria-hidden="true">
                  <Icon size={13} strokeWidth={1.75} />
                </span>
                <span className="section-prompt">{s.id}</span>
              </div>
              <h2 className="section-title">{s.title}</h2>
              <p className="section-lead">{s.lead}</p>
            </header>

            {s.callout && (
              <aside className="callout" aria-label="Key point">
                {renderInlineMarkup(s.callout)}
              </aside>
            )}

            {s.stats && (
              <div className="stats" role="group" aria-label="Key metrics">
                {s.stats.map((st) => (
                  <div className="stat" key={st.label}>
                    <div className="stat-value">{st.value}</div>
                    <div className="stat-label">{st.label}</div>
                    {st.sub && <div className="stat-sub">{st.sub}</div>}
                  </div>
                ))}
              </div>
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

            {s.id === 'how-it-works' && <HowItWorksDiagram />}
            {s.id === 'why' && <WhyExistsDiagram />}
            {s.id === 'skills' && <SkillsDiagram />}
            {s.id === 'extend' && <ExtendDiagram />}

            {s.tables && (
              <div className="table-stack">
                {s.tables.map((table) => (
                  <figure className="data-table-wrap" key={table.caption}>
                    <figcaption className="data-table-caption">
                      {table.caption}
                    </figcaption>
                    <div className="data-table-scroll">
                      <table className="data-table">
                        <thead>
                          <tr>
                            {table.headers.map((h) => (
                              <th key={h} scope="col">
                                {h}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {table.rows.map((row, i) => (
                            <tr
                              key={i}
                              className={
                                table.highlightRow === i
                                  ? 'is-highlight'
                                  : undefined
                              }
                            >
                              {row.map((cell, j) => (
                                <td key={j}>{cell}</td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </figure>
                ))}
              </div>
            )}

            {s.body && (
              <div className="section-body">
                {s.body.map((p, i) => (
                  <p key={i} className="section-para">
                    {renderInlineMarkup(p)}
                  </p>
                ))}
              </div>
            )}
          </div>

          {s.facts && (
            <dl className="facts" aria-label="Details">
              {s.facts.map((f) => (
                <div className="fact" key={f.k}>
                  <dt className="fact-k">{f.k}</dt>
                  <dd className="fact-v">{f.v}</dd>
                </div>
              ))}
            </dl>
          )}
        </div>
      </div>
    </section>
  )
}
