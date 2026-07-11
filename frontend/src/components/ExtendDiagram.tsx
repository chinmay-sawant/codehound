/**
 * Minimal animated SVG for the "Built to extend" section.
 * Shows: sink registry → regenerate catalog, plugins plug in, sections as data.
 */
export function ExtendDiagram() {
  return (
    <figure className="extend-diagram" aria-label="How CodeHound extends">
      <figcaption className="extend-diagram-caption">
        architecture · data in, rules out
      </figcaption>
      <svg
        className="extend-svg"
        viewBox="0 0 720 280"
        xmlns="http://www.w3.org/2000/svg"
        role="img"
      >
        <title>Extensibility: registry, plugins, and page data</title>

        {/* connection lines */}
        <g className="extend-wires" fill="none" strokeWidth="1">
          {/* registry → catalog */}
          <path
            className="extend-wire extend-wire-a"
            d="M 160 70 H 280"
            stroke="currentColor"
          />
          {/* catalog → plugins fan */}
          <path
            className="extend-wire extend-wire-b"
            d="M 440 70 H 500 V 40 H 560"
            stroke="currentColor"
          />
          <path
            className="extend-wire extend-wire-c"
            d="M 440 70 H 500 V 100 H 560"
            stroke="currentColor"
          />
          {/* registry down to sections */}
          <path
            className="extend-wire extend-wire-d"
            d="M 100 100 V 160 H 280"
            stroke="currentColor"
          />
          {/* sections → site */}
          <path
            className="extend-wire extend-wire-e"
            d="M 440 180 H 560"
            stroke="currentColor"
          />
        </g>

        {/* animated pulse dots along paths */}
        <g className="extend-pulses">
          <circle className="extend-pulse extend-pulse-1" r="3" fill="currentColor">
            <animateMotion
              dur="2.4s"
              repeatCount="indefinite"
              path="M 160 70 H 280"
            />
          </circle>
          <circle className="extend-pulse extend-pulse-2" r="3" fill="currentColor">
            <animateMotion
              dur="2.8s"
              begin="0.4s"
              repeatCount="indefinite"
              path="M 440 70 H 500 V 40 H 560"
            />
          </circle>
          <circle className="extend-pulse extend-pulse-3" r="3" fill="currentColor">
            <animateMotion
              dur="2.8s"
              begin="0.8s"
              repeatCount="indefinite"
              path="M 440 70 H 500 V 100 H 560"
            />
          </circle>
          <circle className="extend-pulse extend-pulse-4" r="3" fill="currentColor">
            <animateMotion
              dur="3s"
              begin="0.2s"
              repeatCount="indefinite"
              path="M 100 100 V 160 H 280"
            />
          </circle>
          <circle className="extend-pulse extend-pulse-5" r="3" fill="currentColor">
            <animateMotion
              dur="2.2s"
              begin="1s"
              repeatCount="indefinite"
              path="M 440 180 H 560"
            />
          </circle>
        </g>

        {/* nodes */}
        <g className="extend-nodes" fontFamily="var(--font-mono), monospace">
          {/* sink registry */}
          <g className="extend-node" transform="translate(40, 40)">
            <rect
              className="extend-node-box"
              width="120"
              height="60"
              rx="0"
            />
            <text className="extend-node-label" x="12" y="26">
              sink registry
            </text>
            <text className="extend-node-hint" x="12" y="44">
              +1 entry
            </text>
          </g>

          {/* CWE catalog */}
          <g className="extend-node extend-node-accent" transform="translate(280, 40)">
            <rect
              className="extend-node-box"
              width="160"
              height="60"
              rx="0"
            />
            <text className="extend-node-label" x="12" y="26">
              CWE catalog
            </text>
            <text className="extend-node-hint" x="12" y="44">
              175+ · regenerates
            </text>
            {/* small spin gear hint */}
            <g className="extend-gear" transform="translate(138, 18)">
              <g>
                <circle cx="10" cy="10" r="7" fill="none" stroke="currentColor" strokeWidth="1.2" />
                <circle cx="10" cy="10" r="2.5" fill="currentColor" />
                <line x1="10" y1="1" x2="10" y2="4" stroke="currentColor" strokeWidth="1.2" />
                <line x1="10" y1="16" x2="10" y2="19" stroke="currentColor" strokeWidth="1.2" />
                <line x1="1" y1="10" x2="4" y2="10" stroke="currentColor" strokeWidth="1.2" />
                <line x1="16" y1="10" x2="19" y2="10" stroke="currentColor" strokeWidth="1.2" />
                <animateTransform
                  attributeName="transform"
                  type="rotate"
                  from="0 10 10"
                  to="360 10 10"
                  dur="4s"
                  repeatCount="indefinite"
                />
              </g>
            </g>
          </g>

          {/* language plugins */}
          <g className="extend-node" transform="translate(560, 16)">
            <rect className="extend-node-box" width="120" height="48" rx="0" />
            <text className="extend-node-label" x="12" y="22">
              Go plugin
            </text>
            <text className="extend-node-hint" x="12" y="38">
              production
            </text>
          </g>
          <g className="extend-node" transform="translate(560, 76)">
            <rect className="extend-node-box" width="120" height="48" rx="0" />
            <text className="extend-node-label" x="12" y="22">
              Python
            </text>
            <text className="extend-node-hint" x="12" y="38">
              opt-in · 1 rule
            </text>
          </g>

          {/* sections.ts */}
          <g className="extend-node" transform="translate(280, 150)">
            <rect className="extend-node-box" width="160" height="60" rx="0" />
            <text className="extend-node-label" x="12" y="26">
              sections.ts
            </text>
            <text className="extend-node-hint" x="12" y="44">
              +1 section entry
            </text>
          </g>

          {/* site renderer */}
          <g className="extend-node extend-node-accent" transform="translate(560, 150)">
            <rect className="extend-node-box" width="120" height="60" rx="0" />
            <text className="extend-node-label" x="12" y="26">
              site
            </text>
            <text className="extend-node-hint" x="12" y="44">
              nav · scroll · ui
            </text>
          </g>

          {/* input node left */}
          <g className="extend-node" transform="translate(40, 150)">
            <rect className="extend-node-box" width="120" height="60" rx="0" />
            <text className="extend-node-label" x="12" y="26">
              you
            </text>
            <text className="extend-node-hint" x="12" y="44">
              ship data
            </text>
          </g>
        </g>

        {/* floating + blocks that appear */}
        <g className="extend-blocks" fontFamily="var(--font-mono), monospace">
          <g className="extend-block extend-block-1" transform="translate(190, 48)">
            <rect width="28" height="18" fill="none" stroke="currentColor" strokeWidth="1" />
            <text x="6" y="13" fontSize="10" fill="currentColor">
              +
            </text>
          </g>
          <g className="extend-block extend-block-2" transform="translate(500, 168)">
            <rect width="28" height="18" fill="none" stroke="currentColor" strokeWidth="1" />
            <text x="6" y="13" fontSize="10" fill="currentColor">
              +
            </text>
          </g>
        </g>

        {/* bottom legend */}
        <text
          className="extend-legend"
          x="40"
          y="250"
          fontFamily="var(--font-mono), monospace"
          fontSize="10"
        >
          rules are data · plugins are real · the page is a renderer
        </text>
      </svg>
    </figure>
  )
}
