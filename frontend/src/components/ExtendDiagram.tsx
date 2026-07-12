/**
 * Animated SVG for the "Built to extend" section.
 * Flow: heuristic metadata → fixtures/tests → detector → PR or local fork.
 */
export function ExtendDiagram() {
  return (
    <figure className="extend-diagram" aria-label="How to extend CodeHound with a new rule">
      <figcaption className="extend-diagram-caption">
        extend · metadata → tests → detector → ship
      </figcaption>
      <svg
        className="extend-svg"
        viewBox="0 0 720 280"
        xmlns="http://www.w3.org/2000/svg"
        role="img"
      >
        <title>
          Extend CodeHound: add heuristic metadata, tests, detection logic, then
          PR upstream or keep local
        </title>

        {/* connection lines — left-to-right pipeline */}
        <g className="extend-wires" fill="none" strokeWidth="1">
          <path
            className="extend-wire extend-wire-a"
            d="M 150 70 H 200"
            stroke="currentColor"
          />
          <path
            className="extend-wire extend-wire-b"
            d="M 320 70 H 370"
            stroke="currentColor"
          />
          <path
            className="extend-wire extend-wire-c"
            d="M 490 70 H 540"
            stroke="currentColor"
          />
          {/* detector splits to PR / local */}
          <path
            className="extend-wire extend-wire-d"
            d="M 600 100 V 150 H 200"
            stroke="currentColor"
          />
          <path
            className="extend-wire extend-wire-e"
            d="M 600 100 V 150 H 520"
            stroke="currentColor"
          />
        </g>

        <g className="extend-pulses">
          <circle className="extend-pulse" r="3" fill="currentColor">
            <animateMotion
              dur="2.2s"
              repeatCount="indefinite"
              path="M 150 70 H 200"
            />
          </circle>
          <circle className="extend-pulse" r="3" fill="currentColor">
            <animateMotion
              dur="2.2s"
              begin="0.35s"
              repeatCount="indefinite"
              path="M 320 70 H 370"
            />
          </circle>
          <circle className="extend-pulse" r="3" fill="currentColor">
            <animateMotion
              dur="2.2s"
              begin="0.7s"
              repeatCount="indefinite"
              path="M 490 70 H 540"
            />
          </circle>
          <circle className="extend-pulse" r="3" fill="currentColor">
            <animateMotion
              dur="2.8s"
              begin="1s"
              repeatCount="indefinite"
              path="M 600 100 V 150 H 200"
            />
          </circle>
          <circle className="extend-pulse" r="3" fill="currentColor">
            <animateMotion
              dur="2.8s"
              begin="1.15s"
              repeatCount="indefinite"
              path="M 600 100 V 150 H 520"
            />
          </circle>
        </g>

        <g className="extend-nodes" fontFamily="var(--font-mono), monospace">
          {/* 1 metadata */}
          <g className="extend-node" transform="translate(30, 40)">
            <rect className="extend-node-box" width="120" height="60" rx="0" />
            <text className="extend-node-label" x="12" y="24">
              1 · heuristic
            </text>
            <text className="extend-node-hint" x="12" y="42">
              go · py · …
            </text>
          </g>

          {/* 2 tests */}
          <g className="extend-node" transform="translate(200, 40)">
            <rect className="extend-node-box" width="120" height="60" rx="0" />
            <text className="extend-node-label" x="12" y="24">
              2 · tests
            </text>
            <text className="extend-node-hint" x="12" y="42">
              fixtures · oracles
            </text>
          </g>

          {/* 3 detector */}
          <g className="extend-node extend-node-accent" transform="translate(370, 40)">
            <rect className="extend-node-box" width="120" height="60" rx="0" />
            <text className="extend-node-label" x="12" y="24">
              3 · detector
            </text>
            <text className="extend-node-hint" x="12" y="42">
              plugin logic
            </text>
            <g className="extend-gear" transform="translate(98, 18)">
              <g>
                <circle
                  cx="10"
                  cy="10"
                  r="7"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.2"
                />
                <circle cx="10" cy="10" r="2.5" fill="currentColor" />
                <line
                  x1="10"
                  y1="1"
                  x2="10"
                  y2="4"
                  stroke="currentColor"
                  strokeWidth="1.2"
                />
                <line
                  x1="10"
                  y1="16"
                  x2="10"
                  y2="19"
                  stroke="currentColor"
                  strokeWidth="1.2"
                />
                <line
                  x1="1"
                  y1="10"
                  x2="4"
                  y2="10"
                  stroke="currentColor"
                  strokeWidth="1.2"
                />
                <line
                  x1="16"
                  y1="10"
                  x2="19"
                  y2="10"
                  stroke="currentColor"
                  strokeWidth="1.2"
                />
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

          {/* 4a PR */}
          <g className="extend-node extend-node-accent" transform="translate(540, 24)">
            <rect className="extend-node-box" width="150" height="52" rx="0" />
            <text className="extend-node-label" x="12" y="22">
              4a · open a PR
            </text>
            <text className="extend-node-hint" x="12" y="38">
              official catalog
            </text>
          </g>

          {/* 4b local */}
          <g className="extend-node" transform="translate(540, 88)">
            <rect className="extend-node-box" width="150" height="52" rx="0" />
            <text className="extend-node-label" x="12" y="22">
              4b · keep local
            </text>
            <text className="extend-node-hint" x="12" y="38">
              custom patterns
            </text>
          </g>

          {/* bottom outcomes */}
          <g className="extend-node" transform="translate(80, 170)">
            <rect className="extend-node-box" width="200" height="52" rx="0" />
            <text className="extend-node-label" x="12" y="22">
              upstream release
            </text>
            <text className="extend-node-hint" x="12" y="38">
              everyone gets the rule
            </text>
          </g>

          <g className="extend-node" transform="translate(400, 170)">
            <rect className="extend-node-box" width="220" height="52" rx="0" />
            <text className="extend-node-label" x="12" y="22">
              your binary / fork
            </text>
            <text className="extend-node-hint" x="12" y="38">
              private heuristics OK
            </text>
          </g>
        </g>

        <g className="extend-blocks" fontFamily="var(--font-mono), monospace">
          <g className="extend-block extend-block-1" transform="translate(162, 58)">
            <rect width="28" height="18" fill="none" stroke="currentColor" strokeWidth="1" />
            <text x="8" y="13" fontSize="10" fill="currentColor">
              +
            </text>
          </g>
          <g className="extend-block extend-block-2" transform="translate(332, 58)">
            <rect width="28" height="18" fill="none" stroke="currentColor" strokeWidth="1" />
            <text x="8" y="13" fontSize="10" fill="currentColor">
              +
            </text>
          </g>
        </g>

        <text
          className="extend-legend"
          x="30"
          y="255"
          fontFamily="var(--font-mono), monospace"
          fontSize="10"
        >
          metadata · fixtures · detector · PR or local — same architecture
        </text>
      </svg>
    </figure>
  )
}
