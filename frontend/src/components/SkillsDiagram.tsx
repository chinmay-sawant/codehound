/**
 * Animated SVG for "Skills are no better":
 * drifting skill passes vs a deterministic rule.
 */
export function SkillsDiagram() {
  return (
    <figure className="skills-diagram" aria-label="Skills drift, rules do not">
      <figcaption className="skills-diagram-caption">
        skill passes drift · rules do not
      </figcaption>
      <svg
        className="skills-svg"
        viewBox="0 0 900 240"
        xmlns="http://www.w3.org/2000/svg"
        role="img"
      >
        <title>Four skill iterations vs one deterministic CodeHound scan</title>

        <g fontFamily="var(--font-mono), monospace">
          <text className="skills-col-label" x="40" y="26">
            skill · 4–5 passes
          </text>
          <text className="skills-col-label skills-col-label-good" x="520" y="26">
            codehound · one scan
          </text>
        </g>

        {/* skill chain */}
        <g className="skills-wires" fill="none" strokeWidth="1">
          <path className="skills-wire skills-wire-bad" d="M 150 80 H 190" stroke="currentColor" />
          <path className="skills-wire skills-wire-bad" d="M 300 80 H 340" stroke="currentColor" />
          <path className="skills-wire skills-wire-bad" d="M 450 80 H 490" stroke="currentColor" />
          <path
            className="skills-wire skills-wire-bad skills-wire-wobble"
            d="M 105 110 V 160 H 250"
            stroke="currentColor"
          />
          <path
            className="skills-wire skills-wire-bad skills-wire-wobble"
            d="M 255 110 V 160 H 400"
            stroke="currentColor"
          />
        </g>

        <g className="skills-pulses">
          <circle className="skills-pulse skills-pulse-bad" r="3" fill="currentColor">
            <animateMotion dur="1.6s" repeatCount="indefinite" path="M 150 80 H 190" />
          </circle>
          <circle className="skills-pulse skills-pulse-bad" r="3" fill="currentColor">
            <animateMotion
              dur="1.6s"
              begin="0.4s"
              repeatCount="indefinite"
              path="M 300 80 H 340"
            />
          </circle>
          <circle className="skills-pulse skills-pulse-bad" r="3" fill="currentColor">
            <animateMotion
              dur="1.6s"
              begin="0.8s"
              repeatCount="indefinite"
              path="M 450 80 H 490"
            />
          </circle>
        </g>

        <g fontFamily="var(--font-mono), monospace">
          <g className="skills-node skills-node-bad skills-float-1" transform="translate(40, 50)">
            <rect className="skills-node-box" width="110" height="60" />
            <text className="skills-node-label" x="12" y="24">
              pass 1
            </text>
            <text className="skills-node-hint" x="12" y="42">
              miss A · hit B
            </text>
          </g>

          <g className="skills-node skills-node-bad skills-float-2" transform="translate(190, 50)">
            <rect className="skills-node-box" width="110" height="60" />
            <text className="skills-node-label" x="12" y="24">
              pass 2
            </text>
            <text className="skills-node-hint" x="12" y="42">
              dup B · miss C
            </text>
          </g>

          <g className="skills-node skills-node-bad skills-float-3" transform="translate(340, 50)">
            <rect className="skills-node-box" width="110" height="60" />
            <text className="skills-node-label" x="12" y="24">
              pass 3
            </text>
            <text className="skills-node-hint" x="12" y="42">
              new miss · days
            </text>
          </g>

          <g className="skills-node skills-node-bad skills-float-4" transform="translate(490, 50)">
            <rect className="skills-node-box" width="110" height="60" />
            <text className="skills-node-label" x="12" y="24">
              pass 4–5
            </text>
            <text className="skills-node-hint" x="12" y="42">
              ~$19+ drift
            </text>
          </g>

          {/* ghost findings that appear/disappear */}
          <g className="skills-ghost skills-ghost-1" transform="translate(80, 150)">
            <rect className="skills-ghost-box" width="90" height="28" />
            <text className="skills-ghost-text" x="10" y="18">
              ? finding
            </text>
          </g>
          <g className="skills-ghost skills-ghost-2" transform="translate(230, 150)">
            <rect className="skills-ghost-box" width="90" height="28" />
            <text className="skills-ghost-text" x="10" y="18">
              ? finding
            </text>
          </g>
          <g className="skills-ghost skills-ghost-3" transform="translate(380, 150)">
            <rect className="skills-ghost-box" width="90" height="28" />
            <text className="skills-ghost-text" x="10" y="18">
              ? finding
            </text>
          </g>
        </g>

        {/* vs divider */}
        <g fontFamily="var(--font-mono), monospace">
          <line
            className="skills-divider"
            x1="630"
            y1="40"
            x2="630"
            y2="210"
            stroke="currentColor"
            strokeWidth="1"
            strokeDasharray="3 4"
          />
          <text className="skills-vs" x="630" y="120" textAnchor="middle">
            vs
          </text>
        </g>

        {/* codehound stable */}
        <g fontFamily="var(--font-mono), monospace">
          <g className="skills-node skills-node-good" transform="translate(680, 50)">
            <rect className="skills-node-box" width="180" height="60" />
            <text className="skills-node-label" x="12" y="24">
              one program
            </text>
            <text className="skills-node-hint" x="12" y="42">
              rule IS the check
            </text>
          </g>

          <g className="skills-stable" transform="translate(680, 130)">
            <rect className="skills-stable-box" width="180" height="80" />
            <text className="skills-stable-line" x="12" y="24">
              CWE-22 · fixed id
            </text>
            <text className="skills-stable-line" x="12" y="44">
              file · line · snippet
            </text>
            <text className="skills-stable-hint" x="12" y="66">
              run twice → same
            </text>
          </g>
        </g>

        {/* pulse into stable */}
        <g className="skills-pulses">
          <circle className="skills-pulse skills-pulse-good" r="3" fill="currentColor">
            <animateMotion
              dur="2.4s"
              repeatCount="indefinite"
              path="M 770 110 V 130"
            />
          </circle>
        </g>
        <path
          className="skills-wire skills-wire-good"
          d="M 770 110 V 130"
          fill="none"
          stroke="currentColor"
          strokeWidth="1"
        />
      </svg>
    </figure>
  )
}
