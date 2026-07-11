/**
 * Animated SVG architecture for "How it works":
 * setup → scan → export → agent triage → baseline → re-scan loop
 */
export function HowItWorksDiagram() {
  return (
    <div className="how-diagrams">
      {/* Phase 1: setup → scan → export */}
      <figure className="how-diagram" aria-label="Setup, scan, and export">
        <figcaption className="how-diagram-caption">
          01 · setup → scan → export
        </figcaption>
        <svg
          className="how-svg"
          viewBox="0 0 900 200"
          xmlns="http://www.w3.org/2000/svg"
          role="img"
        >
          <title>Install or clone, run scan, write artifacts</title>

          <g className="how-wires" fill="none" strokeWidth="1">
            <path className="how-wire" d="M 150 90 H 210" stroke="currentColor" />
            <path className="how-wire" d="M 210 90 H 250" stroke="currentColor" />
            <path className="how-wire" d="M 250 60 V 40 H 310" stroke="currentColor" />
            <path className="how-wire" d="M 250 120 V 140 H 310" stroke="currentColor" />
            <path className="how-wire" d="M 430 40 H 480 V 90" stroke="currentColor" />
            <path className="how-wire" d="M 430 140 H 480 V 90" stroke="currentColor" />
            <path className="how-wire" d="M 480 90 H 540" stroke="currentColor" />
            <path className="how-wire" d="M 660 90 H 720" stroke="currentColor" />
          </g>

          <g className="how-pulses">
            <circle className="how-pulse" r="3" fill="currentColor">
              <animateMotion dur="2.2s" repeatCount="indefinite" path="M 150 90 H 250" />
            </circle>
            <circle className="how-pulse" r="3" fill="currentColor">
              <animateMotion
                dur="2.6s"
                begin="0.3s"
                repeatCount="indefinite"
                path="M 250 60 V 40 H 310"
              />
            </circle>
            <circle className="how-pulse" r="3" fill="currentColor">
              <animateMotion
                dur="2.6s"
                begin="0.5s"
                repeatCount="indefinite"
                path="M 250 120 V 140 H 310"
              />
            </circle>
            <circle className="how-pulse" r="3" fill="currentColor">
              <animateMotion
                dur="2.4s"
                begin="0.9s"
                repeatCount="indefinite"
                path="M 430 40 H 480 V 90 H 540"
              />
            </circle>
            <circle className="how-pulse" r="3" fill="currentColor">
              <animateMotion
                dur="2s"
                begin="1.4s"
                repeatCount="indefinite"
                path="M 660 90 H 720"
              />
            </circle>
          </g>

          <g fontFamily="var(--font-mono), monospace">
            <g className="how-node how-node-accent" transform="translate(30, 60)">
              <rect className="how-node-box" width="120" height="60" />
              <text className="how-node-label" x="12" y="26">
                your machine
              </text>
              <text className="how-node-hint" x="12" y="44">
                win · linux · mac
              </text>
            </g>

            <text className="how-or" x="238" y="94" textAnchor="middle">
              or
            </text>

            <g className="how-node" transform="translate(310, 16)">
              <rect className="how-node-box" width="120" height="52" />
              <text className="how-node-label" x="12" y="22">
                binary
              </text>
              <text className="how-node-cmd" x="12" y="40">
                codehound .
              </text>
            </g>

            <g className="how-node" transform="translate(310, 116)">
              <rect className="how-node-box" width="120" height="52" />
              <text className="how-node-label" x="12" y="22">
                clone repo
              </text>
              <text className="how-node-cmd" x="12" y="40">
                make run
              </text>
            </g>

            <g className="how-node how-node-accent" transform="translate(540, 60)">
              <rect className="how-node-box" width="120" height="60" />
              <text className="how-node-label" x="12" y="26">
                scan
              </text>
              <text className="how-node-hint" x="12" y="44">
                offline · $0
              </text>
              <g className="how-scan-ring" transform="translate(96, 12)">
                <circle
                  cx="10"
                  cy="10"
                  r="7"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.2"
                  strokeDasharray="8 6"
                >
                  <animateTransform
                    attributeName="transform"
                    type="rotate"
                    from="0 10 10"
                    to="360 10 10"
                    dur="3s"
                    repeatCount="indefinite"
                  />
                </circle>
              </g>
            </g>

            <g className="how-node" transform="translate(720, 50)">
              <rect className="how-node-box" width="150" height="80" />
              <text className="how-node-label" x="12" y="24">
                artifacts
              </text>
              <text className="how-node-hint" x="12" y="42">
                scripts/findings
              </text>
              <text className="how-node-hint" x="12" y="58">
                scripts/chunks
              </text>
              <g className="how-folder-stack" transform="translate(118, 18)">
                <rect
                  className="how-folder how-folder-1"
                  x="0"
                  y="8"
                  width="22"
                  height="14"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1"
                />
                <rect
                  className="how-folder how-folder-2"
                  x="4"
                  y="2"
                  width="22"
                  height="14"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1"
                />
              </g>
            </g>
          </g>
        </svg>
      </figure>

      {/* Phase 2: agent → baseline → loop */}
      <figure className="how-diagram" aria-label="Agent review, baseline, and loop">
        <figcaption className="how-diagram-caption">
          02 · agent review → baseline → loop
        </figcaption>
        <svg
          className="how-svg"
          viewBox="0 0 900 280"
          xmlns="http://www.w3.org/2000/svg"
          role="img"
        >
          <title>Triage with an agent, baseline debt, re-scan</title>

          <g className="how-wires" fill="none" strokeWidth="1">
            <path className="how-wire" d="M 150 50 H 200" stroke="currentColor" />
            <path className="how-wire" d="M 320 50 H 370" stroke="currentColor" />
            <path className="how-wire" d="M 490 50 H 540" stroke="currentColor" />
            <path className="how-wire" d="M 600 80 V 120" stroke="currentColor" />
            <path className="how-wire" d="M 150 150 H 200" stroke="currentColor" />
            <path className="how-wire" d="M 320 150 H 370" stroke="currentColor" />
            <path className="how-wire" d="M 490 150 H 540" stroke="currentColor" />
            <path className="how-wire" d="M 600 180 V 210 H 450" stroke="currentColor" />
            {/* loop back */}
            <path
              className="how-wire how-wire-loop"
              d="M 450 210 H 80 V 50 H 150"
              stroke="currentColor"
            />
          </g>

          <g className="how-pulses">
            <circle className="how-pulse" r="3" fill="currentColor">
              <animateMotion
                dur="2s"
                repeatCount="indefinite"
                path="M 150 50 H 200"
              />
            </circle>
            <circle className="how-pulse" r="3" fill="currentColor">
              <animateMotion
                dur="2s"
                begin="0.4s"
                repeatCount="indefinite"
                path="M 320 50 H 370"
              />
            </circle>
            <circle className="how-pulse" r="3" fill="currentColor">
              <animateMotion
                dur="2s"
                begin="0.8s"
                repeatCount="indefinite"
                path="M 490 50 H 540"
              />
            </circle>
            <circle className="how-pulse" r="3" fill="currentColor">
              <animateMotion
                dur="2.2s"
                begin="0.2s"
                repeatCount="indefinite"
                path="M 150 150 H 200"
              />
            </circle>
            <circle className="how-pulse" r="3" fill="currentColor">
              <animateMotion
                dur="2.2s"
                begin="0.6s"
                repeatCount="indefinite"
                path="M 320 150 H 370"
              />
            </circle>
            <circle className="how-pulse how-pulse-loop" r="3.5" fill="currentColor">
              <animateMotion
                dur="4.5s"
                begin="1s"
                repeatCount="indefinite"
                path="M 600 180 V 210 H 80 V 50 H 150"
              />
            </circle>
          </g>

          <g fontFamily="var(--font-mono), monospace">
            {/* row 1 */}
            <g className="how-node" transform="translate(30, 20)">
              <rect className="how-node-box" width="120" height="60" />
              <text className="how-node-label" x="12" y="26">
                feed agent
              </text>
              <text className="how-node-hint" x="12" y="44">
                opencode · claude · grok
              </text>
            </g>

            <g className="how-node" transform="translate(200, 20)">
              <rect className="how-node-box" width="120" height="60" />
              <text className="how-node-label" x="12" y="26">
                triage
              </text>
              <text className="how-node-hint" x="12" y="44">
                fp · fix · defer
              </text>
            </g>

            <g className="how-node" transform="translate(370, 20)">
              <rect className="how-node-box" width="120" height="60" />
              <text className="how-node-label" x="12" y="26">
                checklist
              </text>
              <text className="how-node-hint" x="12" y="44">
                you pick what ships
              </text>
            </g>

            <g className="how-node how-node-accent" transform="translate(540, 20)">
              <rect className="how-node-box" width="120" height="60" />
              <text className="how-node-label" x="12" y="26">
                you decide
              </text>
              <text className="how-node-hint" x="12" y="44">
                architecture call
              </text>
            </g>

            {/* row 2 */}
            <g className="how-node" transform="translate(30, 120)">
              <rect className="how-node-box" width="120" height="60" />
              <text className="how-node-label" x="12" y="26">
                100 findings
              </text>
              <text className="how-node-hint" x="12" y="44">
                60 fixed · 40 remain
              </text>
            </g>

            <g className="how-node" transform="translate(200, 120)">
              <rect className="how-node-box" width="120" height="60" />
              <text className="how-node-label" x="12" y="26">
                baseline
              </text>
              <text className="how-node-cmd" x="12" y="44">
                --baseline
              </text>
            </g>

            <g className="how-node" transform="translate(370, 120)">
              <rect className="how-node-box" width="120" height="60" />
              <text className="how-node-label" x="12" y="26">
                re-scan
              </text>
              <text className="how-node-cmd" x="12" y="44">
                codehound .
              </text>
            </g>

            <g className="how-node how-node-accent" transform="translate(540, 120)">
              <rect className="how-node-box" width="120" height="60" />
              <text className="how-node-label" x="12" y="26">
                makefile
              </text>
              <text className="how-node-cmd" x="12" y="44">
                make codehound
              </text>
            </g>

            {/* loop badge */}
            <g className="how-loop-badge" transform="translate(200, 220)">
              <rect className="how-loop-box" width="400" height="36" />
              <text className="how-loop-text" x="16" y="23">
                loop · repeat until clean or baseline is stable  ↩ back to scan
              </text>
            </g>
          </g>
        </svg>
      </figure>
    </div>
  )
}
