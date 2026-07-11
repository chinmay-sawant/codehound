/**
 * Single sequenced architecture for "How it works":
 * setup → scan → artifacts ──pipe──→ agent → triage → baseline → loop
 */
export function HowItWorksDiagram() {
  return (
    <figure className="how-diagram" aria-label="How CodeHound works end to end">
      <figcaption className="how-diagram-caption">
        sequence · setup → scan → artifacts → agent → baseline → loop
      </figcaption>
      <svg
        className="how-svg how-svg-full"
        viewBox="0 0 920 420"
        xmlns="http://www.w3.org/2000/svg"
        role="img"
      >
        <title>
          Install or clone, scan, write artifacts, feed an agent, baseline, re-scan
        </title>

        {/* ── phase labels ─────────────────────────────────────────────── */}
        <g fontFamily="var(--font-mono), monospace">
          <text className="how-phase" x="30" y="22">
            01 · setup → scan → export
          </text>
          <text className="how-phase" x="30" y="230">
            02 · agent review → baseline → loop
          </text>
        </g>

        {/* ── wires phase 1 ─────────────────────────────────────────────── */}
        <g className="how-wires" fill="none" strokeWidth="1">
          <path className="how-wire" d="M 150 90 H 210" stroke="currentColor" />
          <path className="how-wire" d="M 210 90 H 250" stroke="currentColor" />
          <path className="how-wire" d="M 250 60 V 48 H 310" stroke="currentColor" />
          <path className="how-wire" d="M 250 120 V 132 H 310" stroke="currentColor" />
          <path className="how-wire" d="M 430 48 H 480 V 90" stroke="currentColor" />
          <path className="how-wire" d="M 430 132 H 480 V 90" stroke="currentColor" />
          <path className="how-wire" d="M 480 90 H 540" stroke="currentColor" />
          <path className="how-wire" d="M 660 90 H 720" stroke="currentColor" />

          {/* pipe: artifacts → feed agent */}
          <path
            className="how-wire how-wire-pipe"
            d="M 795 130 V 200 H 90 V 260"
            stroke="currentColor"
          />
          {/* pipe label path */}
        </g>

        {/* ── wires phase 2 ─────────────────────────────────────────────── */}
        <g className="how-wires" fill="none" strokeWidth="1">
          <path className="how-wire" d="M 150 290 H 200" stroke="currentColor" />
          <path className="how-wire" d="M 320 290 H 370" stroke="currentColor" />
          <path className="how-wire" d="M 490 290 H 540" stroke="currentColor" />
          <path className="how-wire" d="M 150 350 H 200" stroke="currentColor" />
          <path className="how-wire" d="M 320 350 H 370" stroke="currentColor" />
          <path className="how-wire" d="M 490 350 H 540" stroke="currentColor" />
          <path className="how-wire" d="M 600 380 V 400 H 450" stroke="currentColor" />
          <path
            className="how-wire how-wire-loop"
            d="M 450 400 H 60 V 90 H 150"
            stroke="currentColor"
          />
        </g>

        {/* ── pulses ────────────────────────────────────────────────────── */}
        <g className="how-pulses">
          <circle className="how-pulse" r="3" fill="currentColor">
            <animateMotion dur="2.2s" repeatCount="indefinite" path="M 150 90 H 250" />
          </circle>
          <circle className="how-pulse" r="3" fill="currentColor">
            <animateMotion
              dur="2.4s"
              begin="0.4s"
              repeatCount="indefinite"
              path="M 430 48 H 480 V 90 H 540"
            />
          </circle>
          <circle className="how-pulse" r="3" fill="currentColor">
            <animateMotion
              dur="2s"
              begin="0.9s"
              repeatCount="indefinite"
              path="M 660 90 H 720"
            />
          </circle>
          {/* pipe pulse artifacts → feed agent */}
          <circle className="how-pulse how-pulse-pipe" r="3.5" fill="currentColor">
            <animateMotion
              dur="3.2s"
              begin="1.2s"
              repeatCount="indefinite"
              path="M 795 130 V 200 H 90 V 260"
            />
          </circle>
          <circle className="how-pulse" r="3" fill="currentColor">
            <animateMotion
              dur="2s"
              begin="0.2s"
              repeatCount="indefinite"
              path="M 150 290 H 200"
            />
          </circle>
          <circle className="how-pulse" r="3" fill="currentColor">
            <animateMotion
              dur="2s"
              begin="0.6s"
              repeatCount="indefinite"
              path="M 320 290 H 370"
            />
          </circle>
          <circle className="how-pulse how-pulse-loop" r="3.5" fill="currentColor">
            <animateMotion
              dur="5s"
              begin="1.5s"
              repeatCount="indefinite"
              path="M 600 380 V 400 H 60 V 90 H 150"
            />
          </circle>
        </g>

        {/* ── nodes phase 1 ─────────────────────────────────────────────── */}
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

          <g className="how-node" transform="translate(310, 22)">
            <rect className="how-node-box" width="120" height="52" />
            <text className="how-node-label" x="12" y="22">
              binary
            </text>
            <text className="how-node-cmd" x="12" y="40">
              codehound .
            </text>
          </g>

          <g className="how-node" transform="translate(310, 106)">
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

          <g className="how-node how-node-accent" transform="translate(720, 50)">
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

          {/* pipe badge */}
          <g className="how-pipe-badge" transform="translate(360, 178)">
            <rect className="how-pipe-box" width="200" height="28" />
            <text className="how-pipe-text" x="100" y="18" textAnchor="middle">
              ↓ pipe · artifacts → agent
            </text>
          </g>
        </g>

        {/* ── nodes phase 2 ─────────────────────────────────────────────── */}
        <g fontFamily="var(--font-mono), monospace">
          <g className="how-node how-node-accent" transform="translate(30, 260)">
            <rect className="how-node-box" width="120" height="60" />
            <text className="how-node-label" x="12" y="26">
              feed agent
            </text>
            <text className="how-node-hint" x="12" y="44">
              opencode · claude · grok
            </text>
          </g>

          <g className="how-node" transform="translate(200, 260)">
            <rect className="how-node-box" width="120" height="60" />
            <text className="how-node-label" x="12" y="26">
              triage
            </text>
            <text className="how-node-hint" x="12" y="44">
              fp · fix · defer
            </text>
          </g>

          <g className="how-node" transform="translate(370, 260)">
            <rect className="how-node-box" width="120" height="60" />
            <text className="how-node-label" x="12" y="26">
              checklist
            </text>
            <text className="how-node-hint" x="12" y="44">
              you pick what ships
            </text>
          </g>

          <g className="how-node how-node-accent" transform="translate(540, 260)">
            <rect className="how-node-box" width="120" height="60" />
            <text className="how-node-label" x="12" y="26">
              you decide
            </text>
            <text className="how-node-hint" x="12" y="44">
              architecture call
            </text>
          </g>

          <g className="how-node" transform="translate(30, 320)">
            <rect className="how-node-box" width="120" height="52" />
            <text className="how-node-label" x="12" y="22">
              100 findings
            </text>
            <text className="how-node-hint" x="12" y="40">
              60 fixed · 40 remain
            </text>
          </g>

          <g className="how-node" transform="translate(200, 320)">
            <rect className="how-node-box" width="120" height="52" />
            <text className="how-node-label" x="12" y="22">
              baseline
            </text>
            <text className="how-node-cmd" x="12" y="40">
              --baseline
            </text>
          </g>

          <g className="how-node" transform="translate(370, 320)">
            <rect className="how-node-box" width="120" height="52" />
            <text className="how-node-label" x="12" y="22">
              re-scan
            </text>
            <text className="how-node-cmd" x="12" y="40">
              codehound .
            </text>
          </g>

          <g className="how-node how-node-accent" transform="translate(540, 320)">
            <rect className="how-node-box" width="120" height="52" />
            <text className="how-node-label" x="12" y="22">
              makefile
            </text>
            <text className="how-node-cmd" x="12" y="40">
              make codehound
            </text>
          </g>

          <g className="how-loop-badge" transform="translate(200, 390)">
            <rect className="how-loop-box" width="400" height="28" />
            <text className="how-loop-text" x="16" y="18">
              loop · until clean or baseline stable  ↩ back to scan
            </text>
          </g>
        </g>
      </svg>
    </figure>
  )
}
