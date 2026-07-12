/**
 * Animated SVG for "Why this exists":
 * inference burns tokens every run vs a compiled rule priced once.
 */
export function WhyExistsDiagram() {
  return (
    <figure className="why-diagram" aria-label="Why CodeHound exists">
      <figcaption className="why-diagram-caption">
        inference every run · rule once
      </figcaption>
      <svg
        className="why-svg"
        viewBox="0 0 900 260"
        xmlns="http://www.w3.org/2000/svg"
        role="img"
      >
        <title>
          Skills re-read and burn tokens; CodeHound is a compiled rule at $0
        </title>

        {/* left: agent / skills path */}
        <g fontFamily="var(--font-mono), monospace">
          <text className="why-col-label" x="40" y="28">
            skills / agents
          </text>

          <g className="why-node why-node-bad" transform="translate(40, 48)">
            <rect className="why-node-box" width="130" height="52" />
            <text className="why-node-label" x="12" y="22">
              re-read tree
            </text>
            <text className="why-node-hint" x="12" y="40">
              every pass
            </text>
          </g>

          <g className="why-node why-node-bad" transform="translate(40, 120)">
            <rect className="why-node-box" width="130" height="52" />
            <text className="why-node-label" x="12" y="22">
              drift
            </text>
            <text className="why-node-hint" x="12" y="40">
              different each run
            </text>
          </g>

          <g className="why-node why-node-bad" transform="translate(40, 192)">
            <rect className="why-node-box" width="130" height="52" />
            <text className="why-node-label" x="12" y="22">
              ~$19+
            </text>
            <text className="why-node-hint" x="12" y="40">
              5× open-ended
            </text>
          </g>
        </g>

        {/* left stack wires */}
        <g className="why-wires" fill="none" strokeWidth="1">
          <path className="why-wire why-wire-bad" d="M 105 100 V 120" stroke="currentColor" />
          <path className="why-wire why-wire-bad" d="M 105 172 V 192" stroke="currentColor" />
          {/* leak to void / token meter */}
          <path
            className="why-wire why-wire-bad"
            d="M 170 74 H 280"
            stroke="currentColor"
          />
        </g>

        {/* token burn meter */}
        <g fontFamily="var(--font-mono), monospace" transform="translate(280, 40)">
          <rect className="why-meter-box" width="140" height="180" />
          <text className="why-meter-label" x="12" y="22">
            token burn
          </text>
          <text className="why-meter-hint" x="12" y="38">
            every agent pass
          </text>

          {/* rising bars */}
          <g className="why-bars" transform="translate(24, 56)">
            <rect className="why-bar why-bar-1" x="0" y="80" width="18" height="40" />
            <rect className="why-bar why-bar-2" x="28" y="50" width="18" height="70" />
            <rect className="why-bar why-bar-3" x="56" y="20" width="18" height="100" />
            <rect className="why-bar why-bar-4" x="84" y="0" width="18" height="120" />
          </g>

          <text className="why-meter-foot" x="12" y="168">
            no fixed checklist
          </text>
        </g>

        {/* center: vs */}
        <g fontFamily="var(--font-mono), monospace">
          <text className="why-vs" x="450" y="140" textAnchor="middle">
            vs
          </text>
        </g>

        {/* right: codehound path */}
        <g fontFamily="var(--font-mono), monospace">
          <text className="why-col-label why-col-label-good" x="520" y="28">
            codehound
          </text>

          <g className="why-node why-node-good" transform="translate(520, 48)">
            <rect className="why-node-box" width="150" height="52" />
            <text className="why-node-label" x="12" y="22">
              compiled rule
            </text>
            <text className="why-node-hint" x="12" y="40">
              priced once
            </text>
          </g>

          <g className="why-node why-node-good" transform="translate(520, 120)">
            <rect className="why-node-box" width="150" height="52" />
            <text className="why-node-label" x="12" y="22">
              same answer
            </text>
            <text className="why-node-hint" x="12" y="40">
              run twice · identical
            </text>
          </g>

          <g className="why-node why-node-good" transform="translate(520, 192)">
            <rect className="why-node-box" width="150" height="52" />
            <text className="why-node-label" x="12" y="22">
              $0 scan
            </text>
            <text className="why-node-hint" x="12" y="40">
              offline · no API
            </text>
          </g>
        </g>

        <g className="why-wires" fill="none" strokeWidth="1">
          <path className="why-wire why-wire-good" d="M 595 100 V 120" stroke="currentColor" />
          <path className="why-wire why-wire-good" d="M 595 172 V 192" stroke="currentColor" />
          <path className="why-wire why-wire-good" d="M 670 74 H 740" stroke="currentColor" />
        </g>

        {/* stable output card */}
        <g fontFamily="var(--font-mono), monospace" transform="translate(740, 48)">
          <rect className="why-stable-box" width="130" height="160" />
          <text className="why-stable-label" x="12" y="24">
            export
          </text>
          <text className="why-stable-line" x="12" y="52">
            CWE-79
          </text>
          <text className="why-stable-line" x="12" y="72">
            PERF-140
          </text>
          <text className="why-stable-line" x="12" y="92">
            BP-1
          </text>
          <text className="why-stable-hint" x="12" y="120">
            file · line
          </text>
          <text className="why-stable-hint" x="12" y="138">
            snippet · id
          </text>
          {/* blinking cursor */}
          <rect className="why-cursor" x="12" y="148" width="7" height="12" />
        </g>

        {/* pulses */}
        <g className="why-pulses">
          <circle className="why-pulse why-pulse-bad" r="3" fill="currentColor">
            <animateMotion
              dur="1.8s"
              repeatCount="indefinite"
              path="M 170 74 H 280"
            />
          </circle>
          <circle className="why-pulse why-pulse-good" r="3" fill="currentColor">
            <animateMotion
              dur="2.4s"
              begin="0.4s"
              repeatCount="indefinite"
              path="M 670 74 H 740"
            />
          </circle>
          <circle className="why-pulse why-pulse-good" r="3" fill="currentColor">
            <animateMotion
              dur="2.2s"
              begin="0.2s"
              repeatCount="indefinite"
              path="M 595 100 V 120"
            />
          </circle>
        </g>
      </svg>
    </figure>
  )
}
