# Evidence — G5 advanced taint ceiling gates (v0.0.6)

> **Issue:** [#156](https://github.com/chinmay-sawant/codehound/issues/156) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)  
> **Branch:** `chore/g5-taint-ceiling-gates`  
> **Base:** `origin/master` (includes G4 `--typed` product layer)  
> **Date:** 2026-07-23  
> **Outcome:** **Ceiling chosen + reopen contract locked**; channel edges **still deferred** (no engine change)

---

## Stream selection

| Option | Chosen? |
|--------|---------|
| **Channel / goroutine handoffs** | **Yes** (same as Phase 5 G5) |
| External-package summaries | No — still deferred |
| Decoder-receiver outputs | No — still deferred |

Why channels: strongest existing explicit FN model (`UnsupportedFlow::{Channel,Goroutine}`); highest FP risk if faked; **not** solved by G4 typed facts alone.

---

## Reopen gates (this package)

| Gate | Status |
|------|--------|
| Written FP/FN contract for the stream | **PASS** — [`g5-channel-capability-contract.md`](./g5-channel-capability-contract.md) |
| Design without invented unsupported→assignment edges | **PASS** — [`g5-channel-design-sketch.md`](./g5-channel-design-sketch.md) |
| Fixtures + integration + canary | **OPEN** — required for **impl** PR only |
| Dependency clarity vs G4 | **PASS** — typed optional helper only; no side-door (contract § Dependency clarity) |

Honesty regression (current ceiling still holds):

```text
cargo test --locked --lib channel_send
```

| Test | Result |
|------|--------|
| `channel_send_is_unsupported_not_assignment` | **ok** |
| `channel_send_receive_handoff_remains_silent_fn` | **ok** |

---

## Explicit non-actions (this PR)

- No channel / receive / goroutine taint **edges**  
- No external-package or decoder-receiver work  
- No README / taint.md claim of channel support  
- No weakening of silence tests  

---

## Next (implementation tranche)

Open a **scoped** follow-up (do not bulk under #156 alone) only when ready to ship:

1. `ChannelTransfer` (or equivalent) per design sketch  
2. Vuln + safe + multi-channel fixtures  
3. Canary sanity  
4. Same-PR `documents/taint.md` update + IP-010 plan  

Until then: product taint keeps **honest FN** on concurrent handoffs.
