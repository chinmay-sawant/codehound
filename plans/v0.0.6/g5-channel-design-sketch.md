# G5 — Channel transfer design sketch (no fake assignment edges)

> **Parent contract:** [`g5-channel-capability-contract.md`](./g5-channel-capability-contract.md)  
> **Issue:** [#156](https://github.com/chinmay-sawant/codehound/issues/156)  
> **Date:** 2026-07-23  
> **Status:** Design sketch — **v0 pilot implemented** (`ChannelTransfer` same-function pairing)

---

## Goal

Define how a future impl would model **same-function unbuffered** channel
handoff without turning send/receive into ordinary `AssignmentDetail` sugar.

---

## Proposed record types (sketch)

```text
ChannelIdentity   — binding of a channel value in a scope (not bare name strings
                    across unrelated decls)
ChannelSend       — (channel_id, value_expr, byte_offset)
ChannelRecv       — (channel_id, lhs_binding?, byte_offset)
ChannelTransfer   — directed send→recv edge only when pairing rules hold
UnsupportedFlow   — residual Channel/Goroutine when pairing declines
```

**Rule:** `ChannelSend` must **not** set `AssignmentDetail.is_channel_send` as a
graph assignment. Transfers live in a dedicated list queried by the path finder.

---

## Pairing rules (v0 pilot — same function only)

1. Single lexical function / method body.  
2. One `ChannelIdentity` for the channel operand (same binding).  
3. Unbuffered handoff: at least one send and one recv on that identity.  
4. Conservative: if multiple sends or multiple recvs without a clear order
   model, **decline** → leave `UnsupportedFlow::Channel` (honest FN).  
5. `select` / buffer / close / range: **decline** in v0.  
6. `go` spawn: still `UnsupportedFlow::Goroutine`; v0 does not invent MHP edges.

---

## Path-finder integration (sketch)

When searching sink←source:

- Follow existing assignment / call edges as today.  
- Optionally follow `ChannelTransfer` when contract says the recv binding is
  tainted from the send value.  
- Never treat unsupported Channel sites as assignments.

---

## IP-010 residual

Today, source-as-send-value may still attribute via extractor quirks.  
**Impl PR must either:**

- replace that quirk with `ChannelTransfer` + fixtures, **or**  
- explicitly quarantine/document it as non-support in the same PR.

No dual story (“unsupported” in docs + silent attribution as support).

---

## Fixtures required before merge of any impl

| Fixture | Expectation |
|---------|-------------|
| Vuln: source → send → recv → sink (same fn, one channel) | Finding |
| Safe: constant/sanitized send → recv → sink | Silence |
| Negative: `ch1` taint must not poison `ch2` | Silence on `ch2` path |
| Unit: declined shapes still record `UnsupportedFlow` | Assert kinds |

---

## Non-goals of this sketch

- Package-wide sender/receiver fan-in  
- Cross-goroutine heap taint  
- Security-grade concurrency proofs  
- Implementing edges in this docs PR  
