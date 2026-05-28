# VAR Vertical Scan — Agentic Accountability

*Internal reference — produced 2026-05-28*

---

## Thesis

The demand for "prove exactly what the agent did and when" scales with the real-world consequence of the agent's decisions. VAR's attestation layer is technically indifferent to the domain — the L1 hash chain captures every output, the signature scope proves order and timing, and the BootstrapNonce anchors it to specific hardware. The question is which verticals have the right combination of accountability gap, settlement layer fit, and sales cycle to prioritise.

## Screening criteria

Three properties needed for a vertical to be worth active motion:

1. **Accountability gap is acute** — autonomous agents making decisions with real-world consequences and no clean answer to "prove what happened"
2. **Settlement layer is a natural fit** — financial consequence attached to the agent decision, where Finfiti's attestation-gated payout adds direct value
3. **Sales cycle is manageable** — a commercially motivated buyer, not a buyer trapped in a multi-year regulatory procurement cycle

## Vertical map

| Vertical | Accountability gap | Settlement layer | Sales cycle | Priority |
|:---|:---|:---|:---|:---|
| Freight / logistics | Acute | Natural fit — carrier payments, demurrage, cargo release | Manageable — commercial ops/compliance buyer | **Now** |
| Legal discovery | Acute — agents making relevance decisions on documents | Not needed | Moderate — law firm or in-house counsel | Watch |
| Insurance claims | Acute — agents making coverage decisions | Natural fit — claims payout | Moderate — insurer is commercially motivated | Watch |
| Healthcare | Acute | Possible | Long — regulatory surface too hard right now | Defer |
| Energy trading | Acute | Natural fit | Long — NERC CIP, utility procurement cycles | Defer |

## Notes

**Freight** is the priority because it has all three properties and the near-term opportunity is concrete. AgentAstra (a16z speedrun + Earthling-backed) is building logistics agents that will touch real freight decisions. The window to be the native attestation layer rather than a bolt-on is now.

**Legal discovery and insurance** have the right shape. Neither has freight's urgency but both are worth a line in the thesis. Insurance is the more natural Finfiti fit of the two.

**Healthcare and energy** are confirmed right shape, wrong cycle. Revisit when a specific inbound demand signal exists — don't pursue cold.

## Origin

This scan emerged from a broader framing: "agentic access to physical infrastructure." Container shipping is physical infrastructure wearing a logistics coat. The agents AgentAstra is building will touch real-world freight decisions — release a container, mark a shipment cleared, trigger a settlement. That's the physical-infrastructure thesis in its most commercially actionable form right now.

## Next action

One conversation with AgentAstra. Diagnostic question: *"what happens today when one of your agent decisions is disputed?"* See `freight-one-pager.md`.
