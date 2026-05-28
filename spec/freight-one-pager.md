# VAR + Finfiti for Autonomous Freight Decisions

*Draft — for internal use*

---

## The problem

Freight operations are increasingly automated. Agents are making decisions — releasing containers, marking shipments cleared, triggering carrier payments — that carry real legal and financial weight. When something goes wrong, the question isn't just *what happened* but *who decided it, when, and on what basis.* Today there is no clean answer to that question when the decision-maker is an AI agent.

## The accountability gap

A human freight coordinator who releases a shipment incorrectly is accountable — there's a name, a timestamp, an email. An autonomous agent that does the same thing leaves a gap. Freight companies, customs authorities, and insurers are beginning to ask how that gap gets closed. The answer cannot be "trust the operator" — that's the same answer that has failed in every prior accountability crisis.

The audit trail today is a log file. Log files can be altered. An APEX bundle cannot be — the hardware-rooted signature makes any alteration detectable before the evidence is ever presented.

## What VAR provides

VAR is a runtime for AI agents that produces cryptographic proof of every decision the agent makes. The proof is hardware-rooted — generated inside a Trusted Execution Environment, signed with a key that cannot be extracted, and chained so that any gap or alteration is detectable. The output is an APEX bundle: a tamper-evident record of exactly what the agent did, in what order, with what inputs, at what time.

For a freight agent, an APEX bundle answers the question a compliance officer, insurer, or customs authority will ask: *prove that the agent made this decision correctly and that the record hasn't been touched since.*

## What Finfiti adds

Freight settlement is a separate pain point — disputed invoices, demurrage charges, carrier payments delayed by documentation disputes. Finfiti gates financial settlement on a verified APEX attestation. The agent decision and the financial consequence are linked cryptographically: payment releases only when the attested decision is verified. No attestation, no payout.

This closes the loop in both directions. The freight company can prove the decision was correct. The carrier gets paid faster because the proof is machine-verifiable, not dependent on a human document review cycle.

## The pitch to a compliance buyer

Not: *here is a cryptographic audit trail.*

Instead: *when a dispute arises — and it will — you have evidence that is faster to produce, harder to challenge, and more precise than anything a log file or a human affidavit can provide. That reduces your exposure and shortens your dispute resolution cycle.*

## Next step

Validate the accountability gap directly with an AgentAstra conversation. The question to ask is not *"would you use this?"* but *"what happens today when one of your agent decisions is disputed?"* The answer to that question tells you whether the gap is felt or theoretical.
