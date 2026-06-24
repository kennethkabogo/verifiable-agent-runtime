# APEX Input-Channel Attestation: Scope, Limitations, and Roadmap

*VAR / APEX — Technical Position Paper*  
*Revision 1 — 2026-06-24*  
*Status: Published*

---

## Summary

APEX proves that a specific, unmodified enclave produced specific outputs in a specific sequence. It does **not** cryptographically prove that the inputs sent to the enclave were authorized by the customer and were not modified by the operator before reaching the enclave boundary. This document describes that scope boundary precisely, explains why it is the correct design for v1, identifies the practical mitigations available today, and states the roadmap to full cryptographic closure.

Customers and their auditors should read this document before any audit or settlement engagement.

---

## What APEX Guarantees

An APEX Evidence Bundle gives any third-party verifier the following guarantees without trusting the operator:

1. **Enclave identity.** The bundle was produced by an enclave whose image matches a specific PCR0/PCR1/PCR2 measurement, rooted in hardware attestation signed by AWS Nitro. An operator cannot fake this.

2. **Output integrity.** Every output the agent produced — every terminal line, every command executed, every secret accessed — is committed to a hash chain. Any alteration after the fact is detectable; any gap in the sequence causes verification to fail.

3. **Execution sequence.** The sequence numbers and PrevL1Hash chain enforce strict ordering. An operator cannot reorder, drop, or inject evidence packets without breaking the chain.

4. **Temporal bounds at hibernate boundaries.** Each TEMPORAL_PROOF packet cryptographically bounds the elapsed wall-clock time at every suspend/resume cycle via an Argon2id sequential work function, preventing undetected time manipulation.

5. **Settlement linkage.** A Settlement Block, if present, is signed by the same enclave key and cryptographically linked to the verified evidence chain. A settlement system cannot release funds without a valid, fully verified bundle.

These guarantees are hardware-rooted and do not require trusting the operator, the host, or the network path between the customer and the enclave.

---

## The Input-Channel Scope Boundary

APEX does not currently provide a cryptographic proof that the commands or instructions delivered to the enclave arrived unmodified from an authorized source. Concretely:

- An operator could send a modified system prompt to the enclave without the customer's knowledge.
- An operator could inject additional commands between authorized customer instructions.
- An operator could withhold or delay commands the customer intended to send.

The enclave would faithfully execute and attest to what it received — but the attestation covers the *execution*, not the *authorization chain of the input*.

This is an intentional scope boundary in v1, not an oversight. The analogy is a court reporter: they produce a certified, tamper-evident record of what was said in the proceedings. They do not certify that the proceedings were lawfully convened or that all parties were present with proper authorization. Both guarantees matter; they address different layers of trust.

### What an adversarial operator can do with this gap

- Modify instructions to the agent to produce a specific favored outcome, then use the APEX bundle as proof that the agent "independently" produced it.
- Frame a biased execution as an unbiased attestation.

### What an adversarial operator cannot do

- Alter the agent's output after the fact — the L1 chain detects this.
- Produce a valid bundle from a modified enclave image — PCR0 detects this.
- Fabricate or backdate evidence — the NSM-signed attestation document and the Argon2id temporal proof prevent this.

---

## Why This Scope Is Sufficient for Most v1 Use Cases

For the freight and logistics use case, the customer's primary question is: *"Prove that the agent made this specific decision, correctly, based on the information available to it at the time, and that the record of that decision has not been touched since."*

APEX answers that question fully. The dispute scenarios that freight operators, carriers, and customs authorities face are predominantly output disputes — *what did the agent decide* — not input tampering disputes. An operator who tampers with inputs to cause a favorable agent decision is committing fraud against the customer, not exploiting a protocol gap; that is addressed by contract, ToS, and existing fraud law.

For settlement payouts, the relevant verification is that the agent's attested decision matches the settlement condition. APEX provides that. The question of whether the operator sent the agent legitimate inputs is a customer-operator relationship question that contract governs.

That said: for high-value settlement environments — particularly where the operator is not the customer and the customer has no direct relationship with the infrastructure — the gap becomes load-bearing. See the roadmap below.

---

## Mitigations Available Today

Several partial controls narrow the practical exposure of this gap without requiring protocol changes:

**1. EXEC packet audit trail.**  
Every command the agent executes is recorded in an `EXEC` packet committed to the L1 chain. The packet includes the full command, a SHA-256 of stdout, and a SHA-256 of stderr. An auditor who inspects the bundle can reconstruct every action the agent took and verify it is consistent with the stated task scope. A command injection by the operator would appear in this log.

**2. Operator SLA and contractual commitment.**  
The operator contractually commits to delivering instructions unmodified from the customer source. The APEX bundle, combined with this commitment, makes any deviation provable from the output evidence: if the bundle shows commands that the customer did not authorize, the customer has both the contractual breach and the cryptographic evidence.

**3. Customer-visible session scope.**  
The bundle is delivered to the customer after the session ends. The customer can inspect every EXEC packet and every STREAM packet before any settlement is triggered. An anomalous command — one they did not authorize — is visible in the bundle before they sign off on settlement.

**4. Independent verification.**  
The customer's auditor can independently verify the bundle without installing any operator software. The verification tooling is open-source and the spec is public (APEX.md). This means the operator cannot suppress anomalous evidence without the anomaly being detectable at verification time.

---

## Roadmap to Full Cryptographic Closure

APEX v3.x will close the input-channel gap via a customer-signed command commitment scheme:

**Target design.** Before each command is executed, the customer signs the command payload with a key they hold and the operator does not. The enclave verifies this signature before executing the command and commits the verification result to the L1 chain. A bundle produced under this scheme proves not only what the agent did but that each action was authorized by the customer.

**Implementation path.**
- v2.x (current): Output attestation. Operator is trusted for input delivery; customer audits outputs.
- v3.0: Input commitment. Customer-signed commands committed to L1; operator cannot inject or modify commands without detection.
- v3.x: Blind execution option. Customer communicates directly with the enclave via an mTLS channel using a customer-held key; operator provides compute only and cannot read or modify inputs.

**Timeline.** v3.0 design is in `spec/research-roadmap.md`. No implementation date committed. Customers requiring v3.0 guarantees for initial deployment should discuss requirements with VAR directly.

---

## For Auditors

If you are auditing an APEX bundle on behalf of a customer:

1. Verify the bundle using the reference verifier (link in APEX.md §17). Do not accept an operator-provided verification result.
2. Inspect every `EXEC` packet. The command field shows the exact command the agent ran; the StdoutHash lets you verify the output. Anomalous commands that the customer did not authorize are detectable here.
3. Confirm PCR0 matches the expected enclave image. The expected PCR0 is published separately by the operator and can be cross-referenced with the KMS key policy (which is locked to the same PCR values).
4. Note that you are verifying output fidelity, not input authorization. If the scope of your engagement requires input authorization proof, consult the operator SLA and the customer's instruction log and raise the v3.0 roadmap with the customer as a future requirement.

---

## Contact

Questions on this document or the APEX specification: kenneth@var.dev  
APEX specification: [APEX.md](APEX.md)  
Public repository: https://github.com/kennethkabogo/verifiable-agent-runtime
