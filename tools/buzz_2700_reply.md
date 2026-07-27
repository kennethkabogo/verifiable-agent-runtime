@eriknewton the "different question" framing is exactly right, and worth making explicit:

- **Castle Wall / Sanctuary**: what destinations can this process reach? Answered at the uid/kernel level — below the runtime, above root.
- **VAR / APEX**: what can hold the signing key? Answered at the KMS policy level — the key releases only to a measured enclave whose code hash matches. Root on the host doesn't get the nsec; the enclave does.

Neither alone is sufficient for the Buzz/Nostr case. An agent that can't reach unauthorized endpoints but holds its own nsec in process memory can still sign maliciously on approved channels — and root doesn't need to beat the egress wall to get the key, it can read the signing process's memory directly (ptrace, a core dump, /proc/<pid>/mem) with zero network traffic involved. An agent whose key is enclave-bound but faces no egress constraint can exfiltrate over any reachable channel. The composition closes both.

Worth naming the honest limits on our side in the same spirit you did:

**Trust relocation, not elimination.** "Not even the operator can extract the key" is true conditional on AWS's Nitro hypervisor and attestation signing infrastructure. We're relocating trust from the Buzz operator to AWS, not removing it. That's already explicit in VAR's own README — enclave side-channel attacks are Nitro's responsibility, explicitly out of scope on our end. Worth saying directly rather than leaving it as fine print.

**KMS governance in a self-hosted deployment.** Buzz's model is operator-run infrastructure. If the operator is also the AWS account owner, they wrote the KMS key policy initially and nothing prevents them from widening it later — adding an authorized PCR value for a different, backdoored image, for example. The enclave guarantee holds at runtime given a correctly configured, unchanged policy. Closing the IAM-governance version of "root is above it" requires something separate: a break-glass account the operator doesn't control, multi-party approval on policy changes, or a public log of authorized PCR values. None of that is in what we've described.

A smaller one: attestation confirms the same binary ran, not that it's safe. A compromised dependency in the enclave image is faithfully attested. That's closed by reproducible, independently-auditable builds — a separate problem we don't claim to solve.

For Nostr specifically: the nsec is the identity. Losing it isn't a signing incident — it's an identity incident, retroactive impersonation for the life of the key. That's what makes the enclave question load-bearing here in a way it isn't for most agent runtimes.

Glad to compare notes on composition. APEX spec: https://github.com/kennethkabogo/verifiable-agent-runtime/blob/main/spec/APEX.md
