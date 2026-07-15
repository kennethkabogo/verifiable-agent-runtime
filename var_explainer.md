# VAR — Verifiable Agent Runtime: A Complete Explainer

## The Problem VAR Exists to Solve

Imagine you hire an accountant to audit your invoices. They come back and say: "I found $45,000 in billing errors." You want to believe them. But you also know they typed up that report on their own laptop, could have made mistakes, could have been pressured by someone, could have simply fabricated the finding. Even if you trust this specific accountant personally, there is no way for anyone else — your business partner, your lawyer, an auditor — to independently verify that the report reflects what the software actually found, rather than what the accountant chose to write down.

This is the fundamental problem with AI agents today. An operator runs an AI model on their servers, produces an output, and hands it to you. You can verify the model's weights. You can verify the inputs. But you cannot verify that the operator didn't tamper with the output between when the model produced it and when it reached you. There is no receipt.

VAR — Verifiable Agent Runtime — is the infrastructure that produces that receipt. It makes AI agent output cryptographically auditable, in a way that even the operator who runs the infrastructure cannot forge.

## What a Trusted Execution Environment Is

To understand VAR, you first need to understand Trusted Execution Environments, or TEEs. A TEE is a hardware-enforced isolation boundary inside a processor. Code running inside a TEE is completely isolated from the host operating system, the hypervisor, and everything else on the machine — including the operator who owns and controls that machine.

This is not a software guarantee. It is enforced by the CPU itself. The host cannot read the memory inside the TEE. The host cannot inject code into the TEE. The host cannot intercept the output of a computation running inside the TEE and modify it before returning it. These properties hold even if the host's operating system is fully compromised, even if the operator is malicious.

The second property of a TEE is remote attestation. The TEE can produce a cryptographically signed document — called an attestation — that proves to a third party what code is running inside it. This attestation includes a hash of the exact binary that booted inside the TEE. If even a single bit of that binary differs from the version the third party audited, the hash changes. The attestation is signed by a certificate chain rooted at the hardware manufacturer, which means anyone can verify it without trusting the operator.

Think of it this way: a TEE is a room with no windows and a lock that only the hardware holds the key to. The operator can push inputs through a slot in the door. Results come out through another slot. But the operator cannot see inside, cannot touch what's happening, and cannot forge what comes out. The attestation is the hardware-signed certificate proving that the door is closed and the specific code that was audited is the code running inside.

## AWS Nitro Enclaves

VAR runs on AWS Nitro Enclaves, which is Amazon's TEE implementation built into their Nitro hypervisor. Every modern EC2 instance runs on a Nitro hypervisor — Nitro Enclaves are an optional isolated partition that splits off a portion of the parent instance's CPU and memory and seals it.

The Nitro Security Module (NSM) is a virtual hardware device inside every enclave that produces attestation documents. These documents are COSE-signed structures — a standard cryptographic container format — containing the PCR values of the running enclave and a certificate chain that traces back to a root certificate owned by AWS. PCR stands for Platform Configuration Register: think of each PCR as a running hash that accumulates everything that was loaded as the enclave booted. PCR0 is the hash of the entire Enclave Image File binary. PCR1 is the hash of the Linux kernel and bootstrap environment. PCR2 is the hash of the application code specifically.

If you audit the VAR source code, build the EIF (Enclave Image File) from that source, and measure PCR0, PCR1, and PCR2, then later ask the running enclave to produce an attestation, you can verify that the PCR values in the attestation exactly match what you computed from the audited source. If they match, the code running inside is identical to the code you audited. If they differ by even one bit, you know.

This is what makes the operator-untrusted claim possible. The operator runs the EC2 instance and controls the host machine entirely. But the enclave is sealed. The operator cannot modify what runs inside without changing the PCR values. And the PCR values are embedded in every attestation the enclave produces, signed by AWS's hardware root of trust.

## The KMS Policy: Sealing the Signing Key

VAR uses AWS Key Management Service (KMS) to hold the master encryption key that protects the enclave's signing key. The KMS key policy has a condition: KMS will only allow the Decrypt operation when the request comes with an attestation document whose PCR0, PCR1, and PCR2 values exactly match the audited values. 

This means the enclave cannot retrieve the signing key unless it is running the exact, audited binary. The operator cannot call KMS from outside the enclave and get the signing key — KMS will reject the request because the attestation will not have the right PCR values. Even if the operator tries to run a modified version of the enclave, the PCR values change, KMS rejects the Decrypt call, and the enclave cannot produce valid signatures.

The signing key is born inside the enclave and never leaves it in plaintext. Every output the enclave signs is signed with a key the operator cannot access. This is why we say the system is operator-untrusted: even a fully compromised operator, with root access to the host machine, cannot forge a valid signed output. The forgery would require either breaking Ed25519 or convincing KMS to decrypt without the right PCR values, which is a condition hardcoded into the key policy.

## What VAR Builds on Top of This

VAR wraps this hardware isolation layer with a protocol called APEX — the Attested Protocol for Executable Sessions. APEX defines a precise wire format for recording an entire agent session as a cryptographically chained, hardware-attested bundle.

A VAR session has three components: a header, an evidence chain, and a seal.

The bundle header is produced when a session starts. It contains the session identifier, a bootstrap nonce (a random value generated at session start to prevent replay attacks), and the PCR values of the running enclave. This header is signed by the enclave with its Ed25519 key.

The evidence chain is a sequence of evidence records, one produced for each computation the agent performs during the session. Each evidence record contains a hash of the previous record's state (chaining them together), a hash of the current computation's output (committing to what was produced), the agent's internal state after this step, a cryptographic signature over all of the above, and a sequence number. The chaining means you cannot reorder, insert, or delete steps from the middle of a session without breaking the signature chain. Every computation is permanently recorded in a tamper-evident sequence.

The bundle seal closes the session. It contains a terminal digest — the accumulated hash of the entire session — a bundle hash committing to all the evidence in the chain, and a final signature. Once sealed, the bundle is complete. The session cannot be extended or modified. The seal is the receipt.

## The APEX Verifier: 12 Steps to Certainty

VAR ships an open-source verifier called apex_verify.py. Anyone can run it. It does not require trusting VAR, the operator, or anything except the APEX specification and AWS's public root certificate.

The verifier performs twelve steps. First, it parses the bundle header and checks the magic bytes and version number, confirming this is a valid APEX bundle. Second, it decodes the NSM attestation document from the bundle header. Third, it verifies the NSM attestation document's COSE signature against AWS's Nitro attestation root certificate — this is the hardware root of trust verification. Fourth, it checks the certificate chain inside the attestation document, verifying each certificate in the five-certificate chain from the enclave's signing certificate up to AWS's root. Fifth, it extracts the PCR values from the verified attestation document and records them — these are the hardware-measured values, not anything the operator provided.

Sixth, the verifier parses each evidence record in the chain. Seventh, it verifies the session binding — checking that the session ID and nonce in each evidence record match the header, ensuring all records belong to the same session. Eighth, it verifies the chain linkage — checking that each evidence record's prev_stream field correctly references the hash of the previous record, making the chain tamper-evident. Ninth, it verifies the Ed25519 signature on each evidence record against the public key from the enclave's certificate. Tenth, it verifies the bundle seal's terminal digest against the accumulated chain state. Eleventh, it verifies the seal signature. Twelfth, it computes the Evidence Completeness Ratio — the fraction of evidence records that passed all checks — and reports a final verdict.

A score of ECR 1.0000 means every single computation in the session is verified, chained, and signed by the enclave. No step can be forged, dropped, or replaced.

## The Operator-Untrusted Property in Plain English

Here is the clearest way to say it: the operator runs the machine, but the operator cannot lie about what the machine did.

If you run a company's invoice analysis through VAR, the company cannot tell you it found $45,000 in billing errors unless the enclave actually found $45,000 in billing errors. They cannot inflate the number, deflate it, cherry-pick which errors to include, or modify the report after the fact. The bundle is sealed with a key only the hardware can produce, against PCR values you can verify independently by auditing the source code.

The analysis result is no longer a claim made by the operator. It is a fact attested by the hardware. The operator is a carrier, not a witness.

This flips the trust model entirely. Today, when you receive an AI-generated report, you are trusting the operator's word that the AI produced it and that they didn't modify it. With VAR, you are trusting the AWS Nitro hardware and the APEX verifier — both of which you can audit independently — and the operator's word is irrelevant.

## Real Use Cases

Consider the Mitch Hashimoto scenario: an AI agent analyzes construction invoices and finds $45,000 in billing errors. Without VAR, Mitch presents these findings to his general contractors and they have to take his word that the AI found these errors and that Mitch didn't manipulate the results. With VAR, Mitch sends the sealed APEX bundle. The GCs run apex_verify.py. They see the exact computation that was performed, the exact output that was produced, and a cryptographic proof that neither Mitch nor anyone else could have modified it between computation and delivery. The GCs are not trusting Mitch — they are trusting the hardware.

In financial services, regulators increasingly require audit trails proving that automated decisions were made by specific, approved models without human manipulation. VAR produces those audit trails at the hardware level. A bank using a VAR-sealed model for credit decisions can prove to a regulator that the model produced the specific output, that no one tampered with it, and that the model running today is identical to the model that was approved.

In enterprise procurement, when an AI agent negotiates a contract or approves a purchase, every counterparty wants to know that the decision was made by the agreed-upon system and not modified by a human after the fact. VAR seals each decision into an attested bundle that all parties can verify independently.

In DeFi and blockchain applications, on-chain contracts increasingly rely on off-chain computation for things like price discovery, liquidation triggers, and data feeds. The on-chain contract cannot verify what happened off-chain. VAR bridges this gap: the off-chain computation is sealed in an APEX bundle, and the verifier can be run by anyone to confirm the result before it is accepted on-chain.

## What Makes This Hard to Build

The technical difficulty is not the cryptography — the cryptography is well-established. The difficulty is the protocol design and the verifier.

A naive implementation would simply sign the output. But signing the output doesn't prove anything about the intermediate steps. An operator could run an unauthorized computation, sign only the final result, and claim it came from the approved model. APEX's evidence chain prevents this: every intermediate step is chained and signed, so the verifier can confirm not just the final output but the entire computation path.

A naive implementation might also rely on the operator to correctly assemble the bundle. APEX's design ensures the bundle is assembled inside the enclave and sealed there — the operator receives the sealed bundle and cannot modify it without invalidating the seal signature.

The Argon2id key derivation in APEX's session initialization is another design choice that matters: using Argon2id with parameters tuned to the specific hardware (128 MiB memory, 3 iterations, as measured on a production Nitro instance) ensures the session key derivation is memory-hard, making brute-force attacks against the session even if the ciphertext were exposed computationally infeasible.

## Where VAR Is Today

VAR is running in production on AWS Nitro. The enclave is live. The APEX protocol is at version 2.7.1. A browser-based demo is publicly accessible and connects to the live enclave in real time — when you submit a computation, it travels via vsock into the isolated enclave, the enclave signs the result, and the demo's right panel runs the 12-step verifier and shows you ECR 1.0000 in real time.

The open-source verifier apex_verify.py is available for anyone to run independently. The production bundle can be verified without installing anything except Python. The KMS key policy is published. The PCR values are public. Any auditor can reproduce the entire trust chain from source code to running enclave.

The next milestone is adding a second function to the dispatch table — a document verification primitive that takes a document and expected hash, verifies the match inside the enclave, and returns a signed attestation. This closes the last gap between "here is an echo that proves the plumbing works" and "here is a business primitive that proves the operator-untrusted property is load-bearing for a real outcome you care about."
