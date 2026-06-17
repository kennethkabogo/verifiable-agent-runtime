# ZK Integrity Proof for APEX Hash Chains — Research Notes

## The Gap

APEX v2.3.0 defines a TEE-attested evidence chain where each packet carries an
Ed25519 signature and a running L1/L2 hash. Verification today is O(n·sig) —
a verifier must replay every packet, re-derive the hash chain, and check every
signature. For long-running agent sessions (thousands of evidence packets) this
is expensive and non-scalable.

**The publishable claim:** reduce the verification cost of the chain integrity
claim from O(n·sig) to O(1) using an incremental ZK proof, without replacing
the TEE hardware root of trust.

## What Gets Proven

The ZK proof covers chain integrity only:

```text
∀ i ∈ [1..n]:
  H(prev_stream_i || packet_data_i) == stream_i      // L1 chain step
  verify_ed25519(sig_i, stream_i, pubkey)             // signature check
```

The terminal digest `stream_n` is the public output of the proof. A verifier
checks:

1. The ZK proof is valid (O(1)).
2. The terminal digest matches the attested value in the TEE report (O(1),
   conventional signature check).

TEE attestation remains a conventional side-channel — the hardware root of
trust is not ZK-proven and does not need to be. This is the honest constraint.

## Construction: Nova/SuperNova IVC

Nova's incremental verifiable computation (IVC) is the natural fit:

- The per-step circuit is **uniform** — same hash function, same sig scheme,
  same transition relation at every evidence packet.
- Nova folds n identical step proofs into a single accumulator. The final
  verifier only touches the accumulator proof and the terminal digest.
- SuperNova extends this if future APEX variants need non-uniform step
  circuits (e.g., different hash functions per segment type).

The IVC structure maps directly:

```text
z_0 = (genesis_stream, pubkey)
z_i = fold(z_{i-1}, packet_i)   // hash step + sig check
z_n = terminal_digest            // public output
```

## The Ed25519 Problem

Ed25519 is SNARK-hostile — its field arithmetic does not align with typical
SNARK prime fields (BN254, BLS12-381). Options:

**Option A — SP1 / Risc0 precompile (accepted path):**  
Prove Ed25519 verification via a trusted precompile. The claim becomes:
*"chain integrity is ZK-verifiable given correct Ed25519 precompile behavior."*
This is an explicit trust assumption, stated honestly in the security model.
Still a meaningful claim — the precompile is audited, not arbitrary code.

**Option B — SNARK-friendly signature scheme:**  
Replace Ed25519 with BabyJubJub or Jubjub at the APEX protocol level.
Breaks TEE key generation (secure enclaves generate Ed25519/P-256, not Jubjub).
Only viable if APEX is extended with a key derivation layer that converts the
TEE keypair to a SNARK-friendly key — adds protocol complexity and a new trust
assumption. Not the right tradeoff for v1 of this research.

**Decision:** Option A. Accept the precompile cost. Be explicit in the paper.

## CTMC Session Lifecycle Model

The APEX session lifecycle maps to a four-state continuous-time Markov chain
(CTMC). Each state corresponds to a condition APEX v2.3.0 explicitly handles
(or explicitly does not handle).

```text
        λ_AD                λ_DR
  S_A ──────► S_D ──────► S_R
   │           │            │
   │ λ_AF      │ λ_DF       │ λ_RF
   ▼           ▼            ▼
  S_F         S_F          S_F
```

- **S_A — Active:** Normal operation; evidence flowing. Happy path.
- **S_D — Degraded:** Enclave running but network partitioned. Evidence sealed locally, not yet remotely verified. Sealed checkpoint survives; chain resumes on reconnect (§9, §10).
- **S_R — Recovering:** Crashed; restarting with valid sealed state. RESUME flow: BundleSeal + SESSION_RESUME first packet (§9.2, §9.3).
- **S_F — Failed:** Crashed AND sealed state corrupted or missing. Cold restart; chain break; explicitly unrecoverable.

**Transition rates (to be fitted from deployment data):**
- λ_AD: Active → Degraded (network partition rate)
- λ_DR: Degraded → Recovering (crash-during-partition rate)
- λ_AR: Active → Recovering (clean crash rate, implied via S_A → S_D → S_R)
- λ_xF: any state → Failed (sealed state corruption rate; expected near-zero under KMS)

**The adversarial S_D → S_F transition:**  
If an attacker forces a crash during a network partition, a stale sealed
checkpoint may be replayed on RESUME. The KMS unseals it (PCR measurement is
valid), the chain resumes from stale state, and evidence emitted between the
last checkpoint and the partition is silently dropped. This is the sharpest
adversarial transition in the model: it requires no cryptographic break, only
timing. APEX v2.3.0 documents this as a known gap (§12). The mitigation
(anti-replay on checkpoint sequence number at the KMS layer) is a v3.x
candidate.

The CTMC answers the availability question: given real deployment failure rates
for λ_AD and λ_DR, what fraction of sessions complete with a full, unbroken
chain? This is the formal complement to the ZK integrity proof, which answers
the verification question given a complete chain.

## Two-Layer Thesis (Markantonakis / Royal Holloway)

The full formal treatment of APEX as a dependable, efficiently verifiable
attestation primitive splits cleanly into two independent contributions:

| Layer | Question | Model |
|-------|----------|-------|
| **Availability** | What is the probability the chain is *complete* under real deployment conditions — crashes, OOM, network partition? | CTMC (APEX as ECA/MTBEG) |
| **Verification efficiency** | Given a complete chain, what is the cost of verifying it is correct? | ZK integrity proof (Nova IVC) |

These are complementary, not redundant. The CTMC models whether the chain
exists. The ZK proof models the cost of trusting the chain that exists.
Together they are a complete formal treatment.

**Target venue:** IEEE S&P, CCS, or USENIX Security — the combination of a
formal dependability model and a practical ZK construction is unusual enough
to be a differentiator.

## Online Proof Generation

Current ZK proving systems are batch-after-the-fact: collect all data, then
prove. APEX with Nova IVC is a different primitive: **online proof generation**,
where the accumulator grows incrementally alongside the live session.

`pollEvidenceSince(cursor, timeout_ns)` drains packets in strict sequential
order — cursor advances monotonically, each call returns the next contiguous
slice of `evidence_log`. This is exactly Nova's IVC consumption pattern: each
folding step takes the previous accumulator and the next packet, produces a new
accumulator, and advances. The prover is a natural consumer of the SSE feed.

Consequences:

- **Proof is complete at termination.** By the time `POST /terminate` fires and
  the BundleSeal is written, the accumulator has already processed every packet.
  There is no post-hoc batch proving phase.
- **Mid-session verifiability.** A remote monitor can request the current
  accumulator state at any point and verify chain integrity up to that packet —
  not just at session end. This is a stronger audit guarantee than batch proving
  provides.
- **`GET /evidence/stream` is load-bearing for the prover.** The SSE endpoint
  was justified as a real-time monitoring convenience. The stronger justification
  is architectural: it is the feed a Nova prover would consume. The endpoint's
  existence and its ordered, cursor-based delivery are preconditions for online
  proving, not incidental features.

This is directly relevant for Markantonakis's focus on attestation for
constrained devices. Online proof generation over a live evidence stream on edge
hardware means the device never needs to buffer the full session before proving —
the proof accumulates in bounded memory as the session runs. That property is not
achievable with batch ZK systems.

## Open Questions

1. **Proof generation cost** — Nova folding over n=10,000 Ed25519 precompile
   invocations: what is the wall-clock cost? Needs benchmarking in SP1.
2. **L2 cross-session chain** — L1 is per-session (IVC natural). L2 links
   sessions. Does the ZK proof need to cover L2, or is L2 verification left to
   the conventional verifier?
3. **Prover as SSE consumer** — what is the wire protocol between the SSE
   endpoint and a co-located Nova prover process? Shared memory vs. socket vs.
   in-process folding. The cursor API already has the right shape; the question
   is where the prover runs.
4. **Session resume** — APEX §9/§10 crash recovery emits a SESSION_RESUME
   packet that re-anchors the chain. The IVC circuit needs a special case for
   resume steps, or resume is treated as the start of a new IVC instance linked
   to the prior terminal digest. The online prover must handle this at the
   moment the resume packet appears in the stream, not retroactively.
5. **Temporal attestation gap** — The L1 hash chain proves ordering and
   completeness: nothing was dropped or reordered between genesis and terminal
   digest. It does not prove that the session took any particular amount of
   elapsed time. A precomputed session can produce a valid APEX bundle in
   milliseconds. For most agent workloads this is not the relevant threat — a
   replay of a prior valid execution is caught by the session nonce and
   timestamp in the TEE report, not by chain structure. But duration attestation
   is a distinct claim that the chain does not make.

   Two workloads where this matters: billing by compute time (the agent claims
   10 minutes of work; how do you verify it wasn't precomputed?), and
   preventing pre-canned replay attacks in interactive workflows where the
   agent should be responding to live inputs, not a prerecorded trace.

   Two approaches:
   - **Argon2id SWF (Condrey's approach):** The sequential work function
     forces a minimum wall-clock cost per checkpoint. The chain's existence
     proves elapsed time because Argon2id cannot be parallelized below its
     memory-time parameters. Adds measurable overhead (~25% per Condrey's
     numbers); the overhead *is* the proof.
   - **Trusted timestamp service:** Embed a signed timestamp from a
     verifiable source (RFC 3161 TSA, or a TEE-hosted clock) into the chain
     at regular intervals. Simpler, no computational overhead, but introduces
     a new trust assumption (the timestamp authority). More practical for
     APEX's existing architecture.

   APEX v2.x does not address temporal attestation. Worth flagging as a v3.x
   research candidate, particularly for billing and interactive-agent workloads.

## Prior Art: Condrey et al. (arXiv:2603.00178)

David Condrey (a contributing member of C2PA) independently arrives at the same
four-state CTMC model, the same trust inversion threat model, and the same
sealed state recovery protocol in the context of *human authorship verification*.
His paper is the closest prior work to APEX and must be cited prominently.

**Where the papers converge:**

- Four-state CTMC: Active / Degraded / Recovering / Failed — identical state
  space and transition logic
- Evidence Chain Availability (ECA) closed-form expression and MTBEG metric —
  the same availability question APEX's model answers
- Sealed state recovery: authenticated encryption, predecessor hash chaining,
  recovery markers — structurally identical to APEX §9/§10
- Trust inversion threat model: adversary controls OS and hypervisor, cannot
  read enclave plaintext or forge attestation quotes

**The critical scope boundary (load-bearing for APEX's claim):**

Condrey's paper is explicitly scoped to human authorship in interactive writing
sessions (keystroke dynamics, 30-second checkpoints, behavioral entropy). It
states directly that it does not address agent execution or autonomous systems.
That sentence is the differentiation claim. APEX extends the same formal
framework from human-in-the-loop authorship attestation to fully autonomous
agent execution — a different principal, a different evidence structure, and a
different threat model (no behavioral entropy; the agent's policy is the
constraint, not its typing rhythm).

**Implementation differences (not differentiators — just context):**

- Condrey: Intel SGX2, Argon2id Sequential Work Function, keystroke evidence
- APEX: AWS Nitro Enclave, Ed25519 hash chain, execution trace evidence

**Condrey's Tier model and APEX's input-channel gap:**

Condrey's paper addresses input-channel integrity through a three-tier trust
model. Tier 1: software-attested inputs (clipboard, synthesized text). Tier 2:
OS-mediated hardware inputs (keyboard, mouse — trustworthy against remote
adversaries but not against a compromised OS). Tier 3: hardware-bound input
path, where the input device attests directly to the enclave without passing
through the OS. Tier 3 is the full solution to input-channel trust.

APEX §12 documents the analogous gap: the TEE boundary cannot attest to the
integrity of inputs delivered from outside the enclave (prompt content, tool
call responses, external data). The input-channel section of APEX's threat
table maps directly to the Tier 1/2/3 model. Tier 3 hardware-bound input is
the complete mitigation; it is correctly scoped as out of band for v2.x.
Condrey's paper is the prior art for both the threat framing and the Tier 3
solution architecture.

**What Condrey establishes that APEX inherits:**

ECA >99.5% with <25% per-checkpoint overhead on SGX2. Sealed recovery under
200 ms. These numbers validate the feasibility of the approach before APEX has
its own benchmark data. Cite them; extend them to the Nitro platform.

## Temporal Attestation — Paper Contribution

The research contribution for the formal paper is the SWF placement, not the
full protocol design. Prior work (Condrey et al.) places Argon2id at checkpoint
boundaries for human authorship sessions; APEX places it at hibernation
boundaries for autonomous agent sessions — different principal, different threat
model, same structural solution. The TSA timestamp (SETTLEMENT_INIT) is
engineering practice; the SWF at sealed-state transitions is what distinguishes
APEX temporally from prior work and belongs in the paper. Full protocol design
notes (packet format, verifier rules, parameter governance) live in
[research-roadmap.md](research-roadmap.md).

## Timeline

- **Prototype:** SP1 circuit for L1 chain over Ed25519 precompile, benchmarked
  against naive O(n·sig) verifier. Goal: proof-of-concept numbers.
- **Formal model:** CTMC for APEX session lifecycle (ECA/MTBEG framing).
  Target: align with Markantonakis conversation, February 2027.
- **Combined paper:** Full two-layer thesis (CTMC + ZK) targeting S&P 2028 cycle.
  Non-ZK tracks (C2PA integration, ECR) tracked in
  [research-roadmap.md](research-roadmap.md).
