# Verifiable Agent Runtime (VAR)

**AI agents running in production today have no way to prove what they actually did.**

They run with high-privilege credentials, on infrastructure you don't control, and produce logs that any compromised host can silently alter. When something goes wrong — or when a regulator asks — there is no cryptographic record you can point to.

VAR solves this. It wraps any autonomous agent in a hardware-enforced trust boundary, produces a continuous cryptographic evidence chain of everything the agent did, and lets any external party verify that chain without trusting the host, the operator, or the agent itself.

---

## How it works — in three steps

```
1. ATTEST   Hardware certifies the exact binary running inside the enclave.
            A remote verifier can confirm it has not been tampered with
            before sending a single credential.

2. RUN      The agent executes normally — any language, any framework.
            Every byte of terminal output is folded into a live hash chain
            signed by a key that never leaves the enclave.

3. VERIFY   Anyone with the evidence bundle can independently replay the
            session and confirm that the signed hashes match — after the
            fact, without trusting any single party.
```

---

## Why this matters

The emerging market for autonomous AI agents — coding agents, financial agents, infrastructure agents — will require the same auditability guarantees that regulated industries already demand of human operators. The tooling does not exist yet. VAR is that tooling.

It is not an SDK you ask developers to adopt. It is a **sidecar** that wraps whatever the agent is already running — a trust upgrade that is invisible to the application layer.

---

## The three pillars

### 1. TEE / Silicon Isolation

The agent runtime executes inside a **Trusted Execution Environment** (AWS Nitro Enclave today; ARM CCA in the roadmap). The host operating system cannot read or modify the enclave's memory, even with root access.

```
┌─────────────────────────────────────────────────────────────┐
│                    UNTRUSTED ZONE                           │
│                                                             │
│   ┌─────────────────┐        ┌────────────────────────┐    │
│   │   Agent Process  │        │     Host Proxy          │    │
│   │  (any language)  │        │  (Python / Go / etc.)   │    │
│   └────────┬─────────┘        └───────────┬────────────┘    │
│            │ HTTP REST (loopback)          │ vsock           │
└────────────┼──────────────────────────────┼─────────────────┘
             │                              │
┌────────────┼──────────────────────────────┼─────────────────┐
│            │    TRUSTED EXECUTION ENV     │                 │
│            ▼                              ▼                 │
│   ┌─────────────────┐        ┌────────────────────────┐    │
│   │ HTTP Gateway    │        │   Secure Vault          │    │
│   │  :8765          │        │ (memory-only, wiped on  │    │
│   │                 │        │  process exit)          │    │
│   └────────┬────────┘        └────────────────────────┘    │
│            │                                                │
│   ┌────────▼────────────────────────────────────────────┐  │
│   │   Verifiable Shell  ──  Hash Chain  ──  Ed25519 Key  │  │
│   └────────────────────────────────────────────────────-─┘  │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐  │
│   │   NSM  (Nitro Secure Module — hardware only)         │  │
│   └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

What the hardware boundary buys you:

| Without TEE | With VAR |
|---|---|
| Host OS can read credentials in memory | Credentials only exist inside the enclave |
| Host OS can alter or suppress logs | Logs are hash-chained and hardware-signed |
| "Trust us" audit trail | Cryptographic proof any third party can verify |

---

### 2. Remote Attestation Proofs

Before the first credential is sent, a remote verifier can ask the hardware itself: *"Is this the exact binary I expect, running unmodified?"* This is **remote attestation**, and it is the root of trust for the entire session.

```mermaid
flowchart LR
    NSM["NSM Hardware\n━━━━━━━━━━\nAWS Nitro silicon"]
    DOC["Attestation Doc\n━━━━━━━━━━\nCOSE_Sign1 / CBOR\ncontains PCR0 + ephemeral PK"]
    NONCE["Bootstrap Nonce\n━━━━━━━━━━\nSHA-256(doc ‖ session_id)\nanchors the chain to this session"]
    CHAIN["Hash Chain\n━━━━━━━━━━\nH[n] = SHA-256(H[n-1] ‖ data)\ncontinuous, append-only"]
    BUNDLE["Signed Evidence Bundle\n━━━━━━━━━━\nEd25519 over VARE header\nseq + prev_hash + l1 + l2"]
    VERIFIER["Remote Verifier\n━━━━━━━━━━\naudit any time\nno trust in operator"]

    NSM -->|"hardware signs"| DOC
    DOC -->|"seeds"| NONCE
    NONCE -->|"H_stream[0]"| CHAIN
    CHAIN -->|"committed in"| BUNDLE
    BUNDLE -->|"independently verified by"| VERIFIER
```

**What the chain proves:**

- **PCR0** — the SHA-384 measurement of the enclave image. Any modification to the binary changes this value; the attestation document becomes invalid.
- **Bootstrap Nonce** — `SHA-256(attestation_doc ‖ session_id)`. Ties the hash chain to a specific hardware instance and session. A replay of a different session produces a different nonce and fails verification.
- **Continuity** — each evidence packet includes `PrevL1Hash`. A gap or reorder is immediately detectable; there is no way to delete or reorder entries without breaking the chain.
- **L2 / Terminal State** — the visual state of the terminal is independently hashed at each snapshot. A verifier can replay the raw byte stream through any VT parser and assert it produces the same signed state digest.

---

### 3. POSIX Compatibility

VAR runs as a **sidecar process** alongside any existing agent. There is no SDK to install, no language runtime to replace, and no application code to change.

```mermaid
sequenceDiagram
    participant A as Agent<br/>(any language / framework)
    participant G as VAR Gateway<br/>localhost:8765
    participant V as Verifiable Shell<br/>+ Hash Chain

    Note over A,V: Agent starts — no code changes required

    A->>G: POST /vault/secret {"key":"ANTHROPIC_API_KEY","value":"…"}
    G-->>A: 200 {"status":"ok"}

    A->>G: POST /log {"msg":"task started"}
    G->>V: folds into hash chain
    G-->>A: 200 {"status":"ok"}

    A->>G: GET /evidence
    G->>V: sign snapshot
    G-->>A: 200 {"stream":"…","state":"…","sig":"…"}

    Note over A,V: Verifier audits bundle independently — no operator involvement
```

The HTTP gateway binds to loopback inside the enclave. From the agent's perspective it is a plain JSON REST API. From the verifier's perspective every response to `/evidence` is a cryptographically signed snapshot of the full session.

---

## Trust chain — end to end

```mermaid
flowchart TD
    HW["AWS Nitro Hardware\nPCR0 = SHA-384(enclave image)"]
    ATT["Attestation Document\nCOSE_Sign1 signed by Nitro CA\nbinds: PCR0, ephemeral public key"]
    SID["Session ID  (UUID v4)\ngenerated fresh per boot"]
    BN["Bootstrap Nonce\nSHA-256(AttestationDoc ‖ SessionID)\nH_stream_0"]
    L1["L1 Stream Hash\nSHA-256(H[n-1] ‖ terminal_bytes)\nupdated on every logOutput()"]
    L2["L2 State Hash\nSHA-256(cursor ‖ dimensions ‖ cell_grid)\nterminal visual state snapshot"]
    SIG["Ed25519 Signature\nsigned over: magic ‖ seq ‖ prev_L1 ‖ L1 ‖ L2 ‖ session_id\nprivate key never leaves enclave"]
    AUD["Auditor\n1. Verify attestation doc against Nitro CA\n2. Confirm PCR0 matches expected binary\n3. Recompute bootstrap nonce\n4. Check PrevL1Hash continuity\n5. Replay PTY stream → assert L2 match"]

    HW --> ATT
    SID --> BN
    ATT --> BN
    BN --> L1
    L1 --> L2
    L1 --> SIG
    L2 --> SIG
    SIG --> AUD
```

---

## Threat model

**What VAR protects against:**

- A compromised host OS reading credentials from the agent process
- A compromised host OS tampering with or suppressing log entries
- An operator retroactively altering the evidence record
- A replay attack presenting evidence from a different session as current

**What VAR does not protect against (current scope):**

- A compromised agent *application* (if the agent itself is malicious, it will produce a verifiable record of its malicious actions — which is still useful, but not a prevention control)
- Side-channel attacks against the enclave (Nitro's responsibility)
- Availability — a host can still terminate the enclave; it simply cannot tamper with the evidence already emitted

---

## Getting started

### Prerequisites

- Zig `0.15.x`
- Python 3.x (host proxy)
- AWS Nitro-compatible instance, or any Linux machine (simulation mode auto-activates when `/dev/nsm` is absent)

### Build and run

```bash
# Build the enclave binary
zig build-exe src/main.zig --name var_enclave

# Terminal 1 — start the host proxy
python3 src/host/proxy.py

# Terminal 2 — start the enclave runtime
./var_enclave
```

### Query the gateway (from inside the enclave, or a co-located agent)

```bash
# Store a credential
curl -s -X POST http://127.0.0.1:8765/vault/secret \
  -H 'Content-Type: application/json' \
  -d '{"key":"MY_API_KEY","value":"sk-..."}'

# Emit a log entry
curl -s -X POST http://127.0.0.1:8765/log \
  -H 'Content-Type: application/json' \
  -H 'X-Skill-Id: my-agent' \
  -d '{"msg":"task complete"}'

# Retrieve a signed evidence snapshot
curl -s http://127.0.0.1:8765/evidence

# Verify the session identity
curl -s http://127.0.0.1:8765/session
```

---

## Project structure

```
src/
├── main.zig                  Enclave entry point and lifecycle
├── http_main.zig             HTTP gateway entry point
├── runtime/
│   ├── http.zig              REST gateway (POST /vault/secret, /log, GET /evidence, /session)
│   ├── shell.zig             Verifiable PTY master — hash chain + Ed25519 signing
│   ├── vt.zig                Terminal state machine (VT100/ANSI) and L2 digest
│   ├── vault.zig             Memory-only credential store (wiped on exit)
│   ├── attestation.zig       Hardware identity and quote handling
│   ├── nsm.zig               AWS Nitro Secure Module driver + simulation fallback
│   ├── vsock.zig             AF_VSOCK host–enclave transport
│   └── protocol.zig          Handshake, bundle header, secret delivery
├── host/
│   └── proxy.py              Host-side connectivity bridge
└── agent/                    Example agent integrations
evidence_spec.md              Formal specification of the evidence wire format (v1.1)
```

---

## License

MIT
