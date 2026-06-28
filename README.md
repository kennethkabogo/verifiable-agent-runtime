# Verifiable Agent Runtime (VAR)

VAR wraps any autonomous agent in a hardware-enforced trust boundary and produces a continuous cryptographic evidence chain of everything the agent did. Any external party can verify that chain independently — without trusting the host, the operator, or the agent itself.

**New here?** → [QUICKSTART.md](QUICKSTART.md) — zero to a verified bundle in 30 minutes, no AWS account required.

---

## How it works

```
1. ATTEST   Hardware certifies the exact binary running inside the enclave.
            A remote verifier confirms it has not been tampered with before
            sending a single credential.

2. RUN      The agent executes normally — any language, any framework.
            Every log line and computation is folded into a live hash chain
            signed by a key that never leaves the enclave.

3. VERIFY   Anyone with the evidence bundle can independently replay the
            session and confirm the signed hashes match — after the fact,
            without trusting any single party.
```

---

## Architecture

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
│   │  HTTP Gateway   │        │     Secure Vault         │    │
│   │    :8765        │        │ (memory-only, wiped on  │    │
│   │                 │        │  process exit)          │    │
│   └────────┬────────┘        └────────────────────────┘    │
│            │                                                │
│   ┌────────▼────────────────────────────────────────────┐  │
│   │   Verifiable Shell  ──  Hash Chain  ──  Ed25519 Key  │  │
│   └─────────────────────────────────────────────────────┘  │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐  │
│   │   NSM  (Nitro Secure Module — hardware only)         │  │
│   └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

The HTTP gateway binds to loopback inside the enclave. From the agent's perspective it is a plain JSON REST API. From the verifier's perspective every response to `/evidence` is a cryptographically signed snapshot of the full session, rooted in the hardware attestation at startup.

---

## HTTP API

The `VAR-gateway` binary exposes a JSON REST API on `127.0.0.1:8765`.

| Method | Path | Body | Response |
| ------ | ---- | ---- | -------- |
| `GET` | `/health` | — | `{"status":"healthy"}` |
| `GET` | `/session` | — | session identity + bundle header |
| `GET` | `/attestation` | — | PCR measurements + attestation doc (hex) |
| `GET` | `/evidence` | — | signed chain snapshot |
| `GET` | `/evidence?from=N&to=N` | — | evidence packet range |
| `GET` | `/evidence/stream` | — | SSE stream of evidence events |
| `GET` | `/verify-and-attest` | — | evidence + attestation combined |
| `GET` | `/seal` | — | terminal bundle seal |
| `GET` | `/benchmark` | — | Argon2id latency stats |
| `POST` | `/vault/secret` | `{"key":"…","value":"…"}` | `{"status":"ok"}` |
| `POST` | `/log` | `{"msg":"…"}` | `{"status":"ok"}` |
| `POST` | `/compute` | `{"fn":"…","inputs":{…}}` | `{"fn","inputs_hash","output","evidence"}` |
| `POST` | `/settle` | `{"escrow_id","amount","currency","recipient"}` | settlement line |
| `POST` | `/hibernate` | — | `{"sealed_state":"<hex>"}` — seals state, exits |
| `POST` | `/terminate` | — | final bundle + seal, then exits |

Every `POST /log` and `POST /compute` extends the L1 hash chain. Every `GET /evidence` returns a signed snapshot. See [evidence_spec.md](evidence_spec.md) for the wire format.

---

## Threat model

**Protects against:**

- Host OS reading credentials from the agent process
- Host OS tampering with or suppressing log entries
- An operator retroactively altering the evidence record
- Replay attacks using evidence from a different session

**Out of scope (current):**

- A malicious agent application — VAR records what it did, verifiably, but does not prevent it
- Enclave side-channel attacks — Nitro's responsibility
- Availability attacks — a host can terminate the enclave; it cannot alter evidence already emitted

---

## Deployment (AWS Nitro)

### Prerequisites

- Zig `0.15.x`
- Docker
- `nitro-cli`
- An EC2 instance with Nitro Enclaves enabled (`--enclave-options Enabled=true`)

### 1. Build the EIF

```bash
make build-eif
# Prints PCR0 at the end — you need this for the KMS key policy.
make pcr0   # re-print at any time
```

### 2. Create and configure the KMS key

```bash
KEY_ID=$(aws kms create-key \
  --description "VAR enclave DEK-wrapping key" \
  --query 'KeyMetadata.KeyId' --output text)
aws kms create-alias --alias-name alias/var-enclave --target-key-id "$KEY_ID"
```

Edit `infra/kms-key-policy.json` — replace `ACCOUNT_ID`, `KEY_ADMIN_ARN`, `INSTANCE_ROLE_ARN`, and `PCR0_HEX` — then apply:

```bash
aws kms put-key-policy \
  --key-id alias/var-enclave \
  --policy-name default \
  --policy file://infra/kms-key-policy.json
```

### 3. Install the host-side proxy

```bash
make install-proxy

# Set the key ARN in the systemd override:
sudo systemctl edit var-kms-proxy
# [Service]
# Environment=VAR_KMS_KEY_ARN=arn:aws:kms:us-east-1:…:key/…
# Environment=AWS_DEFAULT_REGION=us-east-1

sudo systemctl restart var-kms-proxy
```

### 4. Run the enclave

```bash
ENCLAVE_MEMORY=1024 ENCLAVE_CPUS=2 make run
make logs   # stream console
make stop   # terminate
```

### Environment variables

| Variable | Component | Default | Description |
| -------- | --------- | ------- | ----------- |
| `VAR_KMS_KEY_ARN` | enclave | — | ARN of the KMS CMK for DEK wrapping |
| `VAR_KMS_PROXY_PORT` | enclave + proxy | `8443` | vsock/TCP port for the KMS proxy |
| `AWS_DEFAULT_REGION` | proxy | credential chain | AWS region for KMS calls |
| `VAR_GATEWAY` | verifier | `http://127.0.0.1:8765` | Gateway URL |
| `VAR_RESUME_STATE` | gateway | — | Hex-encoded sealed blob from a prior `/hibernate`; resumes that session on startup |

### Makefile reference

| Target | Description |
| ------ | ----------- |
| `make build` | `zig build` — compile both binaries |
| `make build-eif` | Build Docker image + EIF, print PCR0 |
| `make push-ecr` | Push Docker image to ECR |
| `make run` | `nitro-cli run-enclave` |
| `make run-debug` | Run with debug console (disables attestation) |
| `make stop` | Terminate the running enclave |
| `make logs` | Stream the enclave console |
| `make pcr0` | Print PCR0 from the EIF |
| `make install-proxy` | Install and enable `var-kms-proxy.service` |
| `make test` | `zig build test` + `pytest` for both Python suites |
| `make clean` | Remove `zig-out/`, `zig-cache/`, and the EIF |

---

## Project structure

```
src/
├── main.zig                    Enclave entry point (vsock line protocol)
├── http_main.zig               HTTP gateway entry point
├── var_cli.py                  Unified CLI: connect / verify / skill / demo
├── var_demo.py                 End-to-end lifecycle demo (Start → Hibernate → Resume → Verify)
├── runtime/
│   ├── http.zig                REST gateway — routes and handlers
│   ├── shell.zig               Verifiable shell — L1 hash chain + Ed25519 signing
│   ├── compute.zig             In-process computation — dispatch table for named fns
│   ├── vt.zig                  VT100/ANSI state machine and L2 terminal digest
│   ├── vault.zig               Memory-only credential store (wiped on exit)
│   ├── sealed_state.zig        Hibernate/resume — AES-256-GCM + KMS DEK wrapping
│   ├── attestation.zig         Hardware identity and NSM attestation quote
│   ├── nsm.zig                 Nitro Secure Module driver + simulation fallback
│   ├── protocol.zig            Handshake, bundle header, secret delivery
│   └── vsock.zig               AF_VSOCK host–enclave transport
├── verifier/
│   └── verify.py               Standalone verifier for live Nitro bundles
├── host/
│   ├── proxy.py                KMS forwarding proxy (vsock → boto3 → KMS)
│   ├── var-kms-proxy.service   Systemd unit for the proxy on the parent instance
│   └── tests/
└── agent/
    ├── agent.py                Example vsock agent
    └── gateway_skill.py        Example HTTP gateway integration
tools/
└── apex_verify.py              APEX §8 verifier — verify any bundle file independently
evidence_spec.md                Wire format specification (APEX v2.7.0)
QUICKSTART.md                   30-minute first-bundle walkthrough
```

---

## License

MIT
