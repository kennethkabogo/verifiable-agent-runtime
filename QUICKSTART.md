# Quickstart — 5 minutes to your first verified bundle

No AWS account required. Simulation mode activates automatically when `/dev/nsm`
is absent — you get a real hash chain and real Ed25519 signatures, with mock
PCR measurements in place of hardware attestation.

---

## 1. Start the gateway

**Option A — Docker Compose (recommended):**

```bash
docker compose up
```

**Option B — plain Docker:**

```bash
docker run --rm -p 127.0.0.1:8765:8765 -e VAR_API_TOKEN=dev-local \
  ghcr.io/kennethkabogo/var:latest
```

Expected output:

```text
warning: [VAR-gateway] VAR_API_TOKEN not set — API auth disabled (loopback only, dev mode)
info: [VAR-gateway] listening on 0.0.0.0:8765 (worker threads: 64)
```

> **Why `VAR_API_TOKEN`?** The gateway binds to `0.0.0.0` inside the container so Docker
> port-forwarding can reach it. Any non-loopback bind requires a token — without one the
> gateway exits immediately. `dev-local` is a throwaway value for local development.
> `-p 127.0.0.1:8765:8765` keeps the host-side port on loopback so no external traffic
> reaches the container.

Leave this terminal open and open a second terminal for the next steps.

Set your token once in the second terminal so the examples below work by copy-paste:

```bash
export VAR_TOKEN=dev-local
```

---

## 2. Inspect the session

Every session has a unique identity and a hardware-signed attestation quote.
In simulation mode the attestation is a mock, but the structure is identical
to production.

```bash
curl -s -H "Authorization: Bearer $VAR_TOKEN" http://127.0.0.1:8765/session | jq .
```

```json
{
  "magic": "APXB",
  "version": "2.7.0",
  "session_id": "00000000000040008000000000000001",
  "bootstrap_nonce": "b751e786…",
  "bundle_header": "BUNDLE_HEADER:magic=APXB:version=2.7.0:…"
}
```

The `bootstrap_nonce` is `SHA-256(attestation_doc ‖ session_id)`. It anchors
the entire evidence chain to this specific session and enclave instance.

---

## 3. Record evidence

### Log a message

```bash
curl -s -X POST http://127.0.0.1:8765/log \
  -H "Authorization: Bearer $VAR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"msg": "agent started — fetching TVL data"}' | jq .
```

Every `/log` call extends the L1 hash chain. The chain is a rolling
`SHA-256(prev_hash ‖ new_data)` — once written, nothing can be removed or
reordered without breaking every subsequent signature.

### Run an attested computation

```bash
curl -s -X POST http://127.0.0.1:8765/compute \
  -H "Authorization: Bearer $VAR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"fn": "echo", "inputs": {"source": "defillama", "tvl_usd": 1250000}}' | jq .
```

```json
{
  "fn": "echo",
  "inputs_hash": "3a7bd3e2…",
  "output": "…",
  "evidence": {
    "stream": "f4a1c9b2…",
    "state": "d8e3f1a7…",
    "sig": "9c2e4b8f…",
    "seq": 2
  }
}
```

`inputs_hash` is `SHA-256("echo:" ‖ canonical_inputs_json)`. Anyone with the
original inputs can recompute it independently. The computation result and its
inputs hash are both folded into the evidence chain — the chain's `state` hash
now commits to this specific computation having run.

---

## 4. Read the evidence bundle

```bash
curl -s -H "Authorization: Bearer $VAR_TOKEN" http://127.0.0.1:8765/evidence | jq .
```

```json
{
  "prev_stream": "b751e786…",
  "stream": "8a4f2c1e…",
  "state": "d8e3f1a7…",
  "sig": "9c2e4b8f…",
  "seq": 3
}
```

| Field | What it is |
| ----- | ---------- |
| `stream` | `SHA-256(prev_stream ‖ all_data_since_last_snapshot)` |
| `state` | `SHA-256(terminal_cursor ‖ cell_grid)` — L2 visual state digest |
| `sig` | Ed25519 signature over `magic ‖ seq ‖ prev_stream ‖ stream ‖ state ‖ session_id` |
| `seq` | Monotonic counter — a gap means evidence was dropped |

The signing key never leaves the enclave. In production, the key's public
counterpart is bound into the NSM attestation document, so a verifier can
confirm the signature originated from inside the measured binary.

---

## 5. Verify a bundle

Run the self-contained verifier against the §14.9 synthetic fixture to see
what a passing verification looks like:

```bash
pip install cryptography argon2-cffi cbor2
python3 tools/apex_verify.py --self-test
```

Expected output:

```text
  APEX Evidence Verifier  —  spec v2.7.0
  Session  : 00000000000040008000000000000001
  Segments : 2
  Packets  : 4

  [PASS] Step 1 Bundle Header
  [SKIP] Step 2 Segment Headers
         simulation mode — COSE skipped
  [PASS] Step 3 Bootstrap Nonce
  [SKIP] Step 3.6 Attestation Timestamp
         simulation mode — timestamp check skipped (§11)
  [PASS] Step 4 Chain Continuity
  [PASS] Step 5 Signatures
  [PASS] Step 6 Terminal Digest
  [PASS] Step 7 Bundle Seal
  [PASS] Step 8 Settlement Block
  [SKIP] Step 9 L2 Replay
  [PASS] Step 10 Segment Boundaries
  [PASS] Step 11 Temporal Proofs
  [PASS] Step 12 ECR

  ECR   : 1.0000
  RESULT: PASS
```

Steps 2, 3.6, and 9 show `SKIP` in simulation mode — this is expected. `SKIP` is not a failure;
it means the check is bypassed because hardware attestation is absent (no `/dev/nsm`).

To verify a bundle captured from the running gateway, first assemble and save it:

```bash
# 1. Capture the bundle header
curl -s -H "Authorization: Bearer $VAR_TOKEN" \
  http://127.0.0.1:8765/session | jq -r '.bundle_header' > bundle.log

# 2. Run a computation (note the sequence number in the response)
curl -s -X POST http://127.0.0.1:8765/compute \
  -H "Authorization: Bearer $VAR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"fn": "echo", "inputs": {"value": 42}}' | jq .

# 3. Append evidence packets (replace N with the "seq" from the compute response)
curl -s -H "Authorization: Bearer $VAR_TOKEN" \
  "http://127.0.0.1:8765/evidence?from=1&to=N" \
  | jq -r '.packets[] |
      "EVIDENCE:prev_stream=\(.prev_stream):stream=\(.stream):state=\(.state):sig=\(.sig):seq=\(.sequence)"' \
  >> bundle.log

# 4. Seal the session and append the seal line
curl -s -H "Authorization: Bearer $VAR_TOKEN" \
  http://127.0.0.1:8765/seal | jq -r '.bundle_seal' >> bundle.log

# 5. Verify
python3 tools/apex_verify.py bundle.log
```

> **Tip:** `tools/demo_server.py` handles this entire bundle assembly automatically.
> Run it alongside the gateway to get a browser UI that drives a full round-trip
> and shows the 12-step verification result inline.

---

## 6. What you just proved

When a verifier runs `apex_verify.py` against your bundle, it checks:

1. **Bootstrap nonce** — the chain is anchored to this session's attestation document
2. **Silicon witness** — the attestation doc contains a real (or mock, in sim mode) NSM signature
3. **Chain continuity** — every `prev_stream` matches the previous packet's `stream`; nothing was dropped or reordered
4. **Ed25519 signatures** — every packet was signed by the enclave's ephemeral key

In simulation mode steps 1–4 all pass with mock attestation. In production
(`--no-debug-mode` on a Nitro instance), step 2 uses a real NSM signature over
the actual PCR0 measurement of the enclave binary, and the KMS key policy
enforces that `kms:Decrypt` only succeeds when that PCR0 matches the expected value.

**The key property:** an auditor can verify the bundle completely independently
— no access to the running enclave, no trust in the operator, no call to any
VAR-controlled infrastructure.

---

## 7. Wrap your own agent

The simplest integration is three HTTP calls:

```python
import json, os, urllib.request

BASE = "http://127.0.0.1:8765"
TOKEN = os.environ.get("VAR_API_TOKEN", "dev-local")

def var(method, path, payload=None):
    body = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(
        f"{BASE}{path}", data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {TOKEN}",
        },
        method=method,
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())

# 1. Store a credential securely inside the enclave
var("POST", "/vault/secret", {"key": "API_KEY", "value": "sk-…"})

# 2. Record what your agent is doing
var("POST", "/log", {"msg": "fetching offchain state"})

# 3. Run an attested computation and get back a signed evidence snapshot
result = var("POST", "/compute", {
    "fn": "echo",                          # replace with your named fn
    "inputs": {"value": 42, "source": "…"}
})
print(result["inputs_hash"])   # commitment to your inputs
print(result["evidence"])      # signed chain snapshot
```

See [src/agent/gateway_skill.py](src/agent/gateway_skill.py) for a fuller
example including vault provisioning, skill ID tagging, and evidence streaming.

---

## Next steps

| Goal | Where to look |
| ---- | ------------- |
| Add a real computation | [src/runtime/compute.zig](src/runtime/compute.zig) — add a branch for your `fn` name |
| Deploy to Nitro | [README.md § Deployment](README.md#deployment-aws-nitro) |
| Understand the wire format | [evidence_spec.md](evidence_spec.md) |
| Run the full test suite | `zig build test && pytest tests/ src/` |
| Resume a session across reboots | `POST /hibernate` → set `VAR_RESUME_STATE` on restart |

---

## Build from source

If you need to modify the runtime or target a non-x86_64 platform:

**Prerequisites:** Zig `0.15.x` — [ziglang.org/download](https://ziglang.org/download/), Python `3.10+`, jq

```bash
git clone https://github.com/kennethkabogo/VAR.git
cd VAR
zig build
./zig-out/bin/VAR-gateway
```

This produces two binaries in `zig-out/bin/`:

- `VAR-gateway` — the HTTP REST gateway (use this for new integrations)
- `VAR` — the vsock line-protocol runtime (for direct enclave embedding)
