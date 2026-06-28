# Quickstart — 30 minutes to your first verified bundle

No AWS account required. Simulation mode activates automatically when `/dev/nsm`
is absent — you get a real hash chain and real Ed25519 signatures, with mock
PCR measurements in place of hardware attestation.

---

## Prerequisites

- **Zig** `0.15.x` — [ziglang.org/download](https://ziglang.org/download/)
- **Python** `3.10+` — for the verifier and example agent
- **jq** — for pretty-printing JSON responses (optional but recommended)

---

## 1. Clone and build

```bash
git clone https://github.com/kennethkabogo/VAR.git
cd VAR
zig build
```

This produces two binaries in `zig-out/bin/`:

- `VAR-gateway` — the HTTP REST gateway (use this for new integrations)
- `VAR` — the vsock line-protocol runtime (for direct enclave embedding)

---

## 2. Start the gateway

```bash
./zig-out/bin/VAR-gateway
```

Expected output:

```
[VAR-gateway] listening on 127.0.0.1:8765 (worker threads: 64)
```

The gateway is now running in simulation mode. Leave this terminal open and
open a second terminal for the next steps.

---

## 3. Inspect the session

Every session has a unique identity and a hardware-signed attestation quote.
In simulation mode the attestation is a mock, but the structure is identical
to production.

```bash
curl -s http://127.0.0.1:8765/session | jq .
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

## 4. Record evidence

### Log a message

```bash
curl -s -X POST http://127.0.0.1:8765/log \
  -H 'Content-Type: application/json' \
  -d '{"msg": "agent started — fetching TVL data"}' | jq .
```

Every `/log` call extends the L1 hash chain. The chain is a rolling
`SHA-256(prev_hash ‖ new_data)` — once written, nothing can be removed or
reordered without breaking every subsequent signature.

### Run an attested computation

```bash
curl -s -X POST http://127.0.0.1:8765/compute \
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

## 5. Read the evidence bundle

```bash
curl -s http://127.0.0.1:8765/evidence | jq .
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

## 6. Verify a bundle

Run the self-contained verifier against the §14.9 synthetic fixture to see
what a passing verification looks like:

```bash
pip install cryptography argon2-cffi cbor2
python3 tools/apex_verify.py --self-test
```

Expected output:

```
Step 1  PASS  bootstrap nonce valid
Step 2  PASS  NSM silicon witness present
Step 3  PASS  chain continuity (2 segments, 4 packets)
Step 4  PASS  Ed25519 signatures valid
…
All steps PASS
```

To verify a bundle file captured from the running gateway:

```bash
# Seal the current session
curl -s -X GET http://127.0.0.1:8765/seal | jq .

# Then run apex_verify against a saved bundle file
python3 tools/apex_verify.py path/to/bundle.log
```

---

## 7. What you just proved

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

## 8. Wrap your own agent

The simplest integration is three HTTP calls:

```python
import json, urllib.request

BASE = "http://127.0.0.1:8765"

def var(method, path, payload=None):
    body = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(
        f"{BASE}{path}", data=body,
        headers={"Content-Type": "application/json"}, method=method
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
