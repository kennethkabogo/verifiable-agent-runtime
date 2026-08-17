#!/usr/bin/env python3
"""
wallet_monitor.py — BSC wallet/position monitoring agent, wrapped in VAR.

A "monitoring agent" (BNB Chain reference category: markets, wallets,
positions) that polls a BNB Smart Chain address over public JSON-RPC and
attests every check into the VAR evidence chain via the HTTP gateway —
the same "Verifiable Sidecar" pattern as gateway_skill.py.

Every poll produces two evidence packets: a human-readable /log line and a
structured /compute(fn=echo) record (hashed via inputs_hash). A balance
swing past --threshold-bnb, or a nonce increase, additionally emits an
ALERT pair.

Usage:
    # Terminal 1 — start the gateway:
    #   docker run -p 127.0.0.1:8765:8765 ghcr.io/kennethkabogo/var:latest
    #
    # Terminal 2 — watch a wallet:
    #   python3 src/agent/wallet_monitor.py --wallet 0xYourAddressHere --iterations 5

    Environment variables:
        VAR_GATEWAY   base URL of the gateway (default: http://127.0.0.1:8765)
        SKILL_ID      name logged on every /log call  (default: wallet-monitor)
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

GATEWAY = os.environ.get("VAR_GATEWAY", "http://127.0.0.1:8765")
SKILL_ID = os.environ.get("SKILL_ID", "wallet-monitor")


# ── VAR gateway HTTP helpers (same pattern as gateway_skill.py) ─────────────

def _req(method: str, path: str, payload: dict | None = None) -> dict:
    url = f"{GATEWAY}{path}"
    body = json.dumps(payload).encode() if payload else None
    headers = {
        "Content-Type": "application/json",
        "X-Skill-Id": SKILL_ID,
    }
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return {"error": exc.read().decode()}
    except OSError as exc:
        return {"error": str(exc)}


def health_check() -> bool:
    return _req("GET", "/health").get("status") == "healthy"


def log(msg: str) -> None:
    """Append a human-readable entry to the hash-chained evidence log."""
    result = _req("POST", "/log", {"msg": msg})
    if result.get("status") != "ok":
        raise RuntimeError(f"log error: {result}")


def compute(fn: str, inputs: dict) -> dict:
    """Commit a structured record into the L1 chain via POST /compute."""
    result = _req("POST", "/compute", {"fn": fn, "inputs": inputs})
    if "error" in result:
        raise RuntimeError(f"compute error: {result}")
    return result


def get_evidence() -> dict:
    """Return the signed evidence bundle (stream hash + state hash)."""
    return _req("GET", "/evidence")


def get_attestation() -> dict:
    """Return the hardware attestation quote for this enclave session."""
    return _req("GET", "/attestation")


# ── BSC JSON-RPC client (stdlib only, no external deps) ─────────────────────

def _rpc(rpc_url: str, method: str, params: list) -> str:
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    }).encode()
    request = urllib.request.Request(
        rpc_url, data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as resp:
        body = json.loads(resp.read())
    if "error" in body:
        raise RuntimeError(f"RPC error: {body['error']}")
    return body["result"]


def get_balance_wei(rpc_url: str, wallet: str) -> int:
    return int(_rpc(rpc_url, "eth_getBalance", [wallet, "latest"]), 16)


def get_nonce(rpc_url: str, wallet: str) -> int:
    return int(_rpc(rpc_url, "eth_getTransactionCount", [wallet, "latest"]), 16)


def get_block_number(rpc_url: str) -> int:
    return int(_rpc(rpc_url, "eth_blockNumber", []), 16)


# ── Monitor loop ──────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="VAR wallet/position monitoring agent")
    parser.add_argument("--wallet", required=True, help="BSC address to monitor (0x...)")
    parser.add_argument("--rpc", default="https://bsc-dataseed.binance.org",
                         help="BSC JSON-RPC endpoint (default: public mainnet)")
    parser.add_argument("--interval", type=float, default=15.0,
                         help="seconds between polls (default: 15)")
    parser.add_argument("--iterations", type=int, default=0,
                         help="number of polls before exiting (default: run forever)")
    parser.add_argument("--threshold-bnb", type=float, default=0.01,
                         help="balance delta (BNB) that triggers an alert (default: 0.01)")
    args = parser.parse_args()

    print(f"[{SKILL_ID}] Connecting to VAR gateway at {GATEWAY} ...")
    if not health_check():
        print(f"ERROR: gateway unreachable at {GATEWAY}", file=sys.stderr)
        sys.exit(1)
    print(f"[{SKILL_ID}] Gateway healthy.")
    print(f"[{SKILL_ID}] Watching {args.wallet} via {args.rpc}\n")

    threshold_wei = int(args.threshold_bnb * 10**18)
    prev_balance_wei: int | None = None
    prev_nonce: int | None = None
    i = 0

    try:
        while args.iterations <= 0 or i < args.iterations:
            i += 1
            balance_wei = get_balance_wei(args.rpc, args.wallet)
            nonce = get_nonce(args.rpc, args.wallet)
            block = get_block_number(args.rpc)
            balance_bnb = balance_wei / 10**18

            check = {
                "check": i,
                "wallet": args.wallet,
                "balance_bnb": round(balance_bnb, 8),
                "nonce": nonce,
                "block": block,
                "timestamp": int(time.time()),
            }
            log(f"check #{i}: {args.wallet} balance={balance_bnb:.6f} BNB "
                f"nonce={nonce} block={block}")
            compute("echo", check)
            print(f"  [{i}] balance={balance_bnb:.6f} BNB  nonce={nonce}  block={block}")

            if prev_balance_wei is not None:
                delta_wei = balance_wei - prev_balance_wei
                nonce_advanced = prev_nonce is not None and nonce > prev_nonce
                if abs(delta_wei) >= threshold_wei or nonce_advanced:
                    delta_bnb = delta_wei / 10**18
                    reason = []
                    if abs(delta_wei) >= threshold_wei:
                        reason.append(f"balance changed {delta_bnb:+.6f} BNB since last check")
                    if nonce_advanced:
                        reason.append(f"nonce advanced {prev_nonce} -> {nonce}")
                    alert_msg = "ALERT: " + "; ".join(reason)
                    log(alert_msg)
                    compute("echo", {**check, "alert": True, "reason": reason})
                    print(f"      {alert_msg}")

            prev_balance_wei = balance_wei
            prev_nonce = nonce

            if args.iterations <= 0 or i < args.iterations:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n[{SKILL_ID}] Interrupted.")

    evidence = get_evidence()
    print(f"\n[{SKILL_ID}] Evidence bundle:")
    print(f"  stream hash : {evidence.get('stream', 'n/a')}")
    print(f"  state  hash : {evidence.get('state', 'n/a')}")
    print(f"  signature   : {evidence.get('sig', 'n/a')}")

    attest = get_attestation()
    print(f"\n[{SKILL_ID}] Attestation:")
    pcr0 = attest.get("pcr0", "n/a")
    pk = attest.get("public_key", "n/a")
    print(f"  pcr0        : {pcr0[:32]}{'...' if len(pcr0) > 32 else ''}")
    print(f"  public_key  : {pk[:32]}{'...' if len(pk) > 32 else ''}")

    print(f"\n[{SKILL_ID}] Done. {i} check(s) verifiably logged.")


if __name__ == "__main__":
    main()
