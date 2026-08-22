#!/usr/bin/env python3
"""
lean_agent.py — Lean 4 proof-search agent for better.codes, wrapped in VAR attestation.

Every proof attempt is logged into the VAR evidence chain via the HTTP gateway.
When a proof succeeds, a hardware-attested evidence snapshot is created BEFORE
the Yukon CLI submission — providing a timestamp proof independent of GitHub and
the better.codes backend.

Environment:
    VAR_GATEWAY    VAR gateway base URL  (default: http://127.0.0.1:8765)
    VAR_API_TOKEN  gateway API token     (default: dev-local)
    YUKON_STUB     if "1", stub Yukon CLI calls (default: 1)
    YUKON_TOKEN    Yukon CLI auth token  (required when YUKON_STUB=0)
    PROOF_DIR      directory for .lean files (default: ./proofs)
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

GATEWAY = os.environ.get("VAR_GATEWAY", "http://127.0.0.1:8765")
API_TOKEN = os.environ.get("VAR_API_TOKEN", "dev-local")
YUKON_STUB = os.environ.get("YUKON_STUB", "1") == "1"
YUKON_TOKEN = os.environ.get("YUKON_TOKEN", "")
PROOF_DIR = Path(os.environ.get("PROOF_DIR", "./proofs"))


# ── VAR gateway client ────────────────────────────────────────────────────────

def _var_req(method: str, path: str, payload: dict | None = None) -> dict:
    url = f"{GATEWAY}{path}"
    body = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(
        url, data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {API_TOKEN}",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode()}
    except OSError as e:
        return {"error": str(e)}


def var_log(msg: str) -> None:
    r = _var_req("POST", "/log", {"msg": msg})
    if r.get("status") != "ok":
        print(f"[warn] VAR log failed: {r}", file=sys.stderr)


def var_compute(fn: str, inputs: dict) -> dict:
    r = _var_req("POST", "/compute", {"fn": fn, "inputs": inputs})
    if "error" in r:
        print(f"[warn] VAR compute failed: {r}", file=sys.stderr)
    return r


def var_evidence() -> dict:
    return _var_req("GET", "/evidence")


def var_health() -> bool:
    return _var_req("GET", "/health").get("status") == "healthy"


# ── Lean 4 runner ─────────────────────────────────────────────────────────────

def lean_check(lean_file: Path) -> tuple[bool, str]:
    """Run lean on a file. Returns (success, output)."""
    try:
        r = subprocess.run(
            ["lean", str(lean_file)],
            capture_output=True, text=True, timeout=120,
        )
        output = r.stdout + r.stderr
        return r.returncode == 0, output
    except FileNotFoundError:
        return False, "lean binary not found"
    except subprocess.TimeoutExpired:
        return False, "lean timed out after 120s"


# ── Yukon CLI ─────────────────────────────────────────────────────────────────

def yukon_submit(lean_file: Path) -> dict:
    """Submit a verified proof to the better.codes platform via the Yukon CLI."""
    if YUKON_STUB:
        print(f"  [yukon stub] would submit: {lean_file}")
        return {"status": "stubbed", "submission_id": "stub-001"}

    try:
        r = subprocess.run(
            ["yukon", "submit", str(lean_file)],
            capture_output=True, text=True, timeout=60,
            env={**os.environ, "YUKON_TOKEN": YUKON_TOKEN},
        )
        if r.returncode != 0:
            return {"error": r.stderr.strip()}
        # Parse Yukon CLI JSON output (exact format TBD once CLI is released)
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            return {"status": "ok", "raw": r.stdout.strip()}
    except FileNotFoundError:
        return {"error": "yukon CLI not found — set YUKON_STUB=1 or install the Yukon CLI"}
    except subprocess.TimeoutExpired:
        return {"error": "yukon submit timed out"}


# ── Main proof-search loop ────────────────────────────────────────────────────

def run_proof_attempt(lean_file: Path, attempt: int) -> bool:
    """
    Check a Lean proof file. If it verifies:
      1. Create a VAR evidence snapshot BEFORE submitting — this is the
         hardware-attested timestamp proof, independent of GitHub / Yukon backend.
      2. Submit via yukon submit.
      3. Log the submission result.

    Returns True if the proof verified.
    """
    var_log(f"attempt #{attempt}: checking {lean_file.name}")

    ok, output = lean_check(lean_file)
    status = "verified" if ok else "failed"
    print(f"  [{attempt}] {lean_file.name}: {status}")

    var_compute("proof_attempt", {
        "attempt": attempt,
        "file": lean_file.name,
        "status": status,
        "lean_output_preview": output[:200],
        "timestamp": int(time.time()),
    })

    if not ok:
        return False

    # ── Proof verified — timestamp the discovery before touching Yukon ──────
    # The APEX bundle snapshot below is hardware-attested by the Nitro enclave.
    # It proves the proof existed at this moment, independent of the Yukon
    # submission timestamp and any git history.

    var_log(f"PROOF VERIFIED: {lean_file.name} — attesting discovery before submission")
    evidence = var_evidence()

    var_compute("proof_verified", {
        "file": lean_file.name,
        "attempt": attempt,
        "evidence_stream": evidence.get("stream", ""),
        "evidence_seq": evidence.get("sequence", ""),
        "discovery_timestamp": int(time.time()),
    })

    # ── Now submit to Yukon ──────────────────────────────────────────────────
    print(f"  [{attempt}] submitting to Yukon...")
    submission = yukon_submit(lean_file)
    print(f"  [{attempt}] submission: {submission}")

    var_compute("yukon_submitted", {
        "file": lean_file.name,
        "submission": submission,
        "timestamp": int(time.time()),
    })

    return True


def main() -> None:
    print(f"[lean-agent] Connecting to VAR gateway at {GATEWAY}...")
    if not var_health():
        print("ERROR: VAR gateway unreachable", file=sys.stderr)
        sys.exit(1)
    print("[lean-agent] Gateway healthy.")

    PROOF_DIR.mkdir(parents=True, exist_ok=True)

    # Discover .lean files in the proof directory
    lean_files = sorted(PROOF_DIR.glob("*.lean"))
    if not lean_files:
        print(f"[lean-agent] No .lean files found in {PROOF_DIR}.")
        print("[lean-agent] Place your proof files there and restart.")
        sys.exit(0)

    print(f"[lean-agent] Found {len(lean_files)} proof file(s).\n")
    var_log(f"lean-agent session started: {len(lean_files)} proof(s) to check")

    verified_count = 0
    for i, lean_file in enumerate(lean_files, 1):
        if run_proof_attempt(lean_file, i):
            verified_count += 1

    print(f"\n[lean-agent] Done. {verified_count}/{len(lean_files)} proof(s) verified and submitted.")

    evidence = var_evidence()
    print(f"\n[lean-agent] APEX evidence bundle:")
    print(f"  stream  : {evidence.get('stream', 'n/a')}")
    print(f"  state   : {evidence.get('state', 'n/a')}")
    print(f"  sig     : {evidence.get('sig', 'n/a')[:32]}...")
    print(f"  seq     : {evidence.get('sequence', 'n/a')}")
    print(f"\nRun ./var-bundle.sh to assemble and verify the full APEX bundle.")


if __name__ == "__main__":
    main()
