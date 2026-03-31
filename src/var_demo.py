#!/usr/bin/env python3
"""
VAR End-to-End Demo
===================
Single-command orchestrator for the full Verifiable Agent Runtime lifecycle:

  Start → Run commands → Hibernate → (simulated reboot) → Resume → Run more
  commands → Verify the complete two-segment chain cryptographically.

Usage:
  python var_demo.py
  python var_demo.py --gateway-bin ./zig-out/bin/VAR-gateway
  python var_demo.py --gateway-url http://127.0.0.1:8765

Exit code: 0 = verification PASSED, 1 = verification FAILED or error.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Load verifier module (sibling directory)
# ---------------------------------------------------------------------------

_SRC = Path(__file__).parent
_VERIFIER_PATH = _SRC / "verifier" / "verify.py"
_spec = importlib.util.spec_from_file_location("verify", _VERIFIER_PATH)
verify = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(verify)  # type: ignore[union-attr]

# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------

_GREEN  = "\033[32m"
_CYAN   = "\033[36m"
_YELLOW = "\033[33m"
_RED    = "\033[31m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"

_W = 62  # banner width


def _banner(text: str) -> None:
    print(f"\n{_BOLD}{'═' * _W}{_RESET}")
    print(f"{_BOLD}  {text}{_RESET}")
    print(f"{_BOLD}{'═' * _W}{_RESET}")


def _step(label: str) -> None:
    print(f"\n{_CYAN}[{label}]{_RESET}")


def _ok(msg: str) -> None:
    print(f"  {_GREEN}✓{_RESET}  {msg}")


def _info(msg: str) -> None:
    print(f"     {msg}")


def _warn(msg: str) -> None:
    print(f"  {_YELLOW}!{_RESET}  {msg}")


def _err(msg: str) -> None:
    print(f"  {_RED}✗{_RESET}  {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------

def _get(url: str, timeout: int = 10) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def _post(url: str, body: dict, timeout: int = 30) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _wait_healthy(base_url: str, retries: int = 40, delay: float = 0.25) -> None:
    """Poll GET /health until the gateway responds or we give up."""
    for _ in range(retries):
        try:
            _get(f"{base_url}/health", timeout=2)
            return
        except Exception:
            time.sleep(delay)
    raise RuntimeError(f"Gateway at {base_url} did not become healthy in time.")


# ---------------------------------------------------------------------------
# Gateway process manager
# ---------------------------------------------------------------------------

def _start_gateway(
    bin_path: str,
    base_url: str,
    env: Optional[dict] = None,
) -> subprocess.Popen:
    merged_env = {**os.environ, **(env or {})}
    proc = subprocess.Popen(
        [bin_path],
        env=merged_env,
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )
    try:
        _wait_healthy(base_url)
    except RuntimeError:
        proc.terminate()
        raise
    return proc


def _wait_exit(proc: subprocess.Popen, timeout: float = 5.0) -> None:
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=2.0)


# ---------------------------------------------------------------------------
# Per-segment data collection
# ---------------------------------------------------------------------------

def _collect_segment(base_url: str) -> tuple[verify.Segment, dict]:
    """
    Fetch the BUNDLE_HEADER (from GET /session) and current evidence (GET
    /evidence) and return a (verify.Segment, raw_evidence_json) pair.
    """
    session_info = _get(f"{base_url}/session")
    bundle_header_line = session_info["bundle_header"]

    evidence_json = _get(f"{base_url}/evidence")

    hdr = verify.parse_header(bundle_header_line)
    pkt = verify.parse_evidence_json(evidence_json)
    seg = verify.Segment(header=hdr, packets=[pkt])
    return seg, evidence_json


# ---------------------------------------------------------------------------
# Main demo flow
# ---------------------------------------------------------------------------

def run_demo(gateway_bin: str, base_url: str) -> bool:
    """
    Execute the full Start→Hibernate→Resume→Verify flow.
    Returns True if verification passes.
    """
    _banner("Verifiable Agent Runtime — End-to-End Demo")

    # ── Segment 0: fresh session ─────────────────────────────────────────────

    _step("SEGMENT 0 — Starting VAR gateway (fresh session)")
    try:
        proc0 = _start_gateway(gateway_bin, base_url)
    except FileNotFoundError:
        _err(f"Gateway binary not found: {gateway_bin!r}")
        _err("Build it first:  zig build")
        return False
    _ok(f"Gateway ready at {base_url}")

    _step("SEGMENT 0 — Running verifiable commands")
    commands = [["uname", "-a"], ["date", "-u"]]
    for cmd in commands:
        try:
            result = _post(f"{base_url}/exec", {"cmd": cmd})
            stdout = __import__("base64").b64decode(
                result.get("stdout_b64", "")
            ).decode(errors="replace").strip()
            _ok(f"EXEC: {' '.join(cmd)}")
            _info(f"stdout : {stdout[:80]}")
            _info(f"exit   : {result.get('exit_code', '?')}")
            _info(f"hash   : {result.get('stdout_hash', '?')[:20]}…")
        except Exception as exc:
            _warn(f"EXEC {cmd} failed: {exc}")

    _step("SEGMENT 0 — Collecting evidence")
    seg0, ev0 = _collect_segment(base_url)
    _ok(f"seq={seg0.packets[0].seq}  stream={seg0.packets[0].stream.hex()[:20]}…")
    exec_count = len(seg0.packets[0].executions)
    _info(f"executions: {exec_count} record(s)")

    _step("SEGMENT 0 — Hibernating")
    try:
        hib = _post(f"{base_url}/hibernate", {})
        sealed_hex: str = hib["sealed_state"]
    except Exception as exc:
        _err(f"POST /hibernate failed: {exc}")
        proc0.terminate()
        return False

    sealed_bytes = len(sealed_hex) // 2
    _ok(f"Sealed state: {sealed_bytes} bytes")
    _wait_exit(proc0)
    _ok("Gateway exited cleanly.")

    # ── Simulated reboot ─────────────────────────────────────────────────────

    print(f"\n  {'─' * (_W - 2)}")
    print(f"  {_YELLOW}Simulating enclave reboot…{_RESET}")
    print(f"  {'─' * (_W - 2)}")
    time.sleep(0.3)

    # ── Segment 1: resumed session ───────────────────────────────────────────

    _step("SEGMENT 1 — Resuming session (VAR_RESUME_STATE set)")
    try:
        proc1 = _start_gateway(
            gateway_bin, base_url,
            env={"VAR_RESUME_STATE": sealed_hex},
        )
    except Exception as exc:
        _err(f"Failed to start resumed gateway: {exc}")
        return False
    _ok(f"Gateway ready at {base_url}")

    _step("SEGMENT 1 — Running verifiable commands")
    resume_commands = [["echo", "Session resumed successfully"], ["date", "-u"]]
    for cmd in resume_commands:
        try:
            result = _post(f"{base_url}/exec", {"cmd": cmd})
            stdout = __import__("base64").b64decode(
                result.get("stdout_b64", "")
            ).decode(errors="replace").strip()
            _ok(f"EXEC: {' '.join(cmd)}")
            _info(f"stdout : {stdout[:80]}")
        except Exception as exc:
            _warn(f"EXEC {cmd} failed: {exc}")

    _step("SEGMENT 1 — Collecting evidence")
    seg1, _ev1 = _collect_segment(base_url)
    _ok(f"seq={seg1.packets[0].seq}  stream={seg1.packets[0].stream.hex()[:20]}…")
    _info(f"executions: {len(seg1.packets[0].executions)} record(s)")

    proc1.terminate()
    _wait_exit(proc1)

    # ── Verification ─────────────────────────────────────────────────────────

    _step("Verifying full session (2 segments, cryptographic chain check)")

    # The chain-continuity check across the segment boundary requires that
    # segment 1's first packet's prev_stream equals segment 0's stream.
    # This is produced naturally by the enclave: GET /evidence in segment 0
    # advances the sequence and sets prev_stream_hash before hibernate, so
    # the resumed session's first evidence packet links back correctly.
    passed, results = verify.verify_segments([seg0, seg1])
    verify.print_report(results, [seg0, seg1], passed)

    if passed:
        _banner("Demo complete — full lifecycle cryptographically verified  ✓")
    else:
        _banner("Demo FAILED — see verification output above")

    return passed


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(args=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="VAR end-to-end demo: Start → Hibernate → Resume → Verify.",
    )
    parser.add_argument(
        "--gateway-bin",
        default=os.environ.get(
            "VAR_GATEWAY_BIN",
            str(Path(__file__).parent.parent / "zig-out" / "bin" / "VAR-gateway"),
        ),
        metavar="PATH",
        help="Path to the VAR-gateway binary (default: zig-out/bin/VAR-gateway).",
    )
    parser.add_argument(
        "--gateway-url",
        default=os.environ.get("VAR_GATEWAY_URL", "http://127.0.0.1:8765"),
        metavar="URL",
        help="Gateway base URL (default: http://127.0.0.1:8765).",
    )
    parsed = parser.parse_args(args)
    ok = run_demo(parsed.gateway_bin, parsed.gateway_url)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
