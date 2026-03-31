#!/usr/bin/env python3
"""
var-cli — Verifiable Agent Runtime command-line interface
=========================================================
A unified entry point for all VAR host-side tooling.

Commands
--------
  connect   Run the demo agent over the vsock / TCP line protocol
  verify    Verify an evidence bundle from the HTTP gateway
  skill     Run the demo gateway skill over HTTP
  proxy     Start the host-enclave stdin/stdout bridge
  demo      Run the full Start→Hibernate→Resume→Verify lifecycle demo

Examples
--------
  # Simulation (TCP loopback, no Nitro hardware)
  var-cli connect
  var-cli connect --api-key sk-ant-…

  # AWS Nitro enclave
  var-cli connect --vsock-cid 16

  # HTTP gateway workflow
  zig-out/bin/VAR-gateway &
  var-cli skill --api-key sk-ant-…
  var-cli verify

  # Host proxy
  var-cli proxy --port 5005
  var-cli proxy --vsock --cid 2 --port 5005

  # End-to-end lifecycle demo (investor / stakeholder demo)
  var-cli demo
  var-cli demo --gateway-bin ./zig-out/bin/VAR-gateway
  var-cli demo --gateway-url http://127.0.0.1:8765
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Module loader
# ---------------------------------------------------------------------------

_SRC = Path(__file__).parent


def _load(name: str, rel_path: str):
    """Load a sibling Python module by file path without requiring __init__.py."""
    path = _SRC / rel_path
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------


def cmd_connect(args: argparse.Namespace) -> None:
    """Run the demo agent (vsock/TCP line protocol)."""
    os.environ.setdefault("VAR_HOST", args.host)
    os.environ["VAR_PORT"] = str(args.port)
    if args.vsock_cid is not None:
        os.environ["VSOCK_CID"] = str(args.vsock_cid)
    if args.api_key:
        os.environ["ANTHROPIC_API_KEY"] = args.api_key
    _load("var_agent", "agent/agent.py").main()


def cmd_verify(args: argparse.Namespace) -> None:
    """Cryptographically verify an evidence bundle from the HTTP gateway."""
    os.environ["VAR_GATEWAY"] = args.gateway
    _load("var_verify", "agent/verify_evidence.py").main()


def cmd_skill(args: argparse.Namespace) -> None:
    """Run the demo gateway skill (HTTP)."""
    os.environ["VAR_GATEWAY"] = args.gateway
    os.environ["SKILL_ID"] = args.skill_id
    if args.api_key:
        os.environ["ANTHROPIC_API_KEY"] = args.api_key
    _load("var_skill", "agent/gateway_skill.py").main()


def cmd_proxy(args: argparse.Namespace) -> None:
    """Start the host-enclave stdin/stdout bridge."""
    mod = _load("var_proxy", "host/proxy.py")
    proxy = mod.HostEnclaveProxy(use_vsock=args.vsock, cid=args.cid, port=args.port)
    proxy.start()


def cmd_demo(args: argparse.Namespace) -> None:
    """Run the full Start→Hibernate→Resume→Verify lifecycle demo."""
    demo_mod = _load("var_demo", "var_demo.py")
    rc = demo_mod.main(
        ["--gateway-bin", args.gateway_bin, "--gateway-url", args.gateway_url]
    )
    sys.exit(rc)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="var-cli",
        description="Verifiable Agent Runtime — command-line interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    # ── connect ──────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "connect",
        help="Run the demo agent (vsock/TCP line protocol)",
        description="Connect to a running VAR runtime and execute the demo agent workflow.",
    )
    transport = p.add_mutually_exclusive_group()
    transport.add_argument(
        "--vsock-cid",
        type=int,
        metavar="CID",
        help="Use AF_VSOCK with this enclave CID (Nitro hardware; default env VSOCK_CID=16)",
    )
    transport.add_argument(
        "--host",
        default=os.environ.get("VAR_HOST", "127.0.0.1"),
        metavar="HOST",
        help="TCP host for simulation mode (default: 127.0.0.1)",
    )
    p.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("VAR_PORT", "5005")),
        metavar="PORT",
        help="TCP/vsock port (default: 5005)",
    )
    p.add_argument(
        "--api-key",
        metavar="KEY",
        help="Anthropic API key; overrides ANTHROPIC_API_KEY env var",
    )
    p.set_defaults(func=cmd_connect)

    # ── verify ───────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "verify",
        help="Cryptographically verify an evidence bundle from the HTTP gateway",
        description=(
            "Fetches /session, /attestation, and /evidence from the gateway and "
            "independently verifies the bootstrap nonce, L1/L2 hashes, and Ed25519 "
            "signature.  Requires: pip install cryptography"
        ),
    )
    p.add_argument(
        "--gateway",
        default=os.environ.get("VAR_GATEWAY", "http://127.0.0.1:8765"),
        metavar="URL",
        help="Gateway base URL (default: http://127.0.0.1:8765)",
    )
    p.set_defaults(func=cmd_verify)

    # ── skill ─────────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "skill",
        help="Run the demo gateway skill (HTTP)",
        description="Demonstrates a modular skill that logs actions into the VAR evidence chain via HTTP.",
    )
    p.add_argument(
        "--gateway",
        default=os.environ.get("VAR_GATEWAY", "http://127.0.0.1:8765"),
        metavar="URL",
        help="Gateway base URL (default: http://127.0.0.1:8765)",
    )
    p.add_argument(
        "--skill-id",
        default=os.environ.get("SKILL_ID", "demo-skill"),
        metavar="ID",
        help="Skill identifier used in audit logs (default: demo-skill)",
    )
    p.add_argument(
        "--api-key",
        metavar="KEY",
        help="Anthropic API key; overrides ANTHROPIC_API_KEY env var",
    )
    p.set_defaults(func=cmd_skill)

    # ── proxy ─────────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "proxy",
        help="Start the host-enclave stdin/stdout bridge",
        description=(
            "Listens on vsock or TCP and bridges stdin/stdout to the enclave. "
            "Useful for interactive debugging or piping agent scripts."
        ),
    )
    p.add_argument(
        "--vsock",
        action="store_true",
        help="Use AF_VSOCK instead of TCP (Linux/Nitro only)",
    )
    p.add_argument(
        "--cid",
        type=int,
        default=2,
        metavar="CID",
        help="vsock CID to bind (default: 2 = VMADDR_CID_HOST)",
    )
    p.add_argument(
        "--port",
        type=int,
        default=5005,
        metavar="PORT",
        help="Port to listen on (default: 5005)",
    )
    p.set_defaults(func=cmd_proxy)

    # ── demo ──────────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "demo",
        help="Run the full Start→Hibernate→Resume→Verify lifecycle demo",
        description=(
            "Starts the VAR gateway, runs verifiable commands, hibernates the session, "
            "simulates an enclave reboot, resumes the session, runs more commands, and "
            "then cryptographically verifies the complete two-segment chain. "
            "Exit code 0 = verification PASSED, 1 = FAILED or error."
        ),
    )
    p.add_argument(
        "--gateway-bin",
        default=os.environ.get(
            "VAR_GATEWAY_BIN",
            str(Path(__file__).parent.parent / "zig-out" / "bin" / "VAR-gateway"),
        ),
        metavar="PATH",
        help="Path to the VAR-gateway binary (default: zig-out/bin/VAR-gateway)",
    )
    p.add_argument(
        "--gateway-url",
        default=os.environ.get("VAR_GATEWAY_URL", "http://127.0.0.1:8765"),
        metavar="URL",
        help="Gateway base URL (default: http://127.0.0.1:8765)",
    )
    p.set_defaults(func=cmd_demo)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n[var-cli] interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
