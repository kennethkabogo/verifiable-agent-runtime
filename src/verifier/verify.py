#!/usr/bin/env python3
"""
VAR Evidence Verifier
=====================
Implements the §4 verification requirements from evidence_spec.md v1.5.

Accepts:
  - A session log file (newline-delimited BUNDLE_HEADER + EVIDENCE lines)
  - JSON evidence bundles from the HTTP gateway (with --header + --json)
  - Multi-segment sessions (hibernate/resume): multiple BUNDLE_HEADERs with
    the same session_id in a single log file

Exit codes:  0 = PASS,  1 = FAIL,  2 = usage / parse error

Ed25519 signature verification (§4.4) requires the `cryptography` package:
  pip install cryptography
All structural checks (bootstrap nonce, chain continuity) work without it.

Usage:
  python verify.py session.log
  python verify.py -                           # read from stdin
  python verify.py --header 'BUNDLE_HEADER:...' --json evidence.json
"""

import argparse
import hashlib
import json
import struct
import sys
import textwrap
from dataclasses import dataclass, field
from typing import Optional

# Ed25519 verification — optional.  If absent, §4.4 is reported as SKIPPED.
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    _ED25519_AVAILABLE = True
except ImportError:
    _ED25519_AVAILABLE = False

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BundleHeader:
    """Parsed BUNDLE_HEADER line."""
    raw: str
    magic: str
    version: str
    session_id: bytes       # 16 bytes — UUID v4
    bootstrap_nonce: bytes  # 32 bytes — SHA-256(attest_doc || session_id)
    enc_pub: bytes          # 32 bytes — X25519 public key (not used in verify)
    pcr0: bytes             # 48 bytes — SHA-384 enclave image measurement
    signing_pub: bytes      # 32 bytes — Ed25519 public key
    attest_doc: bytes       # raw attestation document bytes


@dataclass
class EvidencePacket:
    """Parsed EVIDENCE line or JSON evidence bundle."""
    raw: str
    prev_stream: bytes  # 32 bytes — H_stream[n-1]
    stream: bytes       # 32 bytes — H_stream[n]
    state: bytes        # 32 bytes — L2 terminal state hash
    sig: bytes          # 64 bytes — Ed25519 signature
    seq: int
    executions: list = field(default_factory=list)  # present in JSON bundles


@dataclass
class Segment:
    """One session segment: a BUNDLE_HEADER plus all following EVIDENCE packets."""
    header: BundleHeader
    packets: list[EvidencePacket] = field(default_factory=list)


@dataclass
class CheckResult:
    section: str
    passed: bool
    detail: str
    skipped: bool = False


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _unhex(s: str, label: str, expected_len: Optional[int] = None) -> bytes:
    try:
        b = bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError(f"invalid hex in {label}: {exc}") from exc
    if expected_len is not None and len(b) != expected_len:
        raise ValueError(f"{label}: expected {expected_len} bytes, got {len(b)}")
    return b


def parse_header(line: str) -> BundleHeader:
    """Parse a BUNDLE_HEADER:magic=VARB:... line."""
    fields: dict[str, str] = {}
    for part in line.split(":"):
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k] = v

    magic = fields.get("magic", "")
    if magic != "VARB":
        raise ValueError(f"unexpected magic: {magic!r} (expected 'VARB')")

    session_id      = _unhex(fields["session"],         "session_id",      16)
    bootstrap_nonce = _unhex(fields["nonce"],           "bootstrap_nonce", 32)
    signing_pub     = _unhex(fields["pk"],              "signing_pub",     32)
    enc_pub         = _unhex(fields["enc_pub"],         "enc_pub",         32) if "enc_pub" in fields else b"\x00" * 32
    attest_doc      = _unhex(fields.get("doc", ""),     "attest_doc")
    pcr0_hex        = fields.get("pcr0", "aa" * 48)
    pcr0            = _unhex(pcr0_hex,                  "pcr0",            48)

    return BundleHeader(
        raw=line,
        magic=magic,
        version=fields.get("version", "?"),
        session_id=session_id,
        bootstrap_nonce=bootstrap_nonce,
        enc_pub=enc_pub,
        pcr0=pcr0,
        signing_pub=signing_pub,
        attest_doc=attest_doc,
    )


def parse_evidence_line(line: str) -> EvidencePacket:
    """Parse an EVIDENCE:prev_stream=...:stream=...:... vsock line."""
    fields: dict[str, str] = {}
    for part in line.split(":"):
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k] = v

    return EvidencePacket(
        raw=line,
        prev_stream=_unhex(fields["prev_stream"], "prev_stream", 32),
        stream=_unhex(fields["stream"],           "stream",      32),
        state=_unhex(fields["state"],             "state",       32),
        sig=_unhex(fields["sig"],                 "sig",         64),
        seq=int(fields["seq"]),
    )


def parse_evidence_json(obj: dict) -> EvidencePacket:
    """Build an EvidencePacket from a JSON evidence bundle (HTTP /evidence)."""
    return EvidencePacket(
        raw=json.dumps(obj),
        prev_stream=_unhex(obj["prev_stream"], "prev_stream", 32),
        stream=_unhex(obj["stream"],           "stream",      32),
        state=_unhex(obj["state"],             "state",       32),
        sig=_unhex(obj["sig"],                 "sig",         64),
        seq=int(obj["sequence"]),
        executions=obj.get("executions", []),
    )


# ---------------------------------------------------------------------------
# §3.1  Reconstruct the 161-byte signed message
# ---------------------------------------------------------------------------

# SHA-256("") — used as SHA-256(Payload) in snapshot mode (§3.2).
_SHA256_EMPTY = hashlib.sha256(b"").digest()


def build_signed_message(
    seq: int,
    prev_stream: bytes,
    stream: bytes,
    state: bytes,
    session_id: bytes,
) -> bytes:
    """Reconstruct the 161-byte message the enclave signed (spec §3.1)."""
    msg = bytearray()
    msg += b"VARE"                      # Magic           (4)
    msg += b"\x01"                      # FormatVer       (1)
    msg += struct.pack("<Q", seq)       # Sequence u64 LE (8)
    msg += prev_stream                  # PrevL1Hash      (32)
    msg += stream                       # L1Hash          (32)
    msg += state                        # L2Hash          (32)
    msg += struct.pack("<I", 0)         # PayloadLen = 0  (4)
    msg += _SHA256_EMPTY                # SHA-256("")     (32)
    msg += session_id                   # SessionID       (16)
    assert len(msg) == 161, f"BUG: expected 161-byte message, got {len(msg)}"
    return bytes(msg)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_bootstrap_nonce(header: BundleHeader) -> CheckResult:
    """§4.2: bootstrap_nonce == SHA-256(attest_doc || session_id)."""
    expected = hashlib.sha256(header.attest_doc + header.session_id).digest()
    passed = expected == header.bootstrap_nonce
    if passed:
        detail = f"SHA-256(doc ‖ session_id) = {expected.hex()[:16]}…  matches"
    else:
        detail = (
            f"MISMATCH\n"
            f"  expected : {expected.hex()}\n"
            f"  got      : {header.bootstrap_nonce.hex()}"
        )
    return CheckResult("§4.2 Bootstrap nonce", passed, detail)


def check_chain_continuity(
    packets: list[EvidencePacket],
    anchor: bytes,
    anchor_label: str = "bootstrap_nonce",
) -> CheckResult:
    """§4.3: each packet's prev_stream links to its predecessor."""
    if not packets:
        return CheckResult("§4.3 Chain continuity", True, "no packets — trivially continuous")

    # First packet must connect to the anchor (bootstrap_nonce or last segment's tail).
    if packets[0].prev_stream != anchor:
        return CheckResult(
            "§4.3 Chain continuity", False,
            f"packet seq={packets[0].seq}: prev_stream does not match {anchor_label}\n"
            f"  expected : {anchor.hex()}\n"
            f"  got      : {packets[0].prev_stream.hex()}",
        )

    # Consecutive packet continuity.
    for i in range(1, len(packets)):
        prev, curr = packets[i - 1], packets[i]
        if curr.prev_stream != prev.stream:
            return CheckResult(
                "§4.3 Chain continuity", False,
                f"gap between seq={prev.seq} and seq={curr.seq}\n"
                f"  expected prev_stream : {prev.stream.hex()}\n"
                f"  got prev_stream      : {curr.prev_stream.hex()}",
            )

    return CheckResult(
        "§4.3 Chain continuity", True,
        f"{len(packets)} packet(s), all linked correctly",
    )


def check_signatures(
    packets: list[EvidencePacket],
    header: BundleHeader,
) -> CheckResult:
    """§4.4: verify Ed25519 signature on each packet's 161-byte message."""
    if not _ED25519_AVAILABLE:
        return CheckResult(
            "§4.4 Signatures", True,
            "SKIPPED — run: pip install cryptography",
            skipped=True,
        )
    if not packets:
        return CheckResult("§4.4 Signatures", True, "no packets to verify")

    pub = Ed25519PublicKey.from_public_bytes(header.signing_pub)
    failures = []
    for pkt in packets:
        msg = build_signed_message(
            pkt.seq, pkt.prev_stream, pkt.stream, pkt.state, header.session_id
        )
        try:
            pub.verify(pkt.sig, msg)
        except InvalidSignature:
            failures.append(f"seq={pkt.seq}")

    if failures:
        return CheckResult(
            "§4.4 Signatures", False,
            f"{len(failures)}/{len(packets)} invalid: {', '.join(failures)}",
        )
    return CheckResult(
        "§4.4 Signatures", True,
        f"{len(packets)}/{len(packets)} signature(s) valid (Ed25519)",
    )


def check_exec_hashes(packets: list[EvidencePacket]) -> Optional[CheckResult]:
    """§2.3: validate that exec entry stdout_hash fields are well-formed hex."""
    all_entries = [e for pkt in packets for e in pkt.executions]
    if not all_entries:
        return None

    malformed = []
    for i, rec in enumerate(all_entries):
        h = rec.get("stdout_hash", "")
        if len(h) != 64:
            malformed.append(
                f"entry[{i}] cmd={rec.get('cmd','?')!r}: "
                f"stdout_hash has {len(h)} hex chars (expected 64)"
            )

    if malformed:
        return CheckResult("§2.3 Exec entries", False, "\n  ".join(malformed))
    return CheckResult(
        "§2.3 Exec entries", True,
        f"{len(all_entries)} execution record(s) with well-formed stdout_hash",
    )


# ---------------------------------------------------------------------------
# Multi-segment verification (§5.3)
# ---------------------------------------------------------------------------

def verify_segments(segments: list[Segment]) -> tuple[bool, list[CheckResult]]:
    """Verify one or more session segments.  Returns (all_passed, results)."""
    results: list[CheckResult] = []

    if not segments:
        results.append(CheckResult("input", False, "no segments found in input"))
        return False, results

    # Multi-segment: all segments must share the same session_id and bootstrap_nonce.
    first_sid   = segments[0].header.session_id
    first_nonce = segments[0].header.bootstrap_nonce

    if len(segments) > 1:
        sid_ok = True
        for i, seg in enumerate(segments[1:], start=1):
            if seg.header.session_id != first_sid:
                results.append(CheckResult(
                    f"§5.3 Session identity (segment {i})", False,
                    f"session_id mismatch\n"
                    f"  segment 0 : {first_sid.hex()}\n"
                    f"  segment {i} : {seg.header.session_id.hex()}",
                ))
                sid_ok = False
            if seg.header.bootstrap_nonce != first_nonce:
                results.append(CheckResult(
                    f"§5.3 Bootstrap nonce (segment {i})", False,
                    "bootstrap_nonce differs from segment 0 — chain anchor broken",
                ))
                sid_ok = False
        if not sid_ok:
            return False, results
        results.append(CheckResult(
            "§5.3 Session identity",
            True,
            f"{len(segments)} segment(s) share session_id and bootstrap_nonce",
        ))

    # Per-segment checks, threading the chain tail across segment boundaries.
    last_stream: Optional[bytes] = None

    for i, seg in enumerate(segments):
        seg_label = f" (segment {i})" if len(segments) > 1 else ""

        # §4.2 — bootstrap nonce only needs checking once (segment 0).
        if i == 0:
            results.append(check_bootstrap_nonce(seg.header))

        # §4.3 — chain continuity.
        if i == 0:
            anchor = seg.header.bootstrap_nonce
            anchor_label = "bootstrap_nonce"
        else:
            # Resumed segment: first packet must link to the tail of the prior segment.
            anchor = last_stream  # type: ignore[assignment]
            anchor_label = f"last stream of segment {i-1}"

        cont = check_chain_continuity(seg.packets, anchor, anchor_label)
        cont.section += seg_label
        results.append(cont)

        # §4.4 — signatures (each segment has its own keypair per §5.3).
        sig_check = check_signatures(seg.packets, seg.header)
        sig_check.section += seg_label
        results.append(sig_check)

        # §2.3 — exec entry hash format.
        exec_check = check_exec_hashes(seg.packets)
        if exec_check is not None:
            exec_check.section += seg_label
            results.append(exec_check)

        if seg.packets:
            last_stream = seg.packets[-1].stream

    all_passed = all(r.passed for r in results)
    return all_passed, results


# ---------------------------------------------------------------------------
# Input loaders
# ---------------------------------------------------------------------------

def load_session_log(lines: list[str]) -> list[Segment]:
    """
    Parse a session log into segments.
    Each BUNDLE_HEADER starts a new segment; all following EVIDENCE lines
    belong to that segment until the next BUNDLE_HEADER (or EOF).
    Other lines (READY, SEALED_STATE, LOG, etc.) are silently ignored.
    """
    segments: list[Segment] = []
    current: Optional[Segment] = None

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("BUNDLE_HEADER:"):
            current = Segment(header=parse_header(line))
            segments.append(current)
        elif line.startswith("EVIDENCE:"):
            if current is None:
                raise ValueError("EVIDENCE line found before any BUNDLE_HEADER")
            current.packets.append(parse_evidence_line(line))

    return segments


def load_json_evidence(header_line: str, json_obj: dict) -> list[Segment]:
    """Build a single-segment list from an explicit BUNDLE_HEADER + JSON bundle."""
    hdr = parse_header(header_line)
    seg = Segment(header=hdr)
    seg.packets.append(parse_evidence_json(json_obj))
    return [seg]


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

_GREEN  = "\033[32m"
_RED    = "\033[31m"
_YELLOW = "\033[33m"
_RESET  = "\033[0m"


def _tag(r: CheckResult) -> str:
    if r.skipped:
        return f"{_YELLOW}SKIP{_RESET}"
    return f"{_GREEN}PASS{_RESET}" if r.passed else f"{_RED}FAIL{_RESET}"


def print_report(
    results: list[CheckResult],
    segments: list[Segment],
    all_passed: bool,
) -> None:
    total_packets = sum(len(s.packets) for s in segments)
    total_execs   = sum(len(e) for s in segments for p in s.packets for e in [p.executions])
    session_id    = segments[0].header.session_id.hex() if segments else "?"

    print()
    print("  VAR Evidence Verifier — v1.5")
    print(f"  Session  : {session_id}")
    print(f"  Segments : {len(segments)}")
    print(f"  Packets  : {total_packets}")
    if total_execs:
        print(f"  Execs    : {total_execs}")
    print()

    for r in results:
        print(f"  [{_tag(r)}] {r.section}")
        for line in r.detail.splitlines():
            print(f"          {line}")

    print()
    verdict = f"{_GREEN}PASS{_RESET}" if all_passed else f"{_RED}FAIL{_RESET}"
    print(f"  RESULT: {verdict}")
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify VAR evidence bundles against spec §4.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Verify a full session log (vsock output redirected to file):
              python verify.py session.log

              # Pipe directly from the demo agent:
              python agent.py 2>&1 | grep -E 'BUNDLE_HEADER|EVIDENCE' | python verify.py -

              # Verify JSON evidence from the HTTP gateway:
              python verify.py --header 'BUNDLE_HEADER:magic=VARB:...' --json ev.json

              # Multi-segment (hibernate + resume):
              cat segment0.log segment1.log | python verify.py -
        """),
    )
    parser.add_argument(
        "file",
        nargs="?",
        metavar="FILE",
        help="Session log file; use '-' for stdin.",
    )
    parser.add_argument(
        "--header",
        metavar="LINE",
        help="Explicit BUNDLE_HEADER line (required with --json).",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        dest="json_file",
        help="JSON evidence bundle from GET /evidence.",
    )
    args = parser.parse_args()

    # ── Load input ────────────────────────────────────────────────────────────
    try:
        if args.json_file:
            if not args.header:
                print("error: --json requires --header", file=sys.stderr)
                return 2
            with open(args.json_file) as f:
                json_obj = json.load(f)
            segments = load_json_evidence(args.header, json_obj)

        elif args.file:
            src = sys.stdin if args.file == "-" else open(args.file)
            with src:
                lines = src.readlines()
            segments = load_session_log(lines)

        else:
            parser.print_help()
            return 2

    except (ValueError, KeyError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # ── Verify ────────────────────────────────────────────────────────────────
    try:
        all_passed, results = verify_segments(segments)
    except Exception as exc:
        print(f"verification error: {exc}", file=sys.stderr)
        return 2

    print_report(results, segments, all_passed)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
