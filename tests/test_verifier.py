"""
Tests for src/verifier/verify.py

Run with:  pytest tests/test_verifier.py -v

Ed25519 signature tests require the `cryptography` package.
All other tests use only the Python stdlib.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Optional

import pytest

# Make verify importable regardless of working directory.
sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "verifier"))
import verify  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers — build valid test fixtures
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# Deterministic "attestation doc" for tests — 96 zero bytes (same as mock NSM).
MOCK_ATTEST_DOC = b"\x00" * 96


def _make_session() -> tuple[bytes, bytes, bytes]:
    """Return (session_id, bootstrap_nonce, attest_doc) for a test session."""
    session_id = bytes(range(16))
    attest_doc = MOCK_ATTEST_DOC
    bootstrap_nonce = _sha256(attest_doc + session_id)
    return session_id, bootstrap_nonce, attest_doc


def _hex(b: bytes) -> str:
    return b.hex()


def _make_header(
    session_id: bytes,
    bootstrap_nonce: bytes,
    attest_doc: bytes,
    signing_pub: bytes,
) -> str:
    """Build a BUNDLE_HEADER line matching the format produced by protocol.zig."""
    enc_pub = b"\xab" * 32
    pcr0    = b"\xaa" * 48
    return (
        f"BUNDLE_HEADER:magic=VARB:version=01"
        f":session={_hex(session_id)}"
        f":nonce={_hex(bootstrap_nonce)}"
        f":enc_pub={_hex(enc_pub)}"
        f":QUOTE:pcr0={_hex(pcr0)}:pk={_hex(signing_pub)}:doc={_hex(attest_doc)}"
    )


def _make_evidence_line(
    seq: int,
    prev_stream: bytes,
    stream: bytes,
    state: bytes,
    sig: bytes,
) -> str:
    return (
        f"EVIDENCE"
        f":prev_stream={_hex(prev_stream)}"
        f":stream={_hex(stream)}"
        f":state={_hex(state)}"
        f":sig={_hex(sig)}"
        f":seq={seq}"
    )


def _sign_packet(
    secret_key_bytes: bytes,  # 64-byte Ed25519 secret key (seed || pub)
    seq: int,
    prev_stream: bytes,
    stream: bytes,
    state: bytes,
    session_id: bytes,
) -> bytes:
    """Sign a 161-byte evidence message with an Ed25519 secret key."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        pytest.skip("cryptography package not available")
    msg = verify.build_signed_message(seq, prev_stream, stream, state, session_id)
    priv = Ed25519PrivateKey.from_private_bytes(secret_key_bytes[:32])
    return priv.sign(msg)


def _generate_keypair() -> tuple[bytes, bytes]:
    """Return (secret_key_seed_32, public_key_32)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        pytest.skip("cryptography package not available")
    priv = Ed25519PrivateKey.generate()
    pub  = priv.public_key().public_bytes_raw()
    seed = priv.private_bytes_raw()
    return seed, pub


# ---------------------------------------------------------------------------
# §4.1 / parsing
# ---------------------------------------------------------------------------

class TestParseBundleHeader:
    def test_parses_all_fields(self):
        sid, nonce, doc = _make_session()
        pub = b"\x01" * 32
        line = _make_header(sid, nonce, doc, pub)
        hdr = verify.parse_header(line)
        assert hdr.magic == "VARB"
        assert hdr.session_id == sid
        assert hdr.bootstrap_nonce == nonce
        assert hdr.signing_pub == pub
        assert hdr.attest_doc == doc

    def test_wrong_magic_raises(self):
        line = "BUNDLE_HEADER:magic=XXXX:session=" + "00" * 16 + ":nonce=" + "00" * 32 + ":pk=" + "00" * 32 + ":doc="
        with pytest.raises(ValueError, match="magic"):
            verify.parse_header(line)

    def test_missing_field_raises(self):
        # No 'pk' field
        line = "BUNDLE_HEADER:magic=VARB:session=" + "00" * 16 + ":nonce=" + "00" * 32 + ":doc="
        with pytest.raises(KeyError):
            verify.parse_header(line)


class TestParseEvidenceLine:
    def test_parses_all_fields(self):
        ps = b"\x11" * 32
        s  = b"\x22" * 32
        st = b"\x33" * 32
        sg = b"\x44" * 64
        line = _make_evidence_line(3, ps, s, st, sg)
        pkt = verify.parse_evidence_line(line)
        assert pkt.prev_stream == ps
        assert pkt.stream == s
        assert pkt.state == st
        assert pkt.sig == sg
        assert pkt.seq == 3

    def test_wrong_hash_length_raises(self):
        line = "EVIDENCE:prev_stream=aabb:stream=" + "00" * 32 + ":state=" + "00" * 32 + ":sig=" + "00" * 64 + ":seq=1"
        with pytest.raises(ValueError, match="prev_stream"):
            verify.parse_evidence_line(line)


# ---------------------------------------------------------------------------
# §4.2 Bootstrap nonce
# ---------------------------------------------------------------------------

class TestBootstrapNonce:
    def test_correct_nonce_passes(self):
        sid, nonce, doc = _make_session()
        hdr = verify.parse_header(_make_header(sid, nonce, doc, b"\x00" * 32))
        result = verify.check_bootstrap_nonce(hdr)
        assert result.passed

    def test_wrong_nonce_fails(self):
        sid, _, doc = _make_session()
        bad_nonce = b"\xff" * 32
        hdr = verify.parse_header(_make_header(sid, bad_nonce, doc, b"\x00" * 32))
        result = verify.check_bootstrap_nonce(hdr)
        assert not result.passed
        assert "MISMATCH" in result.detail


# ---------------------------------------------------------------------------
# §4.3 Chain continuity
# ---------------------------------------------------------------------------

class TestChainContinuity:
    def _stream_chain(self, n: int, start: bytes) -> list[bytes]:
        """Build a list of n stream hashes starting from start."""
        hashes = [start]
        for i in range(n):
            hashes.append(_sha256(hashes[-1] + bytes([i])))
        return hashes  # hashes[0] = anchor, hashes[1..n] = stream values

    def test_empty_packets_passes(self):
        result = verify.check_chain_continuity([], b"\x00" * 32)
        assert result.passed

    def test_single_correct_packet_passes(self):
        anchor = b"\xaa" * 32
        stream = _sha256(b"data")
        state  = b"\x00" * 32
        pkt    = verify.EvidencePacket("", anchor, stream, state, b"\x00" * 64, 1)
        result = verify.check_chain_continuity([pkt], anchor)
        assert result.passed

    def test_chain_of_three_passes(self):
        anchor = b"\xaa" * 32
        h = [anchor]
        for i in range(3):
            h.append(_sha256(h[-1] + bytes([i])))
        packets = [
            verify.EvidencePacket("", h[i], h[i + 1], b"\x00" * 32, b"\x00" * 64, i + 1)
            for i in range(3)
        ]
        result = verify.check_chain_continuity(packets, anchor)
        assert result.passed

    def test_first_packet_wrong_anchor_fails(self):
        anchor  = b"\xaa" * 32
        wrong   = b"\xbb" * 32
        stream  = b"\xcc" * 32
        pkt     = verify.EvidencePacket("", wrong, stream, b"\x00" * 32, b"\x00" * 64, 1)
        result  = verify.check_chain_continuity([pkt], anchor)
        assert not result.passed
        assert "does not match" in result.detail

    def test_gap_between_packets_fails(self):
        anchor  = b"\xaa" * 32
        s1      = _sha256(anchor + b"a")
        s2      = _sha256(s1 + b"b")
        s3      = _sha256(s2 + b"c")
        pkt1 = verify.EvidencePacket("", anchor, s1, b"\x00" * 32, b"\x00" * 64, 1)
        # pkt2 has wrong prev_stream (points to s3 instead of s1)
        pkt2 = verify.EvidencePacket("", s3, s2, b"\x00" * 32, b"\x00" * 64, 2)
        result = verify.check_chain_continuity([pkt1, pkt2], anchor)
        assert not result.passed
        assert "gap" in result.detail


# ---------------------------------------------------------------------------
# §4.4 Signatures (skipped if cryptography not installed)
# ---------------------------------------------------------------------------

class TestSignatures:
    def test_valid_signature_passes(self):
        seed, pub = _generate_keypair()
        sid, nonce, doc = _make_session()
        hdr = verify.parse_header(_make_header(sid, nonce, doc, pub))

        prev  = nonce
        s     = _sha256(nonce + b"output")
        state = b"\x00" * 32
        sig   = _sign_packet(seed, 1, prev, s, state, sid)
        pkt   = verify.EvidencePacket("", prev, s, state, sig, 1)

        result = verify.check_signatures([pkt], hdr)
        assert result.passed or result.skipped

    def test_corrupted_signature_fails(self):
        seed, pub = _generate_keypair()
        sid, nonce, doc = _make_session()
        hdr = verify.parse_header(_make_header(sid, nonce, doc, pub))

        prev  = nonce
        s     = _sha256(nonce + b"output")
        state = b"\x00" * 32
        sig   = _sign_packet(seed, 1, prev, s, state, sid)
        bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
        pkt   = verify.EvidencePacket("", prev, s, state, bad_sig, 1)

        result = verify.check_signatures([pkt], hdr)
        if not result.skipped:
            assert not result.passed

    def test_wrong_session_id_fails(self):
        """Signature over a different session_id must not verify."""
        seed, pub = _generate_keypair()
        sid, nonce, doc = _make_session()
        hdr = verify.parse_header(_make_header(sid, nonce, doc, pub))

        prev      = nonce
        s         = _sha256(nonce + b"output")
        state     = b"\x00" * 32
        wrong_sid = bytes(reversed(sid))
        sig       = _sign_packet(seed, 1, prev, s, state, wrong_sid)
        pkt       = verify.EvidencePacket("", prev, s, state, sig, 1)

        result = verify.check_signatures([pkt], hdr)
        if not result.skipped:
            assert not result.passed


# ---------------------------------------------------------------------------
# Session log parsing
# ---------------------------------------------------------------------------

class TestSessionLogParsing:
    def _build_log(self, header_line: str, evidence_lines: list[str]) -> str:
        return "\n".join([header_line] + evidence_lines) + "\n"

    def test_single_segment_parsed(self):
        sid, nonce, doc = _make_session()
        header = _make_header(sid, nonce, doc, b"\x00" * 32)
        prev   = nonce
        s      = _sha256(nonce + b"x")
        e_line = _make_evidence_line(1, prev, s, b"\x00" * 32, b"\x00" * 64)
        log    = self._build_log(header, [e_line])
        segs   = verify.load_session_log(log.splitlines(keepends=True))
        assert len(segs) == 1
        assert len(segs[0].packets) == 1

    def test_non_header_lines_ignored(self):
        sid, nonce, doc = _make_session()
        header = _make_header(sid, nonce, doc, b"\x00" * 32)
        log    = header + "\nREADY\nSEALED_STATE:aabbcc\n"
        segs   = verify.load_session_log(log.splitlines(keepends=True))
        assert len(segs) == 1
        assert len(segs[0].packets) == 0

    def test_two_segments_parsed(self):
        sid, nonce, doc = _make_session()
        h = _make_header(sid, nonce, doc, b"\x00" * 32)
        log = h + "\n" + h + "\n"
        segs = verify.load_session_log(log.splitlines(keepends=True))
        assert len(segs) == 2


# ---------------------------------------------------------------------------
# End-to-end: verify_segments
# ---------------------------------------------------------------------------

class TestVerifySegments:
    def _make_segment(
        self,
        session_id: bytes,
        bootstrap_nonce: bytes,
        attest_doc: bytes,
        num_packets: int = 1,
        signing_keypair: Optional[tuple] = None,
    ) -> verify.Segment:
        if signing_keypair:
            seed, pub = signing_keypair
        else:
            pub = b"\x00" * 32
            seed = None

        hdr = verify.parse_header(
            _make_header(session_id, bootstrap_nonce, attest_doc, pub)
        )
        seg = verify.Segment(header=hdr)

        prev = bootstrap_nonce
        for i in range(num_packets):
            s     = _sha256(prev + bytes([i]))
            state = b"\x00" * 32
            if seed:
                sig = _sign_packet(seed, i + 1, prev, s, state, session_id)
            else:
                sig = b"\x00" * 64
            seg.packets.append(
                verify.EvidencePacket("", prev, s, state, sig, i + 1)
            )
            prev = s

        return seg

    def test_empty_input_fails(self):
        passed, _ = verify.verify_segments([])
        assert not passed

    def test_single_segment_valid_chain(self):
        sid, nonce, doc = _make_session()
        seg = self._make_segment(sid, nonce, doc, num_packets=3)
        passed, results = verify.verify_segments([seg])
        # Chain continuity and nonce checks must pass;
        # signature check may be skipped or pass depending on `cryptography`.
        chain = next(r for r in results if "4.3" in r.section)
        assert chain.passed
        nonce_check = next(r for r in results if "4.2" in r.section)
        assert nonce_check.passed

    def test_wrong_bootstrap_nonce_fails(self):
        sid, _, doc = _make_session()
        bad_nonce = b"\xff" * 32
        seg = self._make_segment(sid, bad_nonce, doc)
        passed, results = verify.verify_segments([seg])
        assert not passed
        nonce_check = next(r for r in results if "4.2" in r.section)
        assert not nonce_check.passed

    def test_chain_gap_fails(self):
        sid, nonce, doc = _make_session()
        hdr = verify.parse_header(_make_header(sid, nonce, doc, b"\x00" * 32))
        seg = verify.Segment(header=hdr)
        s1 = _sha256(nonce + b"a")
        s2 = _sha256(s1 + b"b")
        # Second packet has a broken prev_stream link.
        broken = b"\xde\xad" * 16
        seg.packets = [
            verify.EvidencePacket("", nonce,  s1,     b"\x00" * 32, b"\x00" * 64, 1),
            verify.EvidencePacket("", broken, s2,     b"\x00" * 32, b"\x00" * 64, 2),
        ]
        passed, results = verify.verify_segments([seg])
        assert not passed
        chain = next(r for r in results if "4.3" in r.section)
        assert not chain.passed

    def test_multi_segment_cross_boundary_continuity(self):
        """Resumed segment must connect to the tail of the prior segment."""
        sid, nonce, doc = _make_session()
        seg0 = self._make_segment(sid, nonce, doc, num_packets=2)
        # Segment 1 has a fresh keypair but same session identity.
        seg1 = verify.Segment(
            header=verify.parse_header(_make_header(sid, nonce, doc, b"\x00" * 32))
        )
        # Correctly link seg1 packet to seg0's tail.
        tail = seg0.packets[-1].stream
        s    = _sha256(tail + b"resumed")
        seg1.packets.append(
            verify.EvidencePacket("", tail, s, b"\x00" * 32, b"\x00" * 64, 3)
        )
        passed, results = verify.verify_segments([seg0, seg1])
        # All chain checks must pass; signature may be skipped.
        chain_results = [r for r in results if "4.3" in r.section]
        assert all(r.passed for r in chain_results)

    def test_multi_segment_mismatched_session_id_fails(self):
        sid0, nonce, doc = _make_session()
        sid1 = bytes(reversed(sid0))  # Different session_id
        seg0 = self._make_segment(sid0, nonce, doc)
        seg1 = self._make_segment(sid1, nonce, doc)
        passed, _ = verify.verify_segments([seg0, seg1])
        assert not passed

    def test_multi_segment_mismatched_bootstrap_nonce_fails(self):
        sid, nonce, doc = _make_session()
        seg0 = self._make_segment(sid, nonce, doc)
        seg1 = self._make_segment(sid, b"\xff" * 32, doc)  # Different nonce
        passed, _ = verify.verify_segments([seg0, seg1])
        assert not passed


# ---------------------------------------------------------------------------
# JSON evidence bundle parsing
# ---------------------------------------------------------------------------

class TestJsonEvidenceParsing:
    def test_parses_json_bundle(self):
        sid, nonce, doc = _make_session()
        header = _make_header(sid, nonce, doc, b"\x00" * 32)
        obj = {
            "prev_stream": nonce.hex(),
            "stream": _sha256(nonce + b"x").hex(),
            "state": ("00" * 32),
            "sig": ("00" * 64),
            "sequence": 1,
            "executions": [
                {
                    "cmd": "uname -a",
                    "stdout_hash": "ab" * 32,
                    "stderr_hash": "cd" * 32,
                    "exit_code": 0,
                    "seq": 1,
                }
            ],
        }
        segs = verify.load_json_evidence(header, obj)
        assert len(segs) == 1
        assert segs[0].packets[0].seq == 1
        assert len(segs[0].packets[0].executions) == 1

    def test_exec_hash_length_validated(self):
        sid, nonce, doc = _make_session()
        header = _make_header(sid, nonce, doc, b"\x00" * 32)
        obj = {
            "prev_stream": nonce.hex(),
            "stream": _sha256(nonce + b"x").hex(),
            "state": "00" * 32,
            "sig": "00" * 64,
            "sequence": 1,
            "executions": [
                {
                    "cmd": "ls",
                    "stdout_hash": "aabb",  # too short — only 4 hex chars
                    "stderr_hash": "00" * 32,
                    "exit_code": 0,
                    "seq": 1,
                }
            ],
        }
        segs = verify.load_json_evidence(header, obj)
        result = verify.check_exec_hashes(segs[0].packets)
        assert result is not None
        assert not result.passed


# ---------------------------------------------------------------------------
# 161-byte message construction
# ---------------------------------------------------------------------------

class TestSignedMessage:
    def test_correct_length(self):
        msg = verify.build_signed_message(
            seq=1,
            prev_stream=b"\x00" * 32,
            stream=b"\x01" * 32,
            state=b"\x02" * 32,
            session_id=b"\x03" * 16,
        )
        assert len(msg) == 161

    def test_fields_at_correct_offsets(self):
        seq     = 42
        prev    = b"\x11" * 32
        stream  = b"\x22" * 32
        state   = b"\x33" * 32
        sid     = b"\x44" * 16

        msg = verify.build_signed_message(seq, prev, stream, state, sid)

        assert msg[0:4]   == b"VARE"
        assert msg[4]     == 0x01
        assert struct.unpack_from("<Q", msg, 5)[0] == seq
        assert msg[13:45]  == prev
        assert msg[45:77]  == stream
        assert msg[77:109] == state
        assert msg[145:161] == sid
