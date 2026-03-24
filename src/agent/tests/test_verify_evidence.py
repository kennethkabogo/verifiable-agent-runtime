"""
Tests for src/agent/verify_evidence.py.

Coverage:
  - is_hex256()                      — field-format predicate
  - build_evidence_message()         — 161-byte message layout (spec §3.1)
  - Bootstrap nonce computation      — SHA-256(doc ‖ session_id)
  - Full verify flow (mock _get)     — real Ed25519 keys, happy path
  - Failure paths                    — bad sig, wrong nonce, missing fields,
                                       wrong message length, bad hex fields

Run:
  pip install cryptography pytest
  pytest src/agent/tests/test_verify_evidence.py
"""

import hashlib
import json
import struct
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Make `import verify_evidence` work regardless of working directory.
sys.path.insert(0, str(Path(__file__).parent.parent))
import verify_evidence as ve  # noqa: E402

# ---------------------------------------------------------------------------
# Require `cryptography` for all tests in this file.
# ---------------------------------------------------------------------------
pytest.importorskip("cryptography", reason="pip install cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# ---------------------------------------------------------------------------
# Fixtures — a deterministic test session
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def session():
    """
    Build a complete, cryptographically consistent VAR session fixture.
    All hashes and signatures are derived from real keys and real SHA-256.
    """
    # Ed25519 keypair (fresh per test module run)
    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()
    pk_bytes    = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    pk_hex      = pk_bytes.hex()

    # Session identifiers
    session_id      = bytes(range(16))
    session_id_hex  = session_id.hex()

    # Attestation doc (any bytes; in sim mode the NSM returns 0xAA-filled)
    doc_bytes = b"\xaa" * 96
    doc_hex   = doc_bytes.hex()
    pcr0_hex  = "\xaa" * 32    # 64-char hex of 0xAA-filled PCR0

    # Bootstrap nonce: SHA-256(doc ‖ session_id)
    nonce_bytes = hashlib.sha256(doc_bytes + session_id).digest()
    nonce_hex   = nonce_bytes.hex()

    # L1 / L2 hashes (non-trivial values)
    prev_stream = hashlib.sha256(b"prev").digest()
    stream      = hashlib.sha256(b"stream").digest()
    state       = hashlib.sha256(b"state").digest()

    prev_stream_hex = prev_stream.hex()
    stream_hex      = stream.hex()
    state_hex       = state.hex()
    sequence        = 3

    # Build the 161-byte message and sign it
    msg = ve.build_evidence_message(
        sequence=sequence,
        prev_stream_hex=prev_stream_hex,
        stream_hex=stream_hex,
        state_hex=state_hex,
        session_id_hex=session_id_hex,
    )
    sig_bytes = private_key.sign(msg)
    sig_hex   = sig_bytes.hex()

    return dict(
        session_id_hex=session_id_hex,
        bootstrap_nonce_hex=nonce_hex,
        doc_hex=doc_hex,
        pcr0_hex=pcr0_hex,
        pk_hex=pk_hex,
        prev_stream_hex=prev_stream_hex,
        stream_hex=stream_hex,
        state_hex=state_hex,
        sig_hex=sig_hex,
        sequence=sequence,
        private_key=private_key,
        msg=msg,
    )


def _mock_get(s):
    """Return a _get() patcher that serves the given session fixture."""
    def _side_effect(path):
        if path == "/health":
            return {"status": "healthy"}
        if path == "/session":
            return {
                "magic": "VARB",
                "version": "01",
                "session_id": s["session_id_hex"],
                "bootstrap_nonce": s["bootstrap_nonce_hex"],
            }
        if path == "/attestation":
            return {
                "doc": s["doc_hex"],
                "pcr0": s["pcr0_hex"],
                "public_key": s["pk_hex"],
            }
        if path == "/evidence":
            return {
                "prev_stream": s["prev_stream_hex"],
                "stream": s["stream_hex"],
                "state": s["state_hex"],
                "sig": s["sig_hex"],
                "sequence": s["sequence"],
            }
        return {}
    return _side_effect


# ---------------------------------------------------------------------------
# is_hex256
# ---------------------------------------------------------------------------

class TestIsHex256:
    def test_valid(self):
        assert ve.is_hex256("a" * 64)

    def test_all_digits(self):
        assert ve.is_hex256("0123456789abcdef" * 4)

    def test_too_short(self):
        assert not ve.is_hex256("a" * 63)

    def test_too_long(self):
        assert not ve.is_hex256("a" * 65)

    def test_uppercase_rejected(self):
        assert not ve.is_hex256("A" * 64)

    def test_non_hex_char(self):
        assert not ve.is_hex256("g" * 64)

    def test_empty(self):
        assert not ve.is_hex256("")


# ---------------------------------------------------------------------------
# build_evidence_message — 161-byte layout (spec §3.1)
# ---------------------------------------------------------------------------

class TestBuildEvidenceMessage:
    def test_length_is_161(self, session):
        assert len(session["msg"]) == 161

    def test_magic(self, session):
        assert session["msg"][0:4] == b"VARE"

    def test_format_version(self, session):
        assert session["msg"][4] == 0x01

    def test_sequence_little_endian(self, session):
        seq = struct.unpack_from("<Q", session["msg"], 5)[0]
        assert seq == session["sequence"]

    def test_prev_stream_at_offset_13(self, session):
        assert session["msg"][13:45] == bytes.fromhex(session["prev_stream_hex"])

    def test_stream_at_offset_45(self, session):
        assert session["msg"][45:77] == bytes.fromhex(session["stream_hex"])

    def test_state_at_offset_77(self, session):
        assert session["msg"][77:109] == bytes.fromhex(session["state_hex"])

    def test_payload_len_zero(self, session):
        # Snapshot mode: PayloadLen must be 0
        plen = struct.unpack_from("<I", session["msg"], 109)[0]
        assert plen == 0

    def test_payload_hash_is_sha256_of_empty(self, session):
        expected = hashlib.sha256(b"").digest()
        assert session["msg"][113:145] == expected

    def test_session_id_at_offset_145(self, session):
        assert session["msg"][145:161] == bytes.fromhex(session["session_id_hex"])

    def test_different_sequences_produce_different_messages(self, session):
        msg1 = ve.build_evidence_message(
            sequence=1,
            prev_stream_hex=session["prev_stream_hex"],
            stream_hex=session["stream_hex"],
            state_hex=session["state_hex"],
            session_id_hex=session["session_id_hex"],
        )
        msg2 = ve.build_evidence_message(
            sequence=2,
            prev_stream_hex=session["prev_stream_hex"],
            stream_hex=session["stream_hex"],
            state_hex=session["state_hex"],
            session_id_hex=session["session_id_hex"],
        )
        assert msg1 != msg2

    def test_different_sessions_produce_different_messages(self, session):
        msg_a = ve.build_evidence_message(
            sequence=1,
            prev_stream_hex=session["prev_stream_hex"],
            stream_hex=session["stream_hex"],
            state_hex=session["state_hex"],
            session_id_hex="aa" * 16,
        )
        msg_b = ve.build_evidence_message(
            sequence=1,
            prev_stream_hex=session["prev_stream_hex"],
            stream_hex=session["stream_hex"],
            state_hex=session["state_hex"],
            session_id_hex="bb" * 16,
        )
        assert msg_a != msg_b


# ---------------------------------------------------------------------------
# Bootstrap nonce integrity
# ---------------------------------------------------------------------------

class TestBootstrapNonce:
    def test_correct_nonce(self, session):
        doc   = bytes.fromhex(session["doc_hex"])
        sid   = bytes.fromhex(session["session_id_hex"])
        expected = hashlib.sha256(doc + sid).hexdigest()
        assert expected == session["bootstrap_nonce_hex"]

    def test_wrong_doc_fails(self, session):
        wrong_doc = b"\x00" * 96
        sid       = bytes.fromhex(session["session_id_hex"])
        recomputed = hashlib.sha256(wrong_doc + sid).hexdigest()
        assert recomputed != session["bootstrap_nonce_hex"]

    def test_wrong_session_id_fails(self, session):
        doc = bytes.fromhex(session["doc_hex"])
        wrong_sid = b"\x00" * 16
        recomputed = hashlib.sha256(doc + wrong_sid).hexdigest()
        assert recomputed != session["bootstrap_nonce_hex"]


# ---------------------------------------------------------------------------
# Full verify flow — happy path
# ---------------------------------------------------------------------------

class TestFullVerifyHappyPath:
    def test_all_checks_pass(self, session, capsys):
        with patch.object(ve, "_get", side_effect=_mock_get(session)):
            ve._report.clear()
            result = ve.main(json_mode=False)
        assert result is True

    def test_no_failed_checks(self, session):
        with patch.object(ve, "_get", side_effect=_mock_get(session)):
            ve._report.clear()
            ve.main(json_mode=False)
        failed = [r for r in ve._report if r["passed"] is False]
        assert failed == [], f"unexpected failures: {failed}"

    def test_json_output_structure(self, session, capsys):
        with patch.object(ve, "_get", side_effect=_mock_get(session)):
            ve._report.clear()
            ve.main(json_mode=True)
        captured = capsys.readouterr().out
        # Find the JSON block (last {...} in output)
        start = captured.rfind("{")
        end   = captured.rfind("}") + 1
        data  = json.loads(captured[start:end])
        assert data["result"] == "pass"
        assert data["session_id"] == session["session_id_hex"]
        assert isinstance(data["checks"], list)
        assert len(data["checks"]) > 0


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------

class TestVerifyFailurePaths:
    def test_bad_signature_fails(self, session):
        """A signature over different content must not verify."""
        wrong_sig = session["private_key"].sign(b"wrong message")
        bad = {**session, "sig_hex": wrong_sig.hex()}

        with patch.object(ve, "_get", side_effect=_mock_get(bad)):
            ve._report.clear()
            result = ve.main(json_mode=False)

        assert result is False
        failed_labels = [r["label"] for r in ve._report if r["passed"] is False]
        assert any("signature" in lbl.lower() or "INVALID" in lbl for lbl in failed_labels)

    def test_wrong_bootstrap_nonce_fails(self, session):
        bad_nonce = "00" * 32
        bad = {**session, "bootstrap_nonce_hex": bad_nonce}

        with patch.object(ve, "_get", side_effect=_mock_get(bad)):
            ve._report.clear()
            result = ve.main(json_mode=False)

        assert result is False
        failed_labels = [r["label"] for r in ve._report if r["passed"] is False]
        assert any("bootstrap_nonce" in lbl.lower() or "nonce" in lbl.lower()
                   for lbl in failed_labels)

    def test_missing_stream_fails(self, session):
        bad = {**session, "stream_hex": ""}

        with patch.object(ve, "_get", side_effect=_mock_get(bad)):
            ve._report.clear()
            result = ve.main(json_mode=False)

        assert result is False

    def test_wrong_magic_fails(self, session, monkeypatch):
        def bad_get(path):
            resp = _mock_get(session)(path)
            if path == "/session":
                resp = {**resp, "magic": "XXXX"}
            return resp

        with patch.object(ve, "_get", side_effect=bad_get):
            ve._report.clear()
            result = ve.main(json_mode=False)

        assert result is False

    def test_invalid_hex_in_doc_fails(self, session):
        bad = {**session, "doc_hex": "not-valid-hex"}

        with patch.object(ve, "_get", side_effect=_mock_get(bad)):
            ve._report.clear()
            result = ve.main(json_mode=False)

        assert result is False
        # Should report which field had the bad hex, not a bare ValueError traceback
        detail_texts = " ".join(r.get("detail", "") for r in ve._report)
        assert "attestation doc" in detail_texts.lower()

    def test_malformed_sig_hex_fails(self, session):
        bad = {**session, "sig_hex": "zz" * 64}  # non-hex characters

        with patch.object(ve, "_get", side_effect=_mock_get(bad)):
            ve._report.clear()
            result = ve.main(json_mode=False)

        assert result is False

    def test_wrong_sig_length_fails(self, session):
        bad = {**session, "sig_hex": "aa" * 32}  # 64 hex chars instead of 128

        with patch.object(ve, "_get", side_effect=_mock_get(bad)):
            ve._report.clear()
            result = ve.main(json_mode=False)

        assert result is False
        failed_labels = [r["label"] for r in ve._report if r["passed"] is False]
        assert any("length" in lbl.lower() for lbl in failed_labels)

    def test_cross_session_replay_rejected(self, session):
        """A signature valid for session A must fail when presented with session B's ID."""
        different_session_id = "cc" * 16
        bad = {**session, "session_id_hex": different_session_id}

        with patch.object(ve, "_get", side_effect=_mock_get(bad)):
            ve._report.clear()
            result = ve.main(json_mode=False)

        # The signature was made over the original session_id, so verifying
        # against a different session_id must fail.
        assert result is False
