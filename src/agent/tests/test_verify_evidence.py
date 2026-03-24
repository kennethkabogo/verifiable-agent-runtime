"""
Tests for src/agent/verify_evidence.py.

Coverage:
  - is_hex256()                      — field-format predicate
  - build_evidence_message()         — 161-byte message layout (spec §3.1)
  - Bootstrap nonce computation      — SHA-256(doc ‖ session_id)
  - Full verify flow (mock _get)     — real Ed25519 keys, happy path
  - Failure paths                    — bad sig, wrong nonce, missing fields,
                                       wrong message length, bad hex fields
  - _verify_nitro_cose()             — synthetic COSE_Sign1 (3-cert chain),
                                       happy path + 7 failure modes

Run:
  pip install cryptography cbor2 pytest
  pytest src/agent/tests/test_verify_evidence.py
"""

import datetime
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
    pcr0_hex  = "aa" * 32      # 64-char hex of 0xAA-filled PCR0 (triggers sim-mode skip)

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
        # The JSON object is always the last thing printed, starting on its own
        # line with no indentation.  Using rfind("\n{") avoids matching the
        # indented "{" characters inside the checks array.
        idx  = captured.rfind("\n{")
        data = json.loads(captured[idx + 1:].strip())
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


# ---------------------------------------------------------------------------
# _verify_nitro_cose — synthetic COSE_Sign1 with a 3-cert chain
#
# Strategy: generate throwaway P-384 keys, build root CA → intermediate CA →
# leaf certs with the cryptography library, construct a well-formed COSE_Sign1
# payload (matching the Nitro attestation doc schema), and patch
# _AWS_NITRO_ROOT_DER so the embedded root check passes for the test root.
#
# The 3-cert chain also validates our cabundle chain-order assumption:
#   cabundle = [intermediate_der, root_der]   (leaf-parent first, root last)
# If the assumption were wrong, test_happy_path would fail with
# "cert[0] not signed by cert[1]" — making the test its own early warning.
# ---------------------------------------------------------------------------

cbor2 = pytest.importorskip("cbor2", reason="pip install cbor2")

from cryptography import x509 as _x509                                         # noqa: E402
from cryptography.x509.oid import NameOID as _NameOID                          # noqa: E402
from cryptography.hazmat.primitives import hashes as _h, serialization as _s   # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec as _ec                # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import (                  # noqa: E402
    decode_dss_signature as _decode_dss,
)

_NOW = datetime.datetime.now(datetime.timezone.utc)
_FAR = _NOW + datetime.timedelta(days=3650)


def _make_ca_cert(subject_cn: str, issuer_cn: str, issuer_key, subject_key, serial: int):
    """Build a DER-encoded CA certificate (self-signed when subject == issuer)."""
    return (
        _x509.CertificateBuilder()
        .subject_name(_x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(_x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(subject_key.public_key())
        .serial_number(serial)
        .not_valid_before(_NOW)
        .not_valid_after(_FAR)
        .add_extension(_x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(issuer_key, _h.SHA384())
    )


def _make_leaf_cert(issuer_cert, issuer_key, leaf_key, serial: int):
    """Build a DER-encoded end-entity certificate signed by issuer_key."""
    return (
        _x509.CertificateBuilder()
        .subject_name(_x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, "i-test-enclave")]))
        .issuer_name(issuer_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(_NOW)
        .not_valid_after(_FAR)
        .add_extension(_x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(issuer_key, _h.SHA384())
    )


def _build_cose_doc(
    leaf_cert,
    leaf_key,
    cabundle_certs: list,
    pcr0: bytes = bytes(48),
    corrupt_sig: bool = False,
) -> bytes:
    """
    Build a COSE_Sign1 Nitro-style attestation document.

    cabundle_certs: list of cert objects ordered leaf-parent-first, root-last.
    The COSE_Sign1 signature is made with leaf_key over the Sig_Structure.
    """
    protected_bstr = cbor2.dumps({1: -35})  # alg: ES384

    leaf_der = leaf_cert.public_bytes(_s.Encoding.DER)
    cabundle_ders = [c.public_bytes(_s.Encoding.DER) for c in cabundle_certs]

    payload_bstr = cbor2.dumps({
        "module_id":  "test-module-id",
        "digest":     "SHA384",
        "timestamp":  1_000_000,
        "pcrs":       {0: pcr0, 1: bytes(48), 2: bytes(48)},
        "certificate": leaf_der,
        "cabundle":   cabundle_ders,
        "public_key": None,
        "user_data":  None,
        "nonce":      None,
    })

    sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])
    der_sig = leaf_key.sign(sig_structure, _ec.ECDSA(_h.SHA384()))
    r, s = _decode_dss(der_sig)
    raw_sig = r.to_bytes(48, "big") + s.to_bytes(48, "big")

    if corrupt_sig:
        raw_sig = bytes([raw_sig[0] ^ 0xFF]) + raw_sig[1:]

    return cbor2.dumps(cbor2.CBORTag(18, [protected_bstr, {}, payload_bstr, raw_sig]))


@pytest.fixture(scope="module")
def nitro_pki():
    """
    Generate a throwaway 3-cert PKI:  root CA → intermediate CA → leaf.
    Returns a dict with keys, certs (as objects), DER bytes, and a valid
    COSE_Sign1 doc bytes.
    """
    root_key  = _ec.generate_private_key(_ec.SECP384R1())
    inter_key = _ec.generate_private_key(_ec.SECP384R1())
    leaf_key  = _ec.generate_private_key(_ec.SECP384R1())

    # root_cert  — self-signed with root_key, public key = root_key
    # inter_cert — signed by root_key, public key = inter_key
    # leaf_cert  — signed by inter_key, public key = leaf_key
    root_cert  = _make_ca_cert("Test Root CA",         "Test Root CA",  root_key,  root_key,  serial=1)
    inter_cert = _make_ca_cert("Test Intermediate CA", "Test Root CA",  root_key,  inter_key, serial=2)
    leaf_cert  = _make_leaf_cert(inter_cert,           inter_key,       leaf_key,             serial=3)

    # cabundle order: [leaf-parent, ..., root] — matches our _verify_nitro_cose assumption
    cabundle = [inter_cert, root_cert]
    pcr0 = bytes(range(48))  # deterministic non-zero PCR0 for cross-check test
    doc_bytes = _build_cose_doc(leaf_cert, leaf_key, cabundle, pcr0=pcr0)

    return dict(
        root_key=root_key,   inter_key=inter_key,   leaf_key=leaf_key,
        root_cert=root_cert, inter_cert=inter_cert,  leaf_cert=leaf_cert,
        root_der=root_cert.public_bytes(_s.Encoding.DER),
        cabundle=cabundle,
        pcr0=pcr0,
        doc_bytes=doc_bytes,
    )


class TestVerifyNitroCose:
    """Unit tests for _verify_nitro_cose() using synthetic COSE_Sign1 documents."""

    # ── helpers ──────────────────────────────────────────────────────────────

    def _call(self, pki, doc_bytes=None, root_der=None):
        """Call _verify_nitro_cose with optional root-cert patch."""
        doc = doc_bytes if doc_bytes is not None else pki["doc_bytes"]
        root = root_der if root_der is not None else pki["root_der"]
        with patch.object(ve, "_AWS_NITRO_ROOT_DER", root):
            return ve._verify_nitro_cose(doc)

    # ── happy path ───────────────────────────────────────────────────────────

    def test_happy_path_returns_ok(self, nitro_pki):
        ok, detail, payload = self._call(nitro_pki)
        assert ok is True, f"expected ok=True, got detail={detail!r}"

    def test_happy_path_detail_includes_chain_depth(self, nitro_pki):
        ok, detail, _ = self._call(nitro_pki)
        assert ok
        assert "chain depth=3" in detail

    def test_happy_path_detail_includes_leaf_cn(self, nitro_pki):
        ok, detail, _ = self._call(nitro_pki)
        assert ok
        assert "i-test-enclave" in detail

    def test_happy_path_payload_returned(self, nitro_pki):
        ok, _, payload = self._call(nitro_pki)
        assert ok
        assert payload is not None
        assert isinstance(payload, dict)

    def test_happy_path_pcr0_in_payload(self, nitro_pki):
        ok, _, payload = self._call(nitro_pki)
        assert ok
        pcr0_from_payload = payload["pcrs"][0]
        assert pcr0_from_payload == nitro_pki["pcr0"]

    # ── chain-order assumption ────────────────────────────────────────────────

    def test_reversed_cabundle_fails(self, nitro_pki):
        """
        If cabundle were [root, intermediate] instead of [intermediate, root],
        cert[0] (leaf) would appear not signed by cert[1] (root directly).
        This test documents and guards against that misorder.
        """
        reversed_cabundle = list(reversed(nitro_pki["cabundle"]))
        doc = _build_cose_doc(
            nitro_pki["leaf_cert"], nitro_pki["leaf_key"],
            reversed_cabundle, pcr0=nitro_pki["pcr0"],
        )
        ok, detail, _ = self._call(nitro_pki, doc_bytes=doc)
        assert ok is False
        assert "not signed by" in detail

    # ── failure paths ─────────────────────────────────────────────────────────

    def test_corrupt_cose_signature_fails(self, nitro_pki):
        doc = _build_cose_doc(
            nitro_pki["leaf_cert"], nitro_pki["leaf_key"],
            nitro_pki["cabundle"], corrupt_sig=True,
        )
        ok, detail, _ = self._call(nitro_pki, doc_bytes=doc)
        assert ok is False
        assert "signature" in detail.lower()

    def test_wrong_root_cert_fails(self, nitro_pki):
        """Presenting a different root cert must be rejected."""
        other_key  = _ec.generate_private_key(_ec.SECP384R1())
        other_root = _make_ca_cert("Other Root", "Other Root", other_key, other_key, serial=99)
        other_der  = other_root.public_bytes(_s.Encoding.DER)
        ok, detail, _ = self._call(nitro_pki, root_der=other_der)
        assert ok is False
        assert "root cert" in detail.lower()

    def test_broken_cert_chain_fails(self, nitro_pki):
        """Leaf signed by a rogue key (not the intermediate) must fail chain verification."""
        rogue_key  = _ec.generate_private_key(_ec.SECP384R1())
        bad_leaf   = _make_leaf_cert(nitro_pki["inter_cert"], rogue_key, rogue_key, serial=77)
        doc = _build_cose_doc(
            bad_leaf, rogue_key,
            nitro_pki["cabundle"], pcr0=nitro_pki["pcr0"],
        )
        ok, detail, _ = self._call(nitro_pki, doc_bytes=doc)
        assert ok is False
        assert "not signed by" in detail

    def test_missing_certificate_field_fails(self, nitro_pki):
        """A payload without the 'certificate' field must be rejected."""
        protected_bstr = cbor2.dumps({1: -35})
        payload_bstr   = cbor2.dumps({"pcrs": {0: bytes(48)}})  # no 'certificate'
        sig_struct     = cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])
        der_sig = nitro_pki["leaf_key"].sign(sig_struct, _ec.ECDSA(_h.SHA384()))
        r, s    = _decode_dss(der_sig)
        raw_sig = r.to_bytes(48, "big") + s.to_bytes(48, "big")
        doc = cbor2.dumps(cbor2.CBORTag(18, [protected_bstr, {}, payload_bstr, raw_sig]))
        ok, detail, _ = self._call(nitro_pki, doc_bytes=doc)
        assert ok is False
        assert "certificate" in detail.lower()

    def test_garbage_bytes_fails(self, nitro_pki):
        """Random bytes must fail with a CBOR parse error, not an exception."""
        ok, detail, payload = self._call(nitro_pki, doc_bytes=b"\x00\x01\x02\x03garbage")
        assert ok is False
        assert payload is None

    def test_not_a_4element_array_fails(self, nitro_pki):
        """A CBOR array with wrong element count must be rejected cleanly."""
        doc = cbor2.dumps(cbor2.CBORTag(18, ["only", "three", "elements"]))
        ok, detail, _ = self._call(nitro_pki, doc_bytes=doc)
        assert ok is False
        assert "COSE_Sign1" in detail
