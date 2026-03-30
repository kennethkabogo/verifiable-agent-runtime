"""
Tests for the exec_command() helper in agent.py.

These tests use a mock socket that returns canned EXEC_RESULT lines so no
enclave process is needed.

Run:
  pytest src/agent/tests/test_agent_exec.py
"""

import base64
import hashlib
import json
import sys
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from agent import exec_command, exec_command_http, get_evidence_http  # noqa: E402


def _make_sock(response_line: str) -> MagicMock:
    """Return a mock socket that yields one byte at a time from response_line."""
    data = (response_line + "\n").encode()
    stream = BytesIO(data)

    sock = MagicMock()
    sock.sendall = MagicMock()
    sock.recv = lambda n: stream.read(n)
    return sock


def _b64(s: bytes) -> str:
    return base64.b64encode(s).decode()


def _hex32(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()


class TestExecCommand:
    def test_happy_path(self):
        stdout = b"hello\n"
        stderr = b""
        line = (
            f"EXEC_RESULT:exit=0"
            f":stdout_b64={_b64(stdout)}"
            f":stderr_b64={_b64(stderr)}"
            f":stdout_hash={_hex32(stdout)}"
            f":stderr_hash={_hex32(stderr)}"
        )
        sock = _make_sock(line)
        result = exec_command(sock, ["/bin/echo", "hello"])

        assert result["exit_code"] == 0
        assert result["stdout"] == stdout
        assert result["stderr"] == stderr
        assert result["stdout_hash"] == _hex32(stdout)
        assert result["stderr_hash"] == _hex32(stderr)

    def test_nonzero_exit(self):
        stdout = b""
        stderr = b"error\n"
        line = (
            f"EXEC_RESULT:exit=1"
            f":stdout_b64={_b64(stdout)}"
            f":stderr_b64={_b64(stderr)}"
            f":stdout_hash={_hex32(stdout)}"
            f":stderr_hash={_hex32(stderr)}"
        )
        sock = _make_sock(line)
        result = exec_command(sock, ["/bin/false"])

        assert result["exit_code"] == 1
        assert result["stderr"] == stderr

    def test_exec_error_response_raises(self):
        sock = _make_sock("EXEC_ERROR:spawn_failed")
        with pytest.raises(RuntimeError, match="spawn_failed"):
            exec_command(sock, ["nonexistent_binary"])

    def test_unexpected_response_raises(self):
        sock = _make_sock("GARBAGE:data")
        with pytest.raises(RuntimeError, match="unexpected exec response"):
            exec_command(sock, ["cmd"])


class TestExecCommandHttp:
    """Tests for the HTTP gateway exec path."""

    def _mock_urlopen(self, response_body: dict):
        """Return a context-manager mock that yields a response with json body."""
        import io
        resp = MagicMock()
        resp.read.return_value = json.dumps(response_body).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_happy_path(self):
        stdout = b"hello\n"
        stderr = b""
        body = {
            "exit_code": 0,
            "stdout_b64": _b64(stdout),
            "stderr_b64": _b64(stderr),
            "stdout_hash": _hex32(stdout),
            "stderr_hash": _hex32(stderr),
        }
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(body)):
            result = exec_command_http("http://127.0.0.1:8765", ["/bin/echo", "hello"])

        assert result["exit_code"] == 0
        assert result["stdout"] == stdout
        assert result["stdout_hash"] == _hex32(stdout)

    def test_http_error_raises(self):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(
            url="", code=500, msg="Internal Server Error", hdrs=None, fp=None,
        )):
            with pytest.raises(RuntimeError, match="HTTP 500"):
                exec_command_http("http://127.0.0.1:8765", ["bad"])

    def test_nonzero_exit_code(self):
        body = {
            "exit_code": 42,
            "stdout_b64": _b64(b""),
            "stderr_b64": _b64(b""),
            "stdout_hash": _hex32(b""),
            "stderr_hash": _hex32(b""),
        }
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(body)):
            result = exec_command_http("http://127.0.0.1:8765", ["/bin/false"])
        assert result["exit_code"] == 42


class TestGetEvidenceHttp:
    """Tests for the HTTP gateway /evidence fetch."""

    def test_returns_executions_list(self):
        evidence = {
            "stream": "aa" * 32,
            "state": "bb" * 32,
            "sig": "cc" * 64,
            "sequence": 3,
            "executions": [
                {"cmd": "uname -a", "exit_code": 0, "seq": 1,
                 "stdout_hash": "aa" * 32, "stderr_hash": "bb" * 32},
                {"cmd": "date -u", "exit_code": 0, "seq": 1,
                 "stdout_hash": "cc" * 32, "stderr_hash": "dd" * 32},
            ],
        }
        resp = MagicMock()
        resp.read.return_value = json.dumps(evidence).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=resp):
            result = get_evidence_http("http://127.0.0.1:8765")

        assert len(result["executions"]) == 2
        assert result["executions"][0]["cmd"] == "uname -a"
        assert result["executions"][1]["cmd"] == "date -u"
        assert result["sequence"] == 3
