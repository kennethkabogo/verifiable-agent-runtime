"""
Tests for the exec_command() helper in agent.py.

These tests use a mock socket that returns canned EXEC_RESULT lines so no
enclave process is needed.

Run:
  pytest src/agent/tests/test_agent_exec.py
"""

import base64
import hashlib
import sys
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from agent import exec_command  # noqa: E402


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
