#!/usr/bin/env python3
"""
VAR Demo Server — demo_server.py
=================================
Lightweight HTTP server for the browser demo. Runs on the EC2 host (not
inside the enclave), proxies a single request into the enclave over the
vsock bridge, assembles the resulting evidence into an APEX bundle, and
runs tools/apex_verify.py's 12-step §8 algorithm against it in-process.

  demo.html (browser)
      │  POST /api/run {"input": "..."}
      ▼
  demo_server.py :8080  (this file, on the EC2 host)
      │  HTTP over TCP
      ▼
  vsock_bridge.py :8765  (raw TCP↔vsock pipe, dev-only, already running)
      │  vsock
      ▼
  VAR-gateway (inside the Nitro enclave)

Usage:
  python3 tools/demo_server.py [--port 8080] [--bridge http://127.0.0.1:8765]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

# ── Load apex_verify.py as a module (sibling file) ──────────────────────────
# Registered in sys.modules before exec_module: dataclasses' type-resolution
# looks the module up by name via sys.modules, which fails otherwise.

_TOOLS_DIR = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("apex_verify", _TOOLS_DIR / "apex_verify.py")
apex_verify = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
sys.modules["apex_verify"] = apex_verify
_spec.loader.exec_module(apex_verify)  # type: ignore[union-attr]

_DEMO_HTML_PATH = _TOOLS_DIR / "demo.html"

BRIDGE_URL = "http://127.0.0.1:8765"
REQUEST_TIMEOUT = 15


# ── Bridge HTTP helpers ──────────────────────────────────────────────────────

class BridgeError(Exception):
    """Raised when a call to the vsock bridge / enclave gateway fails."""
    def __init__(self, stage: str, message: str):
        super().__init__(message)
        self.stage = stage
        self.message = message


def _bridge_get(path: str) -> dict:
    url = f"{BRIDGE_URL}{path}"
    try:
        with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        raise BridgeError(f"GET {path}", f"HTTP {exc.code}: {exc.read().decode(errors='replace')[:300]}")
    except (urllib.error.URLError, OSError) as exc:
        raise BridgeError(f"GET {path}", f"bridge unreachable at {url}: {exc}")
    except json.JSONDecodeError as exc:
        raise BridgeError(f"GET {path}", f"invalid JSON from bridge: {exc}")



# src/runtime/http.zig's handleCompute() builds its response body as
# `"output":"{s}"` with result.output interpolated *unescaped*. For
# fn="echo", compute.zig sets output = the raw canonical-JSON of the
# request's `inputs`, so the response is literally invalid JSON (an
# unescaped `{"..."}` embedded inside a quoted string). Recover the fields
# with a split anchored on the surrounding literals from that same format
# string, rather than attempting a generic "repair" of arbitrary broken
# JSON (undecidable if the embedded value itself contains the anchor text).
_COMPUTE_REPAIR_RE = re.compile(
    r'^\{"fn":"([^"]*)","inputs_hash":"([0-9a-f]+)","output":"(.*)","evidence":(\{.*\})\}\s*$',
    re.DOTALL,
)


def _parse_compute_body(text: str) -> dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    m = _COMPUTE_REPAIR_RE.match(text)
    if not m:
        raise BridgeError(
            "POST /compute",
            f"invalid JSON from bridge and could not recover known /compute shape: {text[:300]}",
        )
    fn_name, inputs_hash, output_raw, evidence_raw = m.groups()
    try:
        evidence = json.loads(evidence_raw)
    except json.JSONDecodeError as exc:
        raise BridgeError("POST /compute", f"recovered response but evidence sub-object still invalid: {exc}")
    return {"fn": fn_name, "inputs_hash": inputs_hash, "output": output_raw, "evidence": evidence}


def _bridge_post(path: str, payload: dict) -> dict:
    url = f"{BRIDGE_URL}{path}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as r:
            text = r.read().decode()
    except urllib.error.HTTPError as exc:
        raise BridgeError(f"POST {path}", f"HTTP {exc.code}: {exc.read().decode(errors='replace')[:300]}")
    except (urllib.error.URLError, OSError) as exc:
        raise BridgeError(f"POST {path}", f"bridge unreachable at {url}: {exc}")

    if path == "/compute":
        return _parse_compute_body(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise BridgeError(f"POST {path}", f"invalid JSON from bridge: {exc}")


# ── Bundle assembly ──────────────────────────────────────────────────────────

def _evidence_line(pkt: dict) -> str:
    """Reconstruct a wire-format EVIDENCE line from a gateway JSON packet.

    Field names come from src/runtime/shell.zig's getEvidenceRange/
    getEvidenceBundleJson: {prev_stream, stream, state, sig, sequence}.
    apex_verify.py's parser reads "seq", not "sequence".
    """
    return (
        f"EVIDENCE:prev_stream={pkt['prev_stream']}:stream={pkt['stream']}:"
        f"state={pkt['state']}:sig={pkt['sig']}:seq={pkt['sequence']}"
    )


def run_enclave_request(inputs: dict, fn: str = "echo") -> dict[str, Any]:
    """Drive one full round trip: compute → collect evidence → seal → verify.

    Returns a JSON-serialisable dict describing the compute result, the
    assembled bundle, and the 12-step verification outcome.
    """
    session = _bridge_get("/session")
    header_line = session["bundle_header"]

    compute = _bridge_post("/compute", {"fn": fn, "inputs": inputs})
    latest_seq = compute["evidence"]["sequence"]

    evidence_range = _bridge_get(f"/evidence?from=1&to={latest_seq}")
    packets = evidence_range["packets"]

    seal = _bridge_get("/seal")
    seal_line = seal["bundle_seal"]

    bundle_lines = [header_line] + [_evidence_line(p) for p in packets] + [seal_line]
    bundle_text = "\n".join(bundle_lines) + "\n"

    try:
        all_passed, results, bundle, ecr = apex_verify.run(bundle_text.splitlines(keepends=True))
    except (ValueError, KeyError) as exc:
        raise BridgeError("verify", f"bundle parse error: {exc}")

    hdr = bundle.segments[0].header
    steps = [
        {
            "step": r.step,
            "status": "SKIP" if r.skipped else ("PASS" if r.passed else "FAIL"),
            "detail": r.detail,
        }
        for r in results
    ]

    return {
        "ok": True,
        "compute": {
            "fn": compute["fn"],
            "inputs_hash": compute["inputs_hash"],
            "output": compute["output"],
        },
        "bundle": {
            "session_id": hdr.session_id.hex(),
            "bootstrap_nonce": hdr.bootstrap_nonce.hex(),
            "magic": hdr.magic,
            "version": hdr.version,
            "pcr0": hdr.pcr0.hex(),
            "pcr1": hdr.pcr1.hex(),
            "pcr2": hdr.pcr2.hex(),
            "sim_mode": hdr.sim_flag or all(b == 0xAA for b in hdr.attest_doc) or not hdr.attest_doc,
            "packets": [
                {
                    "seq": p["sequence"],
                    "prev_stream": p["prev_stream"],
                    "stream": p["stream"],
                    "state": p["state"],
                    "sig": p["sig"],
                }
                for p in packets
            ],
            "seal": {
                "terminal_digest": bundle.bundle_seal.terminal_digest.hex(),
                "bundle_hash": bundle.bundle_seal.bundle_hash.hex(),
                "seal_sig": bundle.bundle_seal.seal_sig.hex(),
            },
            "raw_text": bundle_text,
        },
        "verification": {
            "all_passed": all_passed,
            "ecr": ecr,
            "steps": steps,
        },
    }


# ── HTTP server ──────────────────────────────────────────────────────────────

class _RateLimiter:
    """Per-key sliding-window rate limiter.

    In-memory only (resets on restart) — this demo runs as a single process
    on one box, so that's sufficient; no need for shared/persistent state.
    """

    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            hits = self._hits.setdefault(key, [])
            while hits and hits[0] < cutoff:
                hits.pop(0)
            if len(hits) >= self.max_requests:
                return False
            hits.append(now)
            return True


# Applies to POST /api/run only — the endpoint that drives a real enclave
# session (/compute + /evidence + /seal) rather than a static read.
_RUN_RATE_LIMITER = _RateLimiter(max_requests=12, window_seconds=60.0)


class DemoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        cf_ip = self.headers.get("Cf-Connecting-Ip") if self.headers else None
        xff = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip() if self.headers else ""
        ip = (cf_ip or xff or self.client_address[0]).strip()
        sys.stderr.write(f"[demo_server] {ip} - {fmt % args}\n")

    def _client_ip(self) -> str:
        # Behind Cloudflare Tunnel the raw socket peer is always cloudflared
        # on localhost — the real client IP arrives via these headers.
        cf_ip = self.headers.get("Cf-Connecting-Ip")
        if cf_ip:
            return cf_ip.strip()
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:
        if self.path == "/":
            try:
                size = _DEMO_HTML_PATH.stat().st_size
            except OSError:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(size))
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/":
            self._serve_demo_html()
        elif self.path == "/api/health":
            try:
                health = _bridge_get("/health")
                self._send_json(200, {"ok": True, "bridge": health})
            except BridgeError as exc:
                self._send_json(502, {"ok": False, "stage": exc.stage, "error": exc.message})
        else:
            self._send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        # Always drain the body first, regardless of which branch below
        # returns early. On a kept-alive HTTP/1.1 connection (which Cloudflare
        # Tunnel reuses across separate client requests), leftover unread
        # bytes stay in the socket and corrupt the next request's framing.
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"

        if self.path != "/api/run":
            self._send_json(404, {"ok": False, "error": "not found"})
            return

        client_ip = self._client_ip()
        if not _RUN_RATE_LIMITER.allow(client_ip):
            sys.stderr.write(f"[demo_server] RATE_LIMIT {client_ip}\n")
            self._send_json(429, {
                "ok": False,
                "stage": "rate_limit",
                "error": (
                    f"rate limit exceeded — max {_RUN_RATE_LIMITER.max_requests} requests "
                    f"per {int(_RUN_RATE_LIMITER.window_seconds)}s per client. Please wait and retry."
                ),
            })
            return

        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._send_json(400, {"ok": False, "error": "invalid JSON body"})
            return

        fn = body.get("fn", "echo")
        if not isinstance(fn, str):
            self._send_json(400, {"ok": False, "error": "\"fn\" must be a string"})
            return

        # Callers may pass a structured "inputs" dict for functions like
        # "verify" that need more than a single text field. Fall back to
        # wrapping the legacy "input" string as {"text": <value>}.
        if "inputs" in body:
            inputs = body["inputs"]
            if not isinstance(inputs, dict):
                self._send_json(400, {"ok": False, "error": "\"inputs\" must be an object"})
                return
        else:
            user_input = body.get("input", "")
            if not isinstance(user_input, str) or not user_input.strip():
                self._send_json(400, {"ok": False, "error": "\"input\" must be a non-empty string"})
                return
            inputs = {"text": user_input}

        try:
            result = run_enclave_request(inputs, fn=fn)
            self._send_json(200, result)
        except BridgeError as exc:
            self._send_json(502, {"ok": False, "stage": exc.stage, "error": exc.message})
        except Exception as exc:  # noqa: BLE001 - surface unexpected failures to the UI
            self._send_json(500, {"ok": False, "stage": "internal", "error": str(exc)})

    def _serve_demo_html(self) -> None:
        try:
            body = _DEMO_HTML_PATH.read_bytes()
        except OSError as exc:
            self._send_json(500, {"ok": False, "error": f"demo.html not found: {exc}"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    global BRIDGE_URL

    parser = argparse.ArgumentParser(description="VAR browser demo server.")
    parser.add_argument("--port", type=int, default=8080, metavar="PORT")
    parser.add_argument("--bridge", default=BRIDGE_URL, metavar="URL",
                         help="Base URL of the vsock bridge (default: http://127.0.0.1:8765)")
    args = parser.parse_args()

    BRIDGE_URL = args.bridge

    server = ThreadingHTTPServer(("127.0.0.1", args.port), DemoHandler)
    print(f"[demo_server] listening on http://127.0.0.1:{args.port}  (bridge: {BRIDGE_URL})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
