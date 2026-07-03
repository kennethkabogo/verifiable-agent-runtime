#!/bin/bash
# Called by systemd ExecStop before the enclave is killed.
# Sends POST /hibernate over vsock so the session's sealed state is preserved,
# then terminates the enclave.  On the next start, var-kms-proxy picks up the
# saved blob via --resume-state-file and the enclave resumes with the same
# session identity and PCR0.
#
# Exits 0 if hibernate succeeded and sealed state was saved.
# Exits 1 if the vsock call failed (enclave already dead or unreachable) —
# systemd ignores ExecStop exit codes, but it's logged to journald.

ENCLAVE_CID="${ENCLAVE_CID:-16}"
ENCLAVE_PORT="${ENCLAVE_PORT:-8765}"
RESUME_STATE_FILE="${RESUME_STATE_FILE:-/var/lib/var/resume.bin}"
ID_FILE="/run/var/enclave.id"

mkdir -p "$(dirname "${RESUME_STATE_FILE}")"

python3 - <<PYEOF
import socket, json, os, sys

cid  = int(os.environ.get("ENCLAVE_CID", 16))
port = int(os.environ.get("ENCLAVE_PORT", 8765))
out  = os.environ.get("RESUME_STATE_FILE", "/var/lib/var/resume.bin")

try:
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(15)
    s.connect((cid, port))
    s.sendall(b"POST /hibernate HTTP/1.0\r\nContent-Length: 0\r\n\r\n")
    resp = b""
    while True:
        try:
            chunk = s.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        resp += chunk
    s.close()
except Exception as exc:
    print(f"[hibernate] vsock {cid}:{port} unreachable: {exc}", file=sys.stderr)
    sys.exit(1)

if not (resp.startswith(b"HTTP/1.") and b" 200 " in resp[:16]):
    print(f"[hibernate] bad response: {resp[:80]}", file=sys.stderr)
    sys.exit(1)

sep = resp.find(b"\r\n\r\n")
try:
    data = json.loads(resp[sep + 4:])
    sealed = bytes.fromhex(data["sealed_state"])
except Exception as exc:
    print(f"[hibernate] parse error: {exc}", file=sys.stderr)
    sys.exit(1)

os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "wb") as f:
    f.write(sealed)
print(f"[hibernate] sealed state saved to {out} ({len(sealed)} bytes)")
PYEOF
hibernate_ok=$?

# Terminate the enclave regardless of hibernate outcome.
if [ -f "${ID_FILE}" ]; then
    nitro-cli terminate-enclave --enclave-id "$(cat "${ID_FILE}")" 2>/dev/null || true
    rm -f "${ID_FILE}"
else
    nitro-cli terminate-enclave --all 2>/dev/null || true
fi

exit ${hibernate_ok}
