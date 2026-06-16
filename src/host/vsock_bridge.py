#!/usr/bin/env python3
"""
vsock_bridge: forward TCP connections from the host into the enclave via vsock.

⚠️  DEV / OPERATOR TOOL — NOT FOR PRODUCTION DEPLOYMENT ⚠️
This bridge exposes the full VAR-gateway HTTP API (including /vault/secret,
/exec, /hibernate) to any local process on the parent EC2 instance without
additional authentication.  It must not run unattended in production.

Set VAR_BRIDGE_DEV=1 to acknowledge this and start the bridge.

Production path: implement mTLS or a bearer token derived from attestation
inside the gateway (route() → verify token before dispatching to sensitive
handlers), then replace this bridge with one that validates the credential.

Usage:
    VAR_BRIDGE_DEV=1 python3 vsock_bridge.py [--tcp-port 8765] [--vsock-cid 16] [--vsock-port 8765]

SSH tunnel from Mac:
    ssh -i ~/.ssh/var-nitro.pem -L 8765:127.0.0.1:8765 ec2-user@3.238.108.15 -N
    curl http://127.0.0.1:8765/health
"""
import argparse
import os
import socket
import sys
import threading


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            src.shutdown(socket.SHUT_RD)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _handle(client: socket.socket, vsock_cid: int, vsock_port: int) -> None:
    try:
        enclave = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        enclave.connect((vsock_cid, vsock_port))
    except OSError as exc:
        print(f"[bridge] vsock connect CID={vsock_cid} port={vsock_port} failed: {exc}")
        client.close()
        return

    t = threading.Thread(target=_pipe, args=(enclave, client), daemon=True)
    t.start()
    _pipe(client, enclave)
    enclave.close()
    client.close()


def main() -> None:
    if not os.environ.get("VAR_BRIDGE_DEV"):
        print(
            "ERROR: vsock_bridge is a dev/operator tool that exposes the enclave\n"
            "HTTP API to all local processes without authentication.\n"
            "Set VAR_BRIDGE_DEV=1 to acknowledge and proceed.",
            file=sys.stderr,
        )
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Bridge TCP→vsock for VAR enclave")
    parser.add_argument("--tcp-port", type=int, default=8765, metavar="PORT")
    parser.add_argument("--vsock-cid", type=int, default=16, metavar="CID")
    parser.add_argument("--vsock-port", type=int, default=8765, metavar="PORT")
    args = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", args.tcp_port))
    server.listen(16)
    print(
        f"[bridge] TCP 127.0.0.1:{args.tcp_port} "
        f"→ vsock CID={args.vsock_cid} port={args.vsock_port}"
    )

    while True:
        client, _ = server.accept()
        threading.Thread(
            target=_handle,
            args=(client, args.vsock_cid, args.vsock_port),
            daemon=True,
        ).start()


if __name__ == "__main__":
    main()
