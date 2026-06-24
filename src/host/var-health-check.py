#!/usr/bin/env python3
"""
VAR enclave health check — polls GET /health and publishes VAR/EnclaveHealth
to CloudWatch.  Intended to run as a systemd timer unit every 60 seconds.

Production (Nitro):  --vsock connects directly to the enclave via AF_VSOCK.
Dev/simulation:      --tcp-host connects via the vsock bridge (default 127.0.0.1).

Usage:
    python3 var-health-check.py --vsock [--cid CID] [--port PORT]
    python3 var-health-check.py [--tcp-host HOST] [--port PORT] --no-cloudwatch
"""
import argparse
import os
import socket
import sys

DEFAULT_CID  = int(os.environ.get("ENCLAVE_CID", "16"))
DEFAULT_PORT = int(os.environ.get("ENCLAVE_PORT", "8765"))
CW_NAMESPACE = os.environ.get("VAR_CW_NAMESPACE", "VAR")
CW_METRIC    = os.environ.get("VAR_CW_METRIC", "EnclaveHealth")
AWS_REGION   = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

_HEALTH_REQUEST = b"GET /health HTTP/1.0\r\nHost: enclave\r\n\r\n"


def _check_vsock(cid: int, port: int) -> bool:
    try:
        with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((cid, port))
            s.sendall(_HEALTH_REQUEST)
            resp = s.recv(256)
        return b" 200 " in resp[:20] or resp[:12] == b"HTTP/1.0 200" or resp[:12] == b"HTTP/1.1 200"
    except Exception:
        return False


def _check_tcp(host: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((host, port))
            s.sendall(_HEALTH_REQUEST)
            resp = s.recv(256)
        return b" 200 " in resp[:20] or resp[:12] == b"HTTP/1.0 200" or resp[:12] == b"HTTP/1.1 200"
    except Exception:
        return False


def _put_metric(value: int, region: str) -> None:
    import boto3
    cw = boto3.client("cloudwatch", region_name=region)
    cw.put_metric_data(
        Namespace=CW_NAMESPACE,
        MetricData=[{
            "MetricName": CW_METRIC,
            "Value": float(value),
            "Unit": "None",
        }],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="VAR enclave health check")
    parser.add_argument("--vsock", action="store_true",
                        help="connect via AF_VSOCK (production Nitro host)")
    parser.add_argument("--cid", type=int, default=DEFAULT_CID,
                        help=f"enclave vsock CID (default: {DEFAULT_CID})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"gateway port (default: {DEFAULT_PORT})")
    parser.add_argument("--tcp-host", default="127.0.0.1",
                        help="TCP host for bridge/simulation mode (default: 127.0.0.1)")
    parser.add_argument("--no-cloudwatch", action="store_true",
                        help="skip CloudWatch publish (dev/test)")
    parser.add_argument("--region", default=AWS_REGION,
                        help=f"AWS region (default: {AWS_REGION})")
    args = parser.parse_args()

    if args.vsock:
        if not hasattr(socket, "AF_VSOCK"):
            print("ERROR: AF_VSOCK not available on this platform", file=sys.stderr)
            sys.exit(2)
        healthy = _check_vsock(args.cid, args.port)
    else:
        healthy = _check_tcp(args.tcp_host, args.port)

    value = 1 if healthy else 0
    print(f"[var-health] {'HEALTHY' if healthy else 'UNHEALTHY'}", flush=True)

    if not args.no_cloudwatch:
        try:
            _put_metric(value, args.region)
        except Exception as exc:
            print(f"[var-health] CloudWatch publish failed: {exc}", file=sys.stderr)
            sys.exit(1)

    if not healthy:
        sys.exit(1)


if __name__ == "__main__":
    main()
