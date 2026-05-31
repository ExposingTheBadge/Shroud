"""
Parent-side config server.

The enclave has no AWS credentials and no IP network. It connects to us
over vsock CID 3 port 5006 and asks for the encrypted config bundle. We
fetch from S3 using the parent's IAM role and ship it down. The bundle is
encrypted to a KMS key — the enclave can only decrypt it after presenting
an attestation document, which the parent cannot forge.

We are explicitly UNTRUSTED in this design: the parent could substitute
any blob, but the substitute wouldn't decrypt under KMS, so the enclave
would refuse to start.
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import threading

import boto3  # type: ignore

AF_VSOCK = 40
LISTEN_CID = 3
LISTEN_PORT = 5006
BUCKET = os.environ["SHROUD_S3_BUCKET"]
REGION = os.environ.get("SHROUD_REGION", "us-east-1")
CONFIG_KEY = os.environ.get("SHROUD_CONFIG_KEY", "shroud-config.encrypted")

s3 = boto3.client("s3", region_name=REGION)


def _send_framed(sock: socket.socket, body: bytes) -> None:
    sock.sendall(struct.pack(">I", len(body)) + body)


def _recv_framed(sock: socket.socket) -> bytes:
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise IOError("peer closed during length header")
        header += chunk
    (length,) = struct.unpack(">I", header)
    body = b""
    while len(body) < length:
        chunk = sock.recv(min(65536, length - len(body)))
        if not chunk:
            raise IOError("peer closed during body")
        body += chunk
    return body


def handle(sock: socket.socket) -> None:
    try:
        request = _recv_framed(sock)
        if request != b"GET_CONFIG":
            print(f"[config-server] rejected unknown request: {request!r}", file=sys.stderr)
            sock.close()
            return
        obj = s3.get_object(Bucket=BUCKET, Key=CONFIG_KEY)
        encrypted_bundle = obj["Body"].read()
        _send_framed(sock, encrypted_bundle)
        print(f"[config-server] served {len(encrypted_bundle)}B encrypted config")
    finally:
        sock.close()


def main() -> None:
    s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_CID, LISTEN_PORT))
    s.listen(8)
    print(f"[config-server] listening vsock://{LISTEN_CID}:{LISTEN_PORT}")
    while True:
        conn, _addr = s.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
