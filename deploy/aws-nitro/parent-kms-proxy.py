"""
Parent-side KMS proxy.

The enclave asks us to run KMS:Decrypt for it. We forward to KMS using the
parent EC2 instance role's credentials. The enclave embeds an attestation
document in the request — KMS validates it against the key policy's
`kms:RecipientAttestation:ImageSha384` condition, and only releases
plaintext to that specific enclave image.

The plaintext is wrapped in a CMS envelope addressed to an X25519 pubkey
the enclave provided in its attestation document. We forward this
unmodified — we cannot read it. If a malicious parent substitutes the
ciphertext, the CMS envelope decrypts to garbage and the enclave aborts.
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
LISTEN_PORT = 5007
REGION = os.environ.get("SHROUD_REGION", "us-east-1")

kms = boto3.client("kms", region_name=REGION)


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
        # Wire format: b"KMS_DECRYPT\n" + attestation_doc + b"\n" + ciphertext
        if not request.startswith(b"KMS_DECRYPT\n"):
            print(f"[kms-proxy] rejected unknown request type", file=sys.stderr)
            sock.close()
            return
        body = request[len(b"KMS_DECRYPT\n"):]
        nl = body.index(b"\n")
        attestation = body[:nl]
        ciphertext = body[nl + 1:]

        response = kms.decrypt(
            CiphertextBlob=ciphertext,
            Recipient={
                "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
                "AttestationDocument": attestation,
            },
        )

        # CiphertextForRecipient is the CMS-wrapped envelope encrypted to
        # the X25519 pubkey from the attestation document. Only the enclave
        # can decrypt it.
        wrapped = response["CiphertextForRecipient"]
        _send_framed(sock, wrapped)
        print(f"[kms-proxy] forwarded {len(wrapped)}B wrapped plaintext to enclave")
    except Exception as e:
        print(f"[kms-proxy] error: {e}", file=sys.stderr)
    finally:
        sock.close()


def main() -> None:
    s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_CID, LISTEN_PORT))
    s.listen(8)
    print(f"[kms-proxy] listening vsock://{LISTEN_CID}:{LISTEN_PORT}")
    while True:
        conn, _addr = s.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
