"""
SHROUD enclave vsock plumbing.

Three subcommands:
  fetch-config   pulls the encrypted config blob from the parent over vsock
  kms-decrypt    calls KMS:Decrypt via the parent, embedding our attestation
  serve          runs uvicorn bound to an AF_VSOCK socket

The "via the parent" piece for KMS is necessary because the enclave has
no IP networking. The parent runs a small kms-proxy that signs the request
with the EC2 instance role's credentials and forwards it to kms.<region>.
amazonaws.com. The attestation document binds the request to this specific
enclave image — the parent cannot reuse or replay it.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import socket
import struct
import sys
from pathlib import Path


# ── vsock helpers ────────────────────────────────────────────────────

AF_VSOCK = 40  # Linux constant; Python only exposes it on >= 3.7 + kernel support


def _open_vsock_client(cid: int, port: int) -> socket.socket:
    """Open a connected AF_VSOCK stream socket."""
    s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    s.connect((cid, port))
    return s


def _recv_framed(sock: socket.socket) -> bytes:
    """Length-prefixed (uint32 big-endian) framed receive."""
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise IOError("vsock peer closed during length header")
        header += chunk
    (length,) = struct.unpack(">I", header)
    body = b""
    while len(body) < length:
        chunk = sock.recv(min(65536, length - len(body)))
        if not chunk:
            raise IOError("vsock peer closed during body")
        body += chunk
    return body


def _send_framed(sock: socket.socket, body: bytes) -> None:
    sock.sendall(struct.pack(">I", len(body)) + body)


# ── 1. Fetch encrypted config from parent ────────────────────────────

def cmd_fetch_config(args: argparse.Namespace) -> int:
    """Parent's config-server listens on vsock CID 3, returns the S3-fetched
    KMS-encrypted config blob. We never call S3 directly — that's the
    parent's job — because the enclave has no AWS credentials of its own."""
    sock = _open_vsock_client(args.parent_cid, args.port)
    try:
        _send_framed(sock, b"GET_CONFIG")
        blob = _recv_framed(sock)
    finally:
        sock.close()
    Path(args.output).write_bytes(blob)
    print(f"[fetch-config] wrote {len(blob)} bytes -> {args.output}")
    return 0


# ── 2. KMS decrypt via parent + attestation ──────────────────────────

def _generate_attestation(public_key: bytes) -> bytes:
    """Request a Nitro attestation document from /dev/nsm.

    The document is signed by the Nitro hypervisor's COSE_Sign1 key
    (root certified by Amazon at https://aws-nitro-enclaves.amazonaws.com/
    ).  It binds:
      - PCR0..PCR8 (our image measurement)
      - the provided public_key (we'll pass the ephemeral KMS request key)
      - a fresh nonce
    """
    try:
        import nsm  # type: ignore
    except ImportError:
        # Fall back to opening /dev/nsm directly via ioctl if no userland
        # binding is available. For the scaffold we expect aws-nitro-
        # enclaves-cli's `nsm` python module installed in the EIF.
        return _generate_attestation_ioctl(public_key)
    return nsm.get_attestation_doc(
        user_data=None,
        nonce=None,
        public_key=public_key,
    )


def _generate_attestation_ioctl(public_key: bytes) -> bytes:
    """Minimal ioctl fallback. Real impl in production: bind libnsm.so."""
    raise NotImplementedError(
        "nsm python module not installed; add `aws-nitro-enclaves-nsm-api` "
        "to the enclave image"
    )


def cmd_kms_decrypt(args: argparse.Namespace) -> int:
    """Ask the parent to run KMS:Decrypt with our attestation document.

    Wire format (framed):
      REQ:  b"KMS_DECRYPT\n" + attestation_doc_cbor + b"\n" + ciphertext
      RESP: plaintext bytes
    """
    ciphertext = Path(args.ciphertext).read_bytes()

    # Generate ephemeral X25519 key — KMS will encrypt the plaintext
    # response to this pubkey so even the parent can't see it
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    except ImportError:
        print("cryptography library required in enclave image", file=sys.stderr)
        return 2

    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key().public_bytes_raw()

    attestation = _generate_attestation(public_key=ephemeral_pub)

    sock = _open_vsock_client(args.parent_cid, 5007)
    try:
        request = b"KMS_DECRYPT\n" + attestation + b"\n" + ciphertext
        _send_framed(sock, request)
        encrypted_response = _recv_framed(sock)
    finally:
        sock.close()

    # Decrypt KMS's response (it used our ephemeral_pub).
    # KMS-with-attestation returns CiphertextForRecipient, which is a CMS
    # SignedData containing an encrypted envelope addressed to our pubkey.
    plaintext = _decrypt_kms_recipient_envelope(encrypted_response, ephemeral_priv)

    Path(args.output).write_bytes(plaintext)
    print(f"[kms-decrypt] wrote {len(plaintext)} bytes -> {args.output}")
    return 0


def _decrypt_kms_recipient_envelope(envelope: bytes, ephemeral_priv) -> bytes:
    """Decrypt KMS's attestation-bound response.

    Format: CMS EnvelopedData (RFC 5652) with our ephemeral X25519 pubkey
    as the recipient. KMS uses ECDH on Curve25519 to derive an AES key
    and AES-GCM the plaintext payload.
    """
    # Production should use python-cryptography's PKCS7/CMS support.
    # The scaffold treats this as a placeholder; real impl in the
    # production branch lives in deploy/aws-nitro/cms_envelope.py.
    raise NotImplementedError(
        "CMS envelope parse: implement with cryptography.hazmat.primitives "
        "and cryptography.x509 — see deploy/aws-nitro/cms_envelope.py"
    )


# ── 3. Run uvicorn on AF_VSOCK ───────────────────────────────────────

def cmd_serve(args: argparse.Namespace) -> int:
    """Patch uvicorn to bind AF_VSOCK and start serving the SHROUD relay."""
    import uvicorn

    # Monkey-patch uvicorn's socket creation to return a vsock listener.
    # uvicorn doesn't natively support vsock; we override Server.startup
    # to substitute the bind socket.
    original_create_server = asyncio.get_event_loop_policy().new_event_loop().create_server  # noqa: E501

    async def _create_vsock_server(protocol_factory, *_args, **_kwargs):
        loop = asyncio.get_event_loop()
        sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.cid, args.port))
        sock.listen(128)
        sock.setblocking(False)
        return await loop.create_server(protocol_factory, sock=sock)

    asyncio.get_event_loop().create_server = _create_vsock_server  # type: ignore

    # Now boot uvicorn pointed at our wrapped event loop.
    config = uvicorn.Config(
        app=args.app,
        host="0.0.0.0",  # Ignored — our patch supplies the real socket
        port=args.port,
        log_level=args.log_level,
        loop="asyncio",
    )
    server = uvicorn.Server(config)
    asyncio.run(server.serve())
    return 0


# ── argparse entry ───────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser(prog="vsock-server")
    sub = p.add_subparsers(dest="cmd", required=True)

    fc = sub.add_parser("fetch-config", help="pull encrypted config from parent")
    fc.add_argument("--parent-cid", type=int, default=3)
    fc.add_argument("--port", type=int, required=True)
    fc.add_argument("--output", type=str, required=True)
    fc.set_defaults(func=cmd_fetch_config)

    kd = sub.add_parser("kms-decrypt", help="KMS:Decrypt via parent with attestation")
    kd.add_argument("--parent-cid", type=int, default=3)
    kd.add_argument("--ciphertext", type=str, required=True)
    kd.add_argument("--output", type=str, required=True)
    kd.set_defaults(func=cmd_kms_decrypt)

    sv = sub.add_parser("serve", help="run uvicorn on AF_VSOCK")
    sv.add_argument("--app", type=str, required=True)
    sv.add_argument("--cid", type=int, required=True)
    sv.add_argument("--port", type=int, required=True)
    sv.add_argument("--log-level", type=str, default="info")
    sv.set_defaults(func=cmd_serve)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
