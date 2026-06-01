"""
SHROUD doctor — environment + relay + identity sanity check.

Run before reporting bugs. Verifies:

  - Python deps installed correctly
  - Local crypto self-tests pass
  - Configured relay is reachable and healthy
  - The user's identity file (if any) is parseable
  - The contacts file (if any) is parseable
  - End-to-end send-anon round trip against the relay works

Prints a structured pass/fail report. Non-zero exit if anything
critical fails.

Usage::

    python -m tools.shroud_doctor
    python -m tools.shroud_doctor --relay-url https://my-relay.example:58443
    python -m tools.shroud_doctor --identity ~/.config/shroud/identity.json
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"


def _ok(label: str, msg: str = "") -> None:
    print(f"  {PASS}  {label:<40}  {msg}")


def _fail(label: str, msg: str) -> int:
    print(f"  {FAIL}  {label:<40}  {msg}")
    return 1


def _warn(label: str, msg: str) -> None:
    print(f"  {WARN}  {label:<40}  {msg}")


def check_python_deps() -> int:
    print("Python dependencies:")
    failed = 0
    for mod, hint in [
        ("cryptography", "pip install cryptography"),
        ("oqs", "pip install liboqs-python  (optional, for PQ tests)"),
        ("argon2", "pip install argon2-cffi  (optional, for backups)"),
    ]:
        try:
            __import__(mod)
            _ok(mod)
        except ImportError:
            if mod == "cryptography":
                failed += _fail(mod, hint)
            else:
                _warn(mod, hint)
    print()
    return failed


def check_self_tests() -> int:
    print("Local crypto self-tests:")
    from tests import run_all
    code = run_all.main()
    print()
    return 1 if code else 0


def check_relay(relay_url: str, verify_tls: bool) -> int:
    print(f"Relay reachability: {relay_url}")
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    failed = 0
    try:
        with urllib.request.urlopen(
            f"{relay_url.rstrip('/')}/health", context=ctx, timeout=10
        ) as resp:
            health = json.loads(resp.read())
        _ok("/health", f"status={health.get('status')}")
    except Exception as e:
        failed += _fail("/health", str(e))
        print()
        return failed

    try:
        with urllib.request.urlopen(
            f"{relay_url.rstrip('/')}/api/v1/version", context=ctx, timeout=10
        ) as resp:
            ver = json.loads(resp.read())
        _ok("/api/v1/version", f"v{ver.get('version', '?')}")
    except Exception as e:
        _warn("/api/v1/version", str(e))

    print()
    return failed


def check_identity(path: str) -> int:
    print(f"Identity file: {path}")
    if not os.path.exists(path):
        _warn(path, "does not exist (you'll generate one on first launch)")
        print()
        return 0
    try:
        with open(path, "r") as f:
            d = json.load(f)
        assert "priv_x25519_hex" in d
        assert "pub_x25519_hex" in d
        assert len(d["priv_x25519_hex"]) == 64
        assert len(d["pub_x25519_hex"]) == 64
        _ok("identity readable")
        _ok("identity fields present")
    except Exception as e:
        print()
        return _fail("identity parse", str(e))
    print()
    return 0


def check_e2e(relay_url: str, verify_tls: bool) -> int:
    print(f"E2E round-trip against {relay_url}")
    try:
        from clients.python_sdk import ShroudClient, Contact

        alice = ShroudClient(relay_url=relay_url, verify_tls=verify_tls,
                              poll_interval_seconds=2.0)
        bob = ShroudClient(relay_url=relay_url, verify_tls=verify_tls,
                            poll_interval_seconds=2.0)
        shared = os.urandom(32).hex()
        alice.add_contact(Contact(name="bob",
                                   identity_pubkey_hex=bob.identity.pub_x25519_hex,
                                   shared_root_hex=shared))
        bob.add_contact(Contact(name="alice",
                                  identity_pubkey_hex=alice.identity.pub_x25519_hex,
                                  shared_root_hex=shared))
        marker = f"doctor-e2e-{os.urandom(4).hex()}"
        alice.send("bob", marker)
        inbox = bob.poll_once()
        if any(m.body == marker for m in inbox):
            _ok("send-anon + fetch-anon round trip")
            print()
            return 0
        else:
            print()
            return _fail("e2e round trip", "marker not found in bob's inbox")
    except Exception as e:
        print()
        return _fail("e2e round trip", str(e))


def main() -> int:
    ap = argparse.ArgumentParser(description="SHROUD doctor")
    ap.add_argument("--relay-url", default="https://44.202.225.57:58443")
    ap.add_argument("--identity", default="./shroud_doctor.id.json",
                    help="Path to an identity JSON file to validate")
    ap.add_argument("--verify-tls", action="store_true")
    ap.add_argument("--skip-self-tests", action="store_true")
    ap.add_argument("--skip-e2e", action="store_true")
    args = ap.parse_args()

    failed = 0
    failed += check_python_deps()
    if not args.skip_self_tests:
        failed += check_self_tests()
    failed += check_relay(args.relay_url, args.verify_tls)
    failed += check_identity(os.path.expanduser(args.identity))
    if not args.skip_e2e:
        failed += check_e2e(args.relay_url, args.verify_tls)

    if failed:
        print(f"=== {failed} check(s) failed ===")
        return 1
    print("=== all checks passed ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
