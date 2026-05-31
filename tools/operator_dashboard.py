"""
SHROUD operator dashboard.

Console UI for someone running a relay. Polls the relay's health +
stats endpoints, displays current queue depth, federation peer
roster, recent error count, and basic resource usage. Refreshes every
few seconds.

Usage:

    python -m tools.operator_dashboard --relay-url https://localhost:58443

Press Ctrl+C to exit.

This is intentionally minimal — meant for SSH sessions where you
don't have a web browser. For something richer, point Grafana at the
same endpoints.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.request
from typing import Any, Dict, List


def _http_get(relay: str, path: str, verify: bool) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(f"{relay.rstrip('/')}{path}")
    with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
        return json.loads(resp.read())


def _safe_get(relay: str, path: str, verify: bool) -> Any:
    try:
        return _http_get(relay, path, verify)
    except Exception as e:
        return {"_error": str(e)}


def _clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def _hr(width: int = 78) -> str:
    return "─" * width


def _format_size(bytes_count: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if bytes_count < 1024:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0  # type: ignore[assignment]
    return f"{bytes_count:.1f} PiB"


def main() -> int:
    ap = argparse.ArgumentParser(description="SHROUD operator dashboard")
    ap.add_argument("--relay-url", default="https://localhost:58443")
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    relay = args.relay_url.rstrip("/")
    verify = args.verify_tls

    try:
        while True:
            _clear_screen()
            print(f"SHROUD Operator Dashboard — {relay}")
            print(_hr())

            # ── Health ──
            health = _safe_get(relay, "/health", verify)
            if "_error" in health:
                print(f"  /health             ✗  {health['_error']}")
            else:
                print(f"  /health             ✓  {health.get('status', '?')}  "
                      f"v{health.get('version', '?')}  fips={health.get('fips', '?')}")

            # ── Version ──
            ver = _safe_get(relay, "/api/v1/version", verify)
            if "_error" not in ver:
                print(f"  /api/v1/version     ✓  server v{ver.get('version', '?')}  "
                      f"min-client v{ver.get('minimum_supported', '?')}")

            # ── Federation peers ──
            fed = _safe_get(relay, "/api/v1/federation/peers", verify)
            print(_hr())
            if "_error" in fed:
                print(f"Federation peers: (n/a — {fed['_error'][:50]})")
            else:
                peers: List[Dict[str, Any]] = fed.get("peers", [])
                print(f"Federation peers: {len(peers)}")
                for p in peers[:8]:
                    pk = p.get("pubkey_hex", "?")[:16]
                    print(f"    {pk}…  {p.get('endpoint', '?')}")
                if len(peers) > 8:
                    print(f"    … and {len(peers) - 8} more")

            # ── Server-identity (operator-facing) ──
            srv = _safe_get(relay, "/api/v1/server-identity", verify)
            if "_error" not in srv:
                print(_hr())
                ed = srv.get("ed25519_pub_hex", "?")
                print(f"Server identity: ed25519 {ed[:16]}…  fingerprint {srv.get('fingerprint', '?')}")

            # ── Footer ──
            print(_hr())
            print(f"refresh every {args.interval}s — Ctrl+C to exit  "
                  f"({time.strftime('%H:%M:%S')})")

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print()
        return 0


if __name__ == "__main__":
    sys.exit(main())
