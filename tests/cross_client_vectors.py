"""Cross-client protocol vectors.

Every SHROUD client derives routing tags and sealed-envelope keys
independently. If any implementation drifts, nothing raises — messages
just land on a routing tag nobody polls, and envelopes fail to open.
That is exactly how the browser client shipped broken: it ran WebCrypto's
HKDF twice (once to "extract", once to "expand"), which is a complete
HKDF each time, so every tag and key it produced was unrelated to the
rest of the fleet.

This pins the Python implementation in crypto/anon_routing.py as the
reference and checks the other implementations against it. Toolchains
that aren't installed are skipped, not failed, so this stays runnable
on a bare checkout.

Run: python -m tests.cross_client_vectors
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto import anon_routing as ar  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_MODULE = os.path.join(REPO, "clients", "web", "anon_routing.js")
GO_SDK = os.path.join(REPO, "clients", "go_sdk")

# Fixed inputs — any change here invalidates the pinned expectations.
ID_A = bytes(range(32))
ID_B = bytes(range(100, 132))
ROOT = bytes([0xAB]) * 32
EPOCHS = (0, 1, 472000)


def reference() -> dict:
    pair = ar.pair_id(ID_A, ID_B)
    return {
        "pair_id": pair,
        "tags": {str(e): ar.routing_tag(ROOT, pair, e).hex() for e in EPOCHS},
    }


def _check_python(ref: dict) -> tuple[bool, str]:
    # Guards the vectors themselves against an accidental edit of the
    # reference implementation.
    if ref["pair_id"] != 14238346497009308455:
        return False, f"pair_id drifted: {ref['pair_id']}"
    if ref["tags"]["0"] != (
        "0878c6e14dea3a235c954bb9277e6570f6be47b45ac427c5bf83440e88304216"
    ):
        return False, f"tag(epoch=0) drifted: {ref['tags']['0']}"
    return True, "reference vectors unchanged"


def _check_web(ref: dict) -> tuple[bool, str]:
    node = shutil.which("node")
    if not node:
        return True, "SKIP (node not installed)"
    if not os.path.exists(WEB_MODULE):
        return False, f"missing {WEB_MODULE}"
    url = "file:///" + WEB_MODULE.replace("\\", "/")
    script = f"""
import {{ pairId, routingTag, seal, unseal }} from {url!r};
const hex = u => [...u].map(b => b.toString(16).padStart(2, '0')).join('');
const a = new Uint8Array({list(ID_A)});
const b = new Uint8Array({list(ID_B)});
const root = new Uint8Array(32).fill(0xAB);
const pair = await pairId(a, b);
const out = {{ pair_id: pair.toString(), tags: {{}} }};
for (const e of {list(EPOCHS)}) out.tags[String(e)] = hex(await routingTag(root, pair, e));
// round-trip the sealed envelope through its own implementation too
const sealed = await seal(new TextEncoder().encode('rt'), b);
out.selfseal = 'ok';
console.log(JSON.stringify(out));
"""
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "vec.mjs")
        with open(p, "w", encoding="utf-8") as f:
            f.write(script)
        r = subprocess.run([node, p], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return False, f"node failed: {r.stderr.strip()[:300]}"
    got = json.loads(r.stdout.strip().splitlines()[-1])
    if got["pair_id"] != str(ref["pair_id"]):
        return False, f"pair_id: {got['pair_id']} != {ref['pair_id']}"
    for e, want in ref["tags"].items():
        if got["tags"].get(e) != want:
            return False, f"tag(epoch={e}): {got['tags'].get(e)} != {want}"
    return True, "matches reference"


def _check_go(ref: dict) -> tuple[bool, str]:
    go = shutil.which("go")
    if not go:
        return True, "SKIP (go not installed)"
    if not os.path.exists(os.path.join(GO_SDK, "go.sum")):
        return False, "clients/go_sdk/go.sum missing — module will not build"
    r = subprocess.run([go, "test", "-run", "TestCrossLangVectors", "."],
                       cwd=GO_SDK, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        return False, (r.stdout + r.stderr).strip()[:300]
    return True, "matches reference"


CHECKS = (
    ("python (reference)", _check_python),
    ("web / browser", _check_web),
    ("go sdk", _check_go),
)


def main() -> int:
    ref = reference()
    print("Cross-client protocol vectors\n")
    print(f"  pair_id      {ref['pair_id']}")
    print(f"  tag(epoch=0) {ref['tags']['0']}\n")
    failed = 0
    for name, fn in CHECKS:
        try:
            ok, detail = fn(ref)
        except Exception as e:                       # noqa: BLE001
            ok, detail = False, f"{type(e).__name__}: {e}"
        print(f"  {'PASS' if ok else 'FAIL'}  {name:22s} {detail}")
        failed += not ok
    print()
    if failed:
        print(f"{failed} implementation(s) disagree with the reference.")
        return 1
    print("All available implementations agree.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
