"""
Repository consistency checks that need no network and no toolchains.

  * The browser extension ships its own copy of web/anon_routing.js
    (an extension cannot import files outside its folder). The two
    must stay identical.
  * Every icon the extension manifest names exists.
  * Nothing in the tree still points at the retired AWS relays.

Run::

    python -m tests.repo_consistency
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EXT = os.path.join(REPO, "clients", "browser_extension")
RETIRED_HOSTS = ("100.30.51.8", "18.222.72.227", "52.38.93.230", "52.50.29.221",
                 "3.142.185.104", "54.214.75.14", "54.171.165.223")


def check_extension_library_in_sync() -> None:
    a = open(os.path.join(REPO, "clients", "web", "anon_routing.js"), "rb").read()
    b = open(os.path.join(EXT, "lib", "anon_routing.js"), "rb").read()
    assert a == b, ("clients/browser_extension/lib/anon_routing.js differs from "
                    "clients/web/anon_routing.js; copy the web file over it")


def check_extension_icons_exist() -> None:
    m = json.load(open(os.path.join(EXT, "manifest.json")))
    paths = set(m.get("icons", {}).values()) | set(m.get("action", {}).get("default_icon", {}).values())
    missing = [p for p in paths if not os.path.isfile(os.path.join(EXT, p))]
    assert not missing, f"manifest names missing icons: {missing}"


def check_no_retired_relays() -> None:
    files = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True,
                           check=True).stdout.split()
    hits = []
    for f in files:
        if f.startswith(("releases/", "CHANGELOG", "SESSION_NOTES")) or f.endswith(
                (".png", ".ico", ".zip", ".apk", ".exe", ".jar", ".so", ".dll")):
            continue
        p = os.path.join(REPO, f)
        try:
            text = open(p, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        for h in RETIRED_HOSTS:
            if re.search(r"(?<![\d.])" + re.escape(h) + r"(?![\d])", text):
                hits.append(f"{f}: {h}")
    assert not hits, "retired AWS relay addresses still referenced:\n  " + "\n  ".join(hits)


CHECKS = [check_extension_library_in_sync, check_extension_icons_exist, check_no_retired_relays]


def main() -> int:
    failed = 0
    for fn in CHECKS:
        try:
            fn()
            print(f"  PASS  {fn.__name__[6:]}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {fn.__name__[6:]}: {e}")
    print(f"\n{len(CHECKS) - failed}/{len(CHECKS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
