"""
SHROUD master test runner.

Discovers every module under ``crypto/`` (and related folders) that
exposes a ``_self_test()`` callable, runs them in series, and reports
per-module pass/fail with timing.

Use for:
  - quick "is everything still working" check after a refactor
  - CI hook
  - a one-shot sanity check before cutting a release

Run:
  python -m tests.run_all
"""
from __future__ import annotations

import importlib
import os
import sys
import time
import traceback
from typing import List, Tuple


HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


# Modules to run. Order matters: foundation primitives first, then
# everything that depends on them.
MODULES = [
    "crypto.strip_metadata",
    "crypto.anon_routing",
    "crypto.pq_double_ratchet",
    "crypto.link_preview",
    "crypto.stickers",
    "crypto.disappearing",
    "crypto.anon_push",
    "crypto.federation",
    "crypto.calls",
    "crypto.group_calls",
    "crypto.voice_notes",
    "crypto.reactions",
    "crypto.file_transfer",
    "crypto.backup",
    "crypto.local_search",
    "crypto.presence",
    "crypto.safety_numbers",
    "crypto.forward_quote",
    "crypto.device_link",
    "crypto.polling",
    "crypto.archive",
]


def _run_one(name: str) -> Tuple[bool, float, str]:
    """Import the module + invoke _self_test. Returns
    (success, elapsed_seconds, error_message_or_empty)."""
    t0 = time.perf_counter()
    try:
        mod = importlib.import_module(name)
    except Exception:
        return False, time.perf_counter() - t0, f"import failed:\n{traceback.format_exc()}"
    fn = getattr(mod, "_self_test", None)
    if fn is None:
        return False, time.perf_counter() - t0, "no _self_test() defined"
    try:
        # Redirect stdout to absorb the per-module success print —
        # we'll do our own reporting.
        import io
        buf = io.StringIO()
        real_stdout = sys.stdout
        sys.stdout = buf
        try:
            fn()
        finally:
            sys.stdout = real_stdout
        return True, time.perf_counter() - t0, ""
    except Exception:
        return False, time.perf_counter() - t0, traceback.format_exc()


def main() -> int:
    print(f"Running {len(MODULES)} module self-tests...\n")
    results: List[Tuple[str, bool, float, str]] = []
    total_t0 = time.perf_counter()
    for name in MODULES:
        ok, elapsed, err = _run_one(name)
        results.append((name, ok, elapsed, err))
        marker = "PASS" if ok else "FAIL"
        short_name = name.split(".", 1)[1] if "." in name else name
        print(f"  {marker}  {short_name:<28}  ({elapsed * 1000:>5.0f} ms)")
        if not ok and err:
            indent = "         "
            for line in err.rstrip().splitlines():
                print(f"{indent}{line}")
    total_elapsed = time.perf_counter() - total_t0

    failed = [name for name, ok, _, _ in results if not ok]
    print()
    print(f"{len(MODULES) - len(failed)}/{len(MODULES)} passed in {total_elapsed:.2f}s")
    if failed:
        print(f"FAILED: {', '.join(failed)}")
        return 1
    print("All modules green.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
