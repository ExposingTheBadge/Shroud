"""Admin dashboard <-> API contract test.

The admin panel reads fields straight off each endpoint's JSON. When a
field is renamed or dropped server-side, nothing raises: JavaScript
yields `undefined`, the tile renders blank or as "undefined", and the
dashboard keeps looking healthy. That is the same silent-degradation
shape as the rest of this codebase, and it is how a redesign validated
only against a hand-written mock can ship broken.

This boots the real app against a throwaway database, authenticates as
admin, calls each admin endpoint for real, and asserts every field the
corresponding render function reads is actually present in the response.

Run: python -m tests.admin_api_contract
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN_JS = os.path.join(REPO, "server", "admin", "admin.js")

# render function in admin.js  ->  endpoint that feeds it
BINDINGS = [
    ("renderOverview",   "/api/v1/admin/stats/overview"),
    ("renderUsers",      "/api/v1/admin/stats/users"),
    ("renderDevices",    "/api/v1/admin/stats/devices"),
    ("renderCrypto",     "/api/v1/admin/stats/crypto"),
    ("renderFiles",      "/api/v1/admin/stats/files"),
    ("renderActivity",   "/api/v1/admin/stats/activity"),
    ("renderTopBar",     "/api/v1/admin/stats/overview"),
    ("renderToggles",    "/api/v1/admin/stats/overview"),
    ("renderFederation", "/api/v1/admin/federation"),
]

# Reads that are guarded or come from nested/derived objects rather than
# the top-level payload. Listing them explicitly keeps the test honest
# instead of loosening the matcher until everything passes.
EXEMPT = {
    "renderFederation": {"aws"},          # optional; absent without boto3
}


def _fields_read(js: str, fn: str) -> set[str]:
    m = re.search(rf"function {fn}\(\w+\) \{{(.*?)\n\}}", js, re.S)
    if not m:
        raise AssertionError(f"{fn} not found in admin.js")
    body, param = m.group(1), re.search(rf"function {fn}\((\w+)\)", js).group(1)
    return set(re.findall(rf"\b{param}\.([A-Za-z_][A-Za-z0-9_]*)", body))


def main() -> int:
    data_dir = tempfile.mkdtemp(prefix="shroud-contract-")
    os.environ["SHROUD_DATA_DIR"] = data_dir
    os.environ["SHROUD_DB_PATH"] = os.path.join(data_dir, "contract.db")
    sys.path.insert(0, REPO)
    sys.path.insert(0, os.path.join(REPO, "server"))

    spec = importlib.util.spec_from_file_location(
        "shroud_contract_srv", os.path.join(REPO, "server", "server.py"))
    srv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(srv)

    from fastapi.testclient import TestClient
    c = TestClient(srv.app)

    pw = "contract-test-password"
    srv._admin_setup_token()                       # mint
    with open(os.path.join(data_dir, "admin_setup_token"), encoding="utf-8") as f:
        token = f.read().strip()
    r = c.post("/api/v1/admin/setup", json={"password": pw},
               headers={"X-Setup-Token": token})
    assert r.status_code == 200, f"setup failed: {r.status_code} {r.text[:200]}"
    fp = r.json()["fingerprint_id"]
    r = c.post("/api/v1/admin/fingerprint-login",
               json={"fingerprint_id": fp, "password": pw, "hwid": "contract"})
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:200]}"

    with open(ADMIN_JS, encoding="utf-8") as f:
        js = f.read()

    print("Admin dashboard <-> API contract\n")
    failed = 0
    cache: dict[str, dict] = {}
    for fn, endpoint in BINDINGS:
        if endpoint not in cache:
            resp = c.get(endpoint)
            if resp.status_code != 200:
                print(f"  FAIL  {fn:18s} {endpoint} -> HTTP {resp.status_code}")
                failed += 1
                continue
            cache[endpoint] = resp.json()
        payload = cache[endpoint]
        want = _fields_read(js, fn) - EXEMPT.get(fn, set())
        missing = sorted(f for f in want if f not in payload)
        if missing:
            print(f"  FAIL  {fn:18s} missing from {endpoint}: {', '.join(missing)}")
            failed += 1
        else:
            print(f"  PASS  {fn:18s} {len(want):2d} field(s) present")

    print()
    if failed:
        print(f"{failed} renderer(s) read fields the API does not return.")
        return 1
    print("Every field the admin UI reads is returned by the API.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
