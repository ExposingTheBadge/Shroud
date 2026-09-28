"""
Relay regression tests: one check per server bug that has been fixed.

Each check drives the real FastAPI app in-process against a throwaway
database, so it exercises the handlers exactly as a client would reach
them. The checks are ordered to match the bugs they pin; each docstring
says what used to happen.

Run::

    python -m tests.server_regressions
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))


def _load_server():
    data_dir = tempfile.mkdtemp(prefix="shroud-regress-")
    os.environ["SHROUD_DATA_DIR"] = data_dir
    os.environ["SHROUD_DB_PATH"] = os.path.join(data_dir, "regress.db")
    os.environ.pop("SHROUD_FEDERATION", None)
    sys.path.insert(0, REPO)
    sys.path.insert(0, os.path.join(REPO, "server"))
    spec = importlib.util.spec_from_file_location(
        "shroud_regress_srv", os.path.join(REPO, "server", "server.py"))
    srv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(srv)
    return srv, data_dir


class Ctx:
    def __init__(self):
        from fastapi.testclient import TestClient
        self.srv, self.data_dir = _load_server()
        self.c = TestClient(self.srv.app)
        self._n = 0

    def user(self, prefix: str = "user") -> tuple[str, str]:
        self._n += 1
        name, pw = f"{prefix}{self._n}", "correct-horse-battery"
        r = self.c.post("/api/v1/register", json={"username": name, "password": pw})
        assert r.status_code == 200, r.text
        return name, pw

    def device(self, username: str, password: str) -> str:
        from crypto.fips_crypto import generate_keypair, serialize_public_key
        _priv, pub = generate_keypair()
        r = self.c.post("/api/v1/devices", json={
            "username": username, "password": password, "device_name": "t",
            "platform": "android", "public_key": serialize_public_key(pub).hex()})
        assert r.status_code == 200, r.text
        return r.json()["device_id"]

    def admin_client(self):
        """A second client holding an admin session (cookies are per client).
        Admin setup is one-shot, so the session is made once and reused."""
        if getattr(self, "_admin", None) is not None:
            return self._admin
        from fastapi.testclient import TestClient
        a = TestClient(self.srv.app)
        pw = "regression-admin-password"
        self.srv._admin_setup_token()
        with open(os.path.join(self.data_dir, "admin_setup_token")) as f:
            token = f.read().strip()
        r = a.post("/api/v1/admin/setup", json={"password": pw},
                   headers={"X-Setup-Token": token})
        assert r.status_code == 200, r.text
        r = a.post("/api/v1/admin/fingerprint-login",
                   json={"fingerprint_id": r.json()["fingerprint_id"],
                         "password": pw, "hwid": "regress"})
        assert r.status_code == 200, r.text
        self._admin = a
        return a


# ── checks ───────────────────────────────────────────────────────────

def check_federation_closed_when_disabled(x: Ctx):
    """state-event applied anything anyone sent it, with federation on or
    off: admin_fingerprint.added with no password was a free admin login."""
    r = x.c.post("/api/v1/federation/state-event", json={
        "type": "shroud.fed.state-event", "event_id": "e", "ts": 1,
        "event_kind": "admin_fingerprint.added",
        "payload": {"fingerprint_id": "evil"}})
    assert r.status_code == 404, r.status_code
    r = x.c.post("/api/v1/admin/fingerprint-login",
                 json={"fingerprint_id": "evil", "password": ""})
    assert r.status_code != 200, "injected admin fingerprint logged in"
    r = x.c.get("/api/v1/federation/state-events/since?since_ts=0")
    assert r.status_code == 404, "state-event export (password hashes) is public"


def check_ban_does_not_leak_admin_session(x: Ctx):
    """banned_by was str(session_row): the live admin cookie went into the
    bans table, the audit log and the gossiped ban.added event."""
    a = x.admin_client()
    sid = a.cookies.get("shroud_sid")
    r = a.post("/api/v1/admin/bans", json={"kind": "hwid", "value": "hw-1"})
    assert r.status_code == 403, f"ban accepted without CSRF token: {r.status_code}"
    r = a.post("/api/v1/admin/bans", json={"kind": "hwid", "value": "hw-1"},
               headers={"X-CSRF-Token": a.cookies.get("shroud_csrf")})
    assert r.status_code == 200, r.text
    for (bb,) in x.srv.db.execute("SELECT banned_by FROM bans"):
        assert sid not in bb, "admin session id stored in bans.banned_by"
    for (p,) in x.srv.db.execute("SELECT payload FROM federation_state_events"):
        assert sid not in p, "admin session id stored in a state event"


def check_leaked_session_scrubbed(x: Ctx):
    """Rows written by older builds are cleaned and the session logged out."""
    a = x.admin_client()
    sid = a.cookies.get("shroud_sid")
    leaked = f"('{sid}', b'x', 'ua', '2026-01-01', '2026-01-01', 0)"
    x.srv.db.execute("INSERT INTO bans (kind, value, banned_by) VALUES ('hwid','hw-old',?)",
                     (leaked,))
    x.srv.db.commit()
    x.srv._scrub_leaked_admin_sessions()
    assert x.srv.db.execute("SELECT banned_by FROM bans WHERE value='hw-old'"
                            ).fetchone()[0] == "admin"
    assert x.srv.db.execute("SELECT logged_out FROM admin_sessions WHERE id=?",
                            (sid,)).fetchone()[0] == 1


def check_bad_credentials_are_401_not_500(x: Ctx):
    """register_device and change_password referenced undefined names on
    their failure paths and answered 500."""
    from crypto.fips_crypto import generate_keypair, serialize_public_key
    pub = serialize_public_key(generate_keypair()[1]).hex()
    name, _pw = x.user()
    for uname, pw in (("nobody-here", "whatever-password"), (name, "wrong-password-123")):
        r = x.c.post("/api/v1/devices", json={
            "username": uname, "password": pw, "device_name": "t",
            "platform": "android", "public_key": pub})
        assert r.status_code == 401, (uname, r.status_code)
        r = x.c.post("/api/v1/change-password", json={
            "username": uname, "old_password": pw, "new_password": "new-password-123"})
        assert r.status_code == 401, (uname, r.status_code)


def check_registration_toggle_and_bans_everywhere(x: Ctx):
    """/register ignored registration_enabled; it and /srp/register never
    checked bans."""
    x.srv.setting_set("registration_enabled", "0")
    try:
        r = x.c.post("/api/v1/register", json={"username": "closedreg",
                                                "password": "long-enough-pw"})
        assert r.status_code == 403, r.status_code
    finally:
        x.srv.setting_set("registration_enabled", "1")
    x.srv.db.execute("INSERT INTO bans (kind, value) VALUES ('username','banneduser')")
    x.srv.db.commit()
    r = x.c.post("/api/v1/register", json={"username": "banneduser",
                                            "password": "long-enough-pw"})
    assert r.status_code == 403, r.status_code
    if x.srv.SRP_AVAILABLE:
        r = x.c.post("/api/v1/srp/register", json={
            "username": "banneduser", "salt_hex": "00" * 16, "verifier_hex": "05"})
        assert r.status_code == 403, r.status_code


def check_srp_failures_lock_not_wipe(x: Ctx):
    """Five bad proofs, needing only the username, wiped the account."""
    if not x.srv.SRP_AVAILABLE:
        return
    from crypto import srp6a
    salt, v = srp6a.make_verifier("srpvictim", "the-real-password")
    r = x.c.post("/api/v1/srp/register", json={
        "username": "srpvictim", "salt_hex": salt.hex(), "verifier_hex": format(v, "x")})
    assert r.status_code == 200, r.text
    for _ in range(x.srv.SELF_DESTRUCT_THRESHOLD):
        cs = srp6a.ClientSession("srpvictim", "guess")
        ch = x.c.post("/api/v1/srp/challenge", json={
            "username": "srpvictim", "A_hex": format(cs.public(), "x")}).json()
        r = x.c.post("/api/v1/srp/prove", json={"session_id": ch["session_id"],
                                                 "M1_hex": "00"})
        assert r.status_code == 401, r.status_code
    assert x.srv.db.execute("SELECT 1 FROM users WHERE username='srpvictim'").fetchone(), \
        "failed SRP proofs deleted the account"
    # Locked now, even with the right password.
    cs = srp6a.ClientSession("srpvictim", "the-real-password")
    ch = x.c.post("/api/v1/srp/challenge", json={
        "username": "srpvictim", "A_hex": format(cs.public(), "x")}).json()
    m1, _k = cs.derive_session(bytes.fromhex(ch["salt_hex"]), int(ch["B_hex"], 16))
    r = x.c.post("/api/v1/srp/prove", json={"session_id": ch["session_id"],
                                             "M1_hex": m1.hex()})
    assert r.status_code == 429, r.status_code
    # Decoy challenges look like real ones (an empty sid leaked existence).
    ch = x.c.post("/api/v1/srp/challenge", json={"username": "no-such-srp-user",
                                                  "A_hex": "05"}).json()
    assert len(ch["session_id"]) == 32, ch


def check_groups(x: Ctx):
    """create_group always 500'd (rowid used as the uuid group id);
    send_group_message reused one primary key for every recipient; add
    and list had no authorization."""
    devs = [x.device(*x.user("grp")) for _ in range(3)]
    outsider = x.device(*x.user("out"))
    r = x.c.post("/api/v1/groups/create", json={
        "group_name": "g", "creator_device_id": devs[0],
        "members": [{"device_id": d, "encrypted_group_key": "k"} for d in devs]})
    assert r.status_code == 200, r.text
    gid = r.json()["group_id"]
    assert x.srv.db.execute("SELECT 1 FROM group_chats WHERE id=?", (gid,)).fetchone()
    r = x.c.post("/api/v1/groups/send", json={
        "group_id": gid, "sender_device_id": devs[0], "envelope": {"c": "x"}})
    assert r.status_code == 200 and r.json()["delivered_to"] == 2, r.text
    r = x.c.post("/api/v1/groups/send", json={
        "group_id": gid, "sender_device_id": outsider, "envelope": {"c": "x"}})
    assert r.status_code == 403, r.status_code
    r = x.c.post("/api/v1/groups/add", json={
        "group_id": gid, "requester_device_id": outsider,
        "device_id": outsider, "encrypted_group_key": "k"})
    assert r.status_code == 403, r.status_code
    if x.srv.TREEKEM_AVAILABLE:
        tree = {"epoch": 0, "depth": 1, "members": [], "public_path": []}
        r = x.c.post(f"/api/v1/groups/{gid}/treekem/init",
                     json={"device_id": outsider, **tree})
        assert r.status_code == 403, r.status_code
        r = x.c.post(f"/api/v1/groups/{gid}/treekem/init",
                     json={"device_id": devs[0], **tree})
        assert r.status_code == 200, r.text
        r = x.c.post(f"/api/v1/groups/{gid}/treekem/init",
                     json={"device_id": devs[0], **tree})
        assert r.status_code == 409, "tree re-init allowed (epoch rollback)"
        r = x.c.post(f"/api/v1/groups/{gid}/treekem/commit",
                     json={"device_id": outsider, "new_epoch": 5})
        assert r.status_code == 403, r.status_code
        r = x.c.post(f"/api/v1/groups/{gid}/treekem/commit",
                     json={"device_id": devs[1], "new_epoch": "x"})
        assert r.status_code == 400, r.status_code
    # A failed write must not linger in an open transaction.
    assert not x.srv.db._c().in_transaction


def check_file_download_requires_party(x: Ctx):
    """A request with no X-Device-ID skipped the authorization check."""
    a = x.device(*x.user("fa"))
    b = x.device(*x.user("fb"))
    name = "regress.enc"
    with open(os.path.join(x.srv.FILE_DIR, name), "wb") as f:
        f.write(b"\x00" * 16)
    x.srv.db.execute(
        "INSERT INTO file_transfers (id, sender_device_id, recipient_device_id, "
        "storage_name, encrypted_metadata, original_size, encrypted_size) "
        "VALUES ('f1', ?, ?, ?, '', 16, 16)", (a, b, name))
    x.srv.db.commit()
    try:
        assert x.c.get("/api/v1/files/f1").status_code == 403
        assert x.c.get("/api/v1/files/f1/info").status_code == 403
        assert x.c.get("/api/v1/files/f1", headers={"X-Device-ID": b}).status_code == 200
        assert x.c.get("/api/v1/files/f1/info", headers={"X-Device-ID": a}).status_code == 200
    finally:
        os.remove(os.path.join(x.srv.FILE_DIR, name))


def check_malformed_input_is_400(x: Ctx):
    """Non-numeric X-Envelope-Version and array envelopes answered 500."""
    a = x.device(*x.user("ma"))
    b = x.device(*x.user("mb"))
    r = x.c.post("/api/v1/messages/send", json={
        "sender_device_id": a, "recipient_device_id": b,
        "envelope": '["nonce","ciphertext","sig","sender","ts"]'})
    assert r.status_code == 400, r.status_code
    r = x.c.post("/api/v1/messages/send-anon", content=b"\x00" * 4096,
                 headers={"X-Routing-Tag": "00" * 32, "X-Envelope-Version": "two"})
    assert r.status_code == 400, r.status_code


def check_rate_limit_is_429(x: Ctx):
    """HTTPException raised inside BaseHTTPMiddleware surfaced as a 500."""
    codes = [x.c.post("/api/v1/admin/fingerprint-login",
                      json={"fingerprint_id": "nope", "password": "x"},
                      headers={"X-Forwarded-For": "1.2.3.4"}).status_code
             for _ in range(8)]
    assert codes[-1] == 429, codes
    assert x.srv._rate_limit_for("/api/v1/devices/list", "POST")[0] != "register", \
        "/devices/list shares the 20/hour registration budget"
    assert x.srv._rate_limit_for("/api/v1/files/" + "a" * 32, "GET")[0] == "/api/v1/files/:id"


CHECKS = [v for k, v in list(globals().items()) if k.startswith("check_")]


def main() -> int:
    x = Ctx()
    print("Relay regression checks\n")
    failed = 0
    # Rate-limit check last: it burns this client's admin-login budget.
    for fn in sorted(CHECKS, key=lambda f: f is check_rate_limit_is_429):
        x.srv.rate_limits.clear()   # every check comes from one "IP"
        try:
            fn(x)
            print(f"  PASS  {fn.__name__[6:]}")
        except Exception as e:                              # noqa: BLE001
            failed += 1
            print(f"  FAIL  {fn.__name__[6:]}: {type(e).__name__}: {e}")
            traceback.print_exc(limit=3)
    print(f"\n{len(CHECKS) - failed}/{len(CHECKS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
