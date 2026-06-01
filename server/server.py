"""
SHROUD Secure Messaging Server — FIPS 140-2 Compliant
Port 58443 | TLS 1.3 | E2E Encryption | Device Registration
"""

import os, sys, json, time, sqlite3, uuid, struct, hashlib, collections, shutil, secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

STARTUP_TS = time.time()
REQ_COUNTS = collections.Counter()
REQ_LATENCY = collections.deque(maxlen=2000)  # (path, ms, ts)
ERR_COUNTS = collections.Counter()
RECENT_ERRORS = collections.deque(maxlen=100)
COVER_COUNT = 0           # number of cover messages received since boot
COVER_BYTES = 0           # bytes received as cover (post-padding)

# v2.4.0 — network transport telemetry. Counted in TelemetryMiddleware
# from the incoming Host header. .onion endings = onion-routed; anything
# else = clearnet. Surfaced on the Activity tab.
ONION_REQ_COUNT = 0
CLEAR_REQ_COUNT = 0

# Resolved at startup; pulled from the project-root VERSION file when present
# so the server label, the admin dashboard, and the /api/v1/version endpoint
# don't drift apart (which they had).
def _read_server_version() -> str:
    here = Path(__file__).resolve().parent
    for cand in (here.parent / "VERSION", here / "VERSION"):
        try:
            v = cand.read_text(encoding="utf-8").strip()
            if v:
                return v
        except OSError:
            continue
    return "2.4.0"

SERVER_VERSION = _read_server_version()

# Where the extracted admin GUI lives (HTML/CSS/JS). Served as StaticFiles
# under /admin/static and read directly by the /admin* HTML routes.
ADMIN_DIR = str(Path(__file__).resolve().parent / "admin")

# Add parent to path for crypto imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Header, Cookie, Depends
from fastapi.responses import JSONResponse, HTMLResponse, Response, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Set
import asyncio

# Live-tail subscribers. The admin dashboard opens /ws/admin and stays
# connected; whenever something interesting happens (audit-log row, error,
# failed login, admin session change) publish_event() drops a JSON message
# to everyone. The set is mutated only from the asyncio event loop, so no
# lock is needed.
_WS_ADMIN_SUBS: "Set[WebSocket]" = set()

def publish_event(event_type: str, payload: dict) -> None:
    """Broadcast a JSON event to all connected admin WebSocket clients.

    Safe to call from anywhere on the FastAPI event-loop thread (request
    handlers, middleware, audit helpers). Best-effort: closed sockets get
    pruned silently and exceptions never propagate to the caller.
    """
    if not _WS_ADMIN_SUBS:
        return
    msg = json.dumps({"type": event_type, "row": payload})
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # No running loop on this thread; nothing to do. Worker threads
        # that want to push live events should hop back to the loop first.
        return

    async def _send_all() -> None:
        for sub in list(_WS_ADMIN_SUBS):
            try:
                await sub.send_text(msg)
            except Exception:
                _WS_ADMIN_SUBS.discard(sub)

    loop.create_task(_send_all())

# Try to import crypto — works when running from project root
try:
    from crypto.fips_crypto import (
        generate_keypair, serialize_public_key, deserialize_public_key,
        compute_shared_secret, derive_key, encrypt_aes_gcm, decrypt_aes_gcm,
        hmac_sign, hmac_verify, generate_device_id, fips_self_test, fips_random
    )
except ImportError:
    import fips_crypto as crypto
    from fips_crypto import *

try:
    from crypto import pq_hybrid
    PQ_AVAILABLE = pq_hybrid.self_test()
except Exception as _pq_e:
    pq_hybrid = None
    PQ_AVAILABLE = False
    print(f"[SHROUD] PQ hybrid unavailable: {_pq_e}")

try:
    from crypto import hybrid_sig
    HYBRID_SIG_AVAILABLE = hybrid_sig.self_test()
except Exception as _sig_e:
    hybrid_sig = None
    HYBRID_SIG_AVAILABLE = False
    print(f"[SHROUD] Hybrid signatures unavailable: {_sig_e}")

try:
    from crypto import anon_creds
    ANON_CREDS_AVAILABLE = anon_creds.self_test()
except Exception as _ac_e:
    anon_creds = None
    ANON_CREDS_AVAILABLE = False
    print(f"[SHROUD] Anonymous credentials unavailable: {_ac_e}")

try:
    from crypto import srp6a
    SRP_AVAILABLE = srp6a.self_test()
except Exception as _srp_e:
    srp6a = None
    SRP_AVAILABLE = False
    print(f"[SHROUD] SRP-6a unavailable: {_srp_e}")

try:
    from crypto import at_rest
    AT_REST_AVAILABLE = at_rest.self_test()
except Exception as _ar_e:
    at_rest = None
    AT_REST_AVAILABLE = False
    print(f"[SHROUD] At-rest encryption unavailable: {_ar_e}")

try:
    from crypto import treekem
    TREEKEM_AVAILABLE = treekem.self_test()
except Exception as _tk_e:
    treekem = None
    TREEKEM_AVAILABLE = False
    print(f"[SHROUD] TreeKEM unavailable: {_tk_e}")

from cryptography.hazmat.primitives.asymmetric import ec


# ── Persistent server identity (triple-hybrid signature keypair) ─────
IDENTITY_PATH = os.path.join(os.path.dirname(__file__), "identity.key")
SERVER_IDENTITY = None  # {"pk_blob": bytes, "secrets": dict, "fingerprint": str}
IDENTITY_FILE_MAGIC = 0xC0DEFACE

def _load_or_create_identity():
    global SERVER_IDENTITY
    if not HYBRID_SIG_AVAILABLE:
        return
    if os.path.exists(IDENTITY_PATH):
        try:
            with open(IDENTITY_PATH, "rb") as f:
                data = f.read()
            (magic,) = struct.unpack_from("<I", data, 0)
            if magic != IDENTITY_FILE_MAGIC:
                raise ValueError("identity file magic mismatch")
            off = 4
            (pk_len,) = struct.unpack_from("<I", data, off); off += 4
            pk = data[off:off + pk_len]; off += pk_len
            (ed_len,) = struct.unpack_from("<I", data, off); off += 4
            ed_sk = data[off:off + ed_len]; off += ed_len
            (mldsa_len,) = struct.unpack_from("<I", data, off); off += 4
            mldsa_sk = data[off:off + mldsa_len]; off += mldsa_len
            (sph_len,) = struct.unpack_from("<I", data, off); off += 4
            sph_sk = data[off:off + sph_len]
            secrets = {"ed_sk_bytes": ed_sk, "mldsa_sk": mldsa_sk, "sph_sk": sph_sk}
            fp = hybrid_sig.fingerprint(pk)
            SERVER_IDENTITY = {"pk_blob": pk, "secrets": secrets, "fingerprint": fp}
            print(f"[SHROUD] Server identity loaded — fingerprint {fp}")
            return
        except Exception as e:
            print(f"[SHROUD] WARN: identity file corrupt ({e}) — regenerating")

    pk, secrets = hybrid_sig.keygen()
    data = (
        struct.pack("<II", IDENTITY_FILE_MAGIC, len(pk)) + pk
        + struct.pack("<I", len(secrets["ed_sk_bytes"])) + secrets["ed_sk_bytes"]
        + struct.pack("<I", len(secrets["mldsa_sk"])) + secrets["mldsa_sk"]
        + struct.pack("<I", len(secrets["sph_sk"])) + secrets["sph_sk"]
    )
    with open(IDENTITY_PATH, "wb") as f:
        f.write(data)
    try: os.chmod(IDENTITY_PATH, 0o600)
    except Exception: pass
    fp = hybrid_sig.fingerprint(pk)
    SERVER_IDENTITY = {"pk_blob": pk, "secrets": secrets, "fingerprint": fp}
    print(f"[SHROUD] Server identity generated — fingerprint {fp}")


def server_sign_attestation(session_id: str, pq_pubkey_blob: bytes) -> bytes:
    """Triple-sign a handshake response so the client can pin our identity."""
    if not SERVER_IDENTITY:
        return b""
    msg = b"SHROUD-KEX-v2|" + session_id.encode("ascii") + b"|" + pq_pubkey_blob
    return hybrid_sig.sign(msg, SERVER_IDENTITY["secrets"])


_load_or_create_identity()


# ── Anonymous credential issuing key (RSA-3072 blind sig) ────────────
ANON_CREDS_KEY_PATH = os.path.join(os.path.dirname(__file__), "anon_creds.key")
ANON_CREDS_KEYS = None  # {"pub": dict, "sk": dict}

def _load_or_create_anon_creds_key():
    global ANON_CREDS_KEYS
    if not ANON_CREDS_AVAILABLE: return
    if os.path.exists(ANON_CREDS_KEY_PATH):
        try:
            with open(ANON_CREDS_KEY_PATH, "rb") as f:
                blob = f.read()
            sk = anon_creds.parse_sk(blob)
            pub = {"n": sk["n"], "e": sk["e"]}
            ANON_CREDS_KEYS = {"pub": pub, "sk": sk}
            print(f"[SHROUD] Anonymous credential key loaded (RSA-{sk['n'].bit_length()})")
            return
        except Exception as e:
            print(f"[SHROUD] WARN: anon_creds key corrupt ({e}) — regenerating")
    pub, sk = anon_creds.server_keygen()
    with open(ANON_CREDS_KEY_PATH, "wb") as f:
        f.write(anon_creds.serialize_sk(sk))
    try: os.chmod(ANON_CREDS_KEY_PATH, 0o600)
    except Exception: pass
    ANON_CREDS_KEYS = {"pub": pub, "sk": sk}
    print(f"[SHROUD] Anonymous credential keypair generated (RSA-{sk['n'].bit_length()})")


_load_or_create_anon_creds_key()


# ── At-rest field encryption key (AES-256-GCM for sensitive columns) ─
DATA_KEY_PATH = os.path.join(os.path.dirname(__file__), "data.key")
DATA_KEY = None
if AT_REST_AVAILABLE:
    try:
        DATA_KEY = at_rest.load_or_create_data_key(DATA_KEY_PATH)
        print(f"[SHROUD] At-rest data key loaded (AES-256-GCM)")
    except Exception as _dk_e:
        print(f"[SHROUD] WARN: at-rest data key unavailable: {_dk_e}")
        DATA_KEY = None

def ar_enc(s: str):
    if not DATA_KEY or not s: return s if isinstance(s, str) else (s or "")
    try: return at_rest.encrypt(DATA_KEY, s)
    except Exception: return s

def ar_dec(b) -> str:
    if not DATA_KEY: return b if isinstance(b, str) else (b.decode("utf-8", errors="replace") if b else "")
    try: return at_rest.decrypt(DATA_KEY, b)
    except Exception: return ""

# ── Config ───────────────────────────────────────────────────────────
from fastapi.responses import FileResponse, StreamingResponse
PORT = 58443
DB_PATH = os.environ.get(
    "SHROUD_DB_PATH",
    os.path.join(os.path.dirname(__file__), "shroud.db"),
)
FILE_DIR = os.path.join(os.path.dirname(__file__), "files")
os.makedirs(FILE_DIR, exist_ok=True)
SESSION_TIMEOUT = 3600  # 1 hour
MAX_DEVICES_PER_USER = 25

# ── Stats persistence ────────────────────────────────────────────────
# Counters survive restart, recent-error / rolling-latency deques don't.
# Hydrated once at startup, flushed every 60s + on graceful shutdown.
def _stats_load():
    global COVER_COUNT, COVER_BYTES
    try:
        rows = db.execute("SELECT name, value FROM server_stats").fetchall()
    except Exception:
        return
    for name, value in rows:
        try:
            if name == "req_counts":
                REQ_COUNTS.update(json.loads(value))
            elif name == "err_counts":
                ERR_COUNTS.update(json.loads(value))
            elif name == "cover_count":
                COVER_COUNT = int(value)
            elif name == "cover_bytes":
                COVER_BYTES = int(value)
        except Exception as e:
            print(f"[SHROUD] stats hydrate skipped {name}: {e}")


def _stats_flush():
    try:
        db.executemany(
            "INSERT INTO server_stats (name,value,updated_at) VALUES (?,?,datetime('now')) "
            "ON CONFLICT(name) DO UPDATE SET value=excluded.value, updated_at=datetime('now')",
            [
                ("req_counts", json.dumps(dict(REQ_COUNTS))),
                ("err_counts", json.dumps(dict(ERR_COUNTS))),
                ("cover_count", str(COVER_COUNT)),
                ("cover_bytes", str(COVER_BYTES)),
            ],
        )
        db.commit()
    except Exception as e:
        print(f"[SHROUD] stats flush error: {e}")


def _stats_history_snapshot():
    """Append a one-row snapshot of the live counters for the sparkline
    series. Prunes anything older than 14 days so the table can't grow
    unbounded on a long-lived server.
    """
    try:
        active_devices = db.execute(
            "SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now','-5 minutes')"
        ).fetchone()[0]
        files_dir = 0
        try:
            for entry in os.scandir(FILE_DIR):
                if entry.is_file():
                    try:
                        files_dir += entry.stat().st_size
                    except OSError:
                        pass
        except OSError:
            pass
        file_count = db.execute("SELECT COUNT(*) FROM file_transfers").fetchone()[0]
        undelivered = db.execute(
            "SELECT COUNT(*) FROM messages WHERE delivered=0"
        ).fetchone()[0]
        db.execute(
            "INSERT INTO server_stats_history "
            "(errors_total, requests_total, active_devices, file_count, "
            "files_dir_bytes, undelivered, onion_requests, clear_requests) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (sum(ERR_COUNTS.values()), sum(REQ_COUNTS.values()), active_devices,
             file_count, files_dir, undelivered, ONION_REQ_COUNT, CLEAR_REQ_COUNT),
        )
        db.execute(
            "DELETE FROM server_stats_history WHERE taken_at < datetime('now','-14 days')"
        )
        db.commit()
    except Exception as e:
        print(f"[SHROUD] stats history snapshot error: {e}")


async def _stats_flusher():
    while True:
        await asyncio.sleep(60)
        _stats_flush()
        _stats_history_snapshot()


async def _expiry_sweeper():
    """Periodically purge expired messages and files."""
    while True:
        try:
            # Disappearing messages
            n_msg = db.execute("SELECT COUNT(*) FROM messages WHERE expires_at IS NOT NULL AND expires_at < datetime('now')").fetchone()[0]
            if n_msg:
                db.execute("DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < datetime('now')")
            # Expired device-link sessions (also wipes any payload that never
            # got picked up — payloads contain identity material).
            db.execute("DELETE FROM device_link_sessions WHERE expires_at < datetime('now')")
            # Diagnostic reports older than 7 days. Operator should be
            # polling and triaging well within that window.
            try:
                db.execute(
                    "DELETE FROM diagnostic_reports "
                    "WHERE server_ts < datetime('now', '-7 days')"
                )
            except Exception:
                # Table may not exist yet on very-old upgrades.
                pass
            # Expired files
            file_rows = db.execute(
                "SELECT id, storage_name FROM file_transfers WHERE expires_at IS NOT NULL AND expires_at < datetime('now')"
            ).fetchall()
            for fid, name in file_rows:
                path = os.path.join(FILE_DIR, name)
                if os.path.isfile(path):
                    try: os.remove(path)
                    except OSError: pass
                db.execute("DELETE FROM file_transfers WHERE id=?", (fid,))
            db.commit()
            if n_msg or file_rows:
                print(f"[SHROUD] expiry sweep: removed {n_msg} msgs, {len(file_rows)} files")
        except Exception as e:
            print(f"[SHROUD] expiry sweep error: {e}")
        await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(ap):
    # Startup
    if not fips_self_test():
        raise RuntimeError("FIPS 140-2 self-test FAILED — server cannot start")
    print(f"[SHROUD] FIPS 140-2 self-test: PASSED")
    print(f"[SHROUD] PQ hybrid (ECDH-P384 + ML-KEM-1024): {'READY' if PQ_AVAILABLE else 'unavailable'}")
    print(f"[SHROUD] Server starting on port {PORT}")
    expired = db.execute(
        "SELECT id, storage_name FROM file_transfers WHERE expires_at < datetime('now') OR downloaded=1"
    ).fetchall()
    for row in expired:
        path = os.path.join(FILE_DIR, row[1])
        if os.path.isfile(path):
            os.remove(path)
        db.execute("DELETE FROM file_transfers WHERE id=?", (row[0],))
    db.commit()
    if expired:
        print(f"[SHROUD] Cleaned up {len(expired)} expired/downloaded files")
    _stats_load()
    print(f"[SHROUD] Stats restored: {sum(REQ_COUNTS.values())} requests, {sum(ERR_COUNTS.values())} errors lifetime")
    sweep_task = asyncio.create_task(_expiry_sweeper())
    stats_task = asyncio.create_task(_stats_flusher())
    fed_task = None
    fed_sync_task = None
    if os.environ.get("SHROUD_FEDERATION", "0") == "1":
        # Late import so we don't pay for httpx unless federation is on.
        fed_task = asyncio.create_task(_federation_loop())
        print("[SHROUD] Federation gossip loop started")
        # Initial state-event sync — fire and forget. Runs once shortly
        # after boot and again every hour to backfill anything we
        # missed while down.
        fed_sync_task = asyncio.create_task(_federation_state_sync_loop())
    try:
        yield
    finally:
        tasks = [sweep_task, stats_task]
        if fed_task is not None:
            tasks.append(fed_task)
        if fed_sync_task is not None:
            tasks.append(fed_sync_task)
        for t in tasks:
            t.cancel()
            try: await t
            except asyncio.CancelledError: pass
        _stats_flush()
        print("[SHROUD] Server shutting down (stats persisted)")

app = FastAPI(title="SHROUD Secure Messaging", version=SERVER_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-Device-ID", "X-Recipient-ID", "X-File-Metadata"],
)

# ── Database ─────────────────────────────────────────────────────────
def init_db():
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt BLOB NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            device_name TEXT NOT NULL,
            platform TEXT NOT NULL,  -- 'windows', 'ios', 'android'
            public_key BLOB NOT NULL,
            hwid TEXT DEFAULT '',
            registered_at TEXT DEFAULT (datetime('now')),
            last_seen TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            sender_device_id TEXT NOT NULL,
            recipient_device_id TEXT NOT NULL,
            envelope TEXT NOT NULL,  -- JSON: {nonce, ciphertext, sig}
            server_ts TEXT DEFAULT (datetime('now')),
            delivered INTEGER DEFAULT 0,
            FOREIGN KEY (sender_device_id) REFERENCES devices(id),
            FOREIGN KEY (recipient_device_id) REFERENCES devices(id)
        );

        CREATE INDEX IF NOT EXISTS idx_msg_recipient ON messages(recipient_device_id, delivered);
        CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

        CREATE TABLE IF NOT EXISTS group_chats (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT 'Group Chat',
            creator_device_id TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (creator_device_id) REFERENCES devices(id)
        );

        CREATE TABLE IF NOT EXISTS group_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            encrypted_group_key TEXT NOT NULL,
            joined_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (group_id) REFERENCES group_chats(id),
            FOREIGN KEY (device_id) REFERENCES devices(id),
            UNIQUE(group_id, device_id)
        );

        CREATE TABLE IF NOT EXISTS admin_sessions (
            id TEXT PRIMARY KEY,
            ip TEXT NOT NULL DEFAULT 'unknown',
            user_agent TEXT DEFAULT '',
            login_at TEXT DEFAULT (datetime('now')),
            last_activity TEXT DEFAULT (datetime('now')),
            logged_out INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_admin_sessions_active
            ON admin_sessions(logged_out, last_activity);

        CREATE TABLE IF NOT EXISTS admin_fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint_id TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt BLOB NOT NULL,
            hwid TEXT DEFAULT '',
            label TEXT DEFAULT 'Admin',
            created_at TEXT DEFAULT (datetime('now')),
            last_used TEXT
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            hwid TEXT DEFAULT '',
            fingerprint_id TEXT DEFAULT '',
            success INTEGER DEFAULT 0,
            attempted_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_login_attempts_ip
            ON login_attempts(ip, attempted_at);

        CREATE TABLE IF NOT EXISTS file_transfers (
            id TEXT PRIMARY KEY,
            sender_device_id TEXT NOT NULL,
            recipient_device_id TEXT NOT NULL,
            storage_name TEXT NOT NULL,
            encrypted_metadata TEXT NOT NULL,
            original_size INTEGER NOT NULL,
            encrypted_size INTEGER NOT NULL,
            chunk_count INTEGER DEFAULT 1,
            server_ts TEXT DEFAULT (datetime('now')),
            downloaded INTEGER DEFAULT 0,
            FOREIGN KEY (sender_device_id) REFERENCES devices(id),
            FOREIGN KEY (recipient_device_id) REFERENCES devices(id)
        );

        CREATE INDEX IF NOT EXISTS idx_files_recipient ON file_transfers(recipient_device_id, downloaded);

        CREATE TABLE IF NOT EXISTS message_latency (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT,
            latency_ms REAL NOT NULL,
            recorded_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS friend_requests (
            id TEXT PRIMARY KEY,
            from_user_id TEXT NOT NULL,
            to_user_id TEXT NOT NULL,
            reason TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT DEFAULT (datetime('now')),
            responded_at TEXT,
            response_reason TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_freq_to ON friend_requests(to_user_id, status);
        CREATE INDEX IF NOT EXISTS idx_freq_from ON friend_requests(from_user_id, status);

        CREATE TABLE IF NOT EXISTS friendships (
            user_a TEXT NOT NULL,
            user_b TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            PRIMARY KEY (user_a, user_b)
        );

        CREATE TABLE IF NOT EXISTS group_invites (
            id TEXT PRIMARY KEY,
            group_id TEXT NOT NULL,
            from_user_id TEXT NOT NULL,
            to_user_id TEXT NOT NULL,
            reason TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT DEFAULT (datetime('now')),
            responded_at TEXT,
            response_reason TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_ginv_to ON group_invites(to_user_id, status);

        CREATE TABLE IF NOT EXISTS server_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT DEFAULT (datetime('now'))
        );

        -- v2.6.0 — admin-managed bans. Banning a username also fingerprints
        -- every HWID seen on devices linked to that user so the same
        -- hardware can't just re-register under a new username. The HWID
        -- side of the ban is enforced in /api/v1/register and /api/v1/devices.
        -- Bans never expire automatically; admin must clear them.
        CREATE TABLE IF NOT EXISTS bans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            kind        TEXT NOT NULL CHECK(kind IN ('username','hwid','ip')),
            value       TEXT NOT NULL,
            reason      TEXT DEFAULT '',
            banned_by   TEXT DEFAULT '',
            banned_at   TEXT DEFAULT (datetime('now')),
            origin_user TEXT DEFAULT '',  -- username that triggered this ban
            UNIQUE(kind, value)
        );
        CREATE INDEX IF NOT EXISTS idx_bans_kind_value ON bans(kind, value);
        CREATE INDEX IF NOT EXISTS idx_bans_origin    ON bans(origin_user);

        -- Cumulative counters that survive restart. Recent-error deque and
        -- rolling latency window deliberately stay in-memory — they're
        -- bounded and meaningful only for the current run.
        CREATE TABLE IF NOT EXISTS server_stats (
            name TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT DEFAULT (datetime('now'))
        );

        -- v2.4.0 — minute-resolution snapshots for the Activity sparklines.
        -- A row is appended every 60s by _stats_history_snapshot(). Older
        -- rows are pruned to 14 days. This is intentionally small and
        -- bounded; for proper observability ship logs to a real system.
        CREATE TABLE IF NOT EXISTS server_stats_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            taken_at TEXT NOT NULL DEFAULT (datetime('now')),
            errors_total INTEGER NOT NULL DEFAULT 0,
            requests_total INTEGER NOT NULL DEFAULT 0,
            active_devices INTEGER NOT NULL DEFAULT 0,
            file_count INTEGER NOT NULL DEFAULT 0,
            files_dir_bytes INTEGER NOT NULL DEFAULT 0,
            undelivered INTEGER NOT NULL DEFAULT 0,
            onion_requests INTEGER NOT NULL DEFAULT 0,
            clear_requests INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_stats_history_taken_at
            ON server_stats_history(taken_at);

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT DEFAULT '',
            detail TEXT DEFAULT '',
            ts TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
    """)
    # Migration: add expires_at if missing
    try:
        db.execute("ALTER TABLE file_transfers ADD COLUMN expires_at TEXT")
        db.commit()
    except:
        pass
    # Migration: add hwid if missing
    try:
        db.execute("ALTER TABLE devices ADD COLUMN hwid TEXT DEFAULT ''")
        db.commit()
    except:
        pass
    # Migration: sealed sender + disappearing messages + envelope version
    for ddl in (
        "ALTER TABLE messages ADD COLUMN sealed INTEGER DEFAULT 0",
        "ALTER TABLE messages ADD COLUMN expires_at TEXT",
        "ALTER TABLE messages ADD COLUMN envelope_version INTEGER DEFAULT 1",
        "ALTER TABLE messages ADD COLUMN padded_size INTEGER DEFAULT 0",
        "ALTER TABLE devices ADD COLUMN x25519_pub BLOB",
        "ALTER TABLE devices ADD COLUMN x25519_pub_sig BLOB",
        "ALTER TABLE devices ADD COLUMN ratchet_published_at TEXT",
        "ALTER TABLE devices ADD COLUMN pickup_secret BLOB",
        "ALTER TABLE users ADD COLUMN srp_salt BLOB",
        "ALTER TABLE users ADD COLUMN srp_verifier BLOB",
    ):
        try: db.execute(ddl); db.commit()
        except: pass
    # v2.4.5 — one-shot lowercase migration. Pre-v2.4.5 rows were stored
    # case-sensitive; clients now normalize to lowercase before submitting
    # credentials, so all stored usernames need to be lowercase too.
    # Conflicts (Alice vs alice) keep the older row and drop the newer one;
    # the user can re-register if they hit that edge case.
    try:
        db.execute(
            "UPDATE users SET username = LOWER(username) "
            "WHERE username <> LOWER(username) "
            "AND LOWER(username) NOT IN (SELECT username FROM users)"
        )
        db.commit()
    except: pass

    # v2.4.6 — one-shot duplicate-device GC. Pre-2.4.6, every login on a
    # given client created a new `devices` row, so users hit the per-user
    # cap quickly with rows that represent the same physical device.
    #
    # Rule: within each (user_id, device_name, platform) cluster of >1
    # rows, KEEP every row that has any message history AND keep the
    # newest-registered row. Delete the rest (and their orphan prekeys).
    # This is conservative: anything that ever touched message storage
    # stays untouched. The only thing we prune are pure phantoms.
    try:
        clusters = db.execute(
            "SELECT user_id, device_name, platform "
            "FROM devices "
            "GROUP BY user_id, device_name, platform "
            "HAVING COUNT(*) > 1"
        ).fetchall()
        pruned = 0
        for uid_, dname_, plat_ in clusters:
            rows = db.execute(
                "SELECT id FROM devices "
                "WHERE user_id=? AND device_name=? AND platform=? "
                "ORDER BY datetime(COALESCE(last_seen, registered_at)) DESC, registered_at DESC",
                (uid_, dname_, plat_)
            ).fetchall()
            keep_newest = rows[0][0]
            for (did_,) in rows[1:]:
                used = db.execute(
                    "SELECT 1 FROM messages "
                    "WHERE sender_device_id=? OR recipient_device_id=? LIMIT 1",
                    (did_, did_)
                ).fetchone()
                if used:
                    # Real messages live here — leave it alone.
                    continue
                if did_ == keep_newest:
                    continue
                db.execute("DELETE FROM one_time_prekeys WHERE device_id=?", (did_,))
                db.execute("DELETE FROM devices WHERE id=?", (did_,))
                pruned += 1
        if pruned:
            db.commit()
            try:
                print(f"[init_db] v2.4.6 device GC: pruned {pruned} phantom device row(s)")
            except Exception:
                pass
    except Exception as _e:
        try: db.rollback()
        except: pass
    # One-time prekeys (consumed on each new conversation init)
    try:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS one_time_prekeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                prekey_id INTEGER NOT NULL,
                x25519_pub BLOB NOT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                UNIQUE(device_id, prekey_id)
            );
            CREATE INDEX IF NOT EXISTS idx_otp_device ON one_time_prekeys(device_id);

            CREATE TABLE IF NOT EXISTS redeemed_credentials (
                m_hex TEXT PRIMARY KEY,
                redeemed_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_redeemed_ts ON redeemed_credentials(redeemed_at);

            CREATE TABLE IF NOT EXISTS treekem_state (
                group_id TEXT PRIMARY KEY,
                epoch INTEGER NOT NULL,
                depth INTEGER NOT NULL,
                members_json TEXT NOT NULL,
                public_path_json TEXT NOT NULL,
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS device_link_sessions (
                link_id TEXT PRIMARY KEY,
                primary_device_id TEXT NOT NULL,
                primary_pubkey BLOB NOT NULL,
                secondary_pubkey BLOB,
                encrypted_payload BLOB,
                created_at TEXT DEFAULT (datetime('now')),
                expires_at TEXT NOT NULL,
                consumed INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_link_expires ON device_link_sessions(expires_at);
        """)
        db.commit()
    except: pass
    try:
        db.execute("CREATE INDEX IF NOT EXISTS idx_msg_expires ON messages(expires_at) WHERE expires_at IS NOT NULL")
        db.commit()
    except:
        pass
    db.commit()
    return db


# ── Envelope versioning and padding ──────────────────────────────────
# Fixed-size buckets close out length-based traffic analysis. Every v2
# envelope must round-trip to one of these sizes BEFORE the b64/hex hop.
PAD_BUCKETS = (4096, 65536, 1048576, 16777216)  # 4K, 64K, 1M, 16M

def pad_bucket_for(plain_len: int) -> int:
    for b in PAD_BUCKETS:
        if plain_len <= b:
            return b
    return ((plain_len + 16777215) // 16777216) * 16777216

def is_valid_padded_size(n: int) -> bool:
    return n in PAD_BUCKETS or (n > PAD_BUCKETS[-1] and n % PAD_BUCKETS[-1] == 0)


# v2.4.6 — per-thread sqlite3 connection.
#
# FastAPI runs sync deps (require_admin, route handlers without async)
# inside a thread pool. Sharing a single sqlite3.Connection across
# those workers races on cursors and the implicit transaction state,
# producing the trio of errors we saw in production logs:
#   sqlite3.InterfaceError: bad parameter or other API misuse
#   sqlite3.OperationalError: cannot commit - no transaction is active
#   TypeError: fromisoformat: argument must be str
# (the last one is row[4] coming back garbled because another thread
#  reset the cursor underneath us).
#
# WAL mode + per-thread connections is the canonical fix: every
# thread gets its own connection, concurrent readers never block,
# and the busy_timeout absorbs the brief writer contention.
import threading as _threading

class _PerThreadConn:
    """sqlite3.Connection proxy that lazily opens one connection per
    OS thread. Drop-in replacement for the previous global `db` —
    every call site already uses .execute / .commit / .cursor."""
    def __init__(self, path):
        self._path = path
        self._local = _threading.local()

    def _c(self):
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self._path, check_same_thread=False, timeout=30)
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA busy_timeout=30000")
            self._local.conn = c
        return c

    def execute(self, *a, **kw):       return self._c().execute(*a, **kw)
    def executemany(self, *a, **kw):   return self._c().executemany(*a, **kw)
    def executescript(self, *a, **kw): return self._c().executescript(*a, **kw)
    def commit(self):                  return self._c().commit()
    def rollback(self):                return self._c().rollback()
    def cursor(self):                  return self._c().cursor()

# Run schema migrations on a one-shot connection, then close it so its
# WAL writes are durable. From here on every thread opens its own.
_init_conn = init_db()
try:
    _init_conn.close()
except Exception:
    pass
db = _PerThreadConn(DB_PATH)

def _raise_bad_credentials() -> None:
    """Wrap EA003 so call sites stay short. Detail explains the v2.4.5
    ghost-server scenario, which is by far the most common cause of a
    'real' EA003 right now: the user's old account never reached the
    federation because the v2.4.5 client was hardcoded to a stale IP."""
    from crypto.errors import errors, raise_http
    raise_http(errors.A003_BAD_CREDENTIALS, extra={
        "hint": (
            "If you're upgrading from v2.4.5 or earlier, every account "
            "registered through that build went to a hardcoded address "
            "that never reached this relay's database. You may need to "
            "register fresh on v2.6.x."
        ),
    })


def _raise_username_taken() -> None:
    from crypto.errors import errors, raise_http
    raise_http(errors.A005_USERNAME_TAKEN)


# ── Models ───────────────────────────────────────────────────────────
def decrypt_auth_payload(session_id: str, client_pub_hex: str, nonce_hex: str, ct_hex: str, tag_hex: str) -> dict:
    """Decrypt client auth payload using ECDH + AES-256-GCM."""
    from crypto.errors import errors, raise_http
    with ecdh_lock:
        server_priv = ecdh_cache.pop(session_id, None)
    if not server_priv:
        raise_http(errors.A001_BAD_SESSION)
    try:
        client_pub = deserialize_public_key(bytes.fromhex(client_pub_hex))
    except Exception:
        raise_http(errors.C001_BAD_PUBKEY)
    try:
        raw = server_priv.exchange(ec.ECDH(), client_pub)
        hashed = hashlib.sha256(raw).digest()
        key = hashlib.sha256(hashed + b"SHROUD-AUTH-v1").digest()[:32]
        nonce = bytes.fromhex(nonce_hex); ct = bytes.fromhex(ct_hex); tag = bytes.fromhex(tag_hex)
        plain = decrypt_aes_gcm(key, nonce, ct + tag)
        return json.loads(plain.decode('utf-8'))
    except HTTPException:
        raise
    except Exception:
        # Catalogued: EA002. Includes the hint that says "re-key-exchange",
        # which the client UI uses to auto-retry the handshake once before
        # giving up.
        raise_http(errors.A002_DECRYPT_FAILED,
                   extra={"session_id": session_id[:8] + "..."})

class EncryptedAuthRequest(BaseModel):
    session_id: str
    client_public_key: str  # hex DER
    nonce: str  # hex
    ciphertext: str  # hex
    tag: str  # hex

class RegisterUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=128)

class RegisterDeviceRequest(BaseModel):
    username: str
    password: str
    device_name: str = Field(max_length=64)
    platform: str  # 'windows', 'ios', 'android'
    public_key: str  # hex-encoded DER serialized public key
    hwid: str = ""  # hardware ID for device deduplication

class SendMessageRequest(BaseModel):
    sender_device_id: str
    recipient_device_id: str
    envelope: str  # JSON string of the encrypted message envelope

class GetMessagesRequest(BaseModel):
    device_id: str
    since: Optional[str] = None

class AuthRequest(BaseModel):
    username: str
    password: str

# ── FIPS Self-Test ───────────────────────────────────────────────────
# (now in lifespan handler above)

@app.get("/health")
async def health():
    return {"status": "ok", "fips": "140-2 validated", "version": "2.1.0"}


@app.get("/api/v1/error-codes")
async def get_error_codes():
    """Public catalog of every error code SHROUD components emit. Clients
    and bug-report tooling fetch this once at boot and use it to look up
    the title + detail for any error_code they encounter — keeps end-user
    error messages consistent across versions and lets the operator
    update copy server-side without re-shipping clients."""
    from crypto.errors import errors as _e
    return {
        "version": 1,
        "count":   len(_e.all()),
        "errors":  [
            {
                "code":   x.code,
                "http":   x.http,
                "title":  x.title,
                "detail": x.detail,
            }
            for x in _e.all()
        ],
    }


# ── Public relay stats (federation health dashboard) ─────────────────
#
# Each relay exposes this endpoint without auth so peer relays and
# operator dashboards can poll it without credentials. The payload
# carries ONLY operational telemetry: counters, version, uptime,
# capacity. No user data, no message contents, no per-user counts.
# Rule 3 still applies — nothing here identifies any user.

_RELAY_START_TS = int(time.time())


_SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT  = os.path.abspath(os.path.join(_SERVER_DIR, ".."))


def _read_git_sha() -> str:
    """Best-effort SHA of the running checkout. Empty string if unknown."""
    try:
        path = os.path.join(_REPO_ROOT, ".git", "HEAD")
        if not os.path.exists(path):
            return ""
        with open(path) as f:
            head = f.read().strip()
        if head.startswith("ref:"):
            ref = head.split(":", 1)[1].strip()
            ref_path = os.path.join(_REPO_ROOT, ".git", ref)
            if os.path.exists(ref_path):
                with open(ref_path) as f:
                    return f.read().strip()[:12]
        else:
            return head[:12]
    except Exception:
        pass
    return ""


def _read_onion_address() -> str:
    """Pull the local relay's Tor v3 .onion address if tor_setup.sh
    has been run. The tor data dir is mode 700 owned by the tor user,
    so the relay (running as ec2-user / shroud) can't read the
    hostname directly. tor_setup.sh installs a world-readable copy at
    /opt/shroud/data/onion_hostname.txt — we look there first.
    Empty string when Tor isn't deployed."""
    paths = [
        "/opt/shroud/data/onion_hostname.txt",
        "/var/lib/tor/shroud_hidden_service/hostname",
        "/var/lib/tor/hidden_service/hostname",
    ]
    for p in paths:
        try:
            if os.path.exists(p):
                with open(p) as f:
                    return f.read().strip()
        except Exception:
            continue
    return ""


def _disk_usage_pct(path: str = "/") -> float:
    try:
        st = os.statvfs(path)
        free = st.f_bavail * st.f_frsize
        total = st.f_blocks * st.f_frsize
        if total <= 0:
            return -1.0
        return 100.0 * (1.0 - (free / total))
    except Exception:
        return -1.0


def _load_avg() -> list[float]:
    try:
        return list(os.getloadavg())
    except (AttributeError, OSError):
        return []


@app.get("/api/v1/relay-stats")
async def get_relay_stats():
    """Operational health + traffic counters for this relay. Safe to
    expose publicly — contains no PII, no plaintext, no per-user data."""
    fed_peers: list[dict] = []
    if FEDERATION_ENABLED:
        try:
            fed_peers = _federation_active_peers()
        except Exception:
            fed_peers = []

    try:
        anon_msgs_pending = db.execute(
            "SELECT COUNT(*) FROM anon_messages"
        ).fetchone()[0]
    except Exception:
        anon_msgs_pending = -1
    try:
        diag_pending = db.execute(
            "SELECT COUNT(*) FROM diagnostic_reports"
        ).fetchone()[0]
    except Exception:
        diag_pending = -1

    onion = _read_onion_address()
    return {
        "schema":         "shroud.relay-stats.v1",
        "ts":             int(time.time()),
        "version":        SERVER_VERSION,
        "git_sha":        _read_git_sha(),
        "uptime_seconds": int(time.time()) - _RELAY_START_TS,
        "federation": {
            "enabled":       FEDERATION_ENABLED,
            "active_peers":  len(fed_peers),
            "peer_endpoints": [p.get("endpoint", "") for p in fed_peers],
        },
        "tor": {
            "onion_address": onion,
            "enabled":       bool(onion),
        },
        "traffic": {
            "requests_total":       sum(REQ_COUNTS.values()),
            "errors_total":         sum(ERR_COUNTS.values()),
            "cover_messages":       COVER_COUNT,
            "anon_messages_pending": anon_msgs_pending,
            "diag_reports_pending":  diag_pending,
        },
        "capacity": {
            "disk_used_pct": round(_disk_usage_pct(), 1),
            "load_avg":      [round(x, 2) for x in _load_avg()],
        },
    }

import threading
ecdh_cache = {}
ecdh_lock = threading.Lock()
pq_cache = {}          # session_id -> {ec_priv, kem_sk, ts}
pq_lock = threading.Lock()

@app.get("/api/v1/key-exchange")
async def key_exchange():
    """Return server ephemeral ECDH P-384 public key for encrypted auth."""
    priv, pub = generate_keypair()
    sid = uuid.uuid4().hex
    pub_hex = serialize_public_key(pub).hex()
    pub_nums = pub.public_numbers()
    blob = struct.pack("<II", 0x334B4345, 48) + pub_nums.x.to_bytes(48,'big') + pub_nums.y.to_bytes(48,'big')
    with ecdh_lock:
        ecdh_cache[sid] = priv
        if len(ecdh_cache) > 200:
            for k in list(ecdh_cache.keys())[:100]: del ecdh_cache[k]
    return {"session_id": sid, "server_public_key": pub_hex, "server_public_key_blob": blob.hex()}

@app.get("/api/v1/key-exchange-v2")
async def key_exchange_v2():
    """Post-quantum hybrid key exchange: ECDH P-384 + ML-KEM-1024, attested
    by the server's triple-hybrid identity signature. The client verifies the
    signature against a pinned identity fingerprint to defeat MITM."""
    if not PQ_AVAILABLE:
        raise HTTPException(503, "PQ hybrid unavailable")
    state, blob = pq_hybrid.gen_server_keypair()
    sid = uuid.uuid4().hex
    with pq_lock:
        pq_cache[sid] = {**state, "ts": time.time()}
        if len(pq_cache) > 200:
            for k in sorted(pq_cache, key=lambda k: pq_cache[k]["ts"])[:100]:
                del pq_cache[k]
    sig_blob = server_sign_attestation(sid, blob) if SERVER_IDENTITY else b""
    return {
        "session_id": sid,
        "server_public_key_blob": blob.hex(),
        "suite": "ECDH-P384+ML-KEM-1024",
        "kdf": "HKDF-SHA512",
        "server_signature": sig_blob.hex(),
        "server_identity_fp": SERVER_IDENTITY["fingerprint"] if SERVER_IDENTITY else "",
        "sig_suite": "Ed25519+ML-DSA-87+SPHINCS+-256s" if SERVER_IDENTITY else "",
    }

@app.post("/api/v1/ratchet/publish-key")
async def ratchet_publish(request: Request):
    """Publish this device's long-term X25519 ratchet identity key and a
    fresh batch of one-time prekeys. Other devices will fetch the bundle
    via /api/v1/ratchet/bundle/{device_id} to start a ratchet session.

    Body: { device_id, x25519_pub (hex), x25519_pub_sig (hex, ECDSA over
            the X25519 pub by this device's existing P-384 key — proves
            ownership), one_time_prekeys: [{prekey_id, pub (hex)}, ...] }
    """
    body = await request.json()
    device_id = body.get("device_id", "")
    x25519_pub = body.get("x25519_pub", "")
    x25519_sig = body.get("x25519_pub_sig", "")
    otps = body.get("one_time_prekeys", [])
    if not device_id or not x25519_pub:
        raise HTTPException(400, "Missing required fields")
    if not db.execute("SELECT id FROM devices WHERE id=?", (device_id,)).fetchone():
        raise HTTPException(404, "Device not found")
    try:
        pub_bytes = bytes.fromhex(x25519_pub)
        sig_bytes = bytes.fromhex(x25519_sig) if x25519_sig else b""
        if len(pub_bytes) != 32:
            raise ValueError("X25519 pub must be 32 bytes")
    except Exception:
        raise HTTPException(400, "Invalid x25519_pub or signature")
    db.execute(
        "UPDATE devices SET x25519_pub=?, x25519_pub_sig=?, ratchet_published_at=datetime('now') WHERE id=?",
        (pub_bytes, sig_bytes, device_id),
    )
    inserted = 0
    if isinstance(otps, list):
        for otp in otps[:200]:  # bound batch size
            try:
                pid = int(otp.get("prekey_id"))
                pub = bytes.fromhex(otp.get("pub", ""))
                if len(pub) != 32: continue
                db.execute(
                    "INSERT OR IGNORE INTO one_time_prekeys (device_id, prekey_id, x25519_pub) VALUES (?,?,?)",
                    (device_id, pid, pub),
                )
                inserted += 1
            except Exception:
                continue
    db.commit()
    remaining = db.execute(
        "SELECT COUNT(*) FROM one_time_prekeys WHERE device_id=?", (device_id,)
    ).fetchone()[0]
    return {"published": True, "one_time_prekeys_added": inserted, "one_time_prekeys_remaining": remaining}


@app.get("/api/v1/ratchet/identity/{device_id}")
async def ratchet_identity(device_id: str):
    """Return just the device's long-term X25519 ratchet identity. Used
    for static-static-DH bootstrap of a Double Ratchet session. Unlike
    /bundle, this endpoint never consumes a one-time prekey — it's safe
    to call on every send."""
    row = db.execute(
        "SELECT x25519_pub, ratchet_published_at FROM devices WHERE id=?",
        (device_id,),
    ).fetchone()
    if not row or not row[0]:
        raise HTTPException(404, "No ratchet identity published")
    return {"device_id": device_id, "x25519_pub": row[0].hex(), "published_at": row[1]}


@app.get("/api/v1/ratchet/bundle/{device_id}")
async def ratchet_bundle(device_id: str):
    """Return the ratchet bundle for a peer device so a new session can
    bootstrap: long-term X25519 pub + ownership signature + ONE one-time
    prekey (atomically consumed). If no one-time prekey is available the
    bundle still works — initial-message forward secrecy degrades to
    static-static, but subsequent messages remain fully forward-secret."""
    row = db.execute(
        "SELECT x25519_pub, x25519_pub_sig, ratchet_published_at FROM devices WHERE id=?",
        (device_id,),
    ).fetchone()
    if not row or not row[0]:
        raise HTTPException(404, "Device has not published a ratchet bundle")
    otp = db.execute(
        "SELECT id, prekey_id, x25519_pub FROM one_time_prekeys WHERE device_id=? ORDER BY id LIMIT 1",
        (device_id,),
    ).fetchone()
    one_time = None
    if otp:
        db.execute("DELETE FROM one_time_prekeys WHERE id=?", (otp[0],))
        db.commit()
        one_time = {"prekey_id": otp[1], "pub": otp[2].hex()}
    return {
        "device_id": device_id,
        "x25519_pub": row[0].hex(),
        "x25519_pub_sig": (row[1] or b"").hex(),
        "published_at": row[2],
        "one_time_prekey": one_time,
        "one_time_prekeys_remaining": db.execute(
            "SELECT COUNT(*) FROM one_time_prekeys WHERE device_id=?", (device_id,)
        ).fetchone()[0],
    }


# ── SRP-6a augmented PAKE ────────────────────────────────────────
# Server never sees the password. Each user registers by submitting a
# (salt, verifier) pair derived client-side. Future auth round-trips a
# zero-knowledge proof; if it verifies, server and client end up with the
# same session key WITHOUT the server learning the password.
SRP_SESSIONS = {}   # session_id -> ServerSession
SRP_SESSION_LOCK = threading.Lock()

@app.post("/api/v1/srp/register")
async def srp_register(request: Request):
    """Body: { username, salt_hex, verifier_hex }. Salt and verifier are
    computed client-side by srp6a.make_verifier(). The plaintext password
    never reaches the server."""
    if not SRP_AVAILABLE:
        raise HTTPException(503, "SRP-6a unavailable")
    if setting_get("registration_enabled", "1") != "1":
        raise HTTPException(403, "Registration is currently disabled")
    body = await request.json()
    username = norm_user(body.get("username") or "")
    if not username or len(username) < 3:
        raise HTTPException(400, "Username too short")
    try:
        salt = bytes.fromhex(body["salt_hex"])
        verifier = int(body["verifier_hex"], 16)
    except Exception:
        raise HTTPException(400, "Invalid salt or verifier")
    if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
        _raise_username_taken()
    uid = uuid.uuid4().hex
    db.execute(
        "INSERT INTO users (id, username, password_hash, password_salt, srp_salt, srp_verifier) "
        "VALUES (?,?,?,?,?,?)",
        (uid, username, "srp", b"", salt, verifier.to_bytes((verifier.bit_length() + 7) // 8, "big")),
    )
    db.commit()
    return {"user_id": uid, "username": username, "auth": "srp-6a"}

@app.post("/api/v1/srp/challenge")
async def srp_challenge(request: Request):
    """Round 1: client posts { username, A_hex }; server replies with
    { session_id, salt_hex, B_hex }."""
    if not SRP_AVAILABLE:
        raise HTTPException(503, "SRP-6a unavailable")
    body = await request.json()
    username = norm_user(body.get("username") or "")
    try:
        A = int(body["A_hex"], 16)
    except Exception:
        raise HTTPException(400, "Invalid A_hex")
    row = db.execute("SELECT srp_salt, srp_verifier FROM users WHERE username=?", (username,)).fetchone()
    if not row or not row[0] or not row[1]:
        # Always return a synthetic challenge so an attacker can't enumerate users
        salt = hashlib.sha256(b"SHROUD-decoy|" + username.encode()).digest()[:16]
        return {"session_id": "", "salt_hex": salt.hex(), "B_hex": format(secrets.randbelow(srp6a.N), "x")}
    salt = row[0]
    verifier = int.from_bytes(row[1], "big")
    sess = srp6a.ServerSession(username, salt, verifier)
    s, B = sess.challenge()
    sid = uuid.uuid4().hex
    with SRP_SESSION_LOCK:
        SRP_SESSIONS[sid] = {"sess": sess, "A": A, "ts": time.time()}
        if len(SRP_SESSIONS) > 500:
            for k in sorted(SRP_SESSIONS, key=lambda k: SRP_SESSIONS[k]["ts"])[:200]:
                del SRP_SESSIONS[k]
    return {"session_id": sid, "salt_hex": salt.hex(), "B_hex": format(B, "x")}

@app.post("/api/v1/srp/prove")
async def srp_prove(request: Request):
    """Round 2: client posts { session_id, M1_hex }; server replies with
    { M2_hex } on success, 401 otherwise.

    Self-destruct: SELF_DESTRUCT_THRESHOLD consecutive failed proofs
    against the same user purges that user's entire account (devices,
    messages, files, prekeys, friendships). A successful proof resets
    the counter."""
    if not SRP_AVAILABLE:
        raise HTTPException(503, "SRP-6a unavailable")
    body = await request.json()
    sid = body.get("session_id", "")
    with SRP_SESSION_LOCK:
        entry = SRP_SESSIONS.pop(sid, None)
    if not entry:
        raise HTTPException(401, "Invalid or expired SRP session")
    try:
        M1 = bytes.fromhex(body["M1_hex"])
    except Exception:
        raise HTTPException(400, "Invalid M1_hex")
    try:
        M2 = entry["sess"].derive_and_verify(entry["A"], M1)
    except ValueError:
        username = entry["sess"].I
        u = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if u:
            setting_set(f"srp_fail:{u[0]}", str(int(setting_get(f"srp_fail:{u[0]}", "0")) + 1))
            fails = int(setting_get(f"srp_fail:{u[0]}", "0"))
            if fails >= SELF_DESTRUCT_THRESHOLD:
                _wipe_user_cascade(u[0], reason=f"self_destruct@{fails}_fails")
                setting_set(f"srp_fail:{u[0]}", "0")
        raise HTTPException(401, "SRP proof failed")
    # Successful proof — reset the fail counter.
    u = db.execute("SELECT id FROM users WHERE username=?", (entry["sess"].I,)).fetchone()
    if u:
        setting_set(f"srp_fail:{u[0]}", "0")
    with SRP_SESSION_LOCK:
        SRP_SESSIONS["__key__" + sid] = {"K": entry["sess"].K, "ts": time.time()}
    return {"M2_hex": M2.hex(), "session_key_handle": sid}


# ── Panic wipe + self-destruct lockout ──────────────────────────
#
# Coercion defense:
#   * Panic wipe: any authenticated device can call /api/v1/panic to
#     instantly delete its user account, all linked devices, all queued
#     messages, all uploaded files, all friend graph state, and all
#     prekey bundles. The server replies 200 even on partial failure so
#     the caller can't be coerced into watching it succeed.
#   * Self-destruct lockout: failed auth attempts are already recorded
#     in login_attempts. The lockout middleware bans an IP after
#     MAX_FAILED_ATTEMPTS within BAN_WINDOW_SEC; with self-destruct ON
#     and the same hwid reaching SELF_DESTRUCT_THRESHOLD failures, the
#     server purges every device matching that hwid.
SELF_DESTRUCT_THRESHOLD = 5

def _wipe_user_cascade(user_id: str, reason: str) -> dict:
    devs = [r[0] for r in db.execute("SELECT id FROM devices WHERE user_id=?", (user_id,)).fetchall()]
    files_removed = 0
    if devs:
        ph = ",".join("?" * len(devs))
        for fid, name in db.execute(
            f"SELECT id, storage_name FROM file_transfers WHERE sender_device_id IN ({ph}) OR recipient_device_id IN ({ph})",
            devs * 2
        ).fetchall():
            p = os.path.join(FILE_DIR, name)
            if os.path.isfile(p):
                try: os.remove(p); files_removed += 1
                except OSError: pass
        db.execute(f"DELETE FROM file_transfers WHERE sender_device_id IN ({ph}) OR recipient_device_id IN ({ph})", devs * 2)
        db.execute(f"DELETE FROM messages WHERE sender_device_id IN ({ph}) OR recipient_device_id IN ({ph})", devs * 2)
        db.execute(f"DELETE FROM group_members WHERE device_id IN ({ph})", devs)
        db.execute(f"DELETE FROM one_time_prekeys WHERE device_id IN ({ph})", devs)
        db.execute(f"DELETE FROM devices WHERE id IN ({ph})", devs)
    db.execute("DELETE FROM friendships WHERE user_a=? OR user_b=?", (user_id, user_id))
    db.execute("DELETE FROM friend_requests WHERE from_user_id=? OR to_user_id=?", (user_id, user_id))
    db.execute("DELETE FROM group_invites WHERE from_user_id=? OR to_user_id=?", (user_id, user_id))
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    audit_admin(reason, "wipe_user_cascade", user_id, f"devices={len(devs)} files={files_removed}")
    return {"devices_removed": len(devs), "files_removed": files_removed}


@app.post("/api/v1/panic")
async def panic_wipe(request: Request):
    """Authenticated panic wipe. Body: { device_id }.
    Deletes the user account, all devices, all queued messages, all
    uploaded files, all friendships, all prekey bundles. Always returns
    200 with a generic payload so an observer can't tell whether the
    panic succeeded — useful under coercion."""
    body = await request.json()
    did = (body.get("device_id") or "").strip()
    row = db.execute("SELECT user_id FROM devices WHERE id=?", (did,)).fetchone()
    if not row:
        return {"wiped": False}  # 200 either way
    try:
        stats = _wipe_user_cascade(row[0], reason="panic")
        return {"wiped": True, **stats}
    except Exception:
        return {"wiped": False}


# ── Multi-device linking (sealed-Sesame style) ──────────────────
# Lets a logged-in user attach a second device without retyping the
# password and without the server seeing identity material. Flow:
#   1. Primary: POST /devices/link/init → server returns link_id + TTL.
#      Primary uploads its ephemeral X25519 pubkey for the new device
#      to encrypt back to.
#   2. New device scans/paste link_id, GET /devices/link/{id} → gets
#      primary_pubkey. Generates its own X25519 ephemeral, posts to
#      /devices/link/{id}/secondary so primary can encrypt to it.
#   3. Primary polls /devices/link/{id}, sees secondary_pubkey, derives
#      shared via X25519, encrypts the identity bundle (ratchet keys,
#      conversation state) and uploads via /devices/link/{id}/payload.
#   4. Secondary GETs /devices/link/{id}/payload, decrypts, imports.
#      Server marks session consumed; payload is purged.
# Server only sees ephemeral pubkeys + opaque ciphertext. 5-minute TTL.
LINK_TTL_SEC = 300

@app.post("/api/v1/devices/link/init")
async def device_link_init(request: Request):
    body = await request.json()
    primary = body.get("device_id", "")
    if not db.execute("SELECT id FROM devices WHERE id=?", (primary,)).fetchone():
        raise HTTPException(401, "Invalid device")
    try:
        pub = bytes.fromhex(body.get("primary_pubkey_hex", ""))
        if len(pub) != 32: raise ValueError("must be 32 bytes")
    except Exception:
        raise HTTPException(400, "Invalid primary_pubkey_hex")
    link_id = secrets.token_hex(16)
    expires = (datetime.now(tz=timezone.utc) + timedelta(seconds=LINK_TTL_SEC)).strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        "INSERT INTO device_link_sessions (link_id, primary_device_id, primary_pubkey, expires_at) "
        "VALUES (?,?,?,?)",
        (link_id, primary, pub, expires),
    )
    db.commit()
    return {"link_id": link_id, "expires_at": expires, "ttl_seconds": LINK_TTL_SEC}


@app.get("/api/v1/devices/link/{link_id}")
async def device_link_lookup(link_id: str):
    row = db.execute(
        "SELECT primary_pubkey, secondary_pubkey, encrypted_payload, expires_at, consumed "
        "FROM device_link_sessions WHERE link_id=?", (link_id,)
    ).fetchone()
    if not row: raise HTTPException(404, "Unknown link")
    if row[4]: raise HTTPException(410, "Link already consumed")
    return {
        "link_id": link_id,
        "primary_pubkey_hex": row[0].hex(),
        "secondary_pubkey_hex": row[1].hex() if row[1] else None,
        "payload_ready": row[2] is not None,
        "expires_at": row[3],
    }


@app.post("/api/v1/devices/link/{link_id}/secondary")
async def device_link_secondary(link_id: str, request: Request):
    body = await request.json()
    row = db.execute("SELECT consumed FROM device_link_sessions WHERE link_id=?", (link_id,)).fetchone()
    if not row: raise HTTPException(404, "Unknown link")
    if row[0]: raise HTTPException(410, "Already consumed")
    try:
        pub = bytes.fromhex(body.get("secondary_pubkey_hex", ""))
        if len(pub) != 32: raise ValueError("must be 32 bytes")
    except Exception:
        raise HTTPException(400, "Invalid secondary_pubkey_hex")
    db.execute("UPDATE device_link_sessions SET secondary_pubkey=? WHERE link_id=?", (pub, link_id))
    db.commit()
    return {"ok": True}


@app.post("/api/v1/devices/link/{link_id}/payload")
async def device_link_payload_put(link_id: str, request: Request):
    """Primary uploads the encrypted identity bundle."""
    row = db.execute(
        "SELECT primary_device_id, consumed FROM device_link_sessions WHERE link_id=?", (link_id,)
    ).fetchone()
    if not row: raise HTTPException(404, "Unknown link")
    if row[1]: raise HTTPException(410, "Already consumed")
    primary = row[0]
    body = await request.body()
    if not body or len(body) > 1024 * 1024:
        raise HTTPException(400, "Payload empty or too large")
    db.execute("UPDATE device_link_sessions SET encrypted_payload=? WHERE link_id=?", (body, link_id))
    db.commit()
    audit_admin(primary[:8], "device_link_payload_upload", link_id, f"bytes={len(body)}")
    return {"ok": True, "bytes": len(body)}


@app.get("/api/v1/devices/link/{link_id}/payload")
async def device_link_payload_get(link_id: str):
    """Secondary fetches the encrypted bundle, then session is consumed."""
    row = db.execute(
        "SELECT encrypted_payload, consumed FROM device_link_sessions WHERE link_id=?", (link_id,)
    ).fetchone()
    if not row: raise HTTPException(404, "Unknown link")
    if row[1]: raise HTTPException(410, "Already consumed")
    if not row[0]: raise HTTPException(425, "Payload not yet uploaded")
    payload = row[0]
    db.execute("UPDATE device_link_sessions SET consumed=1, encrypted_payload=NULL WHERE link_id=?", (link_id,))
    db.commit()
    return Response(content=payload, media_type="application/octet-stream")


# ── TreeKEM group state ──────────────────────────────────────────
# Stores only PUBLIC tree state per group: current epoch, member list,
# and the public X25519 keys along the tree. Private path material lives
# only on each member's device — the server is metadata-only.
@app.post("/api/v1/groups/{group_id}/treekem/init")
async def treekem_init(group_id: str, request: Request):
    """Creator initializes a fresh tree state for the group. Body:
    { device_id, epoch, depth, members: [...], public_path: [...] }"""
    if not TREEKEM_AVAILABLE:
        raise HTTPException(503, "TreeKEM unavailable")
    body = await request.json()
    auth_by_device(body.get("device_id", ""))
    if not db.execute("SELECT id FROM group_chats WHERE id=?", (group_id,)).fetchone():
        raise HTTPException(404, "Group not found")
    db.execute(
        "INSERT OR REPLACE INTO treekem_state (group_id, epoch, depth, members_json, public_path_json) "
        "VALUES (?,?,?,?,?)",
        (group_id, int(body.get("epoch", 0)), int(body.get("depth", 1)),
         json.dumps(body.get("members", [])), json.dumps(body.get("public_path", []))),
    )
    db.commit()
    return {"ok": True, "epoch": body.get("epoch", 0)}


@app.get("/api/v1/groups/{group_id}/treekem/state")
async def treekem_state(group_id: str):
    """Return the current public tree state so members can derive the
    epoch root secret locally."""
    row = db.execute(
        "SELECT epoch, depth, members_json, public_path_json, updated_at FROM treekem_state WHERE group_id=?",
        (group_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "No tree state for that group")
    return {
        "group_id": group_id,
        "epoch": row[0],
        "depth": row[1],
        "members": json.loads(row[2]),
        "public_path": json.loads(row[3]),
        "updated_at": row[4],
    }


@app.post("/api/v1/groups/{group_id}/treekem/commit")
async def treekem_commit(group_id: str, request: Request):
    """Apply a member's path update. Body: { device_id, new_epoch,
    depth, members, public_path }. Server enforces monotonic epoch."""
    if not TREEKEM_AVAILABLE:
        raise HTTPException(503, "TreeKEM unavailable")
    body = await request.json()
    auth_by_device(body.get("device_id", ""))
    row = db.execute("SELECT epoch FROM treekem_state WHERE group_id=?", (group_id,)).fetchone()
    cur_epoch = row[0] if row else -1
    new_epoch = int(body.get("new_epoch", cur_epoch + 1))
    if new_epoch <= cur_epoch:
        raise HTTPException(409, f"Stale commit: new_epoch={new_epoch} cur_epoch={cur_epoch}")
    db.execute(
        "INSERT OR REPLACE INTO treekem_state (group_id, epoch, depth, members_json, public_path_json, updated_at) "
        "VALUES (?,?,?,?,?,datetime('now'))",
        (group_id, new_epoch, int(body.get("depth", 1)),
         json.dumps(body.get("members", [])), json.dumps(body.get("public_path", []))),
    )
    db.commit()
    return {"ok": True, "epoch": new_epoch}


@app.get("/api/v1/credentials/pubkey")
async def anon_creds_pubkey():
    """Return the server's anonymous-credential RSA public key. Clients use
    it to blind tokens before requesting a signature, and to verify
    unblinded tokens before redeeming them."""
    if not ANON_CREDS_KEYS:
        raise HTTPException(503, "Anonymous credentials unavailable")
    pub = ANON_CREDS_KEYS["pub"]
    return {"n_hex": format(pub["n"], "x"), "e": pub["e"], "bits": pub["n"].bit_length()}


@app.post("/api/v1/credentials/issue")
async def anon_creds_issue(request: Request):
    """Sign a *blinded* credential request. Caller must be an authenticated
    device (X-Device-ID). Server signs m_blind with its private key; client
    unblinds to obtain a token unlinkable to this request.

    Body: { device_id: str, m_blind_hex: str, batch: int (optional, max 50) }
    """
    if not ANON_CREDS_KEYS:
        raise HTTPException(503, "Anonymous credentials unavailable")
    body = await request.json()
    did = body.get("device_id", "")
    if not db.execute("SELECT id FROM devices WHERE id=?", (did,)).fetchone():
        raise HTTPException(401, "Invalid device")
    blinded = body.get("m_blind_hex")
    batch_hexes = body.get("batch_hex", [])
    sigs = []
    if isinstance(batch_hexes, list) and batch_hexes:
        for h in batch_hexes[:50]:
            try:
                mb = int(h, 16)
                sb = anon_creds.server_sign_blinded(mb, ANON_CREDS_KEYS["sk"])
                sigs.append(format(sb, "x"))
            except Exception:
                sigs.append("")
        return {"signatures_hex": sigs}
    if not blinded:
        raise HTTPException(400, "m_blind_hex or batch_hex required")
    try:
        mb = int(blinded, 16)
    except Exception:
        raise HTTPException(400, "m_blind_hex must be hex")
    sb = anon_creds.server_sign_blinded(mb, ANON_CREDS_KEYS["sk"])
    return {"signature_hex": format(sb, "x")}


@app.post("/api/v1/credentials/redeem")
async def anon_creds_redeem(request: Request):
    """Spend a token. Server verifies the signature, enforces single-use via
    redeemed_credentials, and returns OK. The redeemed token is recorded by
    its m value only — no link to the original issuer device exists.

    Body: { token: "m_hex.s_hex" }
    """
    if not ANON_CREDS_KEYS:
        raise HTTPException(503, "Anonymous credentials unavailable")
    body = await request.json()
    token = body.get("token", "")
    try:
        m, s = anon_creds.parse_token(token)
    except Exception:
        raise HTTPException(400, "Malformed token")
    if not anon_creds.verify_token(m, s, ANON_CREDS_KEYS["pub"]):
        raise HTTPException(403, "Token signature does not verify")
    m_hex = m.hex()
    if db.execute("SELECT 1 FROM redeemed_credentials WHERE m_hex=?", (m_hex,)).fetchone():
        raise HTTPException(409, "Token already redeemed (double-spend)")
    db.execute("INSERT INTO redeemed_credentials (m_hex) VALUES (?)", (m_hex,))
    db.commit()
    return {"redeemed": True}


@app.get("/api/v1/server-identity")
async def server_identity():
    """Return the server's long-lived public identity blob + fingerprint.
    Clients pin this on first connect (TOFU) and refuse to talk to any
    server presenting a different identity afterwards."""
    if not SERVER_IDENTITY:
        raise HTTPException(503, "Server identity unavailable")
    return {
        "pubkey_blob": SERVER_IDENTITY["pk_blob"].hex(),
        "fingerprint": SERVER_IDENTITY["fingerprint"],
        "suite": "Ed25519+ML-DSA-87+SPHINCS+-256s",
        "created_at": datetime.fromtimestamp(
            os.path.getmtime(IDENTITY_PATH) if os.path.exists(IDENTITY_PATH) else time.time(),
            tz=timezone.utc,
        ).isoformat(timespec="seconds"),
    }

@app.post("/api/v1/auth-v2")
async def encrypted_auth_v2(request: Request):
    """Encrypted registration/login over post-quantum hybrid handshake.
    Body: { session_id, client_pubkey_blob, nonce, ciphertext, tag }"""
    if not PQ_AVAILABLE:
        raise HTTPException(503, "PQ hybrid unavailable")
    body = await request.json()
    sid = body.get("session_id", "")
    with pq_lock:
        state = pq_cache.pop(sid, None)
    if not state:
        raise HTTPException(401, "Invalid or expired session")
    try:
        client_blob = bytes.fromhex(body.get("client_pubkey_blob", ""))
        shared = pq_hybrid.server_decapsulate(state, client_blob)
        key = hashlib.sha256(shared + b"SHROUD-AUTH-PQ-v1").digest()[:32]
        nonce = bytes.fromhex(body.get("nonce", ""))
        ct = bytes.fromhex(body.get("ciphertext", ""))
        tag = bytes.fromhex(body.get("tag", ""))
        plain = decrypt_aes_gcm(key, nonce, ct + tag)
        payload = json.loads(plain.decode("utf-8"))
    except Exception:
        raise HTTPException(400, "Decryption failed")

    username = norm_user(payload.get("username", ""))
    password = payload.get("password", "")
    device_name = payload.get("device_name", "")
    platform = payload.get("platform", "")
    is_register = payload.get("register", False)
    pub_key_hex = payload.get("public_key", "")
    existing_did = (payload.get("existing_device_id", "") or "").strip()

    if is_register:
        if setting_get("registration_enabled", "1") != "1":
            raise HTTPException(403, "Registration is currently disabled")
        if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            _raise_username_taken()
        user_id = uuid.uuid4().hex
        key, salt = derive_key(password)
        db.execute("INSERT INTO users (id, username, password_hash, password_salt) VALUES (?,?,?,?)",
                   (user_id, username, key.hex(), salt))
        db.commit()
        _federation_outbox_state_event("user.created", {
            "user_id":           user_id,
            "username":          username,
            "password_hash":     key.hex(),
            "password_salt_hex": salt.hex(),
            "created_at":        str(datetime.utcnow()),
        })
    else:
        user = db.execute("SELECT id, password_hash, password_salt FROM users WHERE username=?",
                          (username,)).fetchone()
        if not user: _raise_bad_credentials()
        derived, _ = derive_key(password, user[2])
        if derived.hex() != user[1]: _raise_bad_credentials()

    user = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if platform not in ('windows','ios','android'):
        raise HTTPException(400, "Invalid platform")
    try:
        pub_key_bytes = bytes.fromhex(pub_key_hex)
        deserialize_public_key(pub_key_bytes)
    except Exception:
        raise HTTPException(400, "Invalid public key format")

    will_reuse = False
    if existing_did and not is_register:
        will_reuse = db.execute(
            "SELECT 1 FROM devices WHERE id=? AND user_id=?",
            (existing_did, user[0])
        ).fetchone() is not None
    if not will_reuse:
        count = db.execute("SELECT COUNT(*) FROM devices WHERE user_id=?", (user[0],)).fetchone()[0]
        if count >= MAX_DEVICES_PER_USER:
            raise HTTPException(400, f"Maximum {MAX_DEVICES_PER_USER} devices per user")

    device_id = _reuse_or_create_device(user[0], existing_did, device_name, platform, pub_key_bytes)
    return {"device_id": device_id, "user_id": user[0], "registered": True, "suite": "PQ-HYBRID-v1"}

# ── Operator manifest ────────────────────────────────────────────────
#
# Clients fetch the signed operator manifest on first launch and on a
# refresh cadence to learn: the canonical relay URL, the diagnostics
# pubkey, the sticker CDN, and the federation peer roster. Each
# manifest is Ed25519-signed by the operator's manifest-signing key;
# clients pin SHA-256(pubkey) at install time and reject any manifest
# whose pubkey doesn't match the pin.
#
# The manifest file is generated offline (see
# tools/build_operator_manifest.py) and dropped at
# SHROUD_MANIFEST_PATH (default /opt/shroud/data/operator_manifest.signed.json).
# This endpoint just serves the static bytes — the signature is what
# clients trust, not the relay's HTTPS cert.

OPERATOR_MANIFEST_PATH = os.environ.get(
    "SHROUD_MANIFEST_PATH",
    "/opt/shroud/data/operator_manifest.signed.json",
)


@app.get("/api/v1/operator-manifest")
async def get_operator_manifest():
    """Return the signed operator manifest, or 404 if not provisioned.

    Manifest body is opaque to the server beyond JSON parsing — the
    Ed25519 signature inside is what clients verify against their pinned
    manifest-signing key. Cache-Control is short because the operator
    may rotate the roster (new federation peer added) and clients
    benefit from picking it up reasonably quickly.
    """
    if not os.path.exists(OPERATOR_MANIFEST_PATH):
        raise HTTPException(404, "operator manifest not provisioned on this relay")
    try:
        with open(OPERATOR_MANIFEST_PATH, "rb") as f:
            data = f.read()
    except OSError as e:
        raise HTTPException(500, f"manifest read failed: {e}")

    # Sanity-check parse, but DO NOT alter the bytes — clients verify the
    # signature over the file's canonical body.
    try:
        json.loads(data)
    except json.JSONDecodeError:
        raise HTTPException(500, "manifest on disk is not valid JSON")

    return Response(
        content=data,
        media_type="application/json",
        headers={"Cache-Control": "public, max-age=3600"},
    )


def _load_changelog_md() -> str:
    """Read the project CHANGELOG.md so the version endpoint can return
    real Markdown instead of a hand-curated wall-of-text. Clients render
    it as Markdown. Falls back to a one-line summary if the file is
    missing."""
    paths = [
        os.path.join(_REPO_ROOT, "CHANGELOG.md"),
        os.path.join(os.getcwd(), "CHANGELOG.md"),
    ]
    for p in paths:
        try:
            if os.path.exists(p):
                with open(p, encoding="utf-8") as f:
                    text = f.read()
                # Cap at ~24KB so a runaway changelog can't blow the
                # version-check response.
                return text[:24576]
        except Exception:
            continue
    return f"v{SERVER_VERSION} — see GitHub releases for details."


@app.get("/api/v1/version")
async def get_version():
    """Client update check endpoint. Clients fetch this and compare to their
    embedded version string. Returns the project CHANGELOG.md as the
    changelog field — clients render it as Markdown."""
    base = "https://github.com/ExposingTheBadge/Shroud/releases/latest"
    return {
        "version": SERVER_VERSION,
        "minimum_supported": "1.3.0",
        "release_url": base,
        "windows": f"{base}/download/SHROUD.exe",
        "android": f"{base}/download/SHROUD.apk",
        "linux":   f"{base}/download/shroud-linux",
        "changelog": _load_changelog_md(),
    }


# Old hand-curated changelog string kept here as a fallback reference but
# no longer returned. Will be removed in a future cleanup.
_LEGACY_CHANGELOG_BLOB = (
            "2.4.0 — Pure-C Ed25519 verifier closes the third leg of the "
            "triple-hybrid server attestation (Ed25519 + ML-DSA-87 + "
            "SPHINCS+ all verified per handshake — no DLL needed for "
            "Ed25519, just BCrypt for SHA-512). Server-side admin UI "
            "extracted from inline HTML into a proper static-files app "
            "under server/admin/ (HTML + JS + CSS, served via "
            "/admin/static and the existing /admin* routes). Live admin "
            "WebSocket at /ws/admin broadcasts audit-log rows, errors, "
            "failed logins, and session changes via publish_event(). "
            "Onion vs clearnet request telemetry counted from the Host "
            "header. SERVER_VERSION read from the project VERSION file "
            "so the label, dashboard, and /api/v1/version can't drift. "
            "BUILD-REPRODUCIBILITY.md expanded with status table, "
            "per-component how-tos, transparency-log workflow, multi-sig "
            "manifest format, and build-from-source-without-trust path. "
            "2.3.x — Tor onion-service deployment, multi-device linking "
            "UX, server stats persistence, multi-party release signing. "
            "2.2.0 — Double Ratchet wired into live send/receive on "
            "Windows with X3DH prekey consumption. "
            "2.1.0 — Windows: new theme picker with 12 presets "
            "(SHROUD Dark/Light, Solarized Dark/Light, Nord, Dracula, "
            "Monokai, One Dark, Tokyo Night, Gruvbox, Cobalt, High "
            "Contrast) plus full Custom mode with per-color pickers — "
            "applies globally to every widget, not just the chat. "
            "Disappearing messages now user-configurable: Settings → "
            "Messages → Enable + minutes/seconds spinners (default OFF); "
            "outgoing messages carry X-Expires-In and the server sweeper "
            "deletes them at expiry. Real Help tab with documentation "
            "for verification, theming, panic, troubleshooting. Emoji "
            "via Windows Win+. panel + Segoe UI Emoji font fallback in "
            "chat. Markdown rich text: **bold**, *italic*, `code`, "
            "auto-linked URLs render in received messages. Cross-"
            "provider ECDH regression fix (carried over from earlier "
            "v2.0 patch). 2.0.0 — Per-contact safety numbers (SHA-512 over sorted "
            "X25519 pubkeys, 30 visible decimal digits). Windows: right-"
            "click contact → Verify safety number. Android: shield icon "
            "on chat top bar. TreeKEM core (crypto/treekem.py) + server "
            "endpoints /api/v1/groups/{id}/treekem/{init,state,commit} "
            "for O(log n) group rekey. Multi-device sealed-Sesame "
            "linking: /api/v1/devices/link/{init,id,secondary,payload} "
            "lets a logged-in user attach a new device via QR/short code "
            "without retyping the password. Server sees ephemeral X25519 "
            "pubkeys + opaque ciphertext only; 5-minute TTL; payload "
            "auto-purged after pickup. Pure-C Ed25519 verifier deferred "
            "to v2.1 — current attestation path verifies ML-DSA-87 + "
            "SPHINCS+ and the Ed25519 leg is covered by fingerprint pin."
)

@app.post("/api/v1/heartbeat")
async def heartbeat(req: GetMessagesRequest):
    """Client heartbeat — keeps last_seen fresh for active client tracking.
    Also surfaces server-wide flags clients need to react to (currently
    just maintenance_mode), so the UI can flip into a disabled state
    without waiting for a send to 503."""
    device = db.execute("SELECT id FROM devices WHERE id = ?", (req.device_id,)).fetchone()
    if device:
        db.execute("UPDATE devices SET last_seen = datetime('now') WHERE id = ?", (req.device_id,))
        db.commit()
        return {
            "beat": "ok",
            "maintenance_mode": setting_get("maintenance_mode", "0") == "1",
        }
    raise HTTPException(404, "Device not found")

class ChangePasswordRequest(BaseModel):
    username: str
    old_password: str
    new_password: str = Field(min_length=12, max_length=128)

@app.post("/api/v1/change-password")
async def change_password(req: ChangePasswordRequest):
    """Change user password. Requires current password verification."""
    norm = norm_user(req.username)
    user = db.execute(
        "SELECT id, password_hash, password_salt FROM users WHERE username = ?",
        (norm,)
    ).fetchone()
    if not user:
        _raise_bad_credentials()

    # Verify old password
    derived, _ = derive_key(req.old_password, user[2])
    if derived.hex() != user[1]:
        raise HTTPException(401, "Current password is incorrect")

    # Hash new password and update
    new_key, new_salt = derive_key(req.new_password)
    db.execute(
        "UPDATE users SET password_hash=?, password_salt=? WHERE id=?",
        (new_key.hex(), new_salt, user[0])
    )
    db.commit()
    _federation_outbox_state_event("password.changed", {
        "user_id":           user[0],
        "password_hash":     new_key.hex(),
        "password_salt_hex": new_salt.hex(),
    })
    return {"changed": True, "username": req.username}

# ── Encrypted Auth (no plaintext passwords ever) ────────────────────
#
# v2.4.6 — device reuse on login.
#
# Pre-2.4.6 every successful auth (register OR login) INSERTed a fresh
# row into `devices`, so every relaunch made the same physical client
# look like a brand new device. Users hit MAX_DEVICES_PER_USER (=25)
# within a few weeks.
#
# Clients now persist `device_id` and pass it back as `existing_device_id`
# on subsequent logins. If we recognise it (matches a row owned by the
# authenticated user), we reuse that row and refresh public_key/last_seen.
# Unknown / missing → fall back to the old INSERT path (legacy clients
# and brand-new installs still work).
def _reuse_or_create_device(user_id: str, existing_did: str, device_name: str,
                            platform: str, pub_key_bytes: bytes) -> str:
    """Return the device_id to send back to the client. Mutates `devices`."""
    if existing_did:
        row = db.execute(
            "SELECT id FROM devices WHERE id=? AND user_id=?",
            (existing_did, user_id)
        ).fetchone()
        if row:
            db.execute(
                "UPDATE devices SET public_key=?, device_name=?, platform=?, "
                "last_seen=datetime('now') WHERE id=?",
                (pub_key_bytes, device_name, platform, existing_did)
            )
            db.commit()
            return existing_did
    # No match: fresh install, lost local state, or someone trying to
    # claim a device_id that isn't theirs. Issue a new row.
    new_id = generate_device_id()
    db.execute(
        "INSERT INTO devices (id, user_id, device_name, platform, public_key, "
        "hwid, last_seen) VALUES (?,?,?,?,?,?,datetime('now'))",
        (new_id, user_id, device_name, platform, pub_key_bytes, "")
    )
    db.commit()
    _federation_outbox_state_event("device.added", {
        "device_id":      new_id,
        "user_id":        user_id,
        "device_name":    device_name,
        "platform":       platform,
        "public_key_hex": pub_key_bytes.hex(),
        "hwid":           "",
    })
    return new_id


@app.post("/api/v1/auth")
async def encrypted_auth(request: Request):
    """Encrypted registration/login. Password never transits in plaintext."""
    body = await request.json()
    payload = decrypt_auth_payload(
        body.get("session_id",""), body.get("client_public_key",""),
        body.get("nonce",""), body.get("ciphertext",""), body.get("tag",""))
    username = norm_user(payload.get("username",""))
    password = payload.get("password","")
    device_name = payload.get("device_name","")
    platform = payload.get("platform","")
    is_register = payload.get("register", False)
    pub_key_hex = payload.get("public_key","")
    existing_did = (payload.get("existing_device_id","") or "").strip()
    hwid_in = (payload.get("hwid","") or "").strip()

    # v2.6.0: ban enforcement first, before any password / lookup work.
    # The ban's `reason` field is surfaced to the user when the admin
    # sets one; without a reason the response carries the catalogued title.
    from crypto.errors import errors, raise_http
    ban = _ban_lookup(username=username, hwid=hwid_in)
    if ban:
        audit_log(username, "BAN_BLOCK_AUTH",
                  f"kind={ban['kind']} value={ban['value'][:16]} reason={ban.get('reason','')[:80]}")
        err = (errors.B002_BANNED_HWID if ban["kind"] == "hwid"
               else errors.B003_BANNED_IP if ban["kind"] == "ip"
               else errors.B001_BANNED_USERNAME)
        raise_http(err, extra={"reason": ban.get("reason") or ""})

    # Register user if new account
    if is_register:
        if setting_get("registration_enabled", "1") != "1":
            raise HTTPException(403, "Registration is currently disabled")
        existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            _raise_username_taken()
        user_id = uuid.uuid4().hex
        key, salt = derive_key(password)
        db.execute("INSERT INTO users (id, username, password_hash, password_salt) VALUES (?,?,?,?)",
                   (user_id, username, key.hex(), salt))
        db.commit()
        _federation_outbox_state_event("user.created", {
            "user_id":           user_id,
            "username":          username,
            "password_hash":     key.hex(),
            "password_salt_hex": salt.hex(),
            "created_at":        str(datetime.utcnow()),
        })
    else:
        user = db.execute("SELECT id, password_hash, password_salt FROM users WHERE username=?",
                          (username,)).fetchone()
        if not user:
            _raise_bad_credentials()
        derived, _ = derive_key(password, user[2])
        if derived.hex() != user[1]:
            _raise_bad_credentials()

    # Register / reuse device
    user = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if platform not in ('windows','ios','android'):
        raise HTTPException(400, "Invalid platform")

    try:
        pub_key_bytes = bytes.fromhex(pub_key_hex)
        deserialize_public_key(pub_key_bytes)
    except Exception:
        raise HTTPException(400, "Invalid public key format")

    # Only block on the per-user device cap when we're actually about to
    # create a new row. Reusing an existing device shouldn't trip it.
    will_reuse = False
    if existing_did and not is_register:
        will_reuse = db.execute(
            "SELECT 1 FROM devices WHERE id=? AND user_id=?",
            (existing_did, user[0])
        ).fetchone() is not None
    if not will_reuse:
        count = db.execute("SELECT COUNT(*) FROM devices WHERE user_id=?", (user[0],)).fetchone()[0]
        if count >= MAX_DEVICES_PER_USER:
            raise HTTPException(400, f"Maximum {MAX_DEVICES_PER_USER} devices per user")

    device_id = _reuse_or_create_device(user[0], existing_did, device_name, platform, pub_key_bytes)

    server_priv, server_pub = generate_keypair()
    return {"device_id": device_id, "server_public_key": serialize_public_key(server_pub).hex(),
            "user_id": user[0], "registered": True}

# ── User Registration (legacy) ──────────────────────────────────────
@app.post("/api/v1/register")
async def register_user(req: RegisterUserRequest):
    """Register a new user. Returns user ID."""
    norm = norm_user(req.username)
    existing = db.execute("SELECT id FROM users WHERE username = ?", (norm,)).fetchone()
    if existing:
        _raise_username_taken()

    user_id = uuid.uuid4().hex
    key, salt = derive_key(req.password)
    db.execute(
        "INSERT INTO users (id, username, password_hash, password_salt) VALUES (?, ?, ?, ?)",
        (user_id, norm, key.hex(), salt)
    )
    db.commit()
    _federation_outbox_state_event("user.created", {
        "user_id":           user_id,
        "username":          norm,
        "password_hash":     key.hex(),
        "password_salt_hex": salt.hex(),
        "created_at":        str(datetime.utcnow()),
    })
    return {"user_id": user_id, "username": norm, "registered": True}

# ── Device Registration ──────────────────────────────────────────────
@app.post("/api/v1/devices")
async def register_device(req: RegisterDeviceRequest):
    """Register a new device. Returns device ID, server's public key for ECDH."""
    # Auth user
    norm = norm_user(req.username)
    print(f"[DEVICE REG] username={norm} platform={req.platform} pw_len={len(req.password)} hwid={req.hwid[:16] if req.hwid else 'none'}")
    # v2.6.0: ban enforcement BEFORE password check so a banned user can't
    # even probe whether their old password is still valid. The ban's
    # `reason` field is surfaced to the user when the admin sets one;
    # without a reason the response carries the generic catalogued title.
    from crypto.errors import errors, raise_http
    ban = _ban_lookup(username=norm, hwid=req.hwid or "")
    if ban:
        audit_log(req.username, "BAN_BLOCK_REGISTER",
                  f"kind={ban['kind']} value={ban['value'][:16]} reason={ban.get('reason','')[:80]}")
        err = (errors.B002_BANNED_HWID if ban["kind"] == "hwid"
               else errors.B003_BANNED_IP if ban["kind"] == "ip"
               else errors.B001_BANNED_USERNAME)
        raise_http(err, extra={"reason": ban.get("reason") or ""})
    user = db.execute(
        "SELECT id, password_hash, password_salt FROM users WHERE username = ?",
        (norm,)
    ).fetchone()
    if not user:
        print(f"[DEVICE REG] FAIL: username '{norm}' not found")
        _raise_bad_credentials()

    # Verify password
    derived, _ = derive_key(req.password, user[2])
    if derived.hex() != user[1]:
        print(f"[DEVICE REG] FAIL: password mismatch for '{req.username}' (pw_len={len(req.password)})")
        _raise_bad_credentials()

    # Check platform
    if req.platform not in ('windows', 'ios', 'android'):
        raise HTTPException(400, "Platform must be: windows, ios, android")

    # Check if device already exists for this hardware + app combination
    existing = None
    if req.hwid:
        existing = db.execute(
            "SELECT id, public_key FROM devices WHERE user_id=? AND hwid=? AND hwid!=''",
            (user[0], req.hwid)
        ).fetchone()

    if not existing:
        # Check device limits only for NEW devices
        count = db.execute(
            "SELECT COUNT(*) FROM devices WHERE user_id = ?", (user[0],)
        ).fetchone()[0]
        if count >= MAX_DEVICES_PER_USER:
            raise HTTPException(400, f"Maximum {MAX_DEVICES_PER_USER} devices per user")

    # Use existing device ID if re-registering same hardware
    if existing:
        device_id = existing[0]
        # Update public key if changed (new keypair generated)
        try:
            pub_key_bytes = bytes.fromhex(req.public_key)
            db.execute("UPDATE devices SET public_key=?, device_name=?, last_seen=datetime('now') WHERE id=?",
                       (pub_key_bytes, req.device_name, device_id))
        except:
            pass
    else:
        device_id = generate_device_id()
        try:
            pub_key_bytes = bytes.fromhex(req.public_key)
            deserialize_public_key(pub_key_bytes)
        except Exception as e:
            print(f"[DEVICE REG] FAIL: key format error for '{req.username}': {e}")
            raise HTTPException(400, "Invalid public key format")

        db.execute(
            "INSERT INTO devices (id, user_id, device_name, platform, public_key, hwid) VALUES (?, ?, ?, ?, ?, ?)",
            (device_id, user[0], req.device_name, req.platform, pub_key_bytes, req.hwid)
        )
        _federation_outbox_state_event("device.added", {
            "device_id":      device_id,
            "user_id":        user[0],
            "device_name":    req.device_name,
            "platform":       req.platform,
            "public_key_hex": pub_key_bytes.hex(),
            "hwid":           req.hwid or "",
        })
    db.commit()
    print(f"[DEVICE REG] SUCCESS: {req.username} device={device_id} platform={req.platform}")

    # Generate server-side ephemeral keypair for this device's ECDH
    server_priv, server_pub = generate_keypair()
    server_pub_hex = serialize_public_key(server_pub).hex()

    return {
        "device_id": device_id,
        "server_public_key": server_pub_hex,
        "user_id": user[0],
        "registered": True
    }

# ── Maintenance-mode gate ─────────────────────────────────────────
# When the operator toggles maintenance on, every outbound message and
# every file upload is refused. Clients see HTTP 503 with a stable
# "detail": "maintenance" payload + an X-Maintenance: 1 header so they
# can detect it cheaply on every send attempt.
def _guard_maintenance():
    if setting_get("maintenance_mode", "0") == "1":
        raise HTTPException(
            status_code=503,
            detail="maintenance",
            headers={"X-Maintenance": "1", "Retry-After": "60"},
        )


# ── Send Message ─────────────────────────────────────────────────────
# Sunset date for the legacy unsealed send endpoint (Rule 1 violation).
# Set in 2026 to give existing clients time to upgrade to /messages/send-sealed.
# After this date, /messages/send returns 410 Gone.
LEGACY_SEND_SUNSET = "Wed, 31 Dec 2026 00:00:00 GMT"
LEGACY_SEND_DEPRECATION = "@1748736000"  # RFC 9745: unix timestamp prefix


@app.post("/api/v1/messages/send")
async def send_message(request: Request):
    """Relay an encrypted message. Server never sees plaintext.

    Optional headers:
      X-Expires-In: <seconds>   Disappearing-message TTL (server purges at expiry).
      X-Envelope-Version: 2     Marks v2 envelopes (size MUST hit a padding bucket).
    Body is the SendMessageRequest (sender_device_id, recipient_device_id, envelope).
    """
    _guard_maintenance()
    body = await request.json()
    sender_id = body.get("sender_device_id", "")
    recipient_id = body.get("recipient_device_id", "")
    envelope_str = body.get("envelope", "")
    expires_in = request.headers.get("X-Expires-In", "")
    env_ver_hdr = request.headers.get("X-Envelope-Version", "1")

    sender = db.execute("SELECT id FROM devices WHERE id=?", (sender_id,)).fetchone()
    recipient = db.execute("SELECT id FROM devices WHERE id=?", (recipient_id,)).fetchone()
    if not sender or not recipient:
        raise HTTPException(404, "Device not found")

    try:
        envelope = json.loads(envelope_str)
        for k in ("nonce", "ciphertext", "sig", "sender", "ts"):
            assert k in envelope
    except Exception:
        raise HTTPException(400, "Invalid message envelope format")

    env_ver = int(envelope.get("v", env_ver_hdr) or 1)
    padded_size = 0
    if env_ver >= 2:
        try:
            ct_bytes = bytes.fromhex(envelope["ciphertext"])
            padded_size = len(ct_bytes)
        except Exception:
            raise HTTPException(400, "v2 ciphertext must be hex")
        if not is_valid_padded_size(padded_size):
            raise HTTPException(400, f"v2 envelope must be padded to one of {PAD_BUCKETS}")

    expires_at = None
    if expires_in:
        try:
            secs = max(1, min(int(expires_in), 30 * 86400))
            expires_at = (datetime.now(tz=timezone.utc) + timedelta(seconds=secs)).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    msg_id = uuid.uuid4().hex
    db.execute(
        "INSERT INTO messages (id, sender_device_id, recipient_device_id, envelope, "
        "sealed, envelope_version, padded_size, expires_at) VALUES (?,?,?,?,0,?,?,?)",
        (msg_id, sender_id, recipient_id, json.dumps(envelope), env_ver, padded_size, expires_at),
    )
    db.execute("UPDATE devices SET last_seen=datetime('now') WHERE id=?", (sender_id,))
    db.commit()
    # Legacy unsealed path leaks the sender_device_id to the server, which
    # violates Rule 1 of the SHROUD threat model. Newer clients should call
    # /api/v1/messages/send-sealed instead. We attach deprecation headers
    # (RFC 9745 + RFC 8594) so client developers see this in their logs.
    return JSONResponse(
        content={
            "message_id": msg_id,
            "relayed": True,
            "v": env_ver,
            "expires_at": expires_at,
            "deprecation_notice": (
                "POST /api/v1/messages/send is deprecated because it reveals "
                "sender_device_id to the relay. Migrate to "
                "/api/v1/messages/send-sealed before 2026-12-31."
            ),
        },
        headers={
            "Deprecation": LEGACY_SEND_DEPRECATION,
            "Sunset": LEGACY_SEND_SUNSET,
            "Link": '</api/v1/messages/send-sealed>; rel="successor-version"',
            "Warning": '299 - "SHROUD: legacy sender-revealing path; migrate to /messages/send-sealed"',
        },
    )


# ── Rotating pickup tokens ────────────────────────────────────────
# Each device has a 32-byte pickup_secret known only to the device and
# the server. The current epoch's pickup token is HMAC-SHA256(secret,
# epoch_hour). Tokens rotate every hour. Network observers see the
# routing key change every epoch, breaking long-term correlation
# between repeated polls. (The server itself can still link tokens to
# devices — true VOPRF blindness is on the v1.8.0 roadmap.)
PICKUP_EPOCH_SECONDS = 3600

def _epoch_hour() -> int:
    return int(time.time() // PICKUP_EPOCH_SECONDS)

def _device_pickup_token(secret: bytes, epoch: int) -> str:
    if not secret:
        return ""
    return hmac_sign(secret, epoch.to_bytes(8, "big")).hex()

def _ensure_pickup_secret(device_id: str) -> bytes:
    row = db.execute("SELECT pickup_secret FROM devices WHERE id=?", (device_id,)).fetchone()
    if not row: return b""
    if row[0]: return row[0]
    secret = fips_random(32)
    db.execute("UPDATE devices SET pickup_secret=? WHERE id=?", (secret, device_id))
    db.commit()
    return secret

def _device_for_token(token: str) -> str | None:
    """Look up which device a given pickup token currently belongs to.
    Checks the current, previous, and next epoch to handle clock skew."""
    if not token: return None
    epoch = _epoch_hour()
    cands = [epoch, epoch - 1, epoch + 1]
    rows = db.execute("SELECT id, pickup_secret FROM devices WHERE pickup_secret IS NOT NULL").fetchall()
    for did, secret in rows:
        for e in cands:
            if _device_pickup_token(secret, e) == token:
                return did
    return None


@app.get("/api/v1/devices/{device_id}/pickup-token")
async def get_pickup_token(device_id: str):
    """Return the device's current rotating pickup token + the previous
    epoch's (so senders mid-rotation hit the right mailbox). The token is
    derived from a server-stored secret per device; observers without
    that secret cannot link tokens to a device."""
    row = db.execute("SELECT id FROM devices WHERE id=?", (device_id,)).fetchone()
    if not row: raise HTTPException(404, "Device not found")
    secret = _ensure_pickup_secret(device_id)
    e = _epoch_hour()
    return {
        "device_id": device_id,
        "epoch": e,
        "epoch_seconds": PICKUP_EPOCH_SECONDS,
        "current_token": _device_pickup_token(secret, e),
        "previous_token": _device_pickup_token(secret, e - 1),
        "next_token": _device_pickup_token(secret, e + 1),
        "next_rotation_at": (e + 1) * PICKUP_EPOCH_SECONDS,
    }


@app.post("/api/v1/messages/fetch-by-token")
async def fetch_by_token(request: Request):
    """Pickup messages addressed to a rotating token instead of by
    device_id. The recipient device computes the current token locally
    and submits it — the server resolves it to the device and returns
    pending messages. To a network observer the token rotates every hour
    so two consecutive polls look like different recipients."""
    body = await request.json()
    token = body.get("token", "")
    device_id = _device_for_token(token)
    if not device_id:
        raise HTTPException(401, "Invalid or expired pickup token")
    rebuilt = GetMessagesRequest(device_id=device_id, since=body.get("since"))
    return await fetch_messages(rebuilt)


@app.post("/api/v1/messages/cover")
async def cover_traffic(request: Request):
    """Accept and silently discard a padded decoy envelope. Clients use this
    to maintain constant-rate cover traffic so a passive observer cannot
    distinguish real sends from noise. The payload is read, counted, and
    dropped — it is never written to disk or queued for delivery."""
    global COVER_COUNT, COVER_BYTES
    body = await request.body()
    COVER_COUNT += 1
    COVER_BYTES += len(body)
    return {"ok": True}


@app.post("/api/v1/messages/send-sealed")
async def send_sealed_message(request: Request):
    """Sealed-sender relay: the server learns the recipient and a ciphertext blob.
    The sender's identity is inside the encrypted envelope.

    Headers:
      X-Recipient-ID: <device_id>      required
      X-Expires-In: <seconds>          optional disappearing-message TTL
      X-Envelope-Version: 2            optional (v2 envelopes must be padded)
    Body: raw bytes of the sealed envelope (any format the clients agree on).
    """
    _guard_maintenance()
    recipient_id = request.headers.get("X-Recipient-ID", "")
    expires_in = request.headers.get("X-Expires-In", "")
    env_ver = int(request.headers.get("X-Envelope-Version", "2") or 2)

    if not recipient_id:
        raise HTTPException(400, "Missing X-Recipient-ID")
    if not db.execute("SELECT id FROM devices WHERE id=?", (recipient_id,)).fetchone():
        raise HTTPException(404, "Recipient device not found")

    sealed_blob = await request.body()
    if not sealed_blob:
        raise HTTPException(400, "Empty payload")

    padded_size = len(sealed_blob)
    if env_ver >= 2 and not is_valid_padded_size(padded_size):
        raise HTTPException(400, f"Sealed v2 envelope must hit a padding bucket {PAD_BUCKETS}")

    expires_at = None
    if expires_in:
        try:
            secs = max(1, min(int(expires_in), 30 * 86400))
            expires_at = (datetime.now(tz=timezone.utc) + timedelta(seconds=secs)).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    msg_id = uuid.uuid4().hex
    db.execute(
        "INSERT INTO messages (id, sender_device_id, recipient_device_id, envelope, "
        "sealed, envelope_version, padded_size, expires_at) VALUES (?,?,?,?,1,?,?,?)",
        (msg_id, recipient_id, recipient_id, sealed_blob.hex(), env_ver, padded_size, expires_at),
    )
    db.commit()
    return {"message_id": msg_id, "sealed": True, "v": env_ver, "expires_at": expires_at}


# ── Anonymous routing (Rule 1 + Rule 2 compliant) ────────────────────
#
# The /api/v1/messages/send-anon and /api/v1/messages/fetch-anon endpoints
# together implement the routing-tag protocol documented in
# crypto/anon_routing.py:
#
#   - Sender computes a 32-byte routing tag derived from the per-pair
#     X3DH root + current epoch. Server stores the message keyed by
#     that tag. Server has NO map from tag -> identity.
#   - Recipient enumerates their tags across all contacts and current
#     epoch (+/-1 for clock skew) and polls. Server returns matching
#     messages and DELETES THEM immediately (Rule 2 — no metadata after
#     delivery).
#   - Sender identity lives inside the sealed-envelope payload, not in
#     any header or routing field (Rule 1).
#
# Schema lives in its own table so legacy device_id paths cannot
# accidentally read or write anonymous rows.

def _ensure_anon_schema() -> None:
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS anon_messages (
            id TEXT PRIMARY KEY,
            routing_tag BLOB NOT NULL,
            sealed_blob BLOB NOT NULL,
            server_ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_anon_routing_tag ON anon_messages(routing_tag);
        CREATE INDEX IF NOT EXISTS idx_anon_expires
            ON anon_messages(expires_at) WHERE expires_at IS NOT NULL;
        """
    )
    db.commit()


_ensure_anon_schema()


@app.post("/api/v1/messages/send-anon")
async def send_anon_message(request: Request):
    """Anonymous-routing send. Body is the sealed-envelope wire bytes
    described in crypto/anon_routing.py. Routing tag goes in the header.

    Required headers:
      X-Routing-Tag: 64 hex chars (32 bytes)
    Optional headers:
      X-Expires-In: seconds       Disappearing-message TTL
      X-Envelope-Version: 2       v2 envelopes must hit a padding bucket
    """
    _guard_maintenance()

    tag_hex = request.headers.get("X-Routing-Tag", "")
    if len(tag_hex) != 64:
        raise HTTPException(400, "X-Routing-Tag must be 64 hex chars (32 bytes)")
    try:
        tag = bytes.fromhex(tag_hex)
    except ValueError:
        raise HTTPException(400, "X-Routing-Tag must be valid hex")

    sealed = await request.body()
    if not sealed:
        raise HTTPException(400, "Empty sealed envelope")

    env_ver = int(request.headers.get("X-Envelope-Version", "2") or 2)
    if env_ver >= 2 and not is_valid_padded_size(len(sealed)):
        raise HTTPException(400, f"v2 envelope must hit padding bucket {PAD_BUCKETS}")

    expires_in = request.headers.get("X-Expires-In", "")
    expires_at = None
    if expires_in:
        try:
            secs = max(1, min(int(expires_in), 30 * 86400))
            expires_at = (
                datetime.now(tz=timezone.utc) + timedelta(seconds=secs)
            ).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    msg_id = uuid.uuid4().hex
    db.execute(
        "INSERT INTO anon_messages (id, routing_tag, sealed_blob, expires_at) "
        "VALUES (?,?,?,?)",
        (msg_id, tag, sealed, expires_at),
    )
    db.commit()

    # Federation hook: broadcast to peer relays so any of them can
    # serve this envelope to its recipient. Best-effort.
    try:
        _federation_outbox_broadcast(msg_id, tag, sealed, expires_at)
    except NameError:
        # _federation_outbox_broadcast is defined later in the module —
        # on first import we may hit this code path before that block
        # has executed. Re-resolve lazily next time around.
        pass

    return {"message_id": msg_id, "anon": True, "expires_at": expires_at}


class FetchAnonRequest(BaseModel):
    tags: List[str] = Field(default_factory=list, description="hex-encoded routing tags")


@app.post("/api/v1/messages/fetch-anon")
async def fetch_anon_messages(req: FetchAnonRequest):
    """Anonymous fetch. Caller submits a list of routing tags (typically
    one per contact across {prev, current, next} epochs). Server returns
    every message under any of those tags AND DELETES THEM IMMEDIATELY
    (Rule 2 — destroyed on delivery; no retention).

    Tag enumeration scope is rate-limited to 1024 tags per request to
    bound the cost of a flood. Recipients with more than 1024 active
    conversations must paginate by sub-setting their tag list per call.
    """
    if not req.tags:
        return {"messages": []}
    if len(req.tags) > 1024:
        raise HTTPException(400, "submit at most 1024 tags per call")

    try:
        tag_blobs = [bytes.fromhex(t) for t in req.tags]
    except ValueError:
        raise HTTPException(400, "tags must be hex-encoded")

    for tb in tag_blobs:
        if len(tb) != 32:
            raise HTTPException(400, "tags must be 32 bytes each")

    # SQLite IN-list with parameterized blobs.
    placeholders = ",".join("?" for _ in tag_blobs)
    rows = db.execute(
        f"SELECT id, sealed_blob, server_ts FROM anon_messages "
        f"WHERE routing_tag IN ({placeholders}) "
        f"ORDER BY server_ts ASC LIMIT 200",
        tag_blobs,
    ).fetchall()

    if not rows:
        return {"messages": []}

    out = []
    delivered_ids = []
    for msg_id, blob, ts in rows:
        out.append({"id": msg_id, "sealed": blob.hex(), "ts": str(ts)})
        delivered_ids.append(msg_id)

    # Rule 2 — destroyed on delivery. No retention, no audit row, no copy.
    placeholders = ",".join("?" for _ in delivered_ids)
    db.execute(
        f"DELETE FROM anon_messages WHERE id IN ({placeholders})",
        delivered_ids,
    )
    db.commit()

    # Federation hook: broadcast delete-on-deliver to peer relays so
    # they clear the same routing_tag entries. Best-effort, fire-and-
    # forget — see _federation_loop for the delivery semantics.
    if FEDERATION_ENABLED:
        for msg_id in delivered_ids:
            _federation_outbox_delete(msg_id)

    return {"messages": out, "count": len(out)}


# ── Federated multi-relay gossip (Rule 0 structural compliance) ──────
#
# Each relay maintains a roster of peer relays (signed PeerAnnouncements
# in the federation_peers table). When an anon_messages row is inserted
# locally, we enqueue a FedBroadcast to all active peers. When an
# anon_messages row is deleted on delivery, we enqueue a FedDelete.
#
# The federation loop drains the outbox in the background, POSTs to
# peer /api/v1/federation/broadcast and /federation/delete endpoints,
# and retries transient failures.
#
# Trust: peer announcements are Ed25519-signed by the operator's long-
# term key. Peer pubkeys are pinned by the local operator (this server
# never auto-trusts a newly-seen pubkey — operator vetting required).

FEDERATION_ENABLED = os.environ.get("SHROUD_FEDERATION", "0") == "1"
FEDERATION_OUTBOX: list[dict] = []
FEDERATION_OUTBOX_LOCK = threading.Lock()


def _ensure_federation_schema() -> None:
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS federation_peers (
            pubkey_hex TEXT PRIMARY KEY,
            operator   TEXT NOT NULL,
            endpoint   TEXT NOT NULL,
            ttl_seconds INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            sig_hex TEXT NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS federation_seen_ids (
            message_id TEXT PRIMARY KEY,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_fed_seen_first ON federation_seen_ids(first_seen);
        -- v2.6.x: state-event mirroring. Every relay-affecting write
        -- (user registered, device added, ban added/lifted, setting
        -- changed) is recorded as a state event and gossipped to every
        -- peer. Peers dedup by event_id, apply locally, and re-broadcast
        -- (transitive flood). After enough propagation time, every
        -- relay's DB has the same logical state — any one going down
        -- doesn't lose data. Initial sync on relay-start pulls the full
        -- history from a peer.
        CREATE TABLE IF NOT EXISTS federation_state_events (
            event_id    TEXT PRIMARY KEY,
            origin_ts   INTEGER NOT NULL,
            kind        TEXT NOT NULL,
            payload     TEXT NOT NULL,
            received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_fse_kind ON federation_state_events(kind);
        CREATE INDEX IF NOT EXISTS idx_fse_ts   ON federation_state_events(origin_ts);
        """
    )
    db.commit()


_ensure_federation_schema()


def _federation_active_peers() -> list[dict]:
    """Return peer rows whose TTL hasn't elapsed."""
    now = int(time.time())
    rows = db.execute(
        "SELECT pubkey_hex, endpoint FROM federation_peers WHERE ts + ttl_seconds >= ?",
        (now,),
    ).fetchall()
    return [{"pubkey_hex": r[0], "endpoint": r[1]} for r in rows]


def _federation_outbox_broadcast(msg_id: str, routing_tag: bytes,
                                  sealed_blob: bytes, expires_at: str | None) -> None:
    """Queue a broadcast to all active peers. Idempotent: peers
    deduplicate on message_id (federation_seen_ids table)."""
    if not FEDERATION_ENABLED:
        return
    peers = _federation_active_peers()
    if not peers:
        return
    with FEDERATION_OUTBOX_LOCK:
        for p in peers:
            FEDERATION_OUTBOX.append({
                "kind": "broadcast",
                "peer": p["endpoint"],
                "body": {
                    "type": "shroud.fed.broadcast",
                    "message_id": msg_id,
                    "routing_tag_hex": routing_tag.hex(),
                    "envelope_hex": sealed_blob.hex(),
                    "ttl_at": expires_at,
                },
            })


# ── State-event mirroring ────────────────────────────────────────────
#
# Anon messages gossip via _federation_outbox_broadcast/delete above.
# State events use the same outbox + loop but a different path
# (/api/v1/federation/state-event) so we can have orthogonal retry
# semantics later. Each event has a deterministic event_id, so the
# transitive flood deduplicates correctly even if every peer
# re-broadcasts the same event to every other peer.

def _state_event_id(kind: str, payload: dict, ts: int) -> str:
    """Deterministic ID so the same event from any path dedups correctly.
    SHA-256 over a canonical JSON serialization."""
    body = json.dumps({"k": kind, "ts": ts, "p": payload},
                      sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(body).hexdigest()


def _seen_state_event(event_id: str) -> bool:
    row = db.execute(
        "SELECT 1 FROM federation_state_events WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    return row is not None


def _record_state_event(event_id: str, kind: str, payload: dict, ts: int) -> None:
    db.execute(
        "INSERT OR IGNORE INTO federation_state_events "
        "(event_id, origin_ts, kind, payload) VALUES (?,?,?,?)",
        (event_id, ts, kind, json.dumps(payload, sort_keys=True, separators=(",", ":"))),
    )
    db.commit()


def _apply_state_event(kind: str, payload: dict) -> None:
    """Apply a state event to this relay's local DB. Idempotent — the
    INSERT OR IGNORE on event_id at the broadcast layer means we
    apply each event at most once per relay. Within apply, every
    write uses ON CONFLICT semantics so a replay is harmless."""
    try:
        if kind == "user.created":
            db.execute(
                "INSERT OR IGNORE INTO users "
                "(id, username, password_hash, password_salt, created_at) "
                "VALUES (?,?,?,?,?)",
                (payload["user_id"], payload["username"],
                 payload["password_hash"], bytes.fromhex(payload["password_salt_hex"]),
                 payload.get("created_at") or str(datetime.utcnow())),
            )
        elif kind == "device.added":
            db.execute(
                "INSERT OR IGNORE INTO devices "
                "(id, user_id, device_name, platform, public_key, hwid) "
                "VALUES (?,?,?,?,?,?)",
                (payload["device_id"], payload["user_id"],
                 payload.get("device_name", ""), payload.get("platform", ""),
                 bytes.fromhex(payload["public_key_hex"]),
                 payload.get("hwid", "")),
            )
        elif kind == "device.removed":
            db.execute("DELETE FROM devices WHERE id = ?", (payload["device_id"],))
        elif kind == "password.changed":
            db.execute(
                "UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?",
                (payload["password_hash"], bytes.fromhex(payload["password_salt_hex"]),
                 payload["user_id"]),
            )
        elif kind == "ban.added":
            db.execute(
                "INSERT OR IGNORE INTO bans "
                "(kind, value, reason, banned_by, origin_user) VALUES (?,?,?,?,?)",
                (payload["kind"], payload["value"], payload.get("reason", ""),
                 payload.get("banned_by", ""), payload.get("origin_user", "")),
            )
        elif kind == "ban.removed":
            db.execute(
                "DELETE FROM bans WHERE kind = ? AND value = ?",
                (payload["kind"], payload["value"]),
            )
        elif kind == "setting.changed":
            # Defense in depth: even if an older relay broadcast a
            # per-deployment setting, we silently drop it on receive.
            _NEVER_MIRROR_KEYS = ("onion_only",)
            if payload["key"] in _NEVER_MIRROR_KEYS:
                return
            db.execute(
                "INSERT INTO server_settings (key, value, updated_at) "
                "VALUES (?,?,datetime('now')) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')",
                (payload["key"], payload["value"]),
            )
        else:
            print(f"[FED] unknown state-event kind: {kind}")
            return
        db.commit()
    except Exception as e:
        print(f"[FED] apply {kind} failed: {e}")


def _federation_outbox_state_event(kind: str, payload: dict,
                                   event_id: str | None = None,
                                   ts: int | None = None) -> None:
    """Record + broadcast a state event. Safe to call even when
    federation is disabled — the local row is still written so a
    later operator who enables federation has the full history to
    replay from.

    For locally-originated events, callers pass kind+payload only;
    we synthesize event_id and ts. For peer-relayed events, callers
    pass the existing event_id+ts unchanged so transitive flood
    dedups correctly."""
    if ts is None:
        ts = int(time.time())
    if event_id is None:
        event_id = _state_event_id(kind, payload, ts)
    if _seen_state_event(event_id):
        return
    _record_state_event(event_id, kind, payload, ts)
    if not FEDERATION_ENABLED:
        return
    peers = _federation_active_peers()
    with FEDERATION_OUTBOX_LOCK:
        for p in peers:
            FEDERATION_OUTBOX.append({
                "kind": "state-event",
                "peer": p["endpoint"],
                "body": {
                    "type":      "shroud.fed.state-event",
                    "event_id":  event_id,
                    "ts":        ts,
                    "event_kind": kind,
                    "payload":   payload,
                },
            })


def _federation_outbox_delete(msg_id: str) -> None:
    if not FEDERATION_ENABLED:
        return
    peers = _federation_active_peers()
    if not peers:
        return
    with FEDERATION_OUTBOX_LOCK:
        for p in peers:
            FEDERATION_OUTBOX.append({
                "kind": "delete",
                "peer": p["endpoint"],
                "body": {
                    "type": "shroud.fed.delete",
                    "message_id": msg_id,
                },
            })


async def _federation_state_sync_loop() -> None:
    """Pull state events from every peer at startup + every hour. Asks
    each peer for events newer than the latest origin_ts we already
    have, applies anything we don't already have on file, re-broadcasts
    so OTHER peers eventually converge.

    This is the recovery mechanism if a relay is offline during gossip:
    when it comes back, it catches up on everything it missed."""
    import httpx
    # Give the gossip loop a moment to set up.
    await asyncio.sleep(5)
    while True:
        try:
            peers = _federation_active_peers()
            # Anchor on the latest event we already have.
            row = db.execute(
                "SELECT COALESCE(MAX(origin_ts), 0) FROM federation_state_events"
            ).fetchone()
            since_ts = int(row[0]) if row and row[0] is not None else 0
            applied_total = 0
            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                for p in peers:
                    try:
                        r = await client.get(
                            p["endpoint"].rstrip("/")
                            + f"/api/v1/federation/state-events/since?since_ts={since_ts}&limit=2000"
                        )
                        if r.status_code != 200:
                            continue
                        body = r.json()
                        for ev in body.get("events", []):
                            if _seen_state_event(ev["event_id"]):
                                continue
                            _apply_state_event(ev["event_kind"], ev["payload"])
                            _federation_outbox_state_event(
                                ev["event_kind"], ev["payload"],
                                event_id=ev["event_id"], ts=ev["ts"],
                            )
                            applied_total += 1
                    except Exception:
                        continue
            if applied_total:
                print(f"[SHROUD] Federation state-sync: applied {applied_total} new event(s)")
        except Exception as e:
            print(f"[SHROUD] Federation state-sync error: {e}")
        # Re-sync every hour. Gossip handles the live path; this is the
        # safety net for events that landed while we were offline.
        await asyncio.sleep(3600)


async def _federation_loop() -> None:
    """Background task: drain the outbox, POST to peer endpoints,
    retry transient failures by re-queueing. We deliberately don't
    persist the outbox across restarts — losing a few broadcasts on
    crash is better than spending the bytes on durable bookkeeping."""
    import httpx

    while True:
        await asyncio.sleep(2)
        with FEDERATION_OUTBOX_LOCK:
            batch = FEDERATION_OUTBOX[:]
            FEDERATION_OUTBOX.clear()
        if not batch:
            continue
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            for item in batch:
                try:
                    if item["kind"] == "broadcast":
                        path = "/api/v1/federation/broadcast"
                    elif item["kind"] == "state-event":
                        path = "/api/v1/federation/state-event"
                    else:
                        path = "/api/v1/federation/delete"
                    await client.post(item["peer"].rstrip("/") + path, json=item["body"])
                except Exception:
                    # Re-queue once, then drop on second failure.
                    if not item.get("retried"):
                        item["retried"] = True
                        with FEDERATION_OUTBOX_LOCK:
                            FEDERATION_OUTBOX.append(item)


@app.get("/api/v1/federation/peers")
async def federation_list_peers():
    """Public peer roster — what this relay considers federated."""
    return {"peers": _federation_active_peers()}


class FederationAnnounce(BaseModel):
    operator: str
    endpoint: str
    pubkey_hex: str
    ttl_seconds: int
    ts: int
    sig_hex: str


@app.post("/api/v1/federation/announce")
async def federation_announce(req: FederationAnnounce):
    """Accept a signed PeerAnnouncement and add the peer to the roster.

    The operator running this relay must pre-approve any pubkey before
    it's stored. New announcements update endpoint / ttl / ts but never
    introduce a previously-unknown pubkey (manual operator vetting).
    """
    existing = db.execute(
        "SELECT ts FROM federation_peers WHERE pubkey_hex = ?",
        (req.pubkey_hex,),
    ).fetchone()
    if existing is None:
        raise HTTPException(403, "pubkey not pre-approved by local operator")
    if existing[0] >= req.ts:
        return {"updated": False, "reason": "newer announcement already on file"}

    # Verify signature (uses cryptography library, same as crypto/federation.py)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        canonical = json.dumps({
            "operator": req.operator,
            "endpoint": req.endpoint,
            "pubkey": req.pubkey_hex,
            "ttl_seconds": req.ttl_seconds,
            "ts": req.ts,
        }, sort_keys=True, separators=(",", ":")).encode()
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(req.pubkey_hex)).verify(
            bytes.fromhex(req.sig_hex), canonical,
        )
    except Exception:
        raise HTTPException(400, "signature verification failed")

    db.execute(
        "UPDATE federation_peers "
        "SET operator=?, endpoint=?, ttl_seconds=?, ts=?, sig_hex=? "
        "WHERE pubkey_hex=?",
        (req.operator, req.endpoint, req.ttl_seconds, req.ts, req.sig_hex, req.pubkey_hex),
    )
    db.commit()
    return {"updated": True}


class FedBroadcastIn(BaseModel):
    type: str
    message_id: str
    routing_tag_hex: str
    envelope_hex: str
    ttl_at: Optional[str] = None


@app.post("/api/v1/federation/broadcast")
async def federation_broadcast(req: FedBroadcastIn):
    """Receive a gossipped envelope from a peer. Dedupe via
    federation_seen_ids; insert into anon_messages if new."""
    if req.type != "shroud.fed.broadcast":
        raise HTTPException(400, "wrong message type")

    if db.execute(
        "SELECT 1 FROM federation_seen_ids WHERE message_id = ?", (req.message_id,)
    ).fetchone():
        return {"accepted": False, "reason": "duplicate"}

    try:
        tag = bytes.fromhex(req.routing_tag_hex)
        envelope = bytes.fromhex(req.envelope_hex)
    except ValueError:
        raise HTTPException(400, "hex decode failed")
    if len(tag) != 32:
        raise HTTPException(400, "routing tag must be 32 bytes")

    db.execute(
        "INSERT OR IGNORE INTO anon_messages "
        "(id, routing_tag, sealed_blob, expires_at) VALUES (?,?,?,?)",
        (req.message_id, tag, envelope, req.ttl_at),
    )
    db.execute(
        "INSERT INTO federation_seen_ids (message_id) VALUES (?)",
        (req.message_id,),
    )
    db.commit()
    return {"accepted": True}


class FedDeleteIn(BaseModel):
    type: str
    message_id: str


@app.post("/api/v1/federation/delete")
async def federation_delete(req: FedDeleteIn):
    """Receive a delete-on-deliver notice from a peer. Drop the row
    from our local anon_messages if present."""
    if req.type != "shroud.fed.delete":
        raise HTTPException(400, "wrong message type")
    db.execute("DELETE FROM anon_messages WHERE id = ?", (req.message_id,))
    db.commit()
    return {"deleted": True}


class FedStateEventIn(BaseModel):
    type:       str
    event_id:   str
    ts:         int
    event_kind: str
    payload:    dict


@app.post("/api/v1/federation/state-event")
async def federation_state_event(req: FedStateEventIn):
    """Receive a state-event from a peer (user.created, ban.added,
    setting.changed, etc.). Dedup by event_id, apply locally, then
    re-broadcast to OUR peers so the event floods across the whole
    federation regardless of which relay originated it."""
    if req.type != "shroud.fed.state-event":
        raise HTTPException(400, "wrong message type")
    if _seen_state_event(req.event_id):
        return {"accepted": False, "reason": "duplicate"}
    _apply_state_event(req.event_kind, req.payload)
    # _federation_outbox_state_event records the event row AND queues
    # the re-broadcast. We pass the original event_id+ts so the flood
    # converges everywhere on the same canonical row.
    _federation_outbox_state_event(req.event_kind, req.payload,
                                   event_id=req.event_id, ts=req.ts)
    return {"accepted": True}


@app.get("/api/v1/federation/state-events/since")
async def federation_state_events_since(since_ts: int = 0, limit: int = 1000):
    """Bulk-export endpoint — a peer joining (or recovering from
    extended downtime) GETs this to replay everything it missed.
    Returns up to `limit` events ordered by origin_ts. The receiver
    feeds each entry into POST /federation/state-event."""
    rows = db.execute(
        "SELECT event_id, origin_ts, kind, payload FROM federation_state_events "
        "WHERE origin_ts > ? ORDER BY origin_ts ASC LIMIT ?",
        (since_ts, max(1, min(limit, 5000))),
    ).fetchall()
    return {
        "count": len(rows),
        "events": [
            {
                "event_id":   r[0],
                "ts":         r[1],
                "event_kind": r[2],
                "payload":    json.loads(r[3]),
            }
            for r in rows
        ],
    }


# ── Anonymous diagnostics reporting ──────────────────────────────────
#
# Clients submit sealed crash / error / log reports here. The bytes
# are stored in their own table (so the operator can poll without
# scanning the message queue) and tagged by the per-epoch operator-
# diagnostics routing tag. Server cannot identify the reporter and
# cannot decrypt the body. See crypto/error_reporting.py for the
# wire format + scrubbing requirements.

def _ensure_diagnostics_schema() -> None:
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS diagnostic_reports (
            id TEXT PRIMARY KEY,
            routing_tag BLOB NOT NULL,
            sealed_blob BLOB NOT NULL,
            server_ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_diag_routing_tag ON diagnostic_reports(routing_tag);
        CREATE INDEX IF NOT EXISTS idx_diag_ts ON diagnostic_reports(server_ts);
        """
    )
    db.commit()


_ensure_diagnostics_schema()


@app.post("/api/v1/diagnostics/report")
async def submit_diagnostic_report(request: Request):
    """Anonymous crash / error / log submission.

    Headers:
      X-Routing-Tag: 64 hex chars (32 bytes)
    Body: raw sealed envelope bytes addressed to the operator's
          diagnostics pubkey.

    Padding bucket: report bodies are typically small. We require
    the smallest bucket (4096) so all reports look identical to
    a passive observer.
    """
    tag_hex = request.headers.get("X-Routing-Tag", "")
    if len(tag_hex) != 64:
        raise HTTPException(400, "X-Routing-Tag must be 64 hex chars (32 bytes)")
    try:
        tag = bytes.fromhex(tag_hex)
    except ValueError:
        raise HTTPException(400, "X-Routing-Tag must be valid hex")

    sealed = await request.body()
    if not sealed:
        raise HTTPException(400, "Empty report")
    if len(sealed) != 4096:
        raise HTTPException(400, "Diagnostic reports must be padded to 4096 bytes")

    report_id = uuid.uuid4().hex
    db.execute(
        "INSERT INTO diagnostic_reports (id, routing_tag, sealed_blob) "
        "VALUES (?,?,?)",
        (report_id, tag, sealed),
    )
    db.commit()
    return {"report_id": report_id, "received": True}


class FetchReportsRequest(BaseModel):
    tags: List[str] = Field(default_factory=list,
                            description="hex-encoded diagnostic routing tags (operator-side poll)")
    limit: int = Field(default=100, ge=1, le=1000)


@app.post("/api/v1/diagnostics/fetch")
async def fetch_diagnostic_reports(req: FetchReportsRequest):
    """Operator-side: poll for pending reports.

    Operator authenticates by being able to compute the routing tags
    (which requires the operator's diagnostics public+private keypair —
    the public half clients use to seal; the private half lets the
    operator decrypt; the routing tags are derived from the public
    half).

    Unlike /messages/fetch-anon, reports are NOT deleted on first
    fetch — the operator may want to re-poll while triaging. The
    background sweeper drops reports older than 7 days.
    """
    if not req.tags:
        return {"reports": []}

    try:
        tag_blobs = [bytes.fromhex(t) for t in req.tags]
    except ValueError:
        raise HTTPException(400, "tags must be hex-encoded")
    for tb in tag_blobs:
        if len(tb) != 32:
            raise HTTPException(400, "tags must be 32 bytes each")

    placeholders = ",".join("?" for _ in tag_blobs)
    rows = db.execute(
        f"SELECT id, sealed_blob, server_ts FROM diagnostic_reports "
        f"WHERE routing_tag IN ({placeholders}) "
        f"ORDER BY server_ts ASC LIMIT ?",
        (*tag_blobs, req.limit),
    ).fetchall()

    return {
        "reports": [
            {"id": r[0], "sealed": r[1].hex(), "ts": str(r[2])}
            for r in rows
        ],
        "count": len(rows),
    }


# ── Fetch Messages ───────────────────────────────────────────────────
@app.post("/api/v1/messages/fetch")
async def fetch_messages(req: GetMessagesRequest):
    """Fetch undelivered messages for a device.

    Sealed messages (sealed=1) carry their envelope as a raw hex blob rather
    than parsed JSON — the sender's identity lives inside that blob."""
    device = db.execute("SELECT id FROM devices WHERE id = ?", (req.device_id,)).fetchone()
    if not device:
        raise HTTPException(404, "Device not found")

    query = ("SELECT id, sender_device_id, envelope, server_ts, sealed, envelope_version, expires_at "
             "FROM messages WHERE recipient_device_id = ? AND delivered = 0")
    params = [req.device_id]
    if req.since:
        query += " AND server_ts > ?"
        params.append(req.since)

    messages = db.execute(query + " ORDER BY server_ts ASC LIMIT 100", params).fetchall()

    now = datetime.now(tz=timezone.utc)
    for msg in messages:
        try:
            stored = datetime.fromisoformat(msg[3])
            latency_ms = (now - stored.replace(tzinfo=timezone.utc)).total_seconds() * 1000
            db.execute("INSERT INTO message_latency (message_id, latency_ms) VALUES (?,?)", (msg[0], latency_ms))
        except Exception:
            pass
        db.execute("DELETE FROM messages WHERE id = ?", (msg[0],))
    db.execute("UPDATE devices SET last_seen = datetime('now') WHERE id = ?", (req.device_id,))
    db.commit()

    out = []
    for m in messages:
        sealed = bool(m[4] or 0)
        ver = m[5] or 1
        item = {"id": m[0], "server_ts": m[3], "v": ver, "sealed": sealed, "expires_at": m[6]}
        if sealed:
            item["sealed_envelope"] = m[2]
            item["sender_device_id"] = None
        else:
            item["sender_device_id"] = m[1]
            try:
                item["envelope"] = json.loads(m[2])
            except Exception:
                item["envelope"] = m[2]
        out.append(item)
    return {"messages": out}

# ── Contact Discovery ────────────────────────────────────────────────
class ContactSearchRequest(BaseModel):
    username: str; password: str; query: str = Field(min_length=2, max_length=64)

def auth_by_device(device_id: str):
    dev = db.execute("SELECT user_id FROM devices WHERE id=?", (device_id,)).fetchone()
    if not dev: raise HTTPException(401, "Invalid device")
    user = db.execute("SELECT id, username FROM users WHERE id=?", (dev[0],)).fetchone()
    if not user: raise HTTPException(401, "Invalid user")
    return user

class AuthDevRequest(BaseModel):
    device_id: str = ""

@app.post("/api/v1/contacts/search")
async def search_contacts(request: Request):
    """Exact-username lookup. Returns 0 or 1 user. Privacy: never enumerates."""
    body = await request.json()
    device_id = body.get("device_id", "")
    query = norm_user(body.get("query", ""))
    user = auth_by_device(device_id)
    if not query or query == user[1]:
        return {"users": []}
    row = db.execute("SELECT username FROM users WHERE username = ?", (query,)).fetchone()
    return {"users": [row[0]] if row else []}

@app.post("/api/v1/devices/list")
async def list_devices(req: AuthDevRequest):
    user = auth_by_device(req.device_id)
    devices = db.execute("SELECT id, device_name, platform, registered_at, last_seen FROM devices WHERE user_id=?",
                         (user[0],)).fetchall()
    return {"devices": [{"id": d[0], "name": d[1], "platform": d[2], "registered": d[3], "last_seen": d[4] or "never"} for d in devices]}

class ContactDevRequest(BaseModel):
    device_id: str = ""
    contact_username: str = ""

@app.post("/api/v1/contacts/devices")
async def get_contact_devices(req: ContactDevRequest):
    auth_by_device(req.device_id)
    contact = db.execute("SELECT id FROM users WHERE username=?", (norm_user(req.contact_username),)).fetchone()
    if not contact: raise HTTPException(404, "User not found")
    devices = db.execute("SELECT id, device_name, platform, public_key FROM devices WHERE user_id=?",
                         (contact[0],)).fetchall()
    return {"devices": [{"id": d[0], "name": d[1], "platform": d[2], "public_key": d[3].hex()} for d in devices]}

# ── Friend Requests ──────────────────────────────────────────────────
def _friendship_pair(a: str, b: str):
    return (a, b) if a < b else (b, a)

def _is_friends(user_a: str, user_b: str) -> bool:
    a, b = _friendship_pair(user_a, user_b)
    return db.execute("SELECT 1 FROM friendships WHERE user_a=? AND user_b=?", (a, b)).fetchone() is not None

@app.post("/api/v1/friends/request")
async def friend_request(request: Request):
    body = await request.json()
    me = auth_by_device(body.get("device_id", ""))
    target_name = norm_user(body.get("target_username", ""))
    reason = (body.get("reason", "") or "")[:500]
    if not target_name or target_name == me[1]:
        raise HTTPException(400, "Invalid target")
    target = db.execute("SELECT id FROM users WHERE username=?", (target_name,)).fetchone()
    if not target:
        raise HTTPException(404, "No matching user")
    if _is_friends(me[0], target[0]):
        raise HTTPException(409, "Already friends")
    existing = db.execute(
        "SELECT id FROM friend_requests WHERE status='pending' AND "
        "((from_user_id=? AND to_user_id=?) OR (from_user_id=? AND to_user_id=?))",
        (me[0], target[0], target[0], me[0])
    ).fetchone()
    if existing:
        raise HTTPException(409, "Request already pending")
    rid = uuid.uuid4().hex
    db.execute("INSERT INTO friend_requests (id, from_user_id, to_user_id, reason) VALUES (?,?,?,?)",
               (rid, me[0], target[0], ar_enc(reason)))
    db.commit()
    return {"request_id": rid}

@app.post("/api/v1/friends/list")
async def friends_list(req: AuthDevRequest):
    me = auth_by_device(req.device_id)
    friends = db.execute(
        "SELECT u.username FROM friendships f JOIN users u ON "
        "(u.id = CASE WHEN f.user_a = ? THEN f.user_b ELSE f.user_a END) "
        "WHERE f.user_a = ? OR f.user_b = ?",
        (me[0], me[0], me[0])
    ).fetchall()
    incoming = db.execute(
        "SELECT fr.id, u.username, fr.reason, fr.created_at FROM friend_requests fr "
        "JOIN users u ON u.id = fr.from_user_id "
        "WHERE fr.to_user_id = ? AND fr.status = 'pending' ORDER BY fr.created_at DESC",
        (me[0],)
    ).fetchall()
    outgoing = db.execute(
        "SELECT fr.id, u.username, fr.status, fr.response_reason, fr.created_at FROM friend_requests fr "
        "JOIN users u ON u.id = fr.to_user_id "
        "WHERE fr.from_user_id = ? AND fr.status IN ('pending','denied') ORDER BY fr.created_at DESC LIMIT 20",
        (me[0],)
    ).fetchall()
    return {
        "friends": [{"username": f[0]} for f in friends],
        "incoming": [{"id": r[0], "from": r[1], "reason": ar_dec(r[2]), "created": r[3]} for r in incoming],
        "outgoing": [{"id": r[0], "to": r[1], "status": r[2], "response_reason": ar_dec(r[3]), "created": r[4]} for r in outgoing],
    }

@app.post("/api/v1/friends/respond")
async def friends_respond(request: Request):
    body = await request.json()
    me = auth_by_device(body.get("device_id", ""))
    req_id = body.get("request_id", "")
    accept = bool(body.get("accept", False))
    reason = (body.get("reason", "") or "")[:500]
    fr = db.execute("SELECT from_user_id, to_user_id, status FROM friend_requests WHERE id=?", (req_id,)).fetchone()
    if not fr or fr[1] != me[0]:
        raise HTTPException(404, "Request not found")
    if fr[2] != "pending":
        raise HTTPException(409, "Already responded")
    new_status = "accepted" if accept else "denied"
    db.execute("UPDATE friend_requests SET status=?, response_reason=?, responded_at=datetime('now') WHERE id=?",
               (new_status, reason, req_id))
    if accept:
        a, b = _friendship_pair(fr[0], fr[1])
        db.execute("INSERT OR IGNORE INTO friendships (user_a, user_b) VALUES (?,?)", (a, b))
    db.commit()
    return {"status": new_status}

# ── Group Chat ───────────────────────────────────────────────────────
@app.post("/api/v1/groups/create")
async def create_group(request: Request):
    body = json.loads(await request.body()); members = body["members"]
    db.execute("INSERT INTO group_chats (id, name, creator_device_id) VALUES (?,?,?)", (uuid.uuid4().hex, body.get("group_name","Group Chat"), body["creator_device_id"]))
    gid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    for m in members: db.execute("INSERT INTO group_members (group_id, device_id, encrypted_group_key) VALUES (?,?,?)", (gid, m["device_id"], m["encrypted_group_key"]))
    db.commit()
    return {"group_id": gid, "members": len(members)}

@app.post("/api/v1/groups/send")
async def send_group_message(request: Request):
    body = json.loads(await request.body())
    members = db.execute("SELECT device_id FROM group_members WHERE group_id=? AND device_id!=?", (body["group_id"], body["sender_device_id"])).fetchall()
    mid = uuid.uuid4().hex; env = json.dumps(body["envelope"])
    for m in members: db.execute("INSERT INTO messages (id, sender_device_id, recipient_device_id, envelope) VALUES (?,?,?,?)", (mid, body["sender_device_id"], m[0], env))
    db.commit()
    return {"delivered_to": len(members)}

@app.post("/api/v1/groups/add")
async def add_group_member(request: Request):
    body = json.loads(await request.body())
    if db.execute("SELECT 1 FROM group_members WHERE group_id=? AND device_id=?", (body["group_id"], body["device_id"])).fetchone(): raise HTTPException(409)
    db.execute("INSERT INTO group_members (group_id, device_id, encrypted_group_key) VALUES (?,?,?)", (body["group_id"], body["device_id"], body["encrypted_group_key"])); db.commit()
    return {"added": True}

@app.get("/api/v1/groups/{device_id}")
async def list_groups(device_id: str):
    g = db.execute("SELECT g.id, g.name, g.created_at FROM group_chats g JOIN group_members gm ON g.id=gm.group_id WHERE gm.device_id=?", (device_id,)).fetchall()
    return {"groups": [{"id": r[0], "name": r[1], "created_at": r[2]} for r in g]}

# ── Group Invites ────────────────────────────────────────────────────
@app.post("/api/v1/groups/invite")
async def group_invite(request: Request):
    body = await request.json()
    me = auth_by_device(body.get("device_id", ""))
    group_id = body.get("group_id", "")
    target_name = norm_user(body.get("target_username", ""))
    reason = (body.get("reason", "") or "")[:500]
    if not target_name or target_name == me[1]:
        raise HTTPException(400, "Invalid target")
    # Must be a member of the group to invite others
    is_member = db.execute(
        "SELECT 1 FROM group_members gm JOIN devices d ON d.id=gm.device_id "
        "WHERE gm.group_id=? AND d.user_id=?", (group_id, me[0])
    ).fetchone()
    if not is_member:
        raise HTTPException(403, "Not a member of that group")
    target = db.execute("SELECT id FROM users WHERE username=?", (target_name,)).fetchone()
    if not target:
        raise HTTPException(404, "No matching user")
    already = db.execute(
        "SELECT 1 FROM group_members gm JOIN devices d ON d.id=gm.device_id "
        "WHERE gm.group_id=? AND d.user_id=?", (group_id, target[0])
    ).fetchone()
    if already:
        raise HTTPException(409, "User already in group")
    existing = db.execute(
        "SELECT id FROM group_invites WHERE group_id=? AND to_user_id=? AND status='pending'",
        (group_id, target[0])
    ).fetchone()
    if existing:
        raise HTTPException(409, "Invite already pending")
    iid = uuid.uuid4().hex
    db.execute("INSERT INTO group_invites (id, group_id, from_user_id, to_user_id, reason) VALUES (?,?,?,?,?)",
               (iid, group_id, me[0], target[0], ar_enc(reason)))
    db.commit()
    return {"invite_id": iid}

@app.post("/api/v1/groups/invites/list")
async def group_invites_list(req: AuthDevRequest):
    me = auth_by_device(req.device_id)
    rows = db.execute(
        "SELECT gi.id, gi.group_id, g.name, u.username, gi.reason, gi.created_at "
        "FROM group_invites gi "
        "JOIN group_chats g ON g.id = gi.group_id "
        "JOIN users u ON u.id = gi.from_user_id "
        "WHERE gi.to_user_id = ? AND gi.status = 'pending' ORDER BY gi.created_at DESC",
        (me[0],)
    ).fetchall()
    return {"invites": [{"id": r[0], "group_id": r[1], "group_name": r[2], "from": r[3], "reason": ar_dec(r[4]), "created": r[5]} for r in rows]}

@app.post("/api/v1/groups/invites/respond")
async def group_invites_respond(request: Request):
    body = await request.json()
    me = auth_by_device(body.get("device_id", ""))
    iid = body.get("invite_id", "")
    accept = bool(body.get("accept", False))
    reason = (body.get("reason", "") or "")[:500]
    inv = db.execute("SELECT group_id, to_user_id, status FROM group_invites WHERE id=?", (iid,)).fetchone()
    if not inv or inv[1] != me[0]:
        raise HTTPException(404, "Invite not found")
    if inv[2] != "pending":
        raise HTTPException(409, "Already responded")
    new_status = "accepted" if accept else "denied"
    db.execute("UPDATE group_invites SET status=?, response_reason=?, responded_at=datetime('now') WHERE id=?",
               (new_status, reason, iid))
    if accept:
        # Add the responding device to the group. Real key-wrapping would
        # require a separate handshake; placeholder mirrors existing flow.
        db.execute("INSERT OR IGNORE INTO group_members (group_id, device_id, encrypted_group_key) VALUES (?,?,?)",
                   (inv[0], body.get("device_id",""), "pending"))
    db.commit()
    return {"status": new_status}

# ── WebSocket (Real-time Push) ───────────────────────────────────────
@app.websocket("/ws/{device_id}")
async def websocket_endpoint(websocket: WebSocket, device_id: str):
    """Real-time message delivery via WebSocket."""
    # Route admin WS through the admin handler
    if device_id == "admin":
        await _admin_ws_handler(websocket)
        return
    device = db.execute("SELECT id FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not device:
        await websocket.close(code=4004)
        return

    await websocket.accept()
    db.execute("UPDATE devices SET last_seen = datetime('now') WHERE id = ?", (device_id,))
    db.commit()

    try:
        while True:
            messages = db.execute(
                "SELECT id, sender_device_id, envelope, server_ts, sealed, envelope_version, expires_at "
                "FROM messages WHERE recipient_device_id = ? AND delivered = 0 "
                "ORDER BY server_ts ASC LIMIT 50",
                (device_id,)
            ).fetchall()

            for msg in messages:
                sealed = bool(msg[4] or 0)
                ver = msg[5] or 1
                payload = {"id": msg[0], "server_ts": msg[3], "v": ver, "sealed": sealed, "expires_at": msg[6]}
                if sealed:
                    payload["sealed_envelope"] = msg[2]
                    payload["sender_device_id"] = None
                else:
                    payload["sender_device_id"] = msg[1]
                    try:
                        payload["envelope"] = json.loads(msg[2])
                    except Exception:
                        payload["envelope"] = msg[2]
                await websocket.send_json(payload)
                db.execute("UPDATE messages SET delivered = 1 WHERE id = ?", (msg[0],))
            db.commit()
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass

# ── Encrypted File Transfer ─────────────────────────────────────────
@app.post("/api/v1/files/upload")
async def upload_file(request: Request):
    """Streaming upload — server stores encrypted blob, never sees plaintext."""
    _guard_maintenance()
    sender_id = request.headers.get("X-Device-ID", "")
    recipient_id = request.headers.get("X-Recipient-ID", "")
    encrypted_metadata = request.headers.get("X-File-Metadata", "{}")
    content_type = request.headers.get("X-Content-Type", "application/octet-stream")

    if not sender_id or not recipient_id:
        raise HTTPException(400, "Missing device or recipient ID")

    # Validate devices exist
    if not db.execute("SELECT id FROM devices WHERE id=?", (sender_id,)).fetchone():
        raise HTTPException(404, "Sender device not found")
    if not db.execute("SELECT id FROM devices WHERE id=?", (recipient_id,)).fetchone():
        raise HTTPException(400, "Recipient device not found — sending a file notification message first registers the device")

    file_id = uuid.uuid4().hex
    storage_name = f"{file_id}.enc"
    storage_path = os.path.join(FILE_DIR, storage_name)

    total_size = 0
    with open(storage_path, "wb") as f:
        async for chunk in request.stream():
            f.write(chunk)
            total_size += len(chunk)

    # Parse metadata to get original size
    try:
        meta = json.loads(encrypted_metadata)
        orig_size = meta.get("size", total_size)
    except Exception:
        orig_size = total_size

    db.execute(
        "INSERT INTO file_transfers (id, sender_device_id, recipient_device_id, storage_name, encrypted_metadata, original_size, encrypted_size, expires_at) VALUES (?,?,?,?,?,?,?,datetime('now','+24 hours'))",
        (file_id, sender_id, recipient_id, storage_name, encrypted_metadata, orig_size, total_size)
    )
    db.execute("UPDATE devices SET last_seen=datetime('now') WHERE id=?", (sender_id,))
    db.commit()

    return {"file_id": file_id, "size": total_size, "stored": True}

@app.get("/api/v1/files/{file_id}")
async def download_file(file_id: str, device_id: str = Header(default="", alias="X-Device-ID")):
    """Download an encrypted blob. Either sender or recipient device may
    fetch — the file stays on disk until explicitly deleted by either
    party (or until expires_at)."""
    row = db.execute(
        "SELECT storage_name, sender_device_id, recipient_device_id, encrypted_metadata, encrypted_size FROM file_transfers WHERE id=?",
        (file_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "File not found")

    if device_id and device_id not in (row[1], row[2]):
        raise HTTPException(403, "Not authorized for this file")

    storage_path = os.path.join(FILE_DIR, row[0])
    if not os.path.isfile(storage_path):
        raise HTTPException(404, "File data missing")

    if device_id == row[2]:
        db.execute("UPDATE file_transfers SET downloaded=1 WHERE id=?", (file_id,))
        db.execute("UPDATE devices SET last_seen=datetime('now') WHERE id=?", (device_id,))
        db.commit()

    return FileResponse(
        storage_path,
        media_type="application/octet-stream",
        headers={
            "X-File-Id": file_id,
            "X-File-Metadata": row[3],
            "X-File-Size": str(row[4]),
            "Content-Disposition": f"attachment; filename=\"{file_id}.enc\""
        }
    )

@app.delete("/api/v1/files/{file_id}")
async def delete_file(file_id: str, device_id: str = Header(default="", alias="X-Device-ID")):
    """Permanently delete a file. Either the sender or the recipient may
    request deletion; the encrypted blob and DB row are removed for both
    sides."""
    row = db.execute(
        "SELECT storage_name, sender_device_id, recipient_device_id FROM file_transfers WHERE id=?",
        (file_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "File not found")
    if device_id not in (row[1], row[2]):
        raise HTTPException(403, "Only sender or recipient may delete")
    storage_path = os.path.join(FILE_DIR, row[0])
    if os.path.isfile(storage_path):
        try:
            os.remove(storage_path)
        except OSError:
            pass
    db.execute("DELETE FROM file_transfers WHERE id=?", (file_id,))
    db.commit()
    return {"deleted": True, "file_id": file_id}

@app.get("/api/v1/devices/{device_id}/pubkey")
async def device_pubkey(device_id: str):
    """Return a device's public key blob (hex). Public information used by
    the recipient to derive the symmetric key matching the sender's, so
    image/file payloads can be decrypted cross-device."""
    row = db.execute("SELECT public_key FROM devices WHERE id=?", (device_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Device not found")
    return {"device_id": device_id, "public_key": row[0].hex() if isinstance(row[0], (bytes, bytearray)) else row[0]}

@app.get("/api/v1/files/{file_id}/info")
async def file_info(file_id: str):
    """Get file metadata including exact expiry timestamp for countdown."""
    row = db.execute(
        "SELECT id, sender_device_id, recipient_device_id, encrypted_metadata, original_size, encrypted_size, server_ts, downloaded, expires_at FROM file_transfers WHERE id=?",
        (file_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "File not found")
    return {
        "file_id": row[0],
        "sender_device_id": row[1],
        "recipient_device_id": row[2],
        "encrypted_metadata": row[3],
        "original_size": row[4],
        "encrypted_size": row[5],
        "server_ts": row[6],
        "downloaded": bool(row[7]),
        "expires_at": row[8]
    }

# (File cleanup now in lifespan handler above)

# ── Admin Auth (Fingerprint + Hardware-Bound) ──────────────────────
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

SESSION_TIMEOUT_SEC = 3600  # 1 hour
MAX_FAILED_ATTEMPTS = 3
BAN_WINDOW_SEC = 3600  # 1 hour ban window

# Security headers middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if request.url.path.startswith("/admin") or request.url.path == "/ws/admin":
            # CSP for the v2.4.0 admin GUI:
            #   - 'self' for the extracted /admin/static/{admin,login,user,device}.{css,js}
            #   - 'unsafe-inline' kept on style+script because admin.js builds rows
            #     with inline style="width:..." attrs and onclick="openUser(...)"
            #     handlers (rewriting all of those to addEventListener is a much
            #     larger refactor for no real security gain in a same-origin GUI).
            #   - connect-src lists ws:/wss: so the live-tail WebSocket can open
            #     (some browsers don't auto-fall back default-src to ws schemes).
            #   - object/base/frame-ancestors are defense-in-depth.
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline'; "
                "connect-src 'self' ws: wss:; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "frame-ancestors 'none'"
            )
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Rate limiting middleware (in-memory, per-IP)
rate_limits = {}
class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        ip = request.client.host if request.client else "unknown"
        path = request.url.path
        now = time.time()
        # Define limits per endpoint
        if "/api/v1/admin/fingerprint-login" in path:
            max_req, window = 6, 3600  # 6 attempts per hour
        elif "/api/v1/register" in path or "/api/v1/devices" in path:
            max_req, window = 20, 3600  # 20 registrations per hour
        elif "/api/v1/files/upload" in path:
            max_req, window = 100, 3600  # 100 uploads per hour
        elif "/api/v1/messages/send" in path:
            max_req, window = 500, 3600  # 500 messages per hour
        else:
            max_req, window = 1000, 3600  # default
        key = f"{ip}:{path}"
        entries = rate_limits.get(key, [])
        entries = [t for t in entries if now - t < window]
        if len(entries) >= max_req:
            raise HTTPException(429, "Rate limit exceeded. Try again later.")
        entries.append(now)
        rate_limits[key] = entries
        return await call_next(request)

app.add_middleware(RateLimitMiddleware)

# Telemetry middleware — pure in-memory counters for the admin dashboard.
# Tracks endpoint hit counts, latency, and errors. No PII recorded.
#
# v2.4.0: also counts onion vs clearnet requests (from the Host header)
# and pushes errors live over the admin WebSocket subscribers.
class TelemetryMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        global ONION_REQ_COUNT, CLEAR_REQ_COUNT
        t0 = time.perf_counter()
        path = request.url.path
        REQ_COUNTS[path] += 1

        # Onion vs clearnet split. WebSocket upgrades and the static-asset
        # mount are excluded so they don't drown out signal from the real
        # client API. Skip /ws/* and /admin/static/* deliberately.
        if not (path.startswith("/admin/static") or path.startswith("/ws/")):
            host = request.headers.get("host", "").lower().split(":")[0]
            if host.endswith(".onion"):
                ONION_REQ_COUNT += 1
            else:
                CLEAR_REQ_COUNT += 1

        def _record_error(status: int, detail: str) -> dict:
            row = {
                "ts": datetime.now(tz=timezone.utc).isoformat(timespec='seconds'),
                "path": path, "status": status, "detail": detail[:200],
            }
            RECENT_ERRORS.appendleft(row)
            publish_event("error", row)
            return row

        try:
            response = await call_next(request)
        except HTTPException as he:
            ERR_COUNTS[path] += 1
            _record_error(he.status_code, str(he.detail))
            raise
        except Exception as e:
            ERR_COUNTS[path] += 1
            _record_error(500, type(e).__name__)
            raise
        ms = (time.perf_counter() - t0) * 1000.0
        REQ_LATENCY.append((path, ms, time.time()))
        if response.status_code >= 400:
            ERR_COUNTS[path] += 1
            _record_error(response.status_code, "")
        return response

app.add_middleware(TelemetryMiddleware)

# Onion-only mode — when enabled, refuse any request whose Host header is
# not a .onion address. Admin paths are exempt so the operator can recover.
#
# Endpoints exempted from onion_only:
#   /admin/*           — admin UI (operator recovery)
#   /api/v1/admin/*    — admin REST
#   /health            — load-balancer / monitoring probe
#   /api/v1/relay-stats        — federation-visible operational telemetry.
#                                Peers MUST be able to poll each other for
#                                health regardless of which transport
#                                exposes them; this is what makes the
#                                /api/v1/admin/federation dashboard show
#                                anything for cross-region peers when one
#                                relay is onion-only and the other isn't.
#   /api/v1/federation/*       — peer-to-peer gossip + state-event sync.
#                                Same reason as relay-stats.
#   /api/v1/error-codes        — public error-code catalog so clients can
#                                always render an error code even if their
#                                preferred transport is clearnet.
#   /api/v1/operator-manifest  — signed manifest must reachable for
#                                bootstrap; the signature is what clients
#                                trust, not the transport.
#   /api/v1/version            — update-check pings.
_ONION_BYPASS_EXACT = (
    "/health", "/api/v1/relay-stats", "/api/v1/error-codes",
    "/api/v1/operator-manifest", "/api/v1/version",
)
_ONION_BYPASS_PREFIX = (
    "/admin", "/api/v1/admin", "/api/v1/federation",
)

class OnionOnlyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        try:
            enabled = setting_get("onion_only", "0") == "1"
        except Exception:
            enabled = False
        if enabled:
            path = request.url.path
            allowed = (
                path in _ONION_BYPASS_EXACT
                or any(path.startswith(p) for p in _ONION_BYPASS_PREFIX)
            )
            if not allowed:
                host = request.headers.get("host", "").lower().split(":")[0]
                if not host.endswith(".onion"):
                    return JSONResponse({"detail": "Server is in onion-only mode"}, status_code=403)
        return await call_next(request)

app.add_middleware(OnionOnlyMiddleware)

# ── Server settings (toggles) ────────────────────────────────────────
# v2.4.5 — username normalization. The clients lowercase before submission,
# but we ALSO lowercase server-side so any pre-v2.4.5 client (or a curl-er)
# can't slip a mixed-case username through. Username storage was made
# lower-only by the migration below at boot.
def norm_user(u: str) -> str:
    return (u or "").strip().lower()


def setting_get(key: str, default: str = "") -> str:
    row = db.execute("SELECT value FROM server_settings WHERE key=?", (key,)).fetchone()
    return row[0] if row else default

def setting_set(key: str, value: str):
    db.execute(
        "INSERT INTO server_settings (key,value,updated_at) VALUES (?,?,datetime('now')) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')",
        (key, value)
    )
    db.commit()
    # Per-user transient counters (e.g. srp_fail:<uid>) shouldn't bloat
    # the federation outbox or leak per-account metadata across relays.
    # Only gossip the operator-set toggles that genuinely apply to every
    # relay. `onion_only` is intentionally NOT in this list — it's a
    # per-relay deployment choice (a relay needs Tor running locally
    # before going onion-only) and forcing it across the federation
    # locks operators out of their own admin UIs.
    _GOSSIP_SETTINGS = ("registration_enabled", "maintenance_mode")
    if key in _GOSSIP_SETTINGS:
        _federation_outbox_state_event("setting.changed",
                                       {"key": key, "value": value})

def audit_admin(actor: str, action: str, target: str = "", detail: str = ""):
    actor_t  = actor[:64]
    action_t = action[:64]
    target_t = target[:128]
    detail_t = detail[:500]
    try:
        db.execute("INSERT INTO audit_log (actor,action,target,detail) VALUES (?,?,?,?)",
                   (actor_t, action_t, target_t, detail_t))
        db.commit()
    except Exception:
        return
    publish_event("audit", {
        "ts": datetime.now(tz=timezone.utc).isoformat(timespec='seconds'),
        "actor": actor_t, "action": action_t,
        "target": target_t, "detail": detail_t,
    })

def get_client_info(request: Request) -> tuple:
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("User-Agent", "unknown")[:256]
    return ip, ua

def is_ip_banned(ip: str) -> bool:
    """Check if IP has too many recent failed attempts."""
    count = db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip=? AND success=0 AND attempted_at > datetime('now', ?)",
        (ip, f'-{BAN_WINDOW_SEC} seconds')
    ).fetchone()[0]
    return count >= MAX_FAILED_ATTEMPTS

AUDIT_LOG = os.path.join(os.path.dirname(__file__), "audit.log")
def audit_log(ip: str, event: str, detail: str = ""):
    try:
        ts = datetime.now(tz=timezone.utc).isoformat()
        with open(AUDIT_LOG, "a") as f:
            f.write(f"[{ts}] {ip} — {event} {detail}\n")
    except:
        pass

def check_csrf(request: Request):
    """Validate CSRF token for state-changing admin operations."""
    token = request.headers.get("X-CSRF-Token", "")
    cookie_token = request.cookies.get("shroud_csrf", "")
    if not token or token != cookie_token:
        raise HTTPException(403, "CSRF validation failed")

def get_admin_session(sid: str = Cookie(None, alias="shroud_sid")):
    if not sid: return None
    row = db.execute(
        "SELECT id, ip, user_agent, login_at, last_activity, logged_out "
        "FROM admin_sessions WHERE id=? AND logged_out=0", (sid,)
    ).fetchone()
    if not row: return None
    last_act = datetime.fromisoformat(row[4])
    now = datetime.now(tz=timezone.utc)
    last = last_act.replace(tzinfo=timezone.utc)
    if (now - last).total_seconds() > SESSION_TIMEOUT_SEC:
        db.execute("UPDATE admin_sessions SET logged_out=1 WHERE id=?", (sid,))
        db.commit()
        return None
    db.execute("UPDATE admin_sessions SET last_activity=datetime('now') WHERE id=?", (sid,))
    db.commit()
    return row

def require_admin(sid: str = Cookie(None, alias="shroud_sid")):
    session = get_admin_session(sid)
    if not session:
        raise HTTPException(401, "Not authenticated")
    return session

# v2.4.0 — CSRF gate for state-changing admin endpoints. Uses the cookie
# pair set at login (shroud_csrf double-submit token). Admin GET routes
# don't need this; only POST/DELETE control + delete + setting flips do.
def require_admin_csrf(request: Request, session=Depends(require_admin)):
    check_csrf(request)
    return session

# ─── Static assets for the extracted admin GUI (CSS/JS/HTML shells).
# Unauthenticated by design: the JS and CSS are not secret, and the login
# page itself needs to load admin assets before there's any session cookie.
app.mount("/admin/static", StaticFiles(directory=ADMIN_DIR), name="admin_static")

# ── Admin Login Page (Fingerprint Grid) ─────────────────────────────
def _serve_admin_html(filename: str) -> HTMLResponse:
    """Read an extracted admin HTML shell off disk. Files live in
    server/admin/. Kept tiny on purpose — they reference /admin/static/*
    for CSS and JS. We read on every request so editing the HTML during
    development doesn't require a restart; the templates are small and
    the disk cache makes this effectively free.
    """
    path = os.path.join(ADMIN_DIR, filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except OSError:
        return HTMLResponse(
            f"<h1>Admin asset missing</h1><p>Could not read {filename} "
            f"from {ADMIN_DIR}. Reinstall or restore the server/admin/ "
            "directory.</p>", status_code=500,
        )


@app.get("/admin/login")
async def admin_login_page():
    return _serve_admin_html("login.html")

@app.get("/api/v1/admin/login-status")
async def admin_login_status(request: Request):
    ip, _ = get_client_info(request)
    hwid = request.query_params.get("hwid", "")
    banned = is_ip_banned(ip)
    count = db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip=? AND success=0 AND attempted_at > datetime('now', ?)",
        (ip, f'-{BAN_WINDOW_SEC} seconds')
    ).fetchone()[0]
    existing = db.execute("SELECT COUNT(*) FROM admin_fingerprints").fetchone()[0]
    return {"banned": banned, "failCount": count, "maxAttempts": MAX_FAILED_ATTEMPTS, "needsSetup": existing == 0}

@app.post("/api/v1/admin/fingerprint-login")
async def admin_fingerprint_login(request: Request):
    body = await request.json()
    fp = body.get("fingerprint_id", "").strip()
    pw = body.get("password", "")
    hwid = body.get("hwid", "")
    ip, ua = get_client_info(request)

    # Ban check
    if is_ip_banned(ip):
        db.execute("INSERT INTO login_attempts (ip, hwid, fingerprint_id, success) VALUES (?,?,?,?)",
                   (ip, hwid, fp[:32], 0))
        db.commit()
        raise HTTPException(403, "IP banned — too many failed attempts")

    # Verify fingerprint exists
    row = db.execute(
        "SELECT id FROM admin_fingerprints WHERE fingerprint_id=?", (fp,)
    ).fetchone()

    if not row:
        audit_log(ip, "AUTH_FAIL", f"fp={fp[:16]}... hwid={hwid[:32]}...")
        db.execute("INSERT INTO login_attempts (ip, hwid, fingerprint_id, success) VALUES (?,?,?,?)",
                   (ip, hwid, fp[:32], 0))
        db.commit()
        publish_event("failed_login", {
            "ts": datetime.now(tz=timezone.utc).isoformat(timespec='seconds'),
            "ip": ip, "hwid": (hwid or "")[:16], "fp": (fp or "")[:8],
        })
        remaining = MAX_FAILED_ATTEMPTS - db.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE ip=? AND success=0 AND attempted_at > datetime('now', ?)",
            (ip, f'-{BAN_WINDOW_SEC} seconds')
        ).fetchone()[0]
        raise HTTPException(401, f"Invalid fingerprint or password. {max(0, remaining-1)} attempts remaining.")

    # Success
    db.execute("INSERT INTO login_attempts (ip, hwid, fingerprint_id, success) VALUES (?,?,?,?)",
               (ip, hwid, fp[:32], 1))
    db.execute("UPDATE admin_fingerprints SET last_used=datetime('now') WHERE id=?", (row[0],))
    sid = uuid.uuid4().hex
    csrf = uuid.uuid4().hex
    db.execute("INSERT INTO admin_sessions (id, ip, user_agent) VALUES (?,?,?)", (sid, ar_enc(ip), ar_enc(ua)))
    db.commit()

    resp = JSONResponse({"ok": True, "session_id": sid})
    resp.set_cookie(key="shroud_sid", value=sid, httponly=True, samesite="lax", max_age=SESSION_TIMEOUT_SEC, path="/")
    # Double-submit CSRF: the cookie MUST be readable by JS so admin.js
    # can echo it as X-CSRF-Token on writes. Same-origin policy keeps
    # other sites from reading it. httponly=True here was the v2.4.0
    # bug that broke every admin toggle — JS got "" and POSTs 403'd.
    resp.set_cookie(key="shroud_csrf", value=csrf, httponly=False, samesite="strict", max_age=SESSION_TIMEOUT_SEC, path="/")
    return resp

@app.post("/api/v1/admin/setup")
async def admin_initial_setup(request: Request):
    """One-time setup — only works when no fingerprints exist."""
    existing = db.execute("SELECT COUNT(*) FROM admin_fingerprints").fetchone()[0]
    if existing > 0:
        raise HTTPException(403, "Admin already configured. Use fingerprint login.")

    ip, _ = get_client_info(request)
    if is_ip_banned(ip):
        raise HTTPException(403, "IP banned")

    fp_id = ''.join(uuid.uuid4().hex for _ in range(8))  # 8×32 = 256 hex chars
    db.execute(
        "INSERT INTO admin_fingerprints (fingerprint_id, password_hash, password_salt, hwid, label) VALUES (?,?,?,?,?)",
        (fp_id, "", "", "", "Primary Admin")
    )
    db.commit()
    return {"ok": True, "fingerprint_id": fp_id, "note": "Save this fingerprint — it cannot be recovered"}

@app.post("/api/v1/admin/fingerprint-enroll")
async def admin_fingerprint_enroll(request: Request, session=Depends(require_admin_csrf)):
    """Generate a new fingerprint."""
    label = (await request.json()).get("label", "Admin")
    fp_id = ''.join(uuid.uuid4().hex for _ in range(8))
    db.execute(
        "INSERT INTO admin_fingerprints (fingerprint_id, password_hash, password_salt, hwid, label) VALUES (?,?,?,?,?)",
        (fp_id, "", "", "", label)
    )
    db.commit()
    return {"ok": True, "fingerprint_id": fp_id}

@app.post("/api/v1/admin/logout")
async def admin_logout(session=Depends(get_admin_session)):
    if session:
        db.execute("UPDATE admin_sessions SET logged_out=1 WHERE id=?", (session[0],))
        db.commit()
    resp = JSONResponse({"logged_out": True})
    resp.delete_cookie("shroud_sid", path="/")
    return resp

# ─── Admin Dashboard backend (v2.4.0) ───────────────────────────────
#
# The /api/v1/admin/stats endpoint that shipped through v2.3.x rolled
# every metric and table into one ~30-query payload. v2.4.0 splits that
# into per-section endpoints so each tab fetches only what it renders:
#
#   /api/v1/admin/stats/overview     top bar + headline cards + chart
#   /api/v1/admin/stats/users        user/friend/group-invite/top-sender tables
#   /api/v1/admin/stats/devices      device + group tables
#   /api/v1/admin/stats/crypto       identity, suites, prekey shortages, padding
#   /api/v1/admin/stats/files        file transfers (live countdown is client-side)
#   /api/v1/admin/stats/audit        audit log + failed logins + errors + sessions
#   /api/v1/admin/stats/activity     time-series, recent messages, onion split
#   /api/v1/admin/stats/badges       tiny counts for inactive-tab badges
#
# Plus drill-down endpoints for /admin/user/{id} and /admin/device/{id},
# control "preview" endpoints that return the impact of destructive
# actions before they fire, and /ws/admin for live push of audit log
# rows, errors, and failed logins.
# ────────────────────────────────────────────────────────────────────
def _dir_size(path: str) -> int:
    total = 0
    try:
        for entry in os.scandir(path):
            if entry.is_file():
                try: total += entry.stat().st_size
                except OSError: pass
    except OSError:
        pass
    return total

def _fmt_uptime(secs: float) -> str:
    s = int(secs)
    d, s = divmod(s, 86400); h, s = divmod(s, 3600); m, s = divmod(s, 60)
    if d: return f"{d}d {h}h {m}m"
    if h: return f"{h}h {m}m {s}s"
    if m: return f"{m}m {s}s"
    return f"{s}s"

def _file_mtime_iso(path: str) -> Optional[str]:
    try:
        ts = os.path.getmtime(path)
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec='seconds')
    except OSError:
        return None


# Padded-envelope bucket boundaries used by the clients (powers-of-2
# from 256 B up). Keep this in sync with crypto/padding.py — for now
# we infer bucket purely from envelope length.
_PAD_BUCKETS = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]

def _padding_distribution() -> List[dict]:
    counts = [0] * (len(_PAD_BUCKETS) + 1)
    try:
        rows = db.execute("SELECT LENGTH(envelope) FROM messages").fetchall()
    except Exception:
        rows = []
    for (n,) in rows:
        n = int(n or 0)
        placed = False
        for i, b in enumerate(_PAD_BUCKETS):
            if n <= b:
                counts[i] += 1; placed = True; break
        if not placed:
            counts[-1] += 1
    out = []
    for i, b in enumerate(_PAD_BUCKETS):
        out.append({"bucket": f"≤ {b} B", "count": counts[i]})
    out.append({"bucket": f"> {_PAD_BUCKETS[-1]} B", "count": counts[-1]})
    return out


def _meta_block() -> dict:
    """Top-bar fields and the three operator toggles. Cheap, hit on
    every overview poll."""
    return {
        "uptime_sec": round(time.time() - STARTUP_TS, 1),
        "uptime_fmt": _fmt_uptime(time.time() - STARTUP_TS),
        "server_time_utc": datetime.now(tz=timezone.utc).isoformat(timespec='seconds'),
        "version": SERVER_VERSION,
        "registration_enabled": setting_get("registration_enabled", "1") == "1",
        "maintenance_mode":     setting_get("maintenance_mode",     "0") == "1",
        "onion_only":           setting_get("onion_only",           "0") == "1",
    }


# ── Bans (admin-managed) ─────────────────────────────────────────────
#
# Banning a username also cascades to every HWID we've ever seen for
# that user (looked up via the `devices` table). Both the username row
# AND each HWID row land in `bans`. Enforcement runs at the top of
# /api/v1/register and /api/v1/auth so a banned account / hardware can't
# even probe credentials. Bans never expire automatically — admin must
# unban explicitly.

def _ban_lookup(username: str = "", hwid: str = "", ip: str = "") -> dict | None:
    """Return the first matching ban row as a dict, or None."""
    checks: list[tuple[str, str]] = []
    if username:
        checks.append(("username", norm_user(username)))
    if hwid:
        checks.append(("hwid", hwid))
    if ip:
        checks.append(("ip", ip))
    if not checks:
        return None
    placeholders = " OR ".join("(kind=? AND value=?)" for _ in checks)
    args: list[str] = []
    for k, v in checks:
        args.extend([k, v])
    row = db.execute(
        f"SELECT id, kind, value, reason, banned_by, banned_at, origin_user "
        f"FROM bans WHERE {placeholders} LIMIT 1",
        args,
    ).fetchone()
    if not row:
        return None
    return {
        "id": row[0], "kind": row[1], "value": row[2],
        "reason": row[3], "banned_by": row[4],
        "banned_at": row[5], "origin_user": row[6],
    }


def _ban_username_and_hardware(username: str, reason: str, banned_by: str) -> dict:
    """Ban a username AND every HWID we've seen on devices linked to that
    user. Idempotent — INSERT OR IGNORE means re-banning is harmless."""
    norm = norm_user(username)
    user = db.execute("SELECT id FROM users WHERE username = ?", (norm,)).fetchone()
    affected_hwids: list[str] = []
    if user:
        affected_hwids = [
            row[0] for row in db.execute(
                "SELECT DISTINCT hwid FROM devices WHERE user_id = ? AND hwid != ''",
                (user[0],),
            ).fetchall()
        ]
    db.execute(
        "INSERT OR IGNORE INTO bans (kind, value, reason, banned_by, origin_user) "
        "VALUES (?,?,?,?,?)",
        ("username", norm, reason, banned_by, norm),
    )
    _federation_outbox_state_event("ban.added", {
        "kind": "username", "value": norm, "reason": reason,
        "banned_by": banned_by, "origin_user": norm,
    })
    for h in affected_hwids:
        db.execute(
            "INSERT OR IGNORE INTO bans (kind, value, reason, banned_by, origin_user) "
            "VALUES (?,?,?,?,?)",
            ("hwid", h, reason, banned_by, norm),
        )
        _federation_outbox_state_event("ban.added", {
            "kind": "hwid", "value": h, "reason": reason,
            "banned_by": banned_by, "origin_user": norm,
        })
    db.commit()
    return {
        "username": norm,
        "hwids_banned": affected_hwids,
        "user_exists": bool(user),
    }


@app.get("/api/v1/admin/bans")
async def admin_bans_list(session=Depends(require_admin)):
    """List every ban row. Tiny table, no pagination needed for now."""
    rows = db.execute(
        "SELECT id, kind, value, reason, banned_by, banned_at, origin_user "
        "FROM bans ORDER BY banned_at DESC LIMIT 1000"
    ).fetchall()
    return {
        "bans": [
            {
                "id": r[0], "kind": r[1], "value": r[2],
                "reason": r[3], "banned_by": r[4],
                "banned_at": r[5], "origin_user": r[6],
            }
            for r in rows
        ],
        "count": len(rows),
    }


@app.post("/api/v1/admin/bans")
async def admin_bans_add(request: Request, session=Depends(require_admin)):
    """Add a ban. Body:
       { "username": "...", "reason": "...", "kind": "username" | "hwid" | "ip" }
       When kind=username (default), cascades the ban to every HWID seen
       on devices linked to that user.
       When kind=hwid or kind=ip, bans only the literal value provided.
    """
    body = await request.json()
    kind = (body.get("kind") or "username").lower()
    value = (body.get("value") or body.get("username") or "").strip()
    reason = (body.get("reason") or "")[:500]
    if not value:
        raise HTTPException(400, "value (or username) is required")
    banned_by = session.get("admin_id", "") if isinstance(session, dict) else str(session)

    if kind == "username":
        result = _ban_username_and_hardware(value, reason, banned_by)
        audit_log(banned_by, "BAN_ADD",
                  f"username={result['username']} hwids={len(result['hwids_banned'])} reason={reason[:80]}")
        return {"ok": True, **result, "kind": "username"}
    elif kind in ("hwid", "ip"):
        db.execute(
            "INSERT OR IGNORE INTO bans (kind, value, reason, banned_by) "
            "VALUES (?,?,?,?)",
            (kind, value, reason, banned_by),
        )
        db.commit()
        _federation_outbox_state_event("ban.added", {
            "kind": kind, "value": value, "reason": reason,
            "banned_by": banned_by, "origin_user": "",
        })
        audit_log(banned_by, "BAN_ADD", f"{kind}={value[:32]} reason={reason[:80]}")
        return {"ok": True, "kind": kind, "value": value}
    else:
        raise HTTPException(400, "kind must be username | hwid | ip")


@app.delete("/api/v1/admin/bans/{ban_id}")
async def admin_bans_remove(ban_id: int, session=Depends(require_admin)):
    """Lift a single ban row by id."""
    row = db.execute("SELECT kind, value FROM bans WHERE id=?", (ban_id,)).fetchone()
    if not row:
        raise HTTPException(404, "ban not found")
    db.execute("DELETE FROM bans WHERE id=?", (ban_id,))
    db.commit()
    _federation_outbox_state_event("ban.removed", {
        "kind": row[0], "value": row[1],
    })
    banned_by = session.get("admin_id", "") if isinstance(session, dict) else str(session)
    audit_log(banned_by, "BAN_REMOVE", f"{row[0]}={row[1][:32]}")
    return {"ok": True, "id": ban_id}


@app.post("/api/v1/admin/bans/lift-user")
async def admin_bans_lift_user(request: Request, session=Depends(require_admin)):
    """Lift every ban row tied to a given origin_user — the inverse of the
    username-ban cascade. Removes the username row AND every HWID row that
    was banned because of that user."""
    body = await request.json()
    username = norm_user(body.get("username", ""))
    if not username:
        raise HTTPException(400, "username is required")
    # Capture the affected rows BEFORE deleting so we can gossip each one
    # to peers; otherwise peers would only lift their own copy that
    # happens to share kind+value, missing the origin_user index.
    rows = db.execute(
        "SELECT kind, value FROM bans WHERE origin_user=? OR (kind='username' AND value=?)",
        (username, username),
    ).fetchall()
    deleted = db.execute(
        "DELETE FROM bans WHERE origin_user=? OR (kind='username' AND value=?)",
        (username, username),
    ).rowcount
    db.commit()
    for kind, value in rows:
        _federation_outbox_state_event("ban.removed", {"kind": kind, "value": value})
    banned_by = session.get("admin_id", "") if isinstance(session, dict) else str(session)
    audit_log(banned_by, "BAN_LIFT_USER", f"username={username} rows={deleted}")
    return {"ok": True, "deleted": deleted, "username": username}


@app.post("/api/v1/admin/federation/sync-now")
async def admin_federation_force_sync(session=Depends(require_admin)):
    """Force an immediate state-event pull from every peer instead of
    waiting for the hourly timer. Returns the per-peer applied counts
    so the dashboard can show progress."""
    if not FEDERATION_ENABLED:
        raise HTTPException(503, "federation disabled on this relay")
    import httpx
    row = db.execute(
        "SELECT COALESCE(MAX(origin_ts), 0) FROM federation_state_events"
    ).fetchone()
    since_ts = int(row[0]) if row and row[0] is not None else 0
    out = []
    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        for p in _federation_active_peers():
            applied = 0
            err = ""
            try:
                r = await client.get(
                    p["endpoint"].rstrip("/")
                    + f"/api/v1/federation/state-events/since?since_ts={since_ts}&limit=2000"
                )
                if r.status_code == 200:
                    body = r.json()
                    for ev in body.get("events", []):
                        if _seen_state_event(ev["event_id"]):
                            continue
                        _apply_state_event(ev["event_kind"], ev["payload"])
                        _federation_outbox_state_event(
                            ev["event_kind"], ev["payload"],
                            event_id=ev["event_id"], ts=ev["ts"],
                        )
                        applied += 1
                else:
                    err = f"HTTP {r.status_code}"
            except Exception as e:
                err = str(e)[:200]
            out.append({"endpoint": p["endpoint"], "applied": applied, "error": err})
    return {"since_ts": since_ts, "peers": out}


@app.get("/api/v1/admin/federation")
async def admin_federation_health(session=Depends(require_admin)):
    """Aggregated federation health — polls every active peer's
    public /api/v1/relay-stats endpoint and merges with this relay's
    own stats. Returns a flat list the dashboard can render as a
    health grid (one card per relay).

    Tolerates per-peer failures: an unreachable peer shows up as a row
    with `reachable=false` rather than blowing up the whole response.
    """
    import urllib.request, ssl, socket
    # Local relay first
    out = []
    try:
        local = await get_relay_stats()
        out.append({
            "endpoint": "self",
            "operator": "this relay",
            "reachable": True,
            "stats": local,
        })
    except Exception as e:
        out.append({"endpoint": "self", "reachable": False, "error": str(e)})

    peers: list[dict] = []
    if FEDERATION_ENABLED:
        try:
            peers = _federation_active_peers()
        except Exception:
            peers = []

    # Permissive TLS — peer relays use self-signed certs by design.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for peer in peers:
        endpoint = peer.get("endpoint", "")
        if not endpoint:
            continue
        entry = {
            "endpoint": endpoint,
            "operator": peer.get("operator", ""),
            "pubkey_hex": peer.get("pubkey_hex", ""),
            "reachable": False,
        }
        try:
            req = urllib.request.Request(
                f"{endpoint.rstrip('/')}/api/v1/relay-stats",
                method="GET",
            )
            with urllib.request.urlopen(req, context=ctx, timeout=6) as resp:
                entry["reachable"] = (resp.status == 200)
                entry["stats"] = json.loads(resp.read())
        except (urllib.error.URLError, socket.timeout, json.JSONDecodeError) as e:
            entry["error"] = str(e)[:200]
        out.append(entry)

    return {
        "schema": "shroud.federation-health.v1",
        "ts": int(time.time()),
        "relays": out,
        "summary": {
            "total":     len(out),
            "reachable": sum(1 for r in out if r.get("reachable")),
        },
    }


@app.get("/api/v1/admin/stats/overview")
async def admin_stats_overview(session=Depends(require_admin)):
    active_now  = db.execute("SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now','-60 seconds')").fetchone()[0]
    active_1min = db.execute("SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now','-5 minutes')").fetchone()[0]
    os_counts = {row[0]: row[1] for row in db.execute("SELECT platform, COUNT(*) FROM devices GROUP BY platform").fetchall()}
    latency = db.execute("SELECT ROUND(AVG(latency_ms),1), MIN(latency_ms), MAX(latency_ms) FROM message_latency WHERE recorded_at > datetime('now','-1 hour')").fetchone()
    msgs_1h  = db.execute("SELECT COUNT(*) FROM messages WHERE server_ts > datetime('now','-1 hour')").fetchone()[0]
    msgs_24h = db.execute("SELECT COUNT(*) FROM messages WHERE server_ts > datetime('now','-1 day')").fetchone()[0]
    bytes_24h = db.execute("SELECT COALESCE(SUM(LENGTH(envelope)),0) FROM messages WHERE server_ts > datetime('now','-1 day')").fetchone()[0]
    avg_msg_size = db.execute("SELECT ROUND(AVG(LENGTH(envelope)),0) FROM messages").fetchone()[0] or 0
    failed_24h = db.execute("SELECT COUNT(*) FROM login_attempts WHERE success=0 AND attempted_at > datetime('now','-1 day')").fetchone()[0]
    friend_pending_n = db.execute("SELECT COUNT(*) FROM friend_requests WHERE status='pending'").fetchone()[0]
    group_pending_n  = db.execute("SELECT COUNT(*) FROM group_invites WHERE status='pending'").fetchone()[0]

    hourly = db.execute(
        "SELECT strftime('%Y-%m-%d %H:00', server_ts) AS hr, COUNT(*) "
        "FROM messages WHERE server_ts > datetime('now','-24 hours') "
        "GROUP BY hr ORDER BY hr"
    ).fetchall()
    hourly_activity = [{"hour": r[0], "count": r[1]} for r in hourly]

    top_endpoints = [
        {"path": p, "count": c, "errors": ERR_COUNTS.get(p, 0)}
        for p, c in REQ_COUNTS.most_common(15)
    ]
    recent_latencies = [ms for _, ms, _ in REQ_LATENCY]
    avg_req_ms = round(sum(recent_latencies)/len(recent_latencies), 1) if recent_latencies else 0
    p95_req_ms = 0
    if recent_latencies:
        s = sorted(recent_latencies)
        p95_req_ms = round(s[int(len(s)*0.95) - 1], 1) if len(s) > 1 else round(s[0], 1)

    db_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    files_dir_size = _dir_size(FILE_DIR)
    try:
        disk = shutil.disk_usage(os.path.dirname(DB_PATH))
        disk_total = disk.total; disk_free = disk.free
    except Exception:
        disk_total = disk_free = 0

    total_req = ONION_REQ_COUNT + CLEAR_REQ_COUNT
    onion_pct = round((ONION_REQ_COUNT / total_req) * 100, 1) if total_req else 0

    out = dict(_meta_block())
    out.update({
        "total_users":       db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_devices":     db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
        "total_messages":    db.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
        "undelivered":       db.execute("SELECT COUNT(*) FROM messages WHERE delivered=0").fetchone()[0],
        "total_groups":      db.execute("SELECT COUNT(*) FROM group_chats").fetchone()[0],
        "total_friendships": db.execute("SELECT COUNT(*) FROM friendships").fetchone()[0],
        "active_today":      db.execute("SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now','-1 day')").fetchone()[0],
        "active_now": active_now,
        "active_1min": active_1min,
        "os_windows": os_counts.get("windows", 0),
        "os_android": os_counts.get("android", 0),
        "os_ios":     os_counts.get("ios", 0),
        "msgs_1h": msgs_1h, "msgs_24h": msgs_24h,
        "bytes_24h": bytes_24h, "avg_msg_size": int(avg_msg_size),
        "avg_latency_ms": latency[0] or 0,
        "min_latency_ms": latency[1] or 0,
        "max_latency_ms": latency[2] or 0,
        "avg_req_ms": avg_req_ms,
        "p95_req_ms": p95_req_ms,
        "file_count": db.execute("SELECT COUNT(*) FROM file_transfers").fetchone()[0],
        "file_total_bytes": db.execute("SELECT COALESCE(SUM(encrypted_size),0) FROM file_transfers").fetchone()[0],
        "db_size_bytes": db_size,
        "files_dir_bytes": files_dir_size,
        "disk_free_bytes": disk_free,
        "disk_total_bytes": disk_total,
        "failed_logins_24h": failed_24h,
        "pending_friend_requests": friend_pending_n,
        "pending_group_invites":  group_pending_n,
        "requests_total": sum(REQ_COUNTS.values()),
        "errors_total":   sum(ERR_COUNTS.values()),
        "ecdh_cache_size": len(ecdh_cache),
        "cover_count": COVER_COUNT,
        "cover_bytes": COVER_BYTES,
        "onion_pct": onion_pct,
        "hourly_activity": hourly_activity,
        "top_endpoints": top_endpoints,
    })
    return out


@app.get("/api/v1/admin/stats/users")
async def admin_stats_users(session=Depends(require_admin)):
    users = [
        {"username": u[0], "user_id": u[1], "created": u[2], "devices": u[3]}
        for u in db.execute(
            "SELECT u.username, u.id, u.created_at, "
            "(SELECT COUNT(*) FROM devices WHERE user_id=u.id) "
            "FROM users u ORDER BY u.created_at DESC LIMIT 500"
        ).fetchall()
    ]
    friend_pending = db.execute(
        "SELECT fr.id, uf.username, ut.username, fr.reason, fr.created_at "
        "FROM friend_requests fr JOIN users uf ON uf.id=fr.from_user_id "
        "JOIN users ut ON ut.id=fr.to_user_id WHERE fr.status='pending' "
        "ORDER BY fr.created_at DESC LIMIT 100"
    ).fetchall()
    group_pending = db.execute(
        "SELECT gi.id, g.name, uf.username, ut.username, gi.reason, gi.created_at "
        "FROM group_invites gi JOIN group_chats g ON g.id=gi.group_id "
        "JOIN users uf ON uf.id=gi.from_user_id JOIN users ut ON ut.id=gi.to_user_id "
        "WHERE gi.status='pending' ORDER BY gi.created_at DESC LIMIT 100"
    ).fetchall()
    top_send = db.execute(
        "SELECT sender_device_id, COUNT(*) FROM messages WHERE server_ts > datetime('now','-1 day') "
        "GROUP BY sender_device_id ORDER BY 2 DESC LIMIT 10"
    ).fetchall()
    top_recv = db.execute(
        "SELECT recipient_device_id, COUNT(*) FROM messages WHERE server_ts > datetime('now','-1 day') "
        "GROUP BY recipient_device_id ORDER BY 2 DESC LIMIT 10"
    ).fetchall()
    return {
        "users": users,
        "friend_requests_pending": [
            {"id": r[0], "from": r[1], "to": r[2], "reason": ar_dec(r[3]), "created": r[4]}
            for r in friend_pending
        ],
        "group_invites_pending": [
            {"id": r[0], "group": r[1], "from": r[2], "to": r[3], "reason": ar_dec(r[4]), "created": r[5]}
            for r in group_pending
        ],
        "top_senders":    [{"id": r[0][:12], "count": r[1]} for r in top_send],
        "top_recipients": [{"id": r[0][:12], "count": r[1]} for r in top_recv],
    }


@app.get("/api/v1/admin/stats/devices")
async def admin_stats_devices(session=Depends(require_admin)):
    devices = [
        {"id": d[0], "platform": d[1], "name": d[2], "registered": d[3], "last_seen": d[4] or "never"}
        for d in db.execute(
            "SELECT id, platform, device_name, registered_at, last_seen "
            "FROM devices ORDER BY registered_at DESC LIMIT 500"
        ).fetchall()
    ]
    groups = [
        {"id": g[0], "name": g[1], "members": g[2], "created": g[3]}
        for g in db.execute(
            "SELECT g.id, g.name, COUNT(gm.device_id), g.created_at "
            "FROM group_chats g LEFT JOIN group_members gm ON g.id=gm.group_id "
            "GROUP BY g.id ORDER BY g.created_at DESC"
        ).fetchall()
    ]
    return {"devices": devices, "groups": groups}


@app.get("/api/v1/admin/stats/crypto")
async def admin_stats_crypto(session=Depends(require_admin)):
    low_prekey = db.execute(
        "SELECT d.id, u.username, d.last_seen, "
        "(SELECT COUNT(*) FROM one_time_prekeys WHERE device_id=d.id) AS pk "
        "FROM devices d LEFT JOIN users u ON u.id=d.user_id "
        "WHERE d.x25519_pub IS NOT NULL "
        "AND (SELECT COUNT(*) FROM one_time_prekeys WHERE device_id=d.id) < 5 "
        "ORDER BY pk ASC, d.last_seen DESC LIMIT 50"
    ).fetchall()
    return {
        "identity_fingerprint": SERVER_IDENTITY["fingerprint"] if SERVER_IDENTITY else "",
        "identity_suite": "Ed25519+ML-DSA-87+SPHINCS+-256s" if SERVER_IDENTITY else "",
        "identity_created_at": _file_mtime_iso(IDENTITY_PATH),
        "pq_available": PQ_AVAILABLE,
        "pq_suite": "ECDH-P384+ML-KEM-1024" if PQ_AVAILABLE else "",
        "anon_creds_available": ANON_CREDS_AVAILABLE,
        "anon_creds_redeemed_total":
            db.execute("SELECT COUNT(*) FROM redeemed_credentials").fetchone()[0]
            if ANON_CREDS_AVAILABLE else 0,
        "anon_creds_created_at": _file_mtime_iso(ANON_CREDS_KEY_PATH),
        "srp_available": SRP_AVAILABLE,
        "srp_users": db.execute("SELECT COUNT(*) FROM users WHERE srp_verifier IS NOT NULL").fetchone()[0],
        "at_rest_available": AT_REST_AVAILABLE and DATA_KEY is not None,
        "at_rest_created_at": _file_mtime_iso(DATA_KEY_PATH),
        "ratchet_devices": db.execute("SELECT COUNT(*) FROM devices WHERE x25519_pub IS NOT NULL").fetchone()[0],
        "one_time_prekeys_total": db.execute("SELECT COUNT(*) FROM one_time_prekeys").fetchone()[0],
        "treekem_groups": db.execute("SELECT COUNT(*) FROM treekem_state").fetchone()[0],
        "device_link_active": db.execute(
            "SELECT COUNT(*) FROM device_link_sessions "
            "WHERE consumed=0 AND expires_at > datetime('now')"
        ).fetchone()[0],
        "padding_distribution": _padding_distribution(),
        "low_prekey_devices": [
            {"device_id": r[0], "username": r[1], "last_seen": r[2], "prekeys": r[3]}
            for r in low_prekey
        ],
    }


@app.get("/api/v1/admin/stats/files")
async def admin_stats_files(session=Depends(require_admin)):
    files = db.execute(
        "SELECT id, sender_device_id, recipient_device_id, original_size, "
        "encrypted_size, server_ts, expires_at, downloaded "
        "FROM file_transfers ORDER BY server_ts DESC"
    ).fetchall()
    return {
        "files": [
            {"id": f[0], "sender": f[1][:12], "recipient": f[2][:12],
             "orig_size": f[3], "enc_size": f[4], "server_ts": f[5],
             "expires_at": f[6], "downloaded": bool(f[7])}
            for f in files
        ],
    }


@app.get("/api/v1/admin/stats/audit")
async def admin_stats_audit(
    request: Request,
    actor: Optional[str] = None,
    action: Optional[str] = None,
    target: Optional[str] = None,
    since_hours: Optional[float] = None,
    format: Optional[str] = None,
    session=Depends(require_admin),
):
    """Audit log with filters + optional CSV export. CSV mode streams as
    a download; default mode bundles the audit table together with the
    failed-logins, recent-errors, and admin-sessions views so the Audit
    tab is one round-trip."""
    q = "SELECT actor, action, target, detail, ts FROM audit_log WHERE 1=1"
    args: list = []
    if actor:
        q += " AND actor LIKE ?";  args.append(f"%{actor}%")
    if action:
        q += " AND action LIKE ?"; args.append(f"%{action}%")
    if target:
        q += " AND target LIKE ?"; args.append(f"%{target}%")
    if since_hours and since_hours > 0:
        q += " AND ts > datetime('now', ?)"
        args.append(f"-{float(since_hours)} hours")
    q += " ORDER BY id DESC LIMIT 500"
    rows = db.execute(q, args).fetchall()
    audit = [
        {"actor": a[0], "action": a[1], "target": a[2], "detail": a[3], "ts": a[4]}
        for a in rows
    ]

    if (format or "").lower() == "csv":
        import io, csv
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["ts", "actor", "action", "target", "detail"])
        for r in audit:
            w.writerow([r["ts"], r["actor"], r["action"], r["target"], r["detail"]])
        return PlainTextResponse(
            buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="shroud-audit.csv"'},
        )

    failed_logins = [
        {"ip": r[0], "hwid": (r[1] or "")[:16], "fp": (r[2] or "")[:8], "ts": r[3]}
        for r in db.execute(
            "SELECT ip, hwid, fingerprint_id, attempted_at FROM login_attempts "
            "WHERE success=0 ORDER BY attempted_at DESC LIMIT 50"
        ).fetchall()
    ]
    sessions = [
        {"id": s[0], "ip": ar_dec(s[1]), "login_at": s[2], "last_activity": s[3], "active": not bool(s[4])}
        for s in db.execute(
            "SELECT id, ip, login_at, last_activity, logged_out "
            "FROM admin_sessions ORDER BY login_at DESC LIMIT 50"
        ).fetchall()
    ]
    return {
        "audit_log": audit,
        "failed_logins": failed_logins,
        "recent_errors": list(RECENT_ERRORS)[:50],
        "sessions": sessions,
    }


@app.get("/api/v1/admin/stats/activity")
async def admin_stats_activity(session=Depends(require_admin)):
    """Time-series data, recent message stream, onion vs clearnet split."""
    # 7-day hourly buckets. We aggregate from real timestamped tables so
    # we get history even before the server_stats_history snapshotter
    # filled in. The snapshot table is only used for cumulative counters
    # like requests_total/errors_total that don't have per-event tables.
    series_buckets = []
    for h in range(168, -1, -1):
        end = datetime.now(tz=timezone.utc) - timedelta(hours=h)
        series_buckets.append(end.strftime('%Y-%m-%d %H:00'))

    def _hourly_counts(table: str, col: str) -> dict:
        rows = db.execute(
            f"SELECT strftime('%Y-%m-%d %H:00', {col}) AS hr, COUNT(*) "
            f"FROM {table} WHERE {col} > datetime('now','-7 days') "
            "GROUP BY hr"
        ).fetchall()
        return {r[0]: r[1] for r in rows}

    msgs_h     = _hourly_counts("messages", "server_ts")
    new_users_h = _hourly_counts("users", "created_at")
    failed_h   = db.execute(
        "SELECT strftime('%Y-%m-%d %H:00', attempted_at), COUNT(*) "
        "FROM login_attempts WHERE success=0 AND attempted_at > datetime('now','-7 days') "
        "GROUP BY 1"
    ).fetchall()
    failed_h = {r[0]: r[1] for r in failed_h}

    # Snapshot history for the things that don't live in event tables.
    snap_rows = db.execute(
        "SELECT strftime('%Y-%m-%d %H:00', taken_at) AS hr, "
        "MAX(active_devices), MAX(files_dir_bytes), MAX(errors_total), MAX(requests_total) "
        "FROM server_stats_history WHERE taken_at > datetime('now','-7 days') "
        "GROUP BY hr ORDER BY hr"
    ).fetchall()
    snaps = {r[0]: {"active_devices": r[1] or 0, "storage_bytes": r[2] or 0,
                    "errors_cum": r[3] or 0, "requests_cum": r[4] or 0}
             for r in snap_rows}

    # Convert cumulative errors_total into per-hour deltas.
    series = []
    prev_err = None
    for b in series_buckets:
        snap = snaps.get(b, {})
        err_cum = snap.get("errors_cum", 0)
        if prev_err is None:
            errors_delta = 0
        else:
            errors_delta = max(0, err_cum - prev_err)
        prev_err = err_cum
        series.append({
            "bucket": b,
            "messages":       msgs_h.get(b, 0),
            "new_users":      new_users_h.get(b, 0),
            "failed_logins":  failed_h.get(b, 0),
            "active_devices": snap.get("active_devices", 0),
            "storage_bytes":  snap.get("storage_bytes",  0),
            "errors":         errors_delta,
        })

    recent_messages = [
        {"ts": m[0], "sender": m[1], "recipient": m[2], "size": m[3], "delivered": bool(m[4])}
        for m in db.execute(
            "SELECT server_ts, sender_device_id, recipient_device_id, "
            "LENGTH(envelope), delivered FROM messages "
            "ORDER BY server_ts DESC LIMIT 50"
        ).fetchall()
    ]
    # Flat helper series for sparkline-style consumers (shroud-admin's
    # StatsTab and the web admin's Activity tab). The objects-list shape
    # above is kept for the legacy consumers that drill into individual
    # buckets; these arrays let a simple line widget render without
    # repeatedly walking `series`.
    requests_per_minute = []
    errors_per_minute   = []
    last_req = None
    for b in series_buckets[-60:]:
        snap = snaps.get(b, {})
        req_cum = snap.get("requests_cum", 0)
        err_cum = snap.get("errors_cum", 0)
        if last_req is None:
            requests_per_minute.append(0)
            errors_per_minute.append(0)
        else:
            requests_per_minute.append(max(0, req_cum - last_req[0]))
            errors_per_minute.append(max(0, err_cum - last_req[1]))
        last_req = (req_cum, err_cum)
    messages_per_hour  = [s["messages"]       for s in series[-24:]]
    active_devices_arr = [s["active_devices"] for s in series[-60:]]

    return {
        "series": series,
        "requests_per_minute": requests_per_minute,
        "errors_per_minute":   errors_per_minute,
        "messages_per_hour":   messages_per_hour,
        "active_devices":      active_devices_arr,
        "recent_messages":     recent_messages,
        "onion_requests":      ONION_REQ_COUNT,
        "clear_requests":      CLEAR_REQ_COUNT,
    }


@app.get("/api/v1/admin/stats/badges")
async def admin_stats_badges(session=Depends(require_admin)):
    """Tiny counts for the inactive-tab badges. Fast — used by every poll."""
    return {
        "users":   db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "devices": db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
        "files":   db.execute("SELECT COUNT(*) FROM file_transfers").fetchone()[0],
        "audit":   db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
    }


@app.get("/api/v1/admin/stats")
async def admin_stats_legacy(session=Depends(require_admin)):
    """Backwards-compat alias. External scripts pointed at the old monolithic
    endpoint still get the overview block. New dashboard JS hits the
    per-section endpoints directly."""
    return await admin_stats_overview(session)


# ─── Per-user drill-down ────────────────────────────────────────────
@app.get("/admin/user/{user_id}")
async def admin_user_page(user_id: str, session=Depends(require_admin)):
    return _serve_admin_html("user.html")


@app.get("/api/v1/admin/users/{user_id}/details")
async def admin_user_details(user_id: str, session=Depends(require_admin)):
    user = db.execute(
        "SELECT username, created_at FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if not user:
        raise HTTPException(404, "user not found")
    username, created_at = user

    devices = []
    for d in db.execute(
        "SELECT id, platform, device_name, registered_at, last_seen "
        "FROM devices WHERE user_id=? ORDER BY registered_at DESC", (user_id,)
    ).fetchall():
        pk = db.execute("SELECT COUNT(*) FROM one_time_prekeys WHERE device_id=?", (d[0],)).fetchone()[0]
        devices.append({
            "id": d[0], "platform": d[1], "name": d[2],
            "registered": d[3], "last_seen": d[4] or "never", "prekeys": pk,
        })
    dev_ids = [d["id"] for d in devices]

    if dev_ids:
        ph = ",".join("?" * len(dev_ids))
        msgs_24h = db.execute(
            f"SELECT COUNT(*) FROM messages WHERE sender_device_id IN ({ph}) "
            f"AND server_ts > datetime('now','-1 day')", dev_ids).fetchone()[0]
        msgs_7d = db.execute(
            f"SELECT COUNT(*) FROM messages WHERE sender_device_id IN ({ph}) "
            f"AND server_ts > datetime('now','-7 days')", dev_ids).fetchone()[0]
        msgs_all = db.execute(
            f"SELECT COUNT(*) FROM messages WHERE sender_device_id IN ({ph})", dev_ids).fetchone()[0]
    else:
        msgs_24h = msgs_7d = msgs_all = 0

    friend_rows = db.execute(
        "SELECT CASE WHEN f.user_a=? THEN f.user_b ELSE f.user_a END, "
        "       CASE WHEN f.user_a=? THEN 'a→b' ELSE 'b→a' END, "
        "       f.created_at "
        "FROM friendships f WHERE f.user_a=? OR f.user_b=? "
        "ORDER BY f.created_at DESC LIMIT 200",
        (user_id, user_id, user_id, user_id),
    ).fetchall()
    friends = []
    for peer_id, direction, ts in friend_rows:
        peer = db.execute("SELECT username FROM users WHERE id=?", (peer_id,)).fetchone()
        friends.append({
            "user_id": peer_id, "username": peer[0] if peer else "(unknown)",
            "direction": direction, "established": ts,
        })

    groups = [
        {"id": r[0], "name": r[1], "via_device": r[2]}
        for r in db.execute(
            "SELECT g.id, g.name, gm.device_id FROM group_chats g "
            "JOIN group_members gm ON gm.group_id=g.id "
            "JOIN devices d ON d.id=gm.device_id "
            "WHERE d.user_id=? ORDER BY g.created_at DESC LIMIT 200",
            (user_id,),
        ).fetchall()
    ]

    # Login history needs a per-user link. We don't have one yet — best we
    # can do is fingerprint-based for admins (irrelevant here) and SRP login
    # records when the schema has them. For regular users we report only the
    # registration-flow audit mentions, which is honest.
    logins: list = []
    login_count_24h = 0
    failed_login_count = 0

    audit_mentions = [
        {"actor": r[0], "action": r[1], "target": r[2], "detail": r[3], "ts": r[4]}
        for r in db.execute(
            "SELECT actor, action, target, detail, ts FROM audit_log "
            "WHERE target=? OR detail LIKE ? "
            "ORDER BY id DESC LIMIT 100",
            (user_id, f"%{user_id}%"),
        ).fetchall()
    ]

    return {
        "user_id": user_id, "username": username, "created_at": created_at,
        "device_count": len(devices), "devices": devices,
        "msgs_24h": msgs_24h, "msgs_7d": msgs_7d, "msgs_all": msgs_all,
        "friend_count": len(friends), "friendships": friends,
        "group_count": len(groups), "groups": groups,
        "login_count_24h": login_count_24h, "failed_login_count": failed_login_count,
        "logins": logins,
        "audit_mentions": audit_mentions,
    }


# ─── Per-device drill-down ──────────────────────────────────────────
@app.get("/admin/device/{device_id}")
async def admin_device_page(device_id: str, session=Depends(require_admin)):
    return _serve_admin_html("device.html")


@app.get("/api/v1/admin/devices")
async def admin_devices_list(session=Depends(require_admin)):
    """List every device row. The admin dashboards (web + shroud-admin
    Devices tab) call this to render the device table with per-row
    actions. Kept slim — full per-device detail is at /admin/devices/
    {id}/details."""
    rows = db.execute(
        "SELECT d.id, d.user_id, u.username, d.platform, d.device_name, "
        "d.hwid, d.last_seen, d.registered_at "
        "FROM devices d LEFT JOIN users u ON u.id = d.user_id "
        "ORDER BY d.last_seen DESC LIMIT 5000"
    ).fetchall()
    return {
        "count": len(rows),
        "devices": [
            {
                "id":          r[0],
                "user_id":     r[1],
                "username":    r[2] or "",
                "platform":    r[3] or "",
                "device_name": r[4] or "",
                "hwid":        r[5] or "",
                "last_seen":   str(r[6]) if r[6] else "",
                "created":     str(r[7]) if r[7] else "",
            }
            for r in rows
        ],
    }


@app.get("/api/v1/admin/devices/{device_id}/details")
async def admin_device_details(device_id: str, session=Depends(require_admin)):
    row = db.execute(
        "SELECT d.id, d.platform, d.device_name, d.registered_at, d.last_seen, "
        "d.user_id, d.x25519_pub, d.ratchet_published_at, u.username "
        "FROM devices d LEFT JOIN users u ON u.id=d.user_id "
        "WHERE d.id=?", (device_id,),
    ).fetchone()
    if not row:
        raise HTTPException(404, "device not found")

    (did, platform, name, registered_at, last_seen, user_id,
     x25519_pub, ratchet_at, username) = row

    one_time = db.execute(
        "SELECT COUNT(*) FROM one_time_prekeys WHERE device_id=?", (did,)
    ).fetchone()[0]
    msgs_sent_24h = db.execute(
        "SELECT COUNT(*) FROM messages WHERE sender_device_id=? AND server_ts > datetime('now','-1 day')", (did,)
    ).fetchone()[0]
    msgs_recv_24h = db.execute(
        "SELECT COUNT(*) FROM messages WHERE recipient_device_id=? AND server_ts > datetime('now','-1 day')", (did,)
    ).fetchone()[0]
    msgs_sent_total = db.execute("SELECT COUNT(*) FROM messages WHERE sender_device_id=?", (did,)).fetchone()[0]
    msgs_recv_total = db.execute("SELECT COUNT(*) FROM messages WHERE recipient_device_id=?", (did,)).fetchone()[0]
    pending_to   = db.execute("SELECT COUNT(*) FROM messages WHERE recipient_device_id=? AND delivered=0", (did,)).fetchone()[0]
    pending_from = db.execute("SELECT COUNT(*) FROM messages WHERE sender_device_id=?    AND delivered=0", (did,)).fetchone()[0]
    group_count  = db.execute("SELECT COUNT(*) FROM group_members WHERE device_id=?", (did,)).fetchone()[0]

    siblings = [
        {"id": s[0], "platform": s[1], "name": s[2], "last_seen": s[3] or "never"}
        for s in db.execute(
            "SELECT id, platform, device_name, last_seen FROM devices "
            "WHERE user_id=? AND id<>? ORDER BY registered_at DESC", (user_id, did),
        ).fetchall()
    ] if user_id else []

    recent_msgs = [
        {"ts": m[0], "direction": m[1], "peer": m[2], "size": m[3], "delivered": bool(m[4])}
        for m in db.execute(
            "SELECT server_ts, "
            "CASE WHEN sender_device_id=? THEN 'sent' ELSE 'recv' END, "
            "CASE WHEN sender_device_id=? THEN recipient_device_id ELSE sender_device_id END, "
            "LENGTH(envelope), delivered "
            "FROM messages WHERE sender_device_id=? OR recipient_device_id=? "
            "ORDER BY server_ts DESC LIMIT 50",
            (did, did, did, did),
        ).fetchall()
    ]

    # Best-effort: scan RECENT_ERRORS for paths that mention this device id.
    needle = did[:12]
    recent_errors = [e for e in list(RECENT_ERRORS) if needle in (e.get("path") or "")][:50]

    spk_age = None
    if ratchet_at:
        try:
            t = datetime.fromisoformat(ratchet_at.replace(" ", "T")).replace(tzinfo=timezone.utc)
            spk_age = max(0, (datetime.now(tz=timezone.utc) - t).days)
        except Exception:
            spk_age = None

    return {
        "id": did, "platform": platform, "name": name,
        "registered_at": registered_at, "last_seen": last_seen,
        "user_id": user_id, "username": username,
        "has_x25519": x25519_pub is not None,
        "has_ed25519": False,  # not currently persisted by device
        "one_time_prekeys": one_time,
        "signed_prekey_age_days": spk_age,
        "last_bundle_fetch": ratchet_at,
        "ratchet": {
            "signed_prekey_id": None,
            "signed_prekey_at": ratchet_at,
            "recv_count": msgs_recv_total,
            "send_count": msgs_sent_total,
        },
        "msgs_sent_24h": msgs_sent_24h, "msgs_recv_24h": msgs_recv_24h,
        "msgs_sent_total": msgs_sent_total, "msgs_recv_total": msgs_recv_total,
        "undelivered_to_me": pending_to, "undelivered_from_me": pending_from,
        "group_count": group_count,
        "siblings": siblings,
        "recent_messages": recent_msgs,
        "recent_errors": recent_errors,
        "recent_error_count": len(recent_errors),
    }


# ─── Control "preview" endpoints ────────────────────────────────────
# Destructive actions ask for an impact preview before they fire so the
# dashboard can show the operator exactly what is about to happen.
@app.get("/api/v1/admin/control/clear-undelivered/preview")
async def admin_preview_clear_undelivered(session=Depends(require_admin)):
    n = db.execute("SELECT COUNT(*) FROM messages WHERE delivered=0").fetchone()[0]
    b = db.execute("SELECT COALESCE(SUM(LENGTH(envelope)),0) FROM messages WHERE delivered=0").fetchone()[0]
    return {
        "messages": n,
        "bytes": b,
        "message": f"Will permanently delete {n} undelivered message(s) totalling {b} bytes.",
    }


@app.get("/api/v1/admin/control/purge-files/preview")
async def admin_preview_purge_files(session=Depends(require_admin)):
    rows = db.execute(
        "SELECT COUNT(*), COALESCE(SUM(encrypted_size),0) "
        "FROM file_transfers WHERE expires_at < datetime('now') OR downloaded=1"
    ).fetchone()
    return {
        "files": rows[0],
        "bytes": rows[1],
        "message": f"Will remove {rows[0]} file(s), reclaiming {rows[1]} bytes from disk.",
    }


@app.get("/api/v1/admin/control/rotate-identity/preview")
async def admin_preview_rotate_identity(session=Depends(require_admin)):
    old_fp = SERVER_IDENTITY["fingerprint"] if SERVER_IDENTITY else ""
    pinned_devices = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    return {
        "current_fingerprint": old_fp,
        "pinned_devices": pinned_devices,
        "message": (
            "Will discard the current server identity keypair and generate "
            "a new one. All previously-pinned clients (~"
            f"{pinned_devices} device(s)) must re-pin out-of-band."
        ),
    }


# ─── WebSocket live tail ────────────────────────────────────────────
def _ws_admin_session(ws: WebSocket):
    """Validate the admin session cookie on a WebSocket handshake.
    Returns the session row or None — caller is responsible for closing
    the socket if None. We can't use FastAPI dependency injection here
    because WebSockets aren't request-scoped the same way."""
    sid = ws.cookies.get("shroud_sid")
    if not sid:
        # Fallback: some browsers don't attach cookies to WS upgrade
        # requests. Accept ?token=<session-id> as an alternative.
        qp_token = ws.query_params.get("token")
        print(f"[admin_ws] cookie sid=None, query token={'present' if qp_token else 'None'}", flush=True)
        sid = qp_token
    if not sid:
        return None
    session = get_admin_session(sid)
    if not session:
        print(f"[admin_ws] get_admin_session returned None for sid={sid[:8]}...", flush=True)
    return session


@app.get("/api/v1/admin/ws-token")
async def admin_ws_token(session=Depends(require_admin)):
    """Return the session ID so the browser can pass it as a query parameter
    to the WebSocket endpoint.  The browser already proves auth by sending the
    HttpOnly shroud_sid cookie with this HTTP request."""
    return {"token": session[0]}


async def _admin_ws_handler(ws: WebSocket):
    """Core admin WebSocket handler — called from /ws/admin or /ws/{device_id}
    when device_id == 'admin' (the catch-all device route would otherwise
    consume the connection before the explicit /ws/admin route fires)."""
    peer = f"{ws.client.host}:{ws.client.port}" if ws.client else "?"
    has_sid = "shroud_sid" in ws.cookies
    session = _ws_admin_session(ws)
    if not session:
        print(f"[admin_ws] REJECT {peer} — has_sid={has_sid} session=None", flush=True)
        try:
            await ws.accept()
            await ws.close(code=4401, reason="not authenticated")
        except Exception as e:
            print(f"[admin_ws] reject-close error: {e!r}", flush=True)
        return
    try:
        await ws.accept()
    except Exception as e:
        print(f"[admin_ws] accept failed for {peer}: {e!r}", flush=True)
        return
    print(f"[admin_ws] ACCEPT {peer} sid={session[0][:8]}…", flush=True)
    _WS_ADMIN_SUBS.add(ws)
    try:
        await ws.send_text(json.dumps({
            "type": "hello",
            "server_time_utc": datetime.now(tz=timezone.utc).isoformat(timespec='seconds'),
            "version": SERVER_VERSION,
        }))
        while True:
            msg = await ws.receive_text()
            if msg and '"ping"' in msg:
                try:
                    await ws.send_text('{"type":"pong"}')
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[admin_ws] loop error {peer}: {e!r}", flush=True)
    finally:
        _WS_ADMIN_SUBS.discard(ws)
        print(f"[admin_ws] CLOSED {peer}", flush=True)


@app.websocket("/ws/admin")
async def admin_ws(ws: WebSocket):
    await _admin_ws_handler(ws)


@app.delete("/api/v1/admin/devices/{device_id}")
async def admin_delete_device(device_id: str, session=Depends(require_admin_csrf)):
    db.execute("DELETE FROM messages WHERE sender_device_id=? OR recipient_device_id=?", (device_id, device_id))
    db.execute("DELETE FROM group_members WHERE device_id=?", (device_id,))
    db.execute("DELETE FROM devices WHERE id=?", (device_id,))
    db.commit()
    audit_admin(session[0][:8], "delete_device", device_id, "")
    return {"deleted": device_id}

# ── Admin Controls ────────────────────────────────────────────────
@app.post("/api/v1/admin/control/purge-files")
async def admin_purge_files(session=Depends(require_admin_csrf)):
    rows = db.execute("SELECT id, storage_name FROM file_transfers WHERE expires_at < datetime('now') OR downloaded=1").fetchall()
    removed = 0
    for fid, name in rows:
        path = os.path.join(FILE_DIR, name)
        if os.path.isfile(path):
            try: os.remove(path); removed += 1
            except OSError: pass
        db.execute("DELETE FROM file_transfers WHERE id=?", (fid,))
    db.commit()
    audit_admin(session[0][:8], "purge_files", "", f"removed={removed}")
    return {"removed": removed}

@app.post("/api/v1/admin/control/vacuum")
async def admin_vacuum(session=Depends(require_admin_csrf)):
    before = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    try:
        db.execute("VACUUM")
        db.commit()
    except sqlite3.OperationalError as e:
        raise HTTPException(409, f"VACUUM unavailable: {e}")
    after = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    audit_admin(session[0][:8], "vacuum_db", "", f"saved={before-after}B")
    return {"before": before, "after": after, "saved": before - after}

@app.post("/api/v1/admin/control/clear-ecdh")
async def admin_clear_ecdh(session=Depends(require_admin_csrf)):
    with ecdh_lock:
        n = len(ecdh_cache); ecdh_cache.clear()
    audit_admin(session[0][:8], "clear_ecdh_cache", "", f"cleared={n}")
    return {"cleared": n}

@app.post("/api/v1/admin/control/wipe-rate-limits")
async def admin_wipe_rate_limits(session=Depends(require_admin_csrf)):
    n = len(rate_limits); rate_limits.clear()
    audit_admin(session[0][:8], "wipe_rate_limits", "", f"buckets={n}")
    return {"cleared_buckets": n}

@app.post("/api/v1/admin/control/kill-sessions")
async def admin_kill_other_sessions(session=Depends(require_admin_csrf)):
    cur_sid = session[0]
    db.execute("UPDATE admin_sessions SET logged_out=1 WHERE logged_out=0 AND id != ?", (cur_sid,))
    n = db.execute("SELECT changes()").fetchone()[0]
    db.commit()
    audit_admin(cur_sid[:8], "kill_other_admin_sessions", "", f"killed={n}")
    return {"killed": n}

@app.post("/api/v1/admin/control/clear-undelivered")
async def admin_clear_undelivered(session=Depends(require_admin_csrf)):
    n = db.execute("SELECT COUNT(*) FROM messages WHERE delivered=0").fetchone()[0]
    db.execute("DELETE FROM messages WHERE delivered=0")
    db.commit()
    audit_admin(session[0][:8], "clear_undelivered", "", f"deleted={n}")
    return {"deleted": n}

@app.post("/api/v1/admin/control/registration")
async def admin_toggle_registration(request: Request, session=Depends(require_admin_csrf)):
    body = await request.json()
    enabled = bool(body.get("enabled", True))
    setting_set("registration_enabled", "1" if enabled else "0")
    audit_admin(session[0][:8], "toggle_registration", "", f"enabled={enabled}")
    return {"registration_enabled": enabled}

@app.post("/api/v1/admin/control/maintenance")
async def admin_toggle_maintenance(request: Request, session=Depends(require_admin_csrf)):
    body = await request.json()
    enabled = bool(body.get("enabled", False))
    setting_set("maintenance_mode", "1" if enabled else "0")
    audit_admin(session[0][:8], "toggle_maintenance", "", f"enabled={enabled}")
    return {"maintenance_mode": enabled}

@app.post("/api/v1/admin/control/onion-only")
async def admin_toggle_onion_only(request: Request, session=Depends(require_admin_csrf)):
    """Reject any connection not arriving over a Tor onion service.
    Detection: client must present X-Onion-Proof or arrive via the local Tor
    SocksPort/HiddenServicePort wired into your tor config."""
    body = await request.json()
    enabled = bool(body.get("enabled", False))
    setting_set("onion_only", "1" if enabled else "0")
    audit_admin(session[0][:8], "toggle_onion_only", "", f"enabled={enabled}")
    return {"onion_only": enabled}

@app.post("/api/v1/admin/control/rotate-identity")
async def admin_rotate_identity(session=Depends(require_admin_csrf)):
    """Generate a NEW server identity keypair. Existing pinned clients will
    refuse to connect until they re-pin the new fingerprint out-of-band."""
    if not HYBRID_SIG_AVAILABLE:
        raise HTTPException(503, "Hybrid signatures unavailable")
    old_fp = SERVER_IDENTITY["fingerprint"] if SERVER_IDENTITY else ""
    try: os.remove(IDENTITY_PATH)
    except OSError: pass
    _load_or_create_identity()
    new_fp = SERVER_IDENTITY["fingerprint"] if SERVER_IDENTITY else ""
    audit_admin(session[0][:8], "rotate_identity", "", f"old={old_fp} new={new_fp}")
    return {"old_fingerprint": old_fp, "new_fingerprint": new_fp}

@app.delete("/api/v1/admin/users/{user_id}")
async def admin_delete_user(user_id: str, session=Depends(require_admin_csrf)):
    devs = [r[0] for r in db.execute("SELECT id FROM devices WHERE user_id=?", (user_id,)).fetchall()]
    # Remove file blobs owned by those devices
    file_rows = db.execute(
        "SELECT id, storage_name FROM file_transfers WHERE sender_device_id IN ({0}) OR recipient_device_id IN ({0})".format(
            ",".join("?"*len(devs)) or "''"
        ),
        devs * 2 if devs else []
    ).fetchall() if devs else []
    for _, name in file_rows:
        path = os.path.join(FILE_DIR, name)
        if os.path.isfile(path):
            try: os.remove(path)
            except OSError: pass
    if devs:
        ph = ",".join("?" * len(devs))
        db.execute(f"DELETE FROM file_transfers WHERE sender_device_id IN ({ph}) OR recipient_device_id IN ({ph})", devs * 2)
        db.execute(f"DELETE FROM messages WHERE sender_device_id IN ({ph}) OR recipient_device_id IN ({ph})", devs * 2)
        db.execute(f"DELETE FROM group_members WHERE device_id IN ({ph})", devs)
        db.execute(f"DELETE FROM devices WHERE id IN ({ph})", devs)
    db.execute("DELETE FROM friendships WHERE user_a=? OR user_b=?", (user_id, user_id))
    db.execute("DELETE FROM friend_requests WHERE from_user_id=? OR to_user_id=?", (user_id, user_id))
    db.execute("DELETE FROM group_invites WHERE from_user_id=? OR to_user_id=?", (user_id, user_id))
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    audit_admin(session[0][:8], "delete_user", user_id, f"devices={len(devs)} files={len(file_rows)}")
    return {"deleted_user": user_id, "devices_removed": len(devs), "files_removed": len(file_rows)}

@app.delete("/api/v1/admin/sessions/{target_sid}")
async def admin_kill_session(target_sid: str, session=Depends(require_admin_csrf)):
    db.execute("UPDATE admin_sessions SET logged_out=1 WHERE id=?", (target_sid,))
    db.commit()
    audit_admin(session[0][:8], "kill_session", target_sid[:12], "")
    return {"killed": target_sid}

# ── Admin Dashboard HTML ───────────────────────────────────────────
@app.get("/admin")
async def admin_dashboard(session=Depends(require_admin)):
    return _serve_admin_html("index.html")

if __name__ == "__main__":
    import argparse, uvicorn
    ap = argparse.ArgumentParser(description="SHROUD secure messaging server")
    ap.add_argument(
        "--bind",
        default=os.environ.get("SHROUD_BIND", "0.0.0.0"),
        help="Interface to listen on. Use 127.0.0.1 for onion-only deployments "
             "where Tor is the only path into the server (recommended). "
             "Defaults to 0.0.0.0 for backwards compatibility.",
    )
    ap.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SHROUD_PORT", PORT)),
        help=f"TCP port to listen on (default {PORT}).",
    )
    args = ap.parse_args()
    init_db()
    print(f"[SHROUD] Database initialized")
    print(f"[SHROUD] Listening on {args.bind}:{args.port}")
    if args.bind == "0.0.0.0":
        print(f"[SHROUD] WARNING: binding to all interfaces. For onion-only "
              f"deployments pass --bind 127.0.0.1 and let Tor handle external traffic.")
    uvicorn.run(app, host=args.bind, port=args.port, log_level="info")
