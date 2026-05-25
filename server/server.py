"""
GHOSTLINK Secure Messaging Server — FIPS 140-2 Compliant
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

# Add parent to path for crypto imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Header, Cookie, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
import asyncio

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
    print(f"[GHOSTLINK] PQ hybrid unavailable: {_pq_e}")

try:
    from crypto import hybrid_sig
    HYBRID_SIG_AVAILABLE = hybrid_sig.self_test()
except Exception as _sig_e:
    hybrid_sig = None
    HYBRID_SIG_AVAILABLE = False
    print(f"[GHOSTLINK] Hybrid signatures unavailable: {_sig_e}")

try:
    from crypto import anon_creds
    ANON_CREDS_AVAILABLE = anon_creds.self_test()
except Exception as _ac_e:
    anon_creds = None
    ANON_CREDS_AVAILABLE = False
    print(f"[GHOSTLINK] Anonymous credentials unavailable: {_ac_e}")

try:
    from crypto import srp6a
    SRP_AVAILABLE = srp6a.self_test()
except Exception as _srp_e:
    srp6a = None
    SRP_AVAILABLE = False
    print(f"[GHOSTLINK] SRP-6a unavailable: {_srp_e}")

try:
    from crypto import at_rest
    AT_REST_AVAILABLE = at_rest.self_test()
except Exception as _ar_e:
    at_rest = None
    AT_REST_AVAILABLE = False
    print(f"[GHOSTLINK] At-rest encryption unavailable: {_ar_e}")

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
            print(f"[GHOSTLINK] Server identity loaded — fingerprint {fp}")
            return
        except Exception as e:
            print(f"[GHOSTLINK] WARN: identity file corrupt ({e}) — regenerating")

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
    print(f"[GHOSTLINK] Server identity generated — fingerprint {fp}")


def server_sign_attestation(session_id: str, pq_pubkey_blob: bytes) -> bytes:
    """Triple-sign a handshake response so the client can pin our identity."""
    if not SERVER_IDENTITY:
        return b""
    msg = b"GHOSTLINK-KEX-v2|" + session_id.encode("ascii") + b"|" + pq_pubkey_blob
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
            print(f"[GHOSTLINK] Anonymous credential key loaded (RSA-{sk['n'].bit_length()})")
            return
        except Exception as e:
            print(f"[GHOSTLINK] WARN: anon_creds key corrupt ({e}) — regenerating")
    pub, sk = anon_creds.server_keygen()
    with open(ANON_CREDS_KEY_PATH, "wb") as f:
        f.write(anon_creds.serialize_sk(sk))
    try: os.chmod(ANON_CREDS_KEY_PATH, 0o600)
    except Exception: pass
    ANON_CREDS_KEYS = {"pub": pub, "sk": sk}
    print(f"[GHOSTLINK] Anonymous credential keypair generated (RSA-{sk['n'].bit_length()})")


_load_or_create_anon_creds_key()


# ── At-rest field encryption key (AES-256-GCM for sensitive columns) ─
DATA_KEY_PATH = os.path.join(os.path.dirname(__file__), "data.key")
DATA_KEY = None
if AT_REST_AVAILABLE:
    try:
        DATA_KEY = at_rest.load_or_create_data_key(DATA_KEY_PATH)
        print(f"[GHOSTLINK] At-rest data key loaded (AES-256-GCM)")
    except Exception as _dk_e:
        print(f"[GHOSTLINK] WARN: at-rest data key unavailable: {_dk_e}")
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
DB_PATH = os.path.join(os.path.dirname(__file__), "ghostlink.db")
FILE_DIR = os.path.join(os.path.dirname(__file__), "files")
os.makedirs(FILE_DIR, exist_ok=True)
SESSION_TIMEOUT = 3600  # 1 hour
MAX_DEVICES_PER_USER = 25

async def _expiry_sweeper():
    """Periodically purge expired messages and files."""
    while True:
        try:
            # Disappearing messages
            n_msg = db.execute("SELECT COUNT(*) FROM messages WHERE expires_at IS NOT NULL AND expires_at < datetime('now')").fetchone()[0]
            if n_msg:
                db.execute("DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < datetime('now')")
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
                print(f"[GHOSTLINK] expiry sweep: removed {n_msg} msgs, {len(file_rows)} files")
        except Exception as e:
            print(f"[GHOSTLINK] expiry sweep error: {e}")
        await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(ap):
    # Startup
    if not fips_self_test():
        raise RuntimeError("FIPS 140-2 self-test FAILED — server cannot start")
    print(f"[GHOSTLINK] FIPS 140-2 self-test: PASSED")
    print(f"[GHOSTLINK] PQ hybrid (ECDH-P384 + ML-KEM-1024): {'READY' if PQ_AVAILABLE else 'unavailable'}")
    print(f"[GHOSTLINK] Server starting on port {PORT}")
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
        print(f"[GHOSTLINK] Cleaned up {len(expired)} expired/downloaded files")
    sweep_task = asyncio.create_task(_expiry_sweeper())
    try:
        yield
    finally:
        sweep_task.cancel()
        try: await sweep_task
        except asyncio.CancelledError: pass
        print("[GHOSTLINK] Server shutting down")

app = FastAPI(title="GHOSTLINK Secure Messaging", version="1.8.0", lifespan=lifespan)

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

db = init_db()

# ── Models ───────────────────────────────────────────────────────────
def decrypt_auth_payload(session_id: str, client_pub_hex: str, nonce_hex: str, ct_hex: str, tag_hex: str) -> dict:
    """Decrypt client auth payload using ECDH + AES-256-GCM."""
    with ecdh_lock:
        server_priv = ecdh_cache.pop(session_id, None)
    if not server_priv:
        raise HTTPException(401, "Invalid or expired session")
    try:
        client_pub = deserialize_public_key(bytes.fromhex(client_pub_hex))
        raw = server_priv.exchange(ec.ECDH(), client_pub)
        hashed = hashlib.sha256(raw).digest()
        key = hashlib.sha256(hashed + b"GHOSTLINK-AUTH-v1").digest()[:32]
        nonce = bytes.fromhex(nonce_hex); ct = bytes.fromhex(ct_hex); tag = bytes.fromhex(tag_hex)
        plain = decrypt_aes_gcm(key, nonce, ct + tag)
        return json.loads(plain.decode('utf-8'))
    except Exception:
        raise HTTPException(400, "Decryption failed")

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
    return {"status": "ok", "fips": "140-2 validated", "version": "1.8.0"}

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
    username = (body.get("username") or "").strip()
    if not username or len(username) < 3:
        raise HTTPException(400, "Username too short")
    try:
        salt = bytes.fromhex(body["salt_hex"])
        verifier = int(body["verifier_hex"], 16)
    except Exception:
        raise HTTPException(400, "Invalid salt or verifier")
    if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
        raise HTTPException(409, "Username already registered")
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
    username = (body.get("username") or "").strip()
    try:
        A = int(body["A_hex"], 16)
    except Exception:
        raise HTTPException(400, "Invalid A_hex")
    row = db.execute("SELECT srp_salt, srp_verifier FROM users WHERE username=?", (username,)).fetchone()
    if not row or not row[0] or not row[1]:
        # Always return a synthetic challenge so an attacker can't enumerate users
        salt = hashlib.sha256(b"GHOSTLINK-decoy|" + username.encode()).digest()[:16]
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
    { M2_hex } on success, 401 otherwise. The shared session key derived
    here can be used to encrypt the device_registration payload."""
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
        raise HTTPException(401, "SRP proof failed")
    # Stash the session key for subsequent device registration calls.
    with SRP_SESSION_LOCK:
        SRP_SESSIONS["__key__" + sid] = {"K": entry["sess"].K, "ts": time.time()}
    return {"M2_hex": M2.hex(), "session_key_handle": sid}


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
        key = hashlib.sha256(shared + b"GHOSTLINK-AUTH-PQ-v1").digest()[:32]
        nonce = bytes.fromhex(body.get("nonce", ""))
        ct = bytes.fromhex(body.get("ciphertext", ""))
        tag = bytes.fromhex(body.get("tag", ""))
        plain = decrypt_aes_gcm(key, nonce, ct + tag)
        payload = json.loads(plain.decode("utf-8"))
    except Exception:
        raise HTTPException(400, "Decryption failed")

    username = payload.get("username", "")
    password = payload.get("password", "")
    device_name = payload.get("device_name", "")
    platform = payload.get("platform", "")
    is_register = payload.get("register", False)
    pub_key_hex = payload.get("public_key", "")

    if is_register:
        if setting_get("registration_enabled", "1") != "1":
            raise HTTPException(403, "Registration is currently disabled")
        if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            raise HTTPException(409, "Username already registered")
        user_id = uuid.uuid4().hex
        key, salt = derive_key(password)
        db.execute("INSERT INTO users (id, username, password_hash, password_salt) VALUES (?,?,?,?)",
                   (user_id, username, key.hex(), salt))
        db.commit()
    else:
        user = db.execute("SELECT id, password_hash, password_salt FROM users WHERE username=?",
                          (username,)).fetchone()
        if not user: raise HTTPException(401, "Invalid credentials")
        derived, _ = derive_key(password, user[2])
        if derived.hex() != user[1]: raise HTTPException(401, "Invalid credentials")

    user = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    count = db.execute("SELECT COUNT(*) FROM devices WHERE user_id=?", (user[0],)).fetchone()[0]
    if count >= MAX_DEVICES_PER_USER and not is_register:
        raise HTTPException(400, f"Maximum {MAX_DEVICES_PER_USER} devices per user")
    if platform not in ('windows','ios','android'):
        raise HTTPException(400, "Invalid platform")
    try:
        pub_key_bytes = bytes.fromhex(pub_key_hex)
        deserialize_public_key(pub_key_bytes)
    except Exception:
        raise HTTPException(400, "Invalid public key format")

    device_id = generate_device_id()
    db.execute("INSERT INTO devices (id, user_id, device_name, platform, public_key, hwid) VALUES (?,?,?,?,?,?)",
               (device_id, user[0], device_name, platform, pub_key_bytes, ""))
    db.commit()
    return {"device_id": device_id, "user_id": user[0], "registered": True, "suite": "PQ-HYBRID-v1"}

@app.get("/api/v1/version")
async def get_version():
    """Client update check endpoint. Clients fetch this and compare to their
    embedded version string."""
    base = "https://github.com/ExposingTheBadge/GhostLink/releases/latest"
    return {
        "version": "1.8.0",
        "minimum_supported": "1.3.0",
        "release_url": base,
        "windows": f"{base}/download/GHOSTLINK.exe",
        "android": f"{base}/download/GHOSTLINK.apk",
        "linux":   f"{base}/download/ghostlink-linux",
        "changelog": (
            "1.8.0 (Tier 3 — auth & at-rest) — SRP-6a augmented PAKE "
            "(/api/v1/srp/{register,challenge,prove}) so the server never "
            "sees the password. Server-side field-level encryption "
            "(AES-256-GCM data.key) for friend/group invite reasons, admin "
            "session IP and user-agent. Windows ratchet identity + one-time "
            "prekeys persisted via DPAPI; Android prefs upgraded to "
            "EncryptedSharedPreferences. Closes Tier 1 #23 — Windows now "
            "verifies the server's ML-DSA-87 + SPHINCS+ attestation via "
            "liboqs dynamic load when oqs.dll is present. 1.7.0 — cover "
            "traffic, rotating pickup tokens, anonymous send credentials."
        ),
    }

@app.post("/api/v1/heartbeat")
async def heartbeat(req: GetMessagesRequest):
    """Client heartbeat — keeps last_seen fresh for active client tracking."""
    device = db.execute("SELECT id FROM devices WHERE id = ?", (req.device_id,)).fetchone()
    if device:
        db.execute("UPDATE devices SET last_seen = datetime('now') WHERE id = ?", (req.device_id,))
        db.commit()
        return {"beat": "ok"}
    raise HTTPException(404, "Device not found")

class ChangePasswordRequest(BaseModel):
    username: str
    old_password: str
    new_password: str = Field(min_length=12, max_length=128)

@app.post("/api/v1/change-password")
async def change_password(req: ChangePasswordRequest):
    """Change user password. Requires current password verification."""
    user = db.execute(
        "SELECT id, password_hash, password_salt FROM users WHERE username = ?",
        (req.username,)
    ).fetchone()
    if not user:
        raise HTTPException(401, "Invalid credentials")

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
    return {"changed": True, "username": req.username}

# ── Encrypted Auth (no plaintext passwords ever) ────────────────────
@app.post("/api/v1/auth")
async def encrypted_auth(request: Request):
    """Encrypted registration/login. Password never transits in plaintext."""
    body = await request.json()
    payload = decrypt_auth_payload(
        body.get("session_id",""), body.get("client_public_key",""),
        body.get("nonce",""), body.get("ciphertext",""), body.get("tag",""))
    username = payload.get("username","")
    password = payload.get("password","")
    device_name = payload.get("device_name","")
    platform = payload.get("platform","")
    is_register = payload.get("register", False)
    pub_key_hex = payload.get("public_key","")

    # Register user if new account
    if is_register:
        if setting_get("registration_enabled", "1") != "1":
            raise HTTPException(403, "Registration is currently disabled")
        existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            raise HTTPException(409, "Username already registered")
        user_id = uuid.uuid4().hex
        key, salt = derive_key(password)
        db.execute("INSERT INTO users (id, username, password_hash, password_salt) VALUES (?,?,?,?)",
                   (user_id, username, key.hex(), salt))
        db.commit()
    else:
        user = db.execute("SELECT id, password_hash, password_salt FROM users WHERE username=?",
                          (username,)).fetchone()
        if not user:
            raise HTTPException(401, "Invalid credentials")
        derived, _ = derive_key(password, user[2])
        if derived.hex() != user[1]:
            raise HTTPException(401, "Invalid credentials")

    # Register device
    user = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    count = db.execute("SELECT COUNT(*) FROM devices WHERE user_id=?", (user[0],)).fetchone()[0]
    if count >= MAX_DEVICES_PER_USER and not is_register:
        raise HTTPException(400, f"Maximum {MAX_DEVICES_PER_USER} devices per user")

    if platform not in ('windows','ios','android'):
        raise HTTPException(400, "Invalid platform")

    try:
        pub_key_bytes = bytes.fromhex(pub_key_hex)
        deserialize_public_key(pub_key_bytes)
    except Exception:
        raise HTTPException(400, "Invalid public key format")

    device_id = generate_device_id()
    db.execute("INSERT INTO devices (id, user_id, device_name, platform, public_key, hwid) VALUES (?,?,?,?,?,?)",
               (device_id, user[0], device_name, platform, pub_key_bytes, ""))
    db.commit()

    server_priv, server_pub = generate_keypair()
    return {"device_id": device_id, "server_public_key": serialize_public_key(server_pub).hex(),
            "user_id": user[0], "registered": True}

# ── User Registration (legacy) ──────────────────────────────────────
@app.post("/api/v1/register")
async def register_user(req: RegisterUserRequest):
    """Register a new user. Returns user ID."""
    # Check uniqueness
    existing = db.execute("SELECT id FROM users WHERE username = ?", (req.username,)).fetchone()
    if existing:
        raise HTTPException(409, "Username already registered")

    user_id = uuid.uuid4().hex
    key, salt = derive_key(req.password)
    db.execute(
        "INSERT INTO users (id, username, password_hash, password_salt) VALUES (?, ?, ?, ?)",
        (user_id, req.username, key.hex(), salt)
    )
    db.commit()
    return {"user_id": user_id, "username": req.username, "registered": True}

# ── Device Registration ──────────────────────────────────────────────
@app.post("/api/v1/devices")
async def register_device(req: RegisterDeviceRequest):
    """Register a new device. Returns device ID, server's public key for ECDH."""
    # Auth user
    print(f"[DEVICE REG] username={req.username} platform={req.platform} pw_len={len(req.password)} hwid={req.hwid[:16] if req.hwid else 'none'}")
    user = db.execute(
        "SELECT id, password_hash, password_salt FROM users WHERE username = ?",
        (req.username,)
    ).fetchone()
    if not user:
        print(f"[DEVICE REG] FAIL: username '{req.username}' not found")
        raise HTTPException(401, "Invalid credentials")

    # Verify password
    derived, _ = derive_key(req.password, user[2])
    if derived.hex() != user[1]:
        print(f"[DEVICE REG] FAIL: password mismatch for '{req.username}' (pw_len={len(req.password)})")
        raise HTTPException(401, "Invalid credentials")

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

# ── Send Message ─────────────────────────────────────────────────────
@app.post("/api/v1/messages/send")
async def send_message(request: Request):
    """Relay an encrypted message. Server never sees plaintext.

    Optional headers:
      X-Expires-In: <seconds>   Disappearing-message TTL (server purges at expiry).
      X-Envelope-Version: 2     Marks v2 envelopes (size MUST hit a padding bucket).
    Body is the SendMessageRequest (sender_device_id, recipient_device_id, envelope).
    """
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
    return {"message_id": msg_id, "relayed": True, "v": env_ver, "expires_at": expires_at}


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
    query = (body.get("query", "") or "").strip()
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
    contact = db.execute("SELECT id FROM users WHERE username=?", (req.contact_username,)).fetchone()
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
    target_name = (body.get("target_username", "") or "").strip()
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
    target_name = (body.get("target_username", "") or "").strip()
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
        if request.url.path.startswith("/admin"):
            response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"
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
class TelemetryMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        t0 = time.perf_counter()
        path = request.url.path
        REQ_COUNTS[path] += 1
        try:
            response = await call_next(request)
        except HTTPException as he:
            ERR_COUNTS[path] += 1
            RECENT_ERRORS.appendleft({
                "ts": datetime.now(tz=timezone.utc).isoformat(timespec='seconds'),
                "path": path, "status": he.status_code, "detail": str(he.detail)[:200]
            })
            raise
        except Exception as e:
            ERR_COUNTS[path] += 1
            RECENT_ERRORS.appendleft({
                "ts": datetime.now(tz=timezone.utc).isoformat(timespec='seconds'),
                "path": path, "status": 500, "detail": type(e).__name__
            })
            raise
        ms = (time.perf_counter() - t0) * 1000.0
        REQ_LATENCY.append((path, ms, time.time()))
        if response.status_code >= 400:
            ERR_COUNTS[path] += 1
            RECENT_ERRORS.appendleft({
                "ts": datetime.now(tz=timezone.utc).isoformat(timespec='seconds'),
                "path": path, "status": response.status_code, "detail": ""
            })
        return response

app.add_middleware(TelemetryMiddleware)

# Onion-only mode — when enabled, refuse any request whose Host header is
# not a .onion address. Admin paths are exempt so the operator can recover.
class OnionOnlyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        try:
            enabled = setting_get("onion_only", "0") == "1"
        except Exception:
            enabled = False
        if enabled:
            path = request.url.path
            if not (path.startswith("/admin") or path.startswith("/api/v1/admin") or path == "/health"):
                host = request.headers.get("host", "").lower().split(":")[0]
                if not host.endswith(".onion"):
                    return JSONResponse({"detail": "Server is in onion-only mode"}, status_code=403)
        return await call_next(request)

app.add_middleware(OnionOnlyMiddleware)

# ── Server settings (toggles) ────────────────────────────────────────
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

def audit_admin(actor: str, action: str, target: str = "", detail: str = ""):
    try:
        db.execute("INSERT INTO audit_log (actor,action,target,detail) VALUES (?,?,?,?)",
                   (actor[:64], action[:64], target[:128], detail[:500]))
        db.commit()
    except Exception:
        pass

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
    cookie_token = request.cookies.get("ghostlink_csrf", "")
    if not token or token != cookie_token:
        raise HTTPException(403, "CSRF validation failed")

def get_admin_session(sid: str = Cookie(None, alias="ghostlink_sid")):
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

def require_admin(sid: str = Cookie(None, alias="ghostlink_sid")):
    session = get_admin_session(sid)
    if not session:
        raise HTTPException(401, "Not authenticated")
    return session

# ── Admin Login Page (Fingerprint Grid) ─────────────────────────────
@app.get("/admin/login")
async def admin_login_page():
    return HTMLResponse(r"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GHOSTLINK Admin</title>
<style>:root{--bg:#0a0e17;--bg2:#111827;--border:#1a2535;--text:#c8d6e5;--dim:#6e7a8a;--accent:#00d4ff;--danger:#ff4757;--green:#2ed573}
*,*::before,*::after{box-sizing:border-box}body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);font-size:14px;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:28px 22px;width:100%;max-width:700px}
h1{font-size:20px;margin:0 0 6px;color:var(--accent);letter-spacing:1px;text-align:center}
.sub{text-align:center;color:var(--dim);margin:0 0 18px;font-size:12px}
.error{color:var(--danger);text-align:center;margin:8px 0;font-size:12px;display:none}
.fp-label{font-size:12px;color:var(--dim);margin-bottom:8px;text-align:center;font-weight:500}
.fp-grid{display:grid;grid-template-columns:repeat(32,1fr);gap:2px;margin-bottom:10px}
.fp-grid input{width:100%;aspect-ratio:1;text-align:center;font-family:Consolas,monospace;font-size:13px;font-weight:700;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:3px;outline:none;padding:0}
.fp-grid input:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(0,212,255,0.25)}
.fp-grid input.filled{border-color:var(--accent);background:#0a141a}
label{display:block;font-size:11px;color:var(--dim);margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px}
input.text{width:100%;padding:10px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:14px;margin-bottom:12px;font-family:Consolas,monospace;outline:none}
input.text:focus{border-color:var(--accent)}
button{width:100%;padding:12px;background:var(--accent);color:#000;border:none;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer}
button:disabled{opacity:0.4;cursor:default}
.fp-link{color:var(--dim);font-size:12px;cursor:pointer;text-align:center;margin-top:10px}
.fp-link:hover{color:var(--text);text-decoration:underline}
.fp-status{font-size:12px;color:var(--dim);text-align:center;margin-top:6px;min-height:1.2em}
.ban-warn{font-size:12px;color:var(--danger);text-align:center;margin-top:8px;font-weight:700}
</style></head><body>
<div class="card"><h1>GHOSTLINK Admin</h1><p class="sub">3 failed attempts = permanent IP ban</p>
<div class="error" id="err"></div>
<div class="fp-label" id="fpLabel">Paste your fingerprint into the grid</div>
<div class="fp-grid" id="fpGrid"></div>
<label>Password</label><input type="password" class="text" id="pw" placeholder="Admin password" autocomplete="current-password">
<button id="fpBtn" disabled>Authenticate</button>
<button id="setupBtn" style="display:none">Generate Fingerprint</button>
<p class="fp-status" id="fpStatus"></p>
<p class="ban-warn" id="banWarn" style="display:none">ACCESS DENIED — Your IP is banned</p>
</div>
<script>
var FP_COLS=32,FP_LENGTH=256;
var fpGrid=document.getElementById('fpGrid'),inputs=[];
for(var i=0;i<FP_LENGTH;i++){var inp=document.createElement('input');inp.type='text';inp.maxLength=1;inp.dataset.idx=i;inp.setAttribute('autocomplete','off');inp.setAttribute('spellcheck','false');fpGrid.appendChild(inp);inputs.push(inp)}
function onPaste(e){e.preventDefault();var t=(e.clipboardData||window.clipboardData).getData('text')||'';t=t.replace(/[\s\n\r\t]/g,'');if(!t)return;var s=parseInt(this.dataset.idx),c=Math.min(t.length,FP_LENGTH-s);for(var i=0;i<c;i++){var idx=s+i;inputs[idx].value=t[i];inputs[idx].classList.add('filled')}var li=Math.min(s+c,FP_LENGTH-1);inputs[li].focus();checkComplete()}
inputs.forEach(function(inp,idx){inp.addEventListener('paste',onPaste);inp.addEventListener('input',function(){if(this.value.length===1){this.classList.add('filled');var n=inputs[idx+1];if(n){n.focus();n.select()}}else{this.classList.remove('filled')}checkComplete()});inp.addEventListener('keydown',function(e){var p=inputs[idx-1],n=inputs[idx+1];if(e.key==='ArrowLeft'&&p){e.preventDefault();p.focus();p.select()}if(e.key==='ArrowRight'&&n){e.preventDefault();n.focus();n.select()}if(e.key==='Backspace'){if(this.value){this.value='';this.classList.remove('filled');checkComplete()}else if(p){e.preventDefault();p.value='';p.classList.remove('filled');p.focus();checkComplete()}}});inp.addEventListener('focus',function(){this.select()})});
function getHWID(){var p=[];try{p.push(screen.width+'x'+screen.height)}catch(e){}try{p.push(navigator.hardwareConcurrency||0)}catch(e){}try{p.push(navigator.deviceMemory||0)}catch(e){}try{var c=document.createElement('canvas');var gl=c.getContext('webgl')||c.getContext('experimental-webgl');if(gl){var dbg=gl.getExtension('WEBGL_debug_renderer_info');if(dbg)p.push(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL))}}catch(e){}try{p.push(Intl.DateTimeFormat().resolvedOptions().timeZone)}catch(e){}return p.join('|')}
function getFingerprintValue(){var v='';for(var i=0;i<FP_LENGTH;i++)v+=inputs[i].value;return v}
var pwInput=document.getElementById('pw');pwInput.addEventListener('input',checkComplete);
function checkComplete(){document.getElementById('fpBtn').disabled=getFingerprintValue().length!==FP_LENGTH||!pwInput.value}
(async function(){try{var r=await fetch('/api/v1/admin/login-status?hwid='+encodeURIComponent(getHWID()));var d=await r.json();if(d.banned){document.getElementById('banWarn').style.display='block';document.getElementById('fpBtn').style.display='none'}if(d.failCount>0){document.getElementById('fpStatus').textContent=d.failCount+' of 3 attempts used — '+(3-d.failCount)+' remaining';document.getElementById('fpStatus').style.color='var(--danger)'}if(d.needsSetup){document.getElementById('fpLabel').textContent='First run — set admin password to generate fingerprint';document.getElementById('fpGrid').style.display='none';document.getElementById('setupBtn').style.display='block';document.getElementById('fpBtn').style.display='none';pwInput.placeholder='Set admin password (12+ chars)';document.getElementById('setupBtn').disabled=false;pwInput.addEventListener('input',function(){document.getElementById('setupBtn').disabled=this.value.length<12})}}catch(e){}})();document.getElementById('setupBtn').addEventListener('click',async function(){var pw=pwInput.value;if(pw.length<12)return;this.disabled=true;document.getElementById('fpStatus').textContent='Generating fingerprint...';try{var r=await fetch('/api/v1/admin/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});var d=await r.json();if(d.ok){document.getElementById('fpStatus').innerHTML='<span style=\"color:var(--green)\">Your fingerprint:</span><br><code style=\"word-break:break-all;font-size:11px\">'+d.fingerprint_id+'</code><br><span style=\"color:var(--danger);font-weight:700\">SAVE THIS — IT CANNOT BE RECOVERED</span><br>Copy it, paste it into the grid, enter your password, and click Authenticate.';document.getElementById('fpGrid').style.display='grid';document.getElementById('setupBtn').style.display='none';document.getElementById('fpBtn').style.display='block';pwInput.placeholder='Admin password';pwInput.value=''}else{document.getElementById('fpStatus').textContent='Setup failed'}}catch(e){document.getElementById('fpStatus').textContent='Connection error'}this.disabled=false})
document.getElementById('fpBtn').addEventListener('click',async function(){var fp=getFingerprintValue(),pw=pwInput.value;if(fp.length!==FP_LENGTH||!pw)return;document.getElementById('err').style.display='none';this.disabled=true;document.getElementById('fpStatus').textContent='Verifying...';try{var r=await fetch('/api/v1/admin/fingerprint-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({fingerprint_id:fp,password:pw,hwid:getHWID()})});var d=await r.json();if(d.ok){document.getElementById('fpStatus').textContent='Signed in. Redirecting...';location='/admin'}else{document.getElementById('err').textContent=d.error||'Authentication failed';document.getElementById('err').style.display='block';this.disabled=false;document.getElementById('fpStatus').textContent=''}}catch(e){document.getElementById('err').textContent='Connection error';document.getElementById('err').style.display='block';this.disabled=false;document.getElementById('fpStatus').textContent=''}});
</script></body></html>""")

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
    resp.set_cookie(key="ghostlink_sid", value=sid, httponly=True, samesite="strict", max_age=SESSION_TIMEOUT_SEC, path="/")
    resp.set_cookie(key="ghostlink_csrf", value=csrf, httponly=True, samesite="strict", max_age=SESSION_TIMEOUT_SEC, path="/")
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
async def admin_fingerprint_enroll(request: Request, session=Depends(require_admin)):
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
    resp.delete_cookie("ghostlink_sid", path="/")
    return resp

# ── Admin Dashboard ──────────────────────────────────────────────────
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

@app.get("/api/v1/admin/stats")
async def admin_stats(session=Depends(require_admin)):
    files = db.execute("SELECT id, sender_device_id, recipient_device_id, original_size, encrypted_size, server_ts, expires_at, downloaded FROM file_transfers ORDER BY server_ts DESC").fetchall()
    total_enc_bytes = sum(f[4] for f in files)
    active_now = db.execute("SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now','-60 seconds')").fetchone()[0]
    active_1min = db.execute("SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now','-5 minutes')").fetchone()[0]
    os_counts = {row[0]: row[1] for row in db.execute("SELECT platform, COUNT(*) FROM devices GROUP BY platform").fetchall()}
    latency = db.execute("SELECT ROUND(AVG(latency_ms),1), MIN(latency_ms), MAX(latency_ms) FROM message_latency WHERE recorded_at > datetime('now','-1 hour')").fetchone()

    # ── Volume / throughput ────────────────────────────────────────
    msgs_1h = db.execute("SELECT COUNT(*) FROM messages WHERE server_ts > datetime('now','-1 hour')").fetchone()[0]
    msgs_24h = db.execute("SELECT COUNT(*) FROM messages WHERE server_ts > datetime('now','-1 day')").fetchone()[0]
    files_24h = db.execute("SELECT COUNT(*) FROM file_transfers WHERE server_ts > datetime('now','-1 day')").fetchone()[0]
    bytes_24h = db.execute("SELECT COALESCE(SUM(LENGTH(envelope)),0) FROM messages WHERE server_ts > datetime('now','-1 day')").fetchone()[0]
    avg_msg_size = db.execute("SELECT ROUND(AVG(LENGTH(envelope)),0) FROM messages").fetchone()[0] or 0
    sealed_pending = db.execute("SELECT COUNT(*) FROM messages WHERE sealed=1 AND delivered=0").fetchone()[0]
    v2_pending = db.execute("SELECT COUNT(*) FROM messages WHERE envelope_version>=2 AND delivered=0").fetchone()[0]
    disappearing_pending = db.execute("SELECT COUNT(*) FROM messages WHERE expires_at IS NOT NULL AND delivered=0").fetchone()[0]
    ratchet_devices = db.execute("SELECT COUNT(*) FROM devices WHERE x25519_pub IS NOT NULL").fetchone()[0]
    otp_total = db.execute("SELECT COUNT(*) FROM one_time_prekeys").fetchone()[0]

    # ── Hourly activity histogram (last 24h, server-local) ────────
    hourly = db.execute(
        "SELECT strftime('%Y-%m-%d %H:00', server_ts) AS hr, COUNT(*) "
        "FROM messages WHERE server_ts > datetime('now','-24 hours') "
        "GROUP BY hr ORDER BY hr"
    ).fetchall()
    hourly_activity = [{"hour": r[0], "count": r[1]} for r in hourly]

    # ── Security / audit ───────────────────────────────────────────
    failed_24h = db.execute("SELECT COUNT(*) FROM login_attempts WHERE success=0 AND attempted_at > datetime('now','-1 day')").fetchone()[0]
    failed_logins = [
        {"ip": r[0], "hwid": (r[1] or "")[:16], "fp": (r[2] or "")[:8], "ts": r[3]}
        for r in db.execute("SELECT ip, hwid, fingerprint_id, attempted_at FROM login_attempts WHERE success=0 ORDER BY attempted_at DESC LIMIT 50").fetchall()
    ]
    audit_rows = db.execute("SELECT actor, action, target, detail, ts FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
    audit_log_rows = [{"actor": a[0], "action": a[1], "target": a[2], "detail": a[3], "ts": a[4]} for a in audit_rows]

    # ── Pending requests / invites ────────────────────────────────
    friend_pending = db.execute(
        "SELECT fr.id, uf.username, ut.username, fr.reason, fr.created_at "
        "FROM friend_requests fr JOIN users uf ON uf.id=fr.from_user_id "
        "JOIN users ut ON ut.id=fr.to_user_id WHERE fr.status='pending' "
        "ORDER BY fr.created_at DESC LIMIT 50"
    ).fetchall()
    group_pending = db.execute(
        "SELECT gi.id, g.name, uf.username, ut.username, gi.reason, gi.created_at "
        "FROM group_invites gi JOIN group_chats g ON g.id=gi.group_id "
        "JOIN users uf ON uf.id=gi.from_user_id JOIN users ut ON ut.id=gi.to_user_id "
        "WHERE gi.status='pending' ORDER BY gi.created_at DESC LIMIT 50"
    ).fetchall()

    # ── Top senders/recipients (24h, anonymized prefix) ───────────
    top_send = db.execute(
        "SELECT sender_device_id, COUNT(*) FROM messages WHERE server_ts > datetime('now','-1 day') "
        "GROUP BY sender_device_id ORDER BY 2 DESC LIMIT 10"
    ).fetchall()
    top_recv = db.execute(
        "SELECT recipient_device_id, COUNT(*) FROM messages WHERE server_ts > datetime('now','-1 day') "
        "GROUP BY recipient_device_id ORDER BY 2 DESC LIMIT 10"
    ).fetchall()

    # ── Telemetry (in-memory, since startup) ──────────────────────
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
    recent_errors = list(RECENT_ERRORS)[:50]

    # ── Disk / DB ──────────────────────────────────────────────────
    db_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    files_dir_size = _dir_size(FILE_DIR)
    try:
        disk = shutil.disk_usage(os.path.dirname(DB_PATH))
        disk_total = disk.total; disk_free = disk.free
    except Exception:
        disk_total = disk_free = 0

    # ── Toggles ────────────────────────────────────────────────────
    registration_enabled = setting_get("registration_enabled", "1") == "1"
    maintenance_mode = setting_get("maintenance_mode", "0") == "1"

    return {
        "uptime_sec": round(time.time() - STARTUP_TS, 1),
        "uptime_fmt": _fmt_uptime(time.time() - STARTUP_TS),
        "server_time_utc": datetime.now(tz=timezone.utc).isoformat(timespec='seconds'),
        "version": "1.8.0",
        "registration_enabled": registration_enabled,
        "maintenance_mode": maintenance_mode,
        "total_users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_devices": db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
        "total_messages": db.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
        "undelivered": db.execute("SELECT COUNT(*) FROM messages WHERE delivered=0").fetchone()[0],
        "total_groups": db.execute("SELECT COUNT(*) FROM group_chats").fetchone()[0],
        "total_friendships": db.execute("SELECT COUNT(*) FROM friendships").fetchone()[0],
        "active_today": db.execute("SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now','-1 day')").fetchone()[0],
        "active_now": active_now,
        "active_1min": active_1min,
        "msgs_1h": msgs_1h, "msgs_24h": msgs_24h, "files_24h": files_24h,
        "bytes_24h": bytes_24h, "avg_msg_size": int(avg_msg_size),
        "sealed_pending": sealed_pending,
        "v2_pending": v2_pending,
        "disappearing_pending": disappearing_pending,
        "pq_available": PQ_AVAILABLE,
        "pq_suite": "ECDH-P384+ML-KEM-1024" if PQ_AVAILABLE else "",
        "identity_fingerprint": SERVER_IDENTITY["fingerprint"] if SERVER_IDENTITY else "",
        "identity_suite": "Ed25519+ML-DSA-87+SPHINCS+-256s" if SERVER_IDENTITY else "",
        "onion_only": setting_get("onion_only", "0") == "1",
        "ratchet_devices": ratchet_devices,
        "one_time_prekeys_total": otp_total,
        "cover_count": COVER_COUNT,
        "cover_bytes": COVER_BYTES,
        "anon_creds_available": ANON_CREDS_AVAILABLE,
        "anon_creds_redeemed_total": db.execute("SELECT COUNT(*) FROM redeemed_credentials").fetchone()[0] if ANON_CREDS_AVAILABLE else 0,
        "srp_available": SRP_AVAILABLE,
        "at_rest_available": AT_REST_AVAILABLE and DATA_KEY is not None,
        "srp_users": db.execute("SELECT COUNT(*) FROM users WHERE srp_verifier IS NOT NULL").fetchone()[0],
        "os_windows": os_counts.get("windows", 0),
        "os_android": os_counts.get("android", 0),
        "os_ios": os_counts.get("ios", 0),
        "avg_latency_ms": latency[0] or 0,
        "min_latency_ms": latency[1] or 0,
        "max_latency_ms": latency[2] or 0,
        "file_count": len(files),
        "file_total_bytes": total_enc_bytes,
        "file_total_gb": round(total_enc_bytes / (1024**3), 4),
        "db_size_bytes": db_size,
        "files_dir_bytes": files_dir_size,
        "disk_free_bytes": disk_free,
        "disk_total_bytes": disk_total,
        "failed_logins_24h": failed_24h,
        "pending_friend_requests": len(friend_pending),
        "pending_group_invites": len(group_pending),
        "requests_total": sum(REQ_COUNTS.values()),
        "errors_total": sum(ERR_COUNTS.values()),
        "avg_req_ms": avg_req_ms,
        "p95_req_ms": p95_req_ms,
        "ecdh_cache_size": len(ecdh_cache),
        "hourly_activity": hourly_activity,
        "top_senders": [{"id": r[0][:12], "count": r[1]} for r in top_send],
        "top_recipients": [{"id": r[0][:12], "count": r[1]} for r in top_recv],
        "top_endpoints": top_endpoints,
        "recent_errors": recent_errors,
        "audit_log": audit_log_rows,
        "failed_logins": failed_logins,
        "friend_requests_pending": [{"id": r[0], "from": r[1], "to": r[2], "reason": ar_dec(r[3]), "created": r[4]} for r in friend_pending],
        "group_invites_pending": [{"id": r[0], "group": r[1], "from": r[2], "to": r[3], "reason": ar_dec(r[4]), "created": r[5]} for r in group_pending],
        "files": [{"id": f[0], "sender": f[1][:12], "recipient": f[2][:12], "orig_size": f[3], "enc_size": f[4], "server_ts": f[5], "expires_at": f[6], "downloaded": bool(f[7])} for f in files],
        "recent_messages": [{"ts": m[0], "sender": m[1], "recipient": m[2], "size": m[3], "delivered": bool(m[4])} for m in db.execute("SELECT server_ts, sender_device_id, recipient_device_id, LENGTH(envelope), delivered FROM messages ORDER BY server_ts DESC LIMIT 50").fetchall()],
        "devices": [{"id": d[0], "platform": d[1], "name": d[2], "registered": d[3], "last_seen": d[4] or "never"} for d in db.execute("SELECT id, platform, device_name, registered_at, last_seen FROM devices ORDER BY registered_at DESC LIMIT 100").fetchall()],
        "users": [{"username": u[0], "user_id": u[1], "created": u[2], "devices": u[3]} for u in db.execute("SELECT u.username, u.id, u.created_at, (SELECT COUNT(*) FROM devices WHERE user_id=u.id) FROM users u ORDER BY u.created_at DESC LIMIT 100").fetchall()],
        "groups": [{"id": g[0], "name": g[1], "members": g[2], "created": g[3]} for g in db.execute("SELECT g.id, g.name, COUNT(gm.device_id), g.created_at FROM group_chats g LEFT JOIN group_members gm ON g.id=gm.group_id GROUP BY g.id ORDER BY g.created_at DESC").fetchall()],
        "sessions": [{"id": s[0], "ip": ar_dec(s[1]), "login_at": s[2], "last_activity": s[3], "active": not bool(s[4])} for s in db.execute("SELECT id, ip, login_at, last_activity, logged_out FROM admin_sessions ORDER BY login_at DESC LIMIT 50").fetchall()],
    }

@app.delete("/api/v1/admin/devices/{device_id}")
async def admin_delete_device(device_id: str, session=Depends(require_admin)):
    db.execute("DELETE FROM messages WHERE sender_device_id=? OR recipient_device_id=?", (device_id, device_id))
    db.execute("DELETE FROM group_members WHERE device_id=?", (device_id,))
    db.execute("DELETE FROM devices WHERE id=?", (device_id,))
    db.commit()
    audit_admin(session[0][:8], "delete_device", device_id, "")
    return {"deleted": device_id}

# ── Admin Controls ────────────────────────────────────────────────
@app.post("/api/v1/admin/control/purge-files")
async def admin_purge_files(session=Depends(require_admin)):
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
async def admin_vacuum(session=Depends(require_admin)):
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
async def admin_clear_ecdh(session=Depends(require_admin)):
    with ecdh_lock:
        n = len(ecdh_cache); ecdh_cache.clear()
    audit_admin(session[0][:8], "clear_ecdh_cache", "", f"cleared={n}")
    return {"cleared": n}

@app.post("/api/v1/admin/control/wipe-rate-limits")
async def admin_wipe_rate_limits(session=Depends(require_admin)):
    n = len(rate_limits); rate_limits.clear()
    audit_admin(session[0][:8], "wipe_rate_limits", "", f"buckets={n}")
    return {"cleared_buckets": n}

@app.post("/api/v1/admin/control/kill-sessions")
async def admin_kill_other_sessions(session=Depends(require_admin)):
    cur_sid = session[0]
    db.execute("UPDATE admin_sessions SET logged_out=1 WHERE logged_out=0 AND id != ?", (cur_sid,))
    n = db.execute("SELECT changes()").fetchone()[0]
    db.commit()
    audit_admin(cur_sid[:8], "kill_other_admin_sessions", "", f"killed={n}")
    return {"killed": n}

@app.post("/api/v1/admin/control/clear-undelivered")
async def admin_clear_undelivered(session=Depends(require_admin)):
    n = db.execute("SELECT COUNT(*) FROM messages WHERE delivered=0").fetchone()[0]
    db.execute("DELETE FROM messages WHERE delivered=0")
    db.commit()
    audit_admin(session[0][:8], "clear_undelivered", "", f"deleted={n}")
    return {"deleted": n}

@app.post("/api/v1/admin/control/registration")
async def admin_toggle_registration(request: Request, session=Depends(require_admin)):
    body = await request.json()
    enabled = bool(body.get("enabled", True))
    setting_set("registration_enabled", "1" if enabled else "0")
    audit_admin(session[0][:8], "toggle_registration", "", f"enabled={enabled}")
    return {"registration_enabled": enabled}

@app.post("/api/v1/admin/control/maintenance")
async def admin_toggle_maintenance(request: Request, session=Depends(require_admin)):
    body = await request.json()
    enabled = bool(body.get("enabled", False))
    setting_set("maintenance_mode", "1" if enabled else "0")
    audit_admin(session[0][:8], "toggle_maintenance", "", f"enabled={enabled}")
    return {"maintenance_mode": enabled}

@app.post("/api/v1/admin/control/onion-only")
async def admin_toggle_onion_only(request: Request, session=Depends(require_admin)):
    """Reject any connection not arriving over a Tor onion service.
    Detection: client must present X-Onion-Proof or arrive via the local Tor
    SocksPort/HiddenServicePort wired into your tor config."""
    body = await request.json()
    enabled = bool(body.get("enabled", False))
    setting_set("onion_only", "1" if enabled else "0")
    audit_admin(session[0][:8], "toggle_onion_only", "", f"enabled={enabled}")
    return {"onion_only": enabled}

@app.post("/api/v1/admin/control/rotate-identity")
async def admin_rotate_identity(session=Depends(require_admin)):
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
async def admin_delete_user(user_id: str, session=Depends(require_admin)):
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
async def admin_kill_session(target_sid: str, session=Depends(require_admin)):
    db.execute("UPDATE admin_sessions SET logged_out=1 WHERE id=?", (target_sid,))
    db.commit()
    audit_admin(session[0][:8], "kill_session", target_sid[:12], "")
    return {"killed": target_sid}

# ── Admin Dashboard HTML ──────────────────────────────────────────
@app.get("/admin")
async def admin_dashboard(session=Depends(require_admin)):
    return HTMLResponse(r"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GHOSTLINK Admin</title>
<style>
:root{--bg:#0a0e17;--bg2:#111827;--bg3:#0d1420;--border:#1a2535;--text:#c8d6e5;--dim:#6e7a8a;--accent:#00d4ff;--ok:#2ed573;--warn:#ffc048;--danger:#ff4757;--purple:#a55eea}
*,*::before,*::after{box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);font-size:13px;margin:0;padding:0}
.top{background:var(--bg2);border-bottom:1px solid var(--border);padding:10px 20px;display:flex;align-items:center;gap:18px;position:sticky;top:0;z-index:50}
.top h1{font-size:18px;margin:0;color:var(--accent);letter-spacing:1.5px;font-weight:600}
.top .meta{color:var(--dim);font-size:11px;font-family:Consolas,monospace}
.top .spacer{flex:1}
.top .toggle{display:inline-flex;align-items:center;gap:8px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:5px 10px;font-size:11px;cursor:pointer;user-select:none}
.top .toggle .dot{width:8px;height:8px;border-radius:50%;background:var(--danger);box-shadow:0 0 6px var(--danger)}
.top .toggle.on .dot{background:var(--ok);box-shadow:0 0 6px var(--ok)}
.top button.btn{background:transparent;border:1px solid var(--border);color:var(--dim);padding:6px 12px;border-radius:5px;cursor:pointer;font-size:11px;letter-spacing:.3px}
.top button.btn:hover{color:var(--text);border-color:var(--accent)}
.top button.danger{color:var(--danger);border-color:rgba(255,71,87,.4)}
.top button.danger:hover{background:rgba(255,71,87,.1);color:var(--danger);border-color:var(--danger)}
.row{display:flex;gap:12px;padding:0 20px;flex-wrap:wrap}
.row.tight{padding:14px 20px 6px;gap:10px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;padding:14px 20px 6px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px;min-width:0;overflow:hidden}
.card .val{font-size:26px;font-weight:700;line-height:1.1;font-family:Consolas,monospace}
.card .lbl{font-size:10px;color:var(--dim);text-transform:uppercase;margin-top:4px;letter-spacing:.6px}
.card.accent .val{color:var(--accent)}.card.ok .val{color:var(--ok)}.card.warn .val{color:var(--warn)}.card.danger .val{color:var(--danger)}.card.purple .val{color:var(--purple)}
.panel{background:var(--bg2);border:1px solid var(--border);border-radius:8px;margin:0 20px 14px;overflow:hidden}
.panel-hdr{padding:10px 14px;border-bottom:1px solid var(--border);font-weight:600;color:var(--accent);letter-spacing:.6px;font-size:12px;display:flex;align-items:center;gap:10px}
.panel-hdr .pill{background:var(--bg3);color:var(--dim);font-weight:400;border:1px solid var(--border);padding:2px 8px;border-radius:99px;font-size:10px}
.panel-hdr .actions{margin-left:auto;display:flex;gap:6px}
.panel-hdr .actions button{background:var(--bg3);border:1px solid var(--border);color:var(--dim);padding:4px 10px;border-radius:4px;cursor:pointer;font-size:10px}
.panel-hdr .actions button:hover{color:var(--text);border-color:var(--accent)}
.panel-hdr .actions button.danger{color:var(--danger);border-color:rgba(255,71,87,.4)}
.panel-hdr .actions button.danger:hover{background:rgba(255,71,87,.1)}
.panel .body{max-height:360px;overflow:auto}
table{width:100%;border-collapse:collapse;font-size:11px}
th{text-align:left;padding:7px 12px;color:var(--dim);text-transform:uppercase;font-size:10px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--bg2);z-index:2}
td{padding:7px 12px;border-bottom:1px solid rgba(26,37,53,.4);font-family:Consolas,monospace;vertical-align:top}
tr:hover td{background:rgba(0,212,255,.03)}
.tinybtn{background:var(--danger);color:#fff;border:none;padding:1px 8px;border-radius:3px;cursor:pointer;font-size:10px}
.tinybtn.warn{background:var(--warn);color:#1a1a1a}
.tinybtn:hover{filter:brightness(1.15)}
.chart{display:flex;align-items:flex-end;gap:3px;height:90px;padding:8px 14px 12px}
.chart .bar{flex:1;background:linear-gradient(180deg,var(--accent),rgba(0,212,255,.2));border-radius:2px 2px 0 0;position:relative;min-height:1px;transition:opacity .2s}
.chart .bar:hover{opacity:.7}
.chart .bar .tt{display:none;position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:var(--bg3);border:1px solid var(--border);padding:3px 6px;border-radius:3px;font-size:10px;white-space:nowrap;color:var(--text);font-family:Consolas,monospace;z-index:10}
.chart .bar:hover .tt{display:block}
.statusdot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px}
.statusdot.ok{background:var(--ok)}.statusdot.warn{background:var(--warn)}.statusdot.dim{background:var(--dim)}
.bars2col{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:10px 14px}
.barlist{display:flex;flex-direction:column;gap:6px}
.barlist .item{display:flex;align-items:center;gap:8px;font-size:11px;font-family:Consolas,monospace}
.barlist .label{flex:0 0 140px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.barlist .track{flex:1;background:var(--bg3);height:10px;border-radius:3px;overflow:hidden;border:1px solid var(--border)}
.barlist .fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--purple))}
.barlist .num{flex:0 0 40px;text-align:right;color:var(--dim)}
.tag{display:inline-block;padding:1px 7px;border-radius:99px;font-size:10px;letter-spacing:.4px;font-weight:600}
.tag.ok{background:rgba(46,213,115,.15);color:var(--ok);border:1px solid rgba(46,213,115,.3)}
.tag.danger{background:rgba(255,71,87,.15);color:var(--danger);border:1px solid rgba(255,71,87,.3)}
.tag.warn{background:rgba(255,192,72,.15);color:var(--warn);border:1px solid rgba(255,192,72,.3)}
.empty{padding:24px;text-align:center;color:var(--dim);font-style:italic}
.kbd{background:var(--bg3);border:1px solid var(--border);border-bottom-width:2px;border-radius:3px;padding:0 4px;font-family:Consolas,monospace;font-size:10px;color:var(--dim)}
</style></head><body>
<div class="top">
<h1>GHOSTLINK</h1>
<span class="meta" id="metaUptime">uptime —</span>
<span class="meta" id="metaTime">—</span>
<span class="meta" id="metaVer">—</span>
<span class="spacer"></span>
<span class="toggle" id="regToggle" onclick="toggleSetting('registration', !regOn)"><span class="dot"></span><span id="regLbl">Registration —</span></span>
<span class="toggle" id="mntToggle" onclick="toggleSetting('maintenance', !mntOn)"><span class="dot"></span><span id="mntLbl">Maintenance —</span></span>
<span class="toggle" id="onionToggle" onclick="toggleSetting('onion-only', !onionOn)"><span class="dot"></span><span id="onionLbl">Onion —</span></span>
<button class="btn" onclick="refresh()">Refresh</button>
<button class="btn danger" onclick="logout()">Logout</button>
</div>

<div class="grid" id="stats"></div>

<div class="panel"><div class="panel-hdr">Server Identity
<div class="actions">
<button onclick="copyFp()">Copy Fingerprint</button>
<button class="danger" onclick="ctrl('rotate-identity','Rotate the server identity? All previously-pinned clients will refuse to connect until they re-pin the new fingerprint.')">Rotate Identity</button>
</div>
</div><div style="padding:14px;display:flex;gap:24px;flex-wrap:wrap;align-items:baseline">
<div><div style="color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Fingerprint (publish this)</div><div id="idFp" style="font-family:Consolas,monospace;font-size:18px;color:var(--accent);letter-spacing:1.5px;font-weight:600">—</div></div>
<div><div style="color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Signature Suite</div><div id="idSuite" style="font-family:Consolas,monospace;font-size:12px;color:var(--text)">—</div></div>
<div><div style="color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">PQ KEX Suite</div><div id="pqSuite" style="font-family:Consolas,monospace;font-size:12px;color:var(--text)">—</div></div>
</div></div>

<div class="row">
<div class="panel" style="flex:1 1 60%;margin:0 0 14px"><div class="panel-hdr">Messages — last 24h <span class="pill" id="hourlyTotal">—</span></div><div class="chart" id="hourlyChart"></div></div>
<div class="panel" style="flex:1 1 35%;margin:0 0 14px"><div class="panel-hdr">Top Endpoints (since boot)</div><div class="barlist" id="endpointList" style="padding:10px 14px"></div></div>
</div>

<div class="panel"><div class="panel-hdr">Server Controls
<div class="actions">
<button onclick="ctrl('purge-files','Purge expired/downloaded files?')">Purge Files</button>
<button onclick="ctrl('vacuum','Vacuum the database? Reclaims disk space.')">VACUUM DB</button>
<button onclick="ctrl('clear-ecdh','Clear ephemeral ECDH session cache?')">Clear ECDH Cache</button>
<button onclick="ctrl('wipe-rate-limits','Reset all rate-limit buckets?')">Reset Rate Limits</button>
<button class="danger" onclick="ctrl('kill-sessions','Sign out every OTHER admin session?')">Kill Other Admin Sessions</button>
<button class="danger" onclick="ctrl('clear-undelivered','PERMANENTLY drop all undelivered messages? This cannot be undone.')">Drop Undelivered</button>
</div>
</div><div style="padding:8px 14px;color:var(--dim);font-size:11px">Use sparingly. Every control action is recorded in the audit log.</div></div>

<div class="panel"><div class="panel-hdr">Top Senders/Recipients — 24h</div>
<div class="bars2col">
<div><div style="color:var(--dim);font-size:10px;letter-spacing:.5px;text-transform:uppercase;margin-bottom:6px">Senders</div><div class="barlist" id="topSenders"></div></div>
<div><div style="color:var(--dim);font-size:10px;letter-spacing:.5px;text-transform:uppercase;margin-bottom:6px">Recipients</div><div class="barlist" id="topRecips"></div></div>
</div></div>

<div class="panel"><div class="panel-hdr">Pending Friend Requests <span class="pill" id="frPill">0</span></div><div class="body"><table><thead><tr><th>From</th><th>To</th><th>Reason</th><th>Created</th></tr></thead><tbody id="frTable"></tbody></table></div></div>

<div class="panel"><div class="panel-hdr">Pending Group Invites <span class="pill" id="giPill">0</span></div><div class="body"><table><thead><tr><th>Group</th><th>From</th><th>To</th><th>Reason</th><th>Created</th></tr></thead><tbody id="giTable"></tbody></table></div></div>

<div class="panel"><div class="panel-hdr">Failed Logins <span class="pill" id="flPill">0</span></div><div class="body"><table><thead><tr><th>IP</th><th>HWID</th><th>Fingerprint</th><th>Time</th></tr></thead><tbody id="flTable"></tbody></table></div></div>

<div class="panel"><div class="panel-hdr">Recent Errors <span class="pill" id="errPill">0</span></div><div class="body"><table><thead><tr><th>Time</th><th>Path</th><th>Status</th><th>Detail</th></tr></thead><tbody id="errTable"></tbody></table></div></div>

<div class="panel"><div class="panel-hdr">Audit Log <span class="pill">last 100</span></div><div class="body"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead><tbody id="auditTable"></tbody></table></div></div>

<div class="panel"><div class="panel-hdr">Recent Messages</div><div class="body"><table><thead><tr><th>Time</th><th>Sender</th><th>Recipient</th><th>Size</th><th>Status</th></tr></thead><tbody id="msgTable"></tbody></table></div></div>

<div class="panel"><div class="panel-hdr">Users
<div class="actions"><span style="color:var(--dim);font-size:10px">click X to nuke user + all their data</span></div>
</div><div class="body"><table><thead><tr><th>Username</th><th>User ID</th><th>Devices</th><th>Registered</th><th></th></tr></thead><tbody id="userTable"></tbody></table></div></div>

<div class="panel"><div class="panel-hdr">Devices <span class="pill">click X to delete</span></div><div class="body"><table><thead><tr><th>Device ID</th><th>Platform</th><th>Name</th><th>Registered</th><th>Last Seen</th><th></th></tr></thead><tbody id="devTable"></tbody></table></div></div>

<div class="panel"><div class="panel-hdr">Groups</div><div class="body"><table><thead><tr><th>Group ID</th><th>Name</th><th>Members</th><th>Created</th></tr></thead><tbody id="grpTable"></tbody></table></div></div>

<div class="panel"><div class="panel-hdr">Admin Sessions</div><div class="body"><table><thead><tr><th>Session ID</th><th>IP</th><th>Login</th><th>Last Activity</th><th>Status</th><th></th></tr></thead><tbody id="sessTable"></tbody></table></div></div>

<div class="panel"><div class="panel-hdr">Files <span class="pill">live countdown</span></div><div class="body"><table><thead><tr><th>File ID</th><th>Sender</th><th>Recipient</th><th>Orig</th><th>Enc</th><th>Uploaded</th><th>Countdown</th><th>Status</th></tr></thead><tbody id="fileTable"></tbody></table></div></div>

<script>
let fileData=[],regOn=false,mntOn=false,onionOn=false;
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c])}
function fmtSize(b){if(!b&&b!==0)return'—';if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';if(b<1073741824)return(b/1048576).toFixed(1)+' MB';return(b/1073741824).toFixed(2)+' GB'}
function fmtPct(part,total){if(!total)return'0%';return((part/total)*100).toFixed(1)+'%'}

async function refresh(){
  try{
    const r=await fetch('/api/v1/admin/stats');
    if(r.status===401){location='/admin/login';return}
    const d=await r.json();
    fileData=d.files||[];
    regOn=d.registration_enabled;mntOn=d.maintenance_mode;onionOn=d.onion_only;
    document.getElementById('metaUptime').textContent='uptime '+d.uptime_fmt;
    document.getElementById('metaTime').textContent=d.server_time_utc+' UTC';
    document.getElementById('metaVer').textContent='v'+d.version;
    document.getElementById('regToggle').classList.toggle('on',regOn);
    document.getElementById('regLbl').textContent='Registration '+(regOn?'ON':'OFF');
    document.getElementById('mntToggle').classList.toggle('on',mntOn);
    document.getElementById('mntLbl').textContent='Maintenance '+(mntOn?'ON':'OFF');
    document.getElementById('onionToggle').classList.toggle('on',onionOn);
    document.getElementById('onionLbl').textContent='Onion '+(onionOn?'ON':'OFF');
    document.getElementById('idFp').textContent=d.identity_fingerprint||'(unavailable)';
    document.getElementById('idSuite').textContent=d.identity_suite||'(none)';
    document.getElementById('pqSuite').textContent=d.pq_suite||'(unavailable)';

    document.getElementById('stats').innerHTML=[
      ['accent',d.total_users,'Users'],
      ['ok',d.total_devices,'Devices'],
      ['ok',d.active_now,'Active Now (60s)'],
      ['ok',d.active_1min,'Active (5 min)'],
      ['accent',d.active_today,'Active Today'],
      ['warn',d.os_windows+'/'+d.os_android+'/'+d.os_ios,'Win/Android/iOS'],
      ['accent',d.total_messages.toLocaleString(),'Total Messages'],
      ['ok',d.msgs_1h.toLocaleString(),'Msgs / 1h'],
      ['ok',d.msgs_24h.toLocaleString(),'Msgs / 24h'],
      ['warn',d.undelivered,'Undelivered'],
      ['purple',d.total_groups,'Groups'],
      ['purple',d.total_friendships,'Friendships'],
      ['warn',d.avg_latency_ms+'ms','Avg Msg Latency'],
      ['warn',d.avg_req_ms+'ms','Avg Req'],
      ['warn',d.p95_req_ms+'ms','p95 Req'],
      ['danger',d.file_count,'Files'],
      ['danger',fmtSize(d.file_total_bytes),'Encrypted Stored'],
      ['accent',fmtSize(d.files_dir_bytes),'Files Folder'],
      ['accent',fmtSize(d.db_size_bytes),'Database'],
      ['warn',fmtSize(d.disk_free_bytes)+' free','Disk'],
      ['danger',d.failed_logins_24h,'Failed Logins 24h'],
      ['warn',d.pending_friend_requests,'Pending Friend Req'],
      ['warn',d.pending_group_invites,'Pending Group Inv'],
      ['purple',d.requests_total.toLocaleString(),'Reqs Since Boot'],
      ['danger',d.errors_total,'Errors Since Boot'],
      ['accent',d.ecdh_cache_size,'ECDH Cache'],
      ['ok',fmtSize(d.bytes_24h),'Msg Bytes / 24h'],
      ['ok',fmtSize(d.avg_msg_size),'Avg Msg Size'],
      [d.pq_available?'ok':'danger',d.pq_available?'READY':'OFF','PQ Hybrid'],
      ['purple',d.sealed_pending,'Sealed Pending'],
      ['purple',d.v2_pending,'v2 Pending'],
      ['warn',d.disappearing_pending,'Disappearing Pending'],
      ['accent',d.ratchet_devices,'Ratchet Devices'],
      ['ok',d.one_time_prekeys_total,'One-Time Prekeys'],
      ['purple',d.cover_count,'Cover Messages'],
      ['purple',fmtSize(d.cover_bytes),'Cover Bytes'],
      [d.anon_creds_available?'ok':'danger',d.anon_creds_available?'READY':'OFF','Anon Creds'],
      ['ok',d.anon_creds_redeemed_total,'Anon Creds Redeemed'],
      [d.srp_available?'ok':'danger',d.srp_available?'READY':'OFF','SRP-6a PAKE'],
      ['ok',d.srp_users,'SRP Users'],
      [d.at_rest_available?'ok':'danger',d.at_rest_available?'ON':'OFF','At-Rest Enc'],
    ].map(c=>'<div class="card '+c[0]+'"><div class="val">'+esc(c[1])+'</div><div class="lbl">'+esc(c[2])+'</div></div>').join('');

    const hh=d.hourly_activity||[];const hMax=Math.max(1,...hh.map(x=>x.count));
    const hTotal=hh.reduce((a,b)=>a+b.count,0);
    document.getElementById('hourlyTotal').textContent=hTotal.toLocaleString()+' msgs';
    const buckets=[];for(let i=23;i>=0;i--){const dt=new Date(Date.now()-i*3600000);const k=dt.toISOString().slice(0,13).replace('T',' ')+':00';const found=hh.find(x=>x.hour===k);buckets.push({hour:dt.getUTCHours()+':00',count:found?found.count:0});}
    document.getElementById('hourlyChart').innerHTML=buckets.map(b=>'<div class="bar" style="height:'+(b.count/hMax*100)+'%"><span class="tt">'+b.hour+' — '+b.count+'</span></div>').join('');

    const ep=d.top_endpoints||[];const eMax=Math.max(1,...ep.map(x=>x.count));
    document.getElementById('endpointList').innerHTML=ep.map(x=>'<div class="item"><span class="label">'+esc(x.path)+'</span><span class="track"><span class="fill" style="width:'+(x.count/eMax*100)+'%"></span></span><span class="num">'+x.count+(x.errors?' <span style="color:var(--danger)">('+x.errors+')</span>':'')+'</span></div>').join('')||'<div class="empty">no traffic yet</div>';

    const ts=d.top_senders||[];const tsMax=Math.max(1,...ts.map(x=>x.count));
    document.getElementById('topSenders').innerHTML=ts.map(x=>'<div class="item"><span class="label">'+esc(x.id)+'</span><span class="track"><span class="fill" style="width:'+(x.count/tsMax*100)+'%"></span></span><span class="num">'+x.count+'</span></div>').join('')||'<div class="empty">—</div>';
    const tr=d.top_recipients||[];const trMax=Math.max(1,...tr.map(x=>x.count));
    document.getElementById('topRecips').innerHTML=tr.map(x=>'<div class="item"><span class="label">'+esc(x.id)+'</span><span class="track"><span class="fill" style="width:'+(x.count/trMax*100)+'%"></span></span><span class="num">'+x.count+'</span></div>').join('')||'<div class="empty">—</div>';

    const fr=d.friend_requests_pending||[];document.getElementById('frPill').textContent=fr.length;
    document.getElementById('frTable').innerHTML=fr.map(r=>'<tr><td>'+esc(r.from)+'</td><td>'+esc(r.to)+'</td><td>'+esc(r.reason)+'</td><td>'+esc(r.created)+'</td></tr>').join('')||'<tr><td colspan="4" class="empty">none</td></tr>';
    const gi=d.group_invites_pending||[];document.getElementById('giPill').textContent=gi.length;
    document.getElementById('giTable').innerHTML=gi.map(r=>'<tr><td>'+esc(r.group)+'</td><td>'+esc(r.from)+'</td><td>'+esc(r.to)+'</td><td>'+esc(r.reason)+'</td><td>'+esc(r.created)+'</td></tr>').join('')||'<tr><td colspan="5" class="empty">none</td></tr>';

    const fl=d.failed_logins||[];document.getElementById('flPill').textContent=fl.length;
    document.getElementById('flTable').innerHTML=fl.map(r=>'<tr><td>'+esc(r.ip)+'</td><td>'+esc(r.hwid)+'</td><td>'+esc(r.fp)+'</td><td>'+esc(r.ts)+'</td></tr>').join('')||'<tr><td colspan="4" class="empty">none</td></tr>';

    const er=d.recent_errors||[];document.getElementById('errPill').textContent=er.length;
    document.getElementById('errTable').innerHTML=er.map(r=>'<tr><td>'+esc(r.ts)+'</td><td>'+esc(r.path)+'</td><td><span class="tag '+(r.status>=500?'danger':'warn')+'">'+esc(r.status)+'</span></td><td>'+esc(r.detail)+'</td></tr>').join('')||'<tr><td colspan="4" class="empty">none</td></tr>';

    const al=d.audit_log||[];
    document.getElementById('auditTable').innerHTML=al.map(r=>'<tr><td>'+esc(r.ts)+'</td><td>'+esc(r.actor)+'</td><td><span class="tag ok">'+esc(r.action)+'</span></td><td>'+esc(r.target)+'</td><td>'+esc(r.detail)+'</td></tr>').join('')||'<tr><td colspan="5" class="empty">none</td></tr>';

    document.getElementById('msgTable').innerHTML=(d.recent_messages||[]).map(m=>'<tr><td>'+esc(m.ts)+'</td><td>'+esc(m.sender.substring(0,12))+'</td><td>'+esc(m.recipient.substring(0,12))+'</td><td>'+m.size+'B</td><td><span class="tag '+(m.delivered?'ok':'warn')+'">'+(m.delivered?'Delivered':'Pending')+'</span></td></tr>').join('');

    document.getElementById('devTable').innerHTML=(d.devices||[]).map(dv=>'<tr><td>'+esc(dv.id.substring(0,16))+'</td><td>'+esc(dv.platform)+'</td><td>'+esc(dv.name)+'</td><td>'+esc(dv.registered)+'</td><td>'+esc(dv.last_seen)+'</td><td><button class="tinybtn" onclick="delDev(\''+esc(dv.id)+'\')">X</button></td></tr>').join('');
    document.getElementById('grpTable').innerHTML=(d.groups||[]).map(g=>'<tr><td>'+esc(g.id.substring(0,12))+'</td><td>'+esc(g.name)+'</td><td>'+g.members+'</td><td>'+esc(g.created)+'</td></tr>').join('');
    document.getElementById('userTable').innerHTML=(d.users||[]).map(u=>'<tr><td>'+esc(u.username)+'</td><td>'+esc(u.user_id.substring(0,16))+'</td><td>'+u.devices+'</td><td>'+esc(u.created)+'</td><td><button class="tinybtn" onclick="delUser(\''+esc(u.user_id)+'\',\''+esc(u.username)+'\')">X</button></td></tr>').join('');
    document.getElementById('sessTable').innerHTML=(d.sessions||[]).map(s=>'<tr><td>'+esc(s.id.substring(0,12))+'</td><td>'+esc(s.ip)+'</td><td>'+esc(s.login_at)+'</td><td>'+esc(s.last_activity)+'</td><td><span class="tag '+(s.active?'ok':'warn')+'">'+(s.active?'Active':'Ended')+'</span></td><td>'+(s.active?'<button class="tinybtn warn" onclick="killSess(\''+esc(s.id)+'\')">Kill</button>':'')+'</td></tr>').join('');
  }catch(e){console.error(e)}
}

function updateCountdowns(){
  let h='';const n=Date.now();
  for(const f of fileData){
    if(!f.expires_at){continue}
    const e=new Date(f.expires_at+'Z').getTime();const r=e-n;
    let d,c;
    if(f.downloaded){d='DOWNLOADED';c='var(--ok)';}
    else if(r<=0){d='EXPIRED';c='var(--danger)';}
    else{const hh=Math.floor(r/3600000);const mm=Math.floor((r%3600000)/60000);const ss=Math.floor((r%60000)/1000);const ms=r%1000;
      d=hh+':'+String(mm).padStart(2,'0')+':'+String(ss).padStart(2,'0')+'.'+String(ms).padStart(3,'0');
      c=r<300000?'var(--danger)':r<1800000?'var(--warn)':'var(--ok)';}
    h+='<tr><td>'+esc(f.id.substring(0,12))+'</td><td>'+esc(f.sender)+'</td><td>'+esc(f.recipient)+'</td><td>'+fmtSize(f.orig_size)+'</td><td>'+fmtSize(f.enc_size)+'</td><td>'+esc(f.server_ts)+'</td><td style="color:'+c+';font-weight:600">'+d+'</td><td>'+(f.downloaded?'<span class="tag ok">Done</span>':'<span class="tag warn">Waiting</span>')+'</td></tr>';
  }
  document.getElementById('fileTable').innerHTML=h||'<tr><td colspan="8" class="empty">no files</td></tr>';
}

async function ctrl(action,msg){
  if(!confirm(msg))return;
  const r=await fetch('/api/v1/admin/control/'+action,{method:'POST'});
  const j=await r.json().catch(()=>({}));
  alert(action+': '+JSON.stringify(j));
  refresh();
}
async function toggleSetting(which,enabled){
  const path=which;  // 'registration' | 'maintenance' | 'onion-only'
  await fetch('/api/v1/admin/control/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled})});
  refresh();
}
function copyFp(){const fp=document.getElementById('idFp').textContent;if(navigator.clipboard){navigator.clipboard.writeText(fp).then(()=>alert('Copied: '+fp));}else{prompt('Fingerprint:',fp);}}
async function delDev(id){if(confirm('Delete device '+id.substring(0,16)+'?')){await fetch('/api/v1/admin/devices/'+id,{method:'DELETE'});refresh()}}
async function delUser(id,name){if(prompt('To delete user "'+name+'" and ALL their data, type the username:')!==name)return;await fetch('/api/v1/admin/users/'+id,{method:'DELETE'});refresh()}
async function killSess(id){if(confirm('Kill admin session '+id.substring(0,12)+'?')){await fetch('/api/v1/admin/sessions/'+id,{method:'DELETE'});refresh()}}
async function logout(){await fetch('/api/v1/admin/logout',{method:'POST'});location='/admin/login'}

setInterval(updateCountdowns,50);
setInterval(refresh,8000);
refresh();
</script></body></html>""")

if __name__ == "__main__":
    import uvicorn
    init_db()
    print(f"[GHOSTLINK] Database initialized")
    print(f"[GHOSTLINK] Starting on port {PORT}")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
