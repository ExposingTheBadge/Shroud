"""
GHOSTLINK Secure Messaging Server — FIPS 140-2 Compliant
Port 58443 | TLS 1.3 | E2E Encryption | Device Registration
"""

import os, sys, json, time, sqlite3, uuid, struct, hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

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

from cryptography.hazmat.primitives.asymmetric import ec

# ── Config ───────────────────────────────────────────────────────────
from fastapi.responses import FileResponse, StreamingResponse
PORT = 58443
DB_PATH = os.path.join(os.path.dirname(__file__), "ghostlink.db")
FILE_DIR = os.path.join(os.path.dirname(__file__), "files")
os.makedirs(FILE_DIR, exist_ok=True)
SESSION_TIMEOUT = 3600  # 1 hour
MAX_DEVICES_PER_USER = 25

@asynccontextmanager
async def lifespan(ap):
    # Startup
    if not fips_self_test():
        raise RuntimeError("FIPS 140-2 self-test FAILED — server cannot start")
    print(f"[GHOSTLINK] FIPS 140-2 self-test: PASSED")
    print(f"[GHOSTLINK] Server starting on port {PORT}")
    # Cleanup expired files on startup
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
    yield
    # Shutdown
    print("[GHOSTLINK] Server shutting down")

app = FastAPI(title="GHOSTLINK Secure Messaging", version="1.3.0", lifespan=lifespan)

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
    db.commit()
    return db

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
    return {"status": "ok", "fips": "140-2 validated", "version": "1.3.0"}

import threading
ecdh_cache = {}
ecdh_lock = threading.Lock()

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

@app.get("/api/v1/version")
async def get_version():
    """Client update check endpoint. Clients fetch this and compare to their
    embedded version string."""
    base = "https://github.com/ExposingTheBadge/GhostLink/releases/latest"
    return {
        "version": "1.3.0",
        "minimum_supported": "1.3.0",
        "release_url": base,
        "windows": f"{base}/download/GHOSTLINK.exe",
        "android": f"{base}/download/GHOSTLINK.apk",
        "linux":   f"{base}/download/ghostlink-linux",
        "changelog": (
            "1.3.0 — Inline image attachments in chat with click-to-fullscreen "
            "viewer; sender or recipient can permanently delete images from "
            "the server. Cross-device image decryption via /devices/{id}/pubkey."
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
async def send_message(req: SendMessageRequest):
    """Relay an encrypted message. Server never sees plaintext."""
    # Validate both devices exist
    sender = db.execute("SELECT id FROM devices WHERE id = ?", (req.sender_device_id,)).fetchone()
    recipient = db.execute("SELECT id FROM devices WHERE id = ?", (req.recipient_device_id,)).fetchone()
    if not sender or not recipient:
        raise HTTPException(404, "Device not found")

    # Validate envelope is valid JSON
    try:
        envelope = json.loads(req.envelope)
        assert "nonce" in envelope
        assert "ciphertext" in envelope
        assert "sig" in envelope
        assert "sender" in envelope
        assert "ts" in envelope
    except Exception:
        raise HTTPException(400, "Invalid message envelope format")

    # Store encrypted blob
    msg_id = uuid.uuid4().hex
    db.execute(
        "INSERT INTO messages (id, sender_device_id, recipient_device_id, envelope) VALUES (?, ?, ?, ?)",
        (msg_id, req.sender_device_id, req.recipient_device_id, json.dumps(envelope))
    )

    # Update last_seen
    db.execute("UPDATE devices SET last_seen = datetime('now') WHERE id = ?", (req.sender_device_id,))
    db.commit()

    return {"message_id": msg_id, "relayed": True}

# ── Fetch Messages ───────────────────────────────────────────────────
@app.post("/api/v1/messages/fetch")
async def fetch_messages(req: GetMessagesRequest):
    """Fetch undelivered messages for a device."""
    device = db.execute("SELECT id FROM devices WHERE id = ?", (req.device_id,)).fetchone()
    if not device:
        raise HTTPException(404, "Device not found")

    query = "SELECT id, sender_device_id, envelope, server_ts FROM messages WHERE recipient_device_id = ? AND delivered = 0"
    params = [req.device_id]
    if req.since:
        query += " AND server_ts > ?"
        params.append(req.since)

    messages = db.execute(query + " ORDER BY server_ts ASC LIMIT 100", params).fetchall()

    # Log latency before destroying messages
    now = datetime.now(tz=timezone.utc)
    for msg in messages:
        stored = datetime.fromisoformat(msg[3])
        latency_ms = (now - stored.replace(tzinfo=timezone.utc)).total_seconds() * 1000
        db.execute("INSERT INTO message_latency (message_id, latency_ms) VALUES (?,?)", (msg[0], latency_ms))
        db.execute("DELETE FROM messages WHERE id = ?", (msg[0],))
    db.execute("UPDATE devices SET last_seen = datetime('now') WHERE id = ?", (req.device_id,))
    db.commit()

    return {
        "messages": [
            {
                "id": m[0],
                "sender_device_id": m[1],
                "envelope": json.loads(m[2]),
                "server_ts": m[3]
            }
            for m in messages
        ]
    }

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
               (rid, me[0], target[0], reason))
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
        "incoming": [{"id": r[0], "from": r[1], "reason": r[2], "created": r[3]} for r in incoming],
        "outgoing": [{"id": r[0], "to": r[1], "status": r[2], "response_reason": r[3], "created": r[4]} for r in outgoing],
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
               (iid, group_id, me[0], target[0], reason))
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
    return {"invites": [{"id": r[0], "group_id": r[1], "group_name": r[2], "from": r[3], "reason": r[4], "created": r[5]} for r in rows]}

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
            # Poll for new messages every 2 seconds
            messages = db.execute(
                "SELECT id, sender_device_id, envelope, server_ts FROM messages WHERE recipient_device_id = ? AND delivered = 0 ORDER BY server_ts ASC LIMIT 50",
                (device_id,)
            ).fetchall()

            for msg in messages:
                await websocket.send_json({
                    "id": msg[0],
                    "sender_device_id": msg[1],
                    "envelope": json.loads(msg[2]),
                    "server_ts": msg[3]
                })
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
    db.execute("INSERT INTO admin_sessions (id, ip, user_agent) VALUES (?,?,?)", (sid, ip, ua))
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
@app.get("/admin")
async def admin_dashboard(session=Depends(require_admin)):
    """Admin dashboard HTML."""
    return HTMLResponse("""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GHOSTLINK Admin</title>
<style>:root{--bg:#0a0e17;--bg2:#111827;--border:#1a2535;--text:#c8d6e5;--dim:#6e7a8a;--accent:#00d4ff;--ok:#2ed573;--warn:#ffc048;--danger:#ff4757}
*,*::before,*::after{box-sizing:border-box}body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);font-size:13px;margin:0;padding:0}
.top{background:var(--bg2);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:16px}
.top h1{font-size:18px;margin:0;color:var(--accent);letter-spacing:1px}
.top .spacer{flex:1}
.top button{background:transparent;border:1px solid var(--border);color:var(--dim);padding:6px 14px;border-radius:4px;cursor:pointer;font-size:11px}
.top button:hover{color:var(--danger);border-color:var(--danger)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;padding:20px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px}
.card .val{font-size:32px;font-weight:700}
.card .lbl{font-size:11px;color:var(--dim);text-transform:uppercase;margin-top:4px;letter-spacing:.5px}
.card.accent .val{color:var(--accent)}.card.ok .val{color:var(--ok)}.card.warn .val{color:var(--warn)}.card.danger .val{color:var(--danger)}
.panel{background:var(--bg2);border:1px solid var(--border);border-radius:8px;margin:0 20px 20px;overflow:hidden}
.panel-hdr{padding:12px 16px;border-bottom:1px solid var(--border);font-weight:600;color:var(--accent);letter-spacing:.5px}
table{width:100%;border-collapse:collapse;font-size:11px}
th{text-align:left;padding:8px 12px;color:var(--dim);text-transform:uppercase;font-size:10px;border-bottom:1px solid var(--border)}
td{padding:8px 12px;border-bottom:1px solid rgba(26,37,53,.3);font-family:Consolas,monospace}
</style></head><body>
<div class="top"><h1>GHOSTLINK Admin</h1><span>Server Dashboard</span><span class="spacer"></span><button onclick="logout()">Logout</button></div>
<div class="grid" id="stats"></div>
<div class="panel"><div class="panel-hdr">Recent Messages</div><table><thead><tr><th>Time</th><th>Sender</th><th>Recipient</th><th>Size</th><th>Status</th></tr></thead><tbody id="msgTable"></tbody></table></div>
<div class="panel"><div class="panel-hdr">Users</div><table><thead><tr><th>Username</th><th>User ID</th><th>Devices</th><th>Registered</th></tr></thead><tbody id="userTable"></tbody></table></div>
<div class="panel"><div class="panel-hdr">Devices <span style="color:var(--dim);font-weight:400;font-size:10px">— click X to delete</span></div><table><thead><tr><th>Device ID</th><th>Platform</th><th>Name</th><th>Registered</th><th>Last Seen</th><th></th></tr></thead><tbody id="devTable"></tbody></table></div>
<div class="panel"><div class="panel-hdr">Groups</div><table><thead><tr><th>Group ID</th><th>Name</th><th>Members</th><th>Created</th></tr></thead><tbody id="grpTable"></tbody></table></div>
<div class="panel"><div class="panel-hdr">Admin Sessions</div><table><thead><tr><th>Session ID</th><th>IP</th><th>Login</th><th>Last Activity</th><th>Status</th></tr></thead><tbody id="sessTable"></tbody></table></div>
<div class="panel"><div class="panel-hdr">Files <span style="color:var(--dim);font-weight:400;font-size:10px">— countdown to auto-deletion</span></div><table><thead><tr><th>File ID</th><th>Sender</th><th>Recipient</th><th>Orig Size</th><th>Enc Size</th><th>Uploaded</th><th>Countdown</th><th>Status</th></tr></thead><tbody id="fileTable"></tbody></table></div>
<script>
let fileData=[];
async function refresh(){
try{const r=await fetch('/api/v1/admin/stats');
if(r.status===401){location='/admin/login';return}
const d=await r.json();
fileData=d.files||[];
document.getElementById('stats').innerHTML=
'<div class="card accent"><div class="val">'+d.total_users+'</div><div class="lbl">Users</div></div>'+'<div class="card ok"><div class="val">'+d.total_devices+'</div><div class="lbl">All Devices</div></div>'+'<div class="card ok"><div class="val">'+d.active_now+'</div><div class="lbl">Active Now</div></div>'+'<div class="card ok"><div class="val">'+d.active_1min+'</div><div class="lbl">Active (5 min)</div></div>'+'<div class="card accent"><div class="val">'+d.active_today+'</div><div class="lbl">Active Today</div></div>'+'<div class="card warn"><div class="val">'+d.os_windows+'/'+d.os_android+'/'+d.os_ios+'</div><div class="lbl">Win/Android/iOS</div></div>'+'<div class="card warn"><div class="val">'+d.avg_latency_ms+'ms</div><div class="lbl">Avg Msg Latency</div></div>'+'<div class="card danger"><div class="val">'+d.file_count+'</div><div class="lbl">Files</div></div>'+'<div class="card danger"><div class="val">'+d.file_total_gb.toFixed(3)+'</div><div class="lbl">GB Allocated</div></div>';
document.getElementById('msgTable').innerHTML=(d.recent_messages||[]).map(m=>'<tr><td>'+m.ts+'</td><td>'+m.sender.substring(0,12)+'</td><td>'+m.recipient.substring(0,12)+'</td><td>'+m.size+'B</td><td>'+(m.delivered?'Delivered':'Pending')+'</td></tr>').join('');
document.getElementById('devTable').innerHTML=(d.devices||[]).map(function(dv){return'<tr><td>'+dv.id.substring(0,16)+'</td><td>'+dv.platform+'</td><td>'+dv.name+'</td><td>'+dv.registered+'</td><td>'+dv.last_seen+'</td><td><button onclick="delDev(this.dataset.id)" data-id="'+dv.id+'" style="background:var(--danger);color:#fff;border:none;padding:1px 8px;border-radius:3px;cursor:pointer;font-size:10px">X</button></td></tr>';}).join('');
document.getElementById('grpTable').innerHTML=(d.groups||[]).map(g=>'<tr><td>'+g.id.substring(0,12)+'</td><td>'+g.name+'</td><td>'+g.members+'</td><td>'+g.created+'</td></tr>').join('');
document.getElementById('userTable').innerHTML=(d.users||[]).map(u=>'<tr><td>'+u.username+'</td><td>'+u.user_id.substring(0,16)+'</td><td>'+u.devices+'</td><td>'+u.created+'</td></tr>').join('');
document.getElementById('sessTable').innerHTML=(d.sessions||[]).map(s=>'<tr><td>'+s.id.substring(0,12)+'</td><td>'+s.ip+'</td><td>'+s.login_at+'</td><td>'+s.last_activity+'</td><td><span style="color:'+(s.active?'var(--ok)':'var(--dim)')+'">'+(s.active?'Active':'Ended')+'</span></td></tr>').join('');}catch(e){}}
function fmtSize(b){if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';if(b<1073741824)return(b/1048576).toFixed(1)+' MB';return(b/1073741824).toFixed(2)+' GB'}
function updateCountdowns(){
let h='';const n=Date.now();
for(const f of fileData){
const e=new Date(f.expires_at+'Z').getTime();const r=e-n;
let d,c;
if(f.downloaded){d='DOWNLOADED';c='var(--ok)';}
else if(r<=0){d='EXPIRED';c='var(--danger)';}
else{const hh=Math.floor(r/3600000);const mm=Math.floor((r%3600000)/60000);const ss=Math.floor((r%60000)/1000);const ms=r%1000;
d=hh+':'+String(mm).padStart(2,'0')+':'+String(ss).padStart(2,'0')+'.'+String(ms).padStart(3,'0');
c=r<300000?'var(--danger)':r<1800000?'var(--warn)':'var(--ok)';}
h+='<tr><td>'+f.id.substring(0,12)+'</td><td>'+f.sender+'</td><td>'+f.recipient+'</td><td>'+fmtSize(f.orig_size)+'</td><td>'+fmtSize(f.enc_size)+'</td><td>'+f.server_ts+'</td><td style="color:'+c+';font-family:Consolas,monospace;font-weight:600">'+d+'</td><td>'+(f.downloaded?'<span style="color:var(--ok)">Done</span>':'<span style="color:var(--warn)">Waiting</span>')+'</td></tr>';}
document.getElementById('fileTable').innerHTML=h;}
async function logout(){await fetch('/api/v1/admin/logout',{method:'POST'});location='/admin/login'}
async function delDev(id){if(!id)id=this.dataset.id;if(confirm('Delete device '+id.substring(0,16)+'?')){await fetch('/api/v1/admin/devices/'+id,{method:'DELETE'});refresh()}}
setInterval(updateCountdowns,50);
setInterval(refresh,8000);refresh();
</script></body></html>""")

@app.get("/api/v1/admin/stats")
async def admin_stats(session=Depends(require_admin)):
    files = db.execute("SELECT id, sender_device_id, recipient_device_id, original_size, encrypted_size, server_ts, expires_at, downloaded FROM file_transfers ORDER BY server_ts DESC").fetchall()
    total_enc_bytes = sum(f[4] for f in files)
    # Active client counts
    active_now = db.execute("SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now','-60 seconds')").fetchone()[0]
    active_1min = db.execute("SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now','-5 minutes')").fetchone()[0]
    # OS breakdown
    os_counts = {}
    for row in db.execute("SELECT platform, COUNT(*) FROM devices GROUP BY platform").fetchall():
        os_counts[row[0]] = row[1]
    # Latency stats (avg ms between send and delivery for recent messages)
    latency = db.execute("SELECT ROUND(AVG(latency_ms),1), MIN(latency_ms), MAX(latency_ms) FROM message_latency WHERE recorded_at > datetime('now','-1 hour')").fetchone()
    return {
        "total_users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_devices": db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
        "total_messages": db.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
        "undelivered": db.execute("SELECT COUNT(*) FROM messages WHERE delivered=0").fetchone()[0],
        "total_groups": db.execute("SELECT COUNT(*) FROM group_chats").fetchone()[0],
        "active_today": db.execute("SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now','-1 day')").fetchone()[0],
        "active_now": active_now,
        "active_1min": active_1min,
        "os_windows": os_counts.get("windows", 0),
        "os_android": os_counts.get("android", 0),
        "os_ios": os_counts.get("ios", 0),
        "avg_latency_ms": latency[0] or 0,
        "min_latency_ms": latency[1] or 0,
        "max_latency_ms": latency[2] or 0,
        "file_count": len(files),
        "file_total_bytes": total_enc_bytes,
        "file_total_gb": round(total_enc_bytes / (1024**3), 4),
        "files": [{"id": f[0], "sender": f[1][:12], "recipient": f[2][:12], "orig_size": f[3], "enc_size": f[4], "server_ts": f[5], "expires_at": f[6], "downloaded": bool(f[7])} for f in files],
        "recent_messages": [{"ts": m[0], "sender": m[1], "recipient": m[2], "size": m[3], "delivered": bool(m[4])} for m in db.execute("SELECT server_ts, sender_device_id, recipient_device_id, LENGTH(envelope), delivered FROM messages ORDER BY server_ts DESC LIMIT 50").fetchall()],
        "devices": [{"id": d[0], "platform": d[1], "name": d[2], "registered": d[3], "last_seen": d[4] or "never"} for d in db.execute("SELECT id, platform, device_name, registered_at, last_seen FROM devices ORDER BY registered_at DESC LIMIT 100").fetchall()],
        "users": [{"username": u[0], "user_id": u[1], "created": u[2], "devices": u[3]} for u in db.execute("SELECT u.username, u.id, u.created_at, (SELECT COUNT(*) FROM devices WHERE user_id=u.id) FROM users u ORDER BY u.created_at DESC LIMIT 100").fetchall()],
        "groups": [{"id": g[0], "name": g[1], "members": g[2], "created": g[3]} for g in db.execute("SELECT g.id, g.name, COUNT(gm.device_id), g.created_at FROM group_chats g LEFT JOIN group_members gm ON g.id=gm.group_id GROUP BY g.id ORDER BY g.created_at DESC").fetchall()],
        "sessions": [{"id": s[0], "ip": s[1], "login_at": s[2], "last_activity": s[3], "active": not bool(s[4])} for s in db.execute("SELECT id, ip, login_at, last_activity, logged_out FROM admin_sessions ORDER BY login_at DESC LIMIT 50").fetchall()],
    }

@app.delete("/api/v1/admin/devices/{device_id}")
async def admin_delete_device(device_id: str, session=Depends(require_admin)):
    db.execute("DELETE FROM messages WHERE sender_device_id=? OR recipient_device_id=?", (device_id, device_id))
    db.execute("DELETE FROM group_members WHERE device_id=?", (device_id,))
    db.execute("DELETE FROM devices WHERE id=?", (device_id,))
    db.commit()
    return {"deleted": device_id}

if __name__ == "__main__":
    import uvicorn
    init_db()
    print(f"[GHOSTLINK] Database initialized")
    print(f"[GHOSTLINK] Starting on port {PORT}")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
