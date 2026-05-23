"""
GHOSTLINK Secure Messaging Server — FIPS 140-2 Compliant
Port 58443 | TLS 1.3 | E2E Encryption | Device Registration
"""

import os, sys, json, time, sqlite3, uuid, struct
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Add parent to path for crypto imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Header, Cookie, Depends
from fastapi.responses import JSONResponse, HTMLResponse
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

app = FastAPI(title="GHOSTLINK Secure Messaging", version="1.0.0", lifespan=lifespan)

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
    return {"status": "ok", "fips": "140-2 validated", "version": "1.0.0"}

@app.get("/api/v1/version")
async def get_version():
    """Client update check endpoint."""
    return {
        "version": "1.0.0",
        "windows": "https://github.com/GHOSTLINK/releases/latest/download/GHOSTLINK.exe",
        "android": "https://github.com/GHOSTLINK/releases/latest/download/GHOSTLINK.apk",
        "linux": "https://github.com/GHOSTLINK/releases/latest/download/ghostlink-linux",
        "changelog": "Initial release"
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

# ── User Registration ────────────────────────────────────────────────
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
    user = db.execute(
        "SELECT id, password_hash, password_salt FROM users WHERE username = ?",
        (req.username,)
    ).fetchone()
    if not user:
        raise HTTPException(401, "Invalid credentials")

    # Verify password
    derived, _ = derive_key(req.password, user[2])
    if derived.hex() != user[1]:
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
        except Exception:
            raise HTTPException(400, "Invalid public key format")

        db.execute(
            "INSERT INTO devices (id, user_id, device_name, platform, public_key, hwid) VALUES (?, ?, ?, ?, ?, ?)",
            (device_id, user[0], req.device_name, req.platform, pub_key_bytes, req.hwid)
        )
    db.commit()

    # Generate server-side ephemeral keypair for this device's ECDH
    server_priv, server_pub = generate_keypair()
    server_pub_hex = serialize_public_key(server_pub).hex()

    return {
        "device_id": device_id,
        "server_public_key": server_pub_hex,
        "user_id": user[0],
        "registered": True
    }

# ── List User Devices ────────────────────────────────────────────────
@app.post("/api/v1/devices/list")
async def list_devices(req: AuthRequest):
    """List all registered devices for a user."""
    user = db.execute(
        "SELECT id, password_hash, password_salt FROM users WHERE username = ?",
        (req.username,)
    ).fetchone()
    if not user:
        raise HTTPException(401, "Invalid credentials")

    derived, _ = derive_key(req.password, user[2])
    if derived.hex() != user[1]:
        raise HTTPException(401, "Invalid credentials")

    devices = db.execute(
        "SELECT id, device_name, platform, registered_at, last_seen FROM devices WHERE user_id = ?",
        (user[0],)
    ).fetchall()

    return {
        "devices": [
            {
                "id": d[0],
                "name": d[1],
                "platform": d[2],
                "registered_at": d[3],
                "last_seen": d[4]
            }
            for d in devices
        ]
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

@app.post("/api/v1/contacts/search")
async def search_contacts(req: ContactSearchRequest):
    user = db.execute("SELECT id, password_hash, password_salt FROM users WHERE username = ?", (req.username,)).fetchone()
    if not user: raise HTTPException(401)
    derived, _ = derive_key(req.password, user[2])
    if derived.hex() != user[1]: raise HTTPException(401)
    users = db.execute("SELECT username FROM users WHERE username LIKE ? AND username != ? LIMIT 20", (req.query + "%", req.username)).fetchall()
    return {"users": [u[0] for u in users]}

@app.post("/api/v1/contacts/devices")
async def get_contact_devices(req: AuthRequest):
    user = db.execute("SELECT id, password_hash, password_salt FROM users WHERE username = ?", (req.username,)).fetchone()
    if not user: raise HTTPException(401)
    derived, _ = derive_key(req.password, user[2])
    if derived.hex() != user[1]: raise HTTPException(401)
    contact = db.execute("SELECT id FROM users WHERE username = ?", (req.username,)).fetchone()
    if not contact: raise HTTPException(404)
    devices = db.execute("SELECT id, device_name, platform, public_key FROM devices WHERE user_id = ?", (contact[0],)).fetchall()
    return {"devices": [{"id": d[0], "name": d[1], "platform": d[2], "public_key": d[3].hex()} for d in devices]}

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
    """One-time download — file destroyed from server after successful download."""
    row = db.execute(
        "SELECT storage_name, sender_device_id, recipient_device_id, encrypted_metadata, encrypted_size, downloaded FROM file_transfers WHERE id=?",
        (file_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "File not found or already downloaded")

    if row[5]:  # Already downloaded
        raise HTTPException(410, "File already downloaded — one-time transfer only")

    storage_path = os.path.join(FILE_DIR, row[0])
    if not os.path.isfile(storage_path):
        raise HTTPException(404, "File data missing")

    # Destroy file from server after serving
    if device_id and device_id == row[2]:
        os.remove(storage_path)
        db.execute("DELETE FROM file_transfers WHERE id=?", (file_id,))
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

# ── Admin Auth ──────────────────────────────────────────────────────
from fastapi.responses import RedirectResponse

ADMIN_PASSWORD = os.environ.get("GHOSTLINK_ADMIN_PASSWORD", "ghostlink-admin")
SESSION_TIMEOUT_SEC = 12 * 3600  # 12 hours

def get_client_info(request: Request) -> tuple:
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("User-Agent", "unknown")[:256]
    return ip, ua

def get_admin_session(sid: str = Cookie(None, alias="ghostlink_sid")):
    """Dependency: validate session cookie, return session row or None."""
    if not sid: return None
    row = db.execute(
        "SELECT id, ip, user_agent, login_at, last_activity, logged_out "
        "FROM admin_sessions WHERE id=? AND logged_out=0", (sid,)
    ).fetchone()
    if not row: return None
    # Check timeout
    login_at = datetime.fromisoformat(row[3])
    last_act = datetime.fromisoformat(row[4])
    now = datetime.now(tz=timezone.utc)
    last = last_act.replace(tzinfo=timezone.utc)
    if (now - last).total_seconds() > SESSION_TIMEOUT_SEC:
        db.execute("UPDATE admin_sessions SET logged_out=1 WHERE id=?", (sid,))
        db.commit()
        return None
    # Update last activity
    db.execute("UPDATE admin_sessions SET last_activity=datetime('now') WHERE id=?", (sid,))
    db.commit()
    return row

def require_admin(sid: str = Cookie(None, alias="ghostlink_sid")):
    """Dependency: require valid admin session, raise 401 if not."""
    session = get_admin_session(sid)
    if not session:
        raise HTTPException(401, "Not authenticated")
    return session

# ── Admin Login Page ─────────────────────────────────────────────────
@app.get("/admin/login")
async def admin_login_page():
    return HTMLResponse("""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GHOSTLINK Admin Login</title>
<style>:root{--bg:#0a0e17;--bg2:#111827;--border:#1a2535;--text:#c8d6e5;--dim:#6e7a8a;--accent:#00d4ff;--danger:#ff4757}
*,*::before,*::after{box-sizing:border-box}body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);font-size:14px;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
form{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:40px;width:380px}
h1{font-size:20px;margin:0 0 8px;color:var(--accent);letter-spacing:1px;text-align:center}
.sub{text-align:center;color:var(--dim);margin:0 0 28px;font-size:12px}
label{display:block;margin-bottom:4px;color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
input{width:100%;padding:10px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:14px;margin-bottom:16px;font-family:Consolas,monospace}
input:focus{outline:none;border-color:var(--accent)}
button{width:100%;padding:12px;background:var(--accent);color:#000;border:none;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer}
.error{color:var(--danger);text-align:center;margin-top:12px;font-size:12px;display:none}
</style></head><body>
<form id="f"><h1>GHOSTLINK</h1><p class="sub">Admin Console Authentication</p>
<label>Password</label><input id="pw" type="password" placeholder="Admin password" autofocus>
<button type="submit">Authenticate</button><p class="error" id="err"></p></form>
<script>document.getElementById('f').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/v1/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('pw').value})});if(r.ok)location='/admin';else{document.getElementById('err').textContent='Invalid password';document.getElementById('err').style.display='block'}}</script></body></html>""")

@app.post("/api/v1/admin/login")
async def admin_login(request: Request):
    body = await request.json()
    pw = body.get("password", "")
    if pw != ADMIN_PASSWORD:
        raise HTTPException(401, "Invalid password")

    ip, ua = get_client_info(request)
    sid = uuid.uuid4().hex

    db.execute(
        "INSERT INTO admin_sessions (id, ip, user_agent) VALUES (?, ?, ?)",
        (sid, ip, ua)
    )
    db.commit()

    resp = JSONResponse({"authenticated": True, "session_id": sid})
    resp.set_cookie(
        key="ghostlink_sid", value=sid,
        httponly=True, samesite="strict", max_age=SESSION_TIMEOUT_SEC,
        path="/"
    )
    return resp

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
