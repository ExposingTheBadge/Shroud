# GHOSTLINK Changelog

## v1.3.0 — May 24, 2026
**Windows Client (Qt6)**
- Inline image attachments with fullscreen viewer
- Delete message functionality
- Chat UI refinements

**Server**
- Fingerprint grid admin authentication (256-char grid, 3 fails = IP ban)
- Security headers middleware (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy)
- Rate limiting middleware (per-IP request throttling)
- CORS middleware
- Audit logging to audit.log
- Encrypted auth endpoint `/api/v1/auth` (ECDH + AES-256-GCM)

**Android Client**
- Complete Jetpack Compose Material3 rewrite
- Dark theme with orange accent
- Encrypted auth handshake (ECDH P-384 key exchange + AES-256-GCM)
- XOR-obfuscated server IP at rest
- Login/register toggle UI

## v1.2.0 — May 23, 2026
**Windows Client (Qt6)**
- Animated splash screen
- Orange theme (dark/light toggle via Qt Style Sheets)
- Redesigned lattice icon
- Menu bar with File/Edit/View/Help
- Settings dialog (theme, password change, nuke account)
- Stacked widget layout (auth/chat views)
- Connection status indicator (green/red)

**Cryptography**
- Quantum-resistant hybrid key exchange: P-384 ECDH + ML-KEM-1024 (Kyber)
- AES-256-GCM message encryption
- Key derivation: SHA-256(SHA-256(ECDH_raw) + "GHOSTLINK-AUTH-v1")[:32]
- Windows CNG backend via NCrypt (BCRYPT_ECDH_P384_ALGORITHM)
- AndroidKeyStore ECDH key exchange
- liboqs Python bindings for ML-KEM-1024

**Server**
- Blind relay architecture — server never sees plaintext
- Messages destroyed on delivery
- Ephemeral key exchange endpoint `/api/v1/key-exchange`
- Encrypted device registration (no plaintext passwords over wire)
- Device-based authentication (device_id instead of password)

## v1.1.0 — May 23, 2026
- Friends/group contact management
- Exact-match contact search
- Key derivation fix for auth handshake
- Group invite system

## v1.0.1 — May 23, 2026
- Menu bar added
- Settings dialog with theme toggle
- Dark/light theme support via Qt Style Sheets
- Linux client (Makefile + main.c)

## v1.0.0 — May 22, 2026
**Initial Release**
- Windows client: Qt6/C++ with CMake + MSVC
- Android client: Jetpack Compose with Material3
- Blind relay server: Python/FastAPI
- End-to-end encrypted messaging
- XOR-obfuscated server IP in client binaries
- Contact sidebar with search
- Chat area with message input
- Polling-based message fetch
