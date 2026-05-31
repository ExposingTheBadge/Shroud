# GHOSTLINK

> Post-quantum, end-to-end encrypted, blind-relay messaging — for Windows, Android, and iOS.

## What is GHOSTLINK?

GHOSTLINK is a secure messenger built for people who don't want to trust the server. You install the app, register an account, and the app generates cryptographic keys that **never leave your device**. Messages you send are encrypted on *your* device, travel through the GHOSTLINK relay as opaque ciphertext, and are decrypted only on the recipient's device. The server can't read them, your ISP can't read them, and a future quantum computer that intercepts them today can't read them either.

Unlike most messengers, GHOSTLINK is built with three uncommon design choices:

1. **The server is intentionally dumb.** It stores nothing about you. No phone number, no email, no contact list, no message history. It forwards encrypted bytes and deletes them on delivery.
2. **Every cryptographic primitive runs in hybrid classical + post-quantum mode.** If either family of math is broken — today's classical curves or tomorrow's quantum-resistant lattices — your messages remain protected.
3. **Releases are verified by multiple independent signers**, so even if a maintainer's key is stolen, a single attacker cannot push a malicious build to users.

It's free. It's open source. You can run your own relay server if you don't want to use the public one.

---

## Government Requests / Warrant Policy

> [!IMPORTANT]
> **No government warrant, subpoena, court order, or lawful demand of any kind will ever be honored.**
>
> This is not bluster — it is architecture. **God himself could not extract user data from the server or its owner.** The data does not exist there in a form anyone can read, including us.

### What the server cannot surrender

The blind-relay design makes most categories of "data request" technically meaningless:

- **Your messages, past or present** — encrypted with keys that never leave your device. The server holds opaque ciphertext briefly, then destroys it on delivery. There is no master key. There is no escrow. There is no backdoor.
- **Your social graph** — the server doesn't maintain one. Contact lists are stored client-side only.
- **Your contact list** — see above. Even we don't know who your friends are.
- **Your real identity** — no phone number, no email, no name, no PII of any kind is collected at registration. Usernames are pseudonyms by default.
- **Your account contents** — your password is the root of your local vault key. We do not have it, cannot derive it, and cannot reset it.
- **Group membership** — TreeKEM state is collectively owned by group members; the server stores only encrypted ciphertext routing information.
- **Message history** — destroyed on delivery. Retention is measured in milliseconds, not days.

### What we will say to law enforcement

Any lawful demand received will be answered with:

1. A polite acknowledgment of receipt.
2. This README, with this section highlighted.
3. A copy of [`BUILD-REPRODUCIBILITY.md`](BUILD-REPRODUCIBILITY.md) and [`docs/multisig-releases.md`](docs/multisig-releases.md) so the requestor can verify, against open source, that we are not lying about the architecture.
4. Nothing else. We have nothing else to give.

### Backdoor demands

Any demand attempting to compel the introduction of a backdoor, the weakening of a cryptographic primitive, the addition of telemetry, the leaking of metadata to a third party, or any other architectural change that would let the server become a trust anchor will be **refused outright.**

If a court attempts to compel backdoor introduction over our refusal, **the project will be shut down** — every server instance, every signing key, the entire GitHub repository, the entire release pipeline — rather than complied with. A final commit and release notice to that effect will appear in this section before takedown. The absence of that notice is your warrant canary: as long as this section reads as it does today, no backdoor has been introduced.

### Scope

This policy binds **the maintainers, all release signers, and any operator of the public GHOSTLINK relay**. Self-hosted operators (people running their own server on their own hardware) make their own policy for their own users — that's the entire point of a self-hostable, open-source design.

### Why

Because the only way to make a promise of confidentiality you can keep is to architect a system where breaking the promise is *impossible*, not merely *forbidden*. Policies can be changed. Architectures, once shipped and reproduced by users, cannot.

---

## Features

### Messaging
- 1-on-1 chats with **forward secrecy** and **post-compromise security** (Signal-style Double Ratchet)
- **Group chats** with cryptographic membership control (TreeKEM, MLS-style)
- **Inline image attachments** with fullscreen viewer
- **Disappearing messages** (per-chat setting)
- **Delete-for-everyone** (removes the ciphertext from the relay queue before delivery; once delivered, deletion is best-effort)
- **Read receipts** can be toggled off per-chat
- **Rich text + emoji** (Win + `.` opens the system emoji picker on Windows)

### Identity & contacts
- **Friends-only contact list** — no public directory, no "people you may know"
- **Exact-username search** — you can only find someone if you already know their handle
- **Group invites** by username (recipient confirms before joining)
- **Multi-device linking** — link a second device (phone ↔ desktop) without exposing your master key to the server; uses a one-time QR/code handshake
- **Anonymous credentials** for join-tokens — you can prove you're invited to a group without revealing *which* invite is yours

### Privacy & safety
- **Panic button** — wipes local state, drops all sessions, marks the device as compromised on the server so other devices stop trusting it
- **At-rest encryption** of the local message store (AES-256-GCM, key sealed in TPM on Windows / AndroidKeyStore on Android)
- **Tor / hidden-service routing** for users who don't trust their network operator
- **Cover-traffic loop** — the desktop client periodically sends meaningless traffic so that real messaging is harder to time-correlate against your network presence
- **Server-side rate limiting + IP-ban for failed auth** — protects against scraping and brute-force enumeration

### Interface
- Native Qt6 desktop UI (Windows) with dark/light themes, accent color (orange) toggle, animated splash, system tray
- Native Jetpack Compose UI (Android) with Material 3 dark theme
- Theme, password, multi-device, and disappearing-messages controls in a unified Settings dialog

---

## Install

### Windows

1. Open [Releases](https://github.com/ExposingTheBadge/GhostLink/releases) and download the latest `GHOSTLINK-v<version>-win64.zip` and `SHA256SUMS.txt`.
2. (Optional but recommended) verify the download — see [Verifying a Release](#verifying-a-release).
3. Extract the zip anywhere — Program Files, your desktop, a USB stick, it doesn't matter.
4. Run `ghostlink.exe`.
   - Windows shows **"Verified publisher: Brent Gordon"** — that's the Authenticode signature from Azure Artifact Signing.
   - If you see "Windows protected your PC" the first time, click *More info → Run anyway* (this happens with all new signed apps until they accumulate SmartScreen reputation).

### Android

1. Download `GHOSTLINK-v<version>.apk` from Releases.
2. (Optional) verify the APK SHA-256 against `SHA256SUMS.txt`.
3. Sideload via your file manager. You'll need *Install unknown apps* enabled for whichever launcher you use.
4. Open the app and register.

> GHOSTLINK is **not on Google Play** and won't be. Play Store distribution requires Google to act as an intermediary trust point, which conflicts with the project's "no operator trust" principle.

### iOS

iOS is currently experimental — build from `clients/ios/` in Xcode 15+ and sideload to your device.

---

## How to Use

### First launch — register an account

1. Open the app. You'll see the auth screen.
2. Click *Don't have an account? Register*.
3. Enter:
   - **Username** — your public handle. Other users find you by this. **Case-insensitive** since v2.4.5. Pick carefully; usernames are not currently reusable after deletion.
   - **Password** — used to derive your local key-vault key. Pick a strong one; if you forget it, your account and all messages are gone forever — there is no recovery, by design.
4. Click **Register**.
5. The app generates your hybrid keypair (P-384 ECDH + ML-KEM-1024 Kyber + Ed25519 + ML-DSA-87), seals the private parts into TPM (Windows) / AndroidKeyStore (Android), and publishes only the public components to the relay.

### Sign in on a returning device

Just enter your username and password and click **Login**. The app re-derives your vault key, unseals your private keys from the TPM, and reconnects to the relay.

If you've enabled **multi-device** and you're on a fresh device, see *Link a second device* below instead — you'll need an active session on your existing device to authorize the new one.

### Add a contact

1. In the sidebar, click **+ Add contact** (or the search bar at the top).
2. Type the **exact** username. There is no autocomplete and no fuzzy match — this is deliberate, to prevent the server from being usable as a phone-book.
3. Click **Search**. If the user exists, they appear with an *Add friend* button. Click it.
4. The other user must accept the request from their *Friend requests* tray. Until they accept, you cannot message them.

### Send a message

1. Click a contact in the sidebar.
2. Type into the message box at the bottom.
3. Press **Enter** to send, or **Shift+Enter** for a newline. On Windows, **Win + `.`** opens the emoji picker.
4. To send an image, click the paperclip icon. Images are encrypted before upload; the relay only sees ciphertext.
5. To delete a message you just sent, right-click → *Delete*. If the recipient hasn't fetched it yet, it's gone for both of you. If they already have it, deletion is best-effort.

### Group chats

1. Click **+ New group** in the sidebar.
2. Name the group, pick an icon color.
3. Invite members by username (same exact-match search as contacts).
4. Each invitee gets an invite notification. Once they accept, they're added via TreeKEM — every existing member's keys rotate so the new member can't read history, and removed members can't read future messages.
5. Group settings (rename, kick, leave, mute) live behind the gear icon at the top of the chat.

### Link a second device

1. On the device you're already signed in to, open **Settings → Devices → Link new device**.
2. A 6-digit code + QR code appears. It's good for 5 minutes.
3. On the new device, install GHOSTLINK and choose **Sign in → Link from existing device**.
4. Scan the QR or type the code.
5. The two devices perform an encrypted handshake **directly through the relay** — the server sees the handshake go by but can't decrypt it. After verification, your encrypted vault is replicated to the new device.

The relay never sees your password or vault key.

### Enable disappearing messages

Per-chat:
1. Open the chat.
2. Click the timer icon at the top.
3. Pick a TTL — 10 seconds, 1 hour, 1 day, 1 week.
4. New messages from then on will be deleted from both sides after the timer expires. Existing messages are unaffected.

### Use the panic button

If you think your device is compromised — stolen, seized, hostile network:

1. Open **Settings → Privacy → Panic**.
2. Confirm.
3. The app immediately:
   - Wipes the local message database
   - Drops all active sessions
   - Sends a one-shot signed *device-compromised* notice to the server (which marks the device as untrusted; your *other* devices will stop trusting messages claiming to come from it)
   - Deletes its own at-rest encryption keys

Once panic fires, the only recovery on that specific device is uninstall + reinstall + re-register or re-link.

### Change your password

**Settings → Account → Change password.** You'll be asked for the current password (used to unseal your vault) and a new one. The vault is re-encrypted under the new key. Server stores nothing about either.

### Delete your account

**Settings → Account → Nuke account.** This:
1. Sends a tombstone to the server, which deletes your username, public keys, and any queued ciphertext.
2. Wipes all local state.
3. Marks the username as deleted (not currently reusable).

This is irreversible. There is no "Are you sure I'm sure?" confirm-by-typing flow — the dialog asks once. Don't click it accidentally.

### Use over Tor

If you have Tor running locally (default SOCKS5 on `127.0.0.1:9050`):

1. **Settings → Network → Route through Tor**, enable it.
2. The client will start using SOCKS5. If you also configure the GHOSTLINK relay as a hidden service in your `torrc` (see [`docs/tor.md`](docs/tor.md) and [`docs/torrc.example`](docs/torrc.example)), traffic stays inside Tor end-to-end.

---

## Security

This section documents **every cryptographic primitive in GHOSTLINK** and why it's there. If you don't care about the details, skip to the next section.

### Threat model — what GHOSTLINK protects against

| Threat                                                         | Protected? |
|---------------------------------------------------------------|------------|
| Network observer (ISP, Wi-Fi MITM) reads plaintext            | ✅ (E2EE) |
| Server operator reads plaintext                               | ✅ (blind relay) |
| Server operator stores message metadata for future analysis   | ✅ (destroyed on delivery, no contact graph) |
| Future quantum computer decrypts harvested ciphertext         | ✅ (ML-KEM-1024 hybrid) |
| Server enumerates the userbase via the contact-search API     | ✅ (exact-match only, rate-limited, IP-banned on abuse) |
| Single signing key compromise → forged malicious release      | ✅ (M-of-N threshold multisig) |
| Tampered build server / supply-chain attack on Windows binary | ✅ (Authenticode + reproducible builds + multisig) |
| Network observer correlates *who is messaging whom*           | ✅ (with Tor enabled) |
| Endpoint compromise (malware on user's device)                | ❌ — out of scope |

### Cryptographic primitives

Every direction in the protocol is **hybrid** — a classical curve runs in parallel with a NIST-standardized post-quantum algorithm, and a value is considered authentic only if *both* halves verify.

| Purpose                          | Classical                | Post-Quantum            | Notes                                                  |
|----------------------------------|--------------------------|-------------------------|--------------------------------------------------------|
| Initial handshake (X3DH)         | X25519                   | ML-KEM-1024 (Kyber)     | Hybrid X3DH; root key fed into Double Ratchet          |
| Per-message keys (ratchet)       | X25519 chain             | —                       | Signal Double Ratchet, fwd secrecy + post-compromise   |
| Message confidentiality          | AES-256-GCM              | —                       | Per-message subkey from ratchet                        |
| Identity & message signing       | Ed25519                  | ML-DSA-87 + SPHINCS+-256s | Triple hybrid; release manifests use the same        |
| Group key agreement              | TreeKEM (MLS-style)      | —                       | Per-epoch rotation; removed members can't read forward |
| Transport auth handshake         | ECDH P-384 (NCrypt)      | ML-KEM-1024             | Used by `/api/v1/auth-v2`; AES-256-GCM tunnel          |
| Password authentication          | SRP-6a                   | —                       | Server never sees the password or a hash of it         |
| At-rest vault encryption         | AES-256-GCM              | —                       | Key derived from password + TPM-sealed entropy         |
| Anonymous credentials            | BLS12-381                | —                       | Blind-signature join tokens — prove invite-validity without revealing identity |
| Release manifest signing         | Ed25519                  | ML-DSA-87 + SPHINCS+-256s | Plus M-of-N threshold over the manifest                |

### Forward secrecy and post-compromise security

Every message uses a one-shot key derived from a chain (the Double Ratchet). If today's device is compromised and the attacker reads your current state, **they cannot decrypt past messages** (forward secrecy) and **they cannot decrypt new messages** as soon as you exchange one more message with the peer (post-compromise security — the ratchet heals).

### Key storage

- **Windows:** identity private keys are generated inside TPM 2.0 via the NCrypt API. They are non-extractable from the host. Even malware running as Administrator cannot copy them off the machine.
- **Android:** identity private keys live in AndroidKeyStore, hardware-backed where available (StrongBox or TEE).
- **iOS:** Secure Enclave (planned).

### What the server can and cannot see

**Can see:** that device_id X uploaded a ciphertext blob addressed to device_id Y, the timestamp of upload/delivery, and the blob size. That's it.

**Cannot see:** plaintext, your social graph (the server never returns "who are your contacts" because it doesn't know), your message history (deleted on delivery), or anything connecting device_id to a human identity.

**Cannot impersonate:** a user (identity keys are TOFU-pinned on first message), or a release (manifests require M valid signatures from a published roster).

### Release signing

Every release ships with:

1. **Authenticode signature** on `ghostlink.exe` from Microsoft Azure Artifact Signing (publisher: Brent Gordon). Verified by Windows on every launch.
2. **SHA-256 checksums** of every distribution artifact in `SHA256SUMS.txt`.
3. **Hybrid identity signature** (`sign_manifest.py`) — single key, proves "this came from the GHOSTLINK identity".
4. **Threshold multi-signature** (`multisig.py`) — M-of-N independent signers attest the manifest. Compromise of fewer than M signing keys cannot forge a release. Full protocol in [`docs/multisig-releases.md`](docs/multisig-releases.md).

### Reproducibility

The server image and Android APK are fully reproducible — anyone can rebuild from source and get bit-identical artifacts. Windows EXE reproducibility is partial today (timestamp suppression with `/Brepro` is in place; Qt deployment is still host-dependent). The full story is in [`BUILD-REPRODUCIBILITY.md`](BUILD-REPRODUCIBILITY.md).

---

## Verifying a Release

### Hash check

```powershell
# Windows
Get-FileHash GHOSTLINK-v2.4.6-win64.zip -Algorithm SHA256
# Compare to SHA256SUMS.txt
```

```bash
# Linux / macOS
sha256sum --check SHA256SUMS.txt
```

### Authenticode (Windows only)

```powershell
Get-AuthenticodeSignature .\ghostlink.exe | Format-List Status, SignerCertificate
# Status should be Valid; signer should be Brent Gordon
```

Or right-click `ghostlink.exe` → **Properties → Digital Signatures**.

### Multi-party threshold signature

```bash
python release/multisig_verify.py \
    --bundle RELEASES-2.4.6.multisig.json \
    --windows-zip GHOSTLINK-v2.4.6-win64.zip
```

Exits 0 only when ≥ M valid sigs over the same canonicalized manifest are present and the local file's hash matches.

### End-to-end reproducibility verifier

```bash
./scripts/repro-check.sh --version 2.4.6
```

Rebuilds the server image + APK, strips the APK signing block, compares all hashes against the published manifest, and verifies the multisig bundle. Exit 0 iff everything matches.

---

## Self-hosting the Server

You don't have to use the default GHOSTLINK relay. If you'd rather run your own:

1. Get a small VPS (1 CPU, 1 GB RAM is fine; the server is I/O-bound).
2. Get a TLS cert for your domain (Let's Encrypt is fine).
3. Build the server image reproducibly:
   ```bash
   docker buildx build --no-cache --pull \
       --output type=docker -f Dockerfile.repro \
       -t ghostlink-server:repro .
   ```
4. Run it, exposing port `58443`:
   ```bash
   docker run -d --name ghostlink \
       -p 58443:58443 \
       -v ghostlink-data:/var/lib/ghostlink \
       ghostlink-server:repro
   ```
5. Point your clients at `https://your-domain:58443/`.

The server stores nothing about users beyond ephemeral message queues, public keys, and an audit log of *delivery events* (timestamps + device IDs, no content).

For HTTPS, expert tip: terminate TLS at the application (uvicorn supports this directly) rather than at a reverse proxy — every additional layer is another place that needs to be reproducible.

---

## Building from Source

If you'd rather build the binaries yourself than trust ours:

```bash
# Windows client (Qt6 + CMake + MSVC)
cd clients/windows && cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build

# Android client (reproducible)
cd clients/android && ./gradlew --no-daemon assembleRelease -PsourceDateEpoch=1700000000

# Server (reproducible Docker)
docker buildx build --no-cache --pull --output type=docker -f Dockerfile.repro -t ghostlink-server:repro .
```

Full per-platform requirements, deployment steps, and reproducibility notes are in [`BUILD-REPRODUCIBILITY.md`](BUILD-REPRODUCIBILITY.md). The Windows CI build is defined in [`.github/workflows/release-windows.yml`](.github/workflows/release-windows.yml) and is the canonical source of truth.

---

## License

GHOSTLINK is licensed under the **GNU General Public License v3.0 or later (GPL-3.0-or-later)**. See [`LICENSE`](LICENSE) for the full text.

Short version: you can use it, study it, modify it, redistribute it, and run your own server, freely. If you distribute a modified version, you must release your changes under the same license. This is intentional — it keeps the cryptographic and trust properties verifiable in any downstream fork.

---

## Acknowledgments

GHOSTLINK builds on a lot of others' work:

- **[Open Quantum Safe (liboqs)](https://openquantumsafe.org/)** — reference implementations of ML-KEM, ML-DSA, and SPHINCS+.
- **NIST PQC standardization** — ML-KEM (Kyber), ML-DSA (Dilithium), and SLH-DSA (SPHINCS+).
- **[Signal Foundation](https://signal.org/docs/)** — the X3DH + Double Ratchet design.
- **MLS Working Group** — TreeKEM and group key agreement.
- **[Tor Project](https://www.torproject.org/)** — hidden services and SOCKS5 transport.
- **Qt for Open Source** — the desktop UI framework.
- **FastAPI / Starlette / Pydantic** — the server framework.

---

## Project links

- **Releases:** https://github.com/ExposingTheBadge/GhostLink/releases
- **Issues / bugs:** https://github.com/ExposingTheBadge/GhostLink/issues
- **Security disclosure:** `security@fuseobd.com` (do not file public issues for security bugs)
- **Active development branch:** `master`
