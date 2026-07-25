# Windows client test harnesses

Small MSVC programs that exercise the client's real C code rather than a
reimplementation of it. Built ad hoc; see the header comment in each.

| File | What it proves |
|---|---|
| `anon_vectors.c` | `anon_routing.c` derives the same routing tags as `crypto/anon_routing.py`. Run by `tests/cross_client_vectors.py`. |
| `auth_live.c` | The login encryption path (`crypto_auth_derive_key` + `crypto_aes_gcm_encrypt` + `network_post`) is accepted by a live relay. Distinguishes a crypto fault from a genuine credential mismatch. |
| `ecdh_diag.c`, `ecdh_diag2.c` | Per-call CNG status for ECDH secret agreement, including the TPM-backed path. |

Build (adjust the local-dev include if you are not pointing at 127.0.0.1):

```bat
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cl /nologo /I. /Fe:tests\auth_live.exe /Fo:tests\ tests\auth_live.c ^
   crypto.c network.c storage.c tpm.c kyber1024.c ratchet.c ed25519.c ^
   oqs_sig.c anon_routing.c ^
   bcrypt.lib ncrypt.lib crypt32.lib tbs.lib winhttp.lib ws2_32.lib ^
   user32.lib shell32.lib advapi32.lib
tests\auth_live.exe <username> <password>
```

**`crypto_init()` first.** It opens the global BCrypt AES-GCM and SHA-256
algorithm handles. `main.cpp` calls it at startup; a harness that skips it
gets `FALSE` out of `crypto_auth_derive_key` for reasons that have nothing
to do with the keys, which is a convincing false positive.
