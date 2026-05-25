"""
Build a signed release manifest.

Run from the repo root after producing the release artifacts:
    python release/sign_manifest.py \
        --git-commit $(git rev-parse HEAD) \
        --server-image sha256:abcd... \
        --windows-exe   path/to/GHOSTLINK.exe \
        --android-apk   path/to/GHOSTLINK.apk

The output is a `RELEASES-<version>.txt` plus a `.sig` file. Anyone holding
the server identity fingerprint can verify the manifest with the matching
public key from `/api/v1/server-identity` (or a separately-published copy).
"""
import argparse, hashlib, json, sys, time, struct, os, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from crypto import hybrid_sig


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--git-commit", required=True)
    ap.add_argument("--server-image", default="")
    ap.add_argument("--windows-exe", default="")
    ap.add_argument("--android-apk", default="")
    ap.add_argument("--identity", default="server/identity.key",
                    help="Path to the server identity key file (must be writable owner-only)")
    args = ap.parse_args()

    manifest = {
        "product": "GHOSTLINK",
        "version": args.version,
        "git_commit": args.git_commit,
        "built_at_utc": int(time.time()),
        "server_image_digest": args.server_image,
    }
    if args.windows_exe:
        manifest["windows_exe_sha256"] = file_sha256(args.windows_exe)
    if args.android_apk:
        manifest["android_apk_sha256"] = file_sha256(args.android_apk)

    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()

    with open(args.identity, "rb") as f:
        data = f.read()
    (magic,) = struct.unpack_from("<I", data, 0)
    if magic != 0xC0DEFACE:
        raise SystemExit("identity file magic mismatch")
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

    sig = hybrid_sig.sign(payload, secrets)
    fp = hybrid_sig.fingerprint(pk)
    out = f"RELEASES-{args.version}.txt"
    sig_out = out + ".sig"

    with open(out, "wb") as f:
        f.write(payload)
    with open(sig_out, "wb") as f:
        f.write(sig)

    print(f"manifest -> {out} ({len(payload)} bytes)")
    print(f"sig      -> {sig_out} ({len(sig)} bytes)")
    print(f"identity fingerprint: {fp}")
    print(f"verify: python -c \"from crypto import hybrid_sig; "
          f"print(hybrid_sig.verify(open('{out}','rb').read(), open('{sig_out}','rb').read(), "
          f"<pubkey blob from /api/v1/server-identity>))\"")


if __name__ == "__main__":
    main()
