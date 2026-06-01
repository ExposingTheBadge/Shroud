"""
SHROUD sticker pack authoring tool.

Pack a directory of image files into a content-addressed SHROUD
sticker pack: a JSON manifest listing each sticker by SHA-256 hash
of its metadata-stripped bytes, plus the cleaned files ready to be
served at /stickers/<hash>.

Usage::

    python -m tools.sticker_authoring build \\
        --in ./my_pack_source/ \\
        --out ./build/my-pack/ \\
        --pack-id "shroud-default-pack-v1" \\
        --pack-name "Shroud Default"

    # Then upload ./build/my-pack/cdn/* to your CDN bucket and
    # ./build/my-pack/manifest.json to https://stickers.example/
    # manifests/shroud-default-pack-v1.json (or wherever clients
    # are configured to fetch from).

Each input file's label is its filename minus extension and
lowercase. e.g. "Thumbs Up.png" becomes label "thumbs up".
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from crypto.stickers import build_pack
from crypto.strip_metadata import UnsupportedMimeError


def cmd_build(args) -> int:
    if not os.path.isdir(args.input):
        print(f"input dir does not exist: {args.input}", file=sys.stderr)
        return 1

    inputs = []
    skipped = []
    for fn in sorted(os.listdir(args.input)):
        path = os.path.join(args.input, fn)
        if not os.path.isfile(path):
            continue
        mime, _ = mimetypes.guess_type(path)
        if mime is None:
            skipped.append((fn, "unknown MIME"))
            continue
        if not mime.startswith("image/"):
            skipped.append((fn, f"not an image ({mime})"))
            continue
        label = os.path.splitext(fn)[0].lower().replace(" ", "_")
        with open(path, "rb") as f:
            inputs.append((label, mime, f.read()))

    if not inputs:
        print("no input images found", file=sys.stderr)
        return 1

    try:
        pack, cdn_assets = build_pack(args.pack_id, args.pack_name, inputs)
    except UnsupportedMimeError as e:
        print(f"build failed: {e}", file=sys.stderr)
        return 1

    out_dir = os.path.abspath(args.output)
    cdn_dir = os.path.join(out_dir, "cdn")
    os.makedirs(cdn_dir, exist_ok=True)

    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        f.write(pack.to_json())

    for hash_hex, blob in cdn_assets.items():
        cdn_path = os.path.join(cdn_dir, hash_hex)
        with open(cdn_path, "wb") as f:
            f.write(blob)

    print(f"pack id:     {pack.id}")
    print(f"stickers:    {len(pack.stickers)}")
    if skipped:
        print(f"skipped:     {len(skipped)}")
        for fn, reason in skipped:
            print(f"  - {fn}: {reason}")
    print()
    print(f"manifest:    {manifest_path}")
    print(f"cdn assets:  {cdn_dir}")
    print()
    print("Next steps:")
    print(f"  1. Upload all of {cdn_dir}/* to your CDN bucket as /stickers/<hash>")
    print(f"  2. Publish {manifest_path} at the manifest URL clients fetch from")
    print(f"  3. Add the manifest URL to the operator manifest (crypto/operator_manifest.py)")
    return 0


def cmd_inspect(args) -> int:
    if not os.path.isfile(args.manifest):
        print(f"manifest does not exist: {args.manifest}", file=sys.stderr)
        return 1
    with open(args.manifest, "r") as f:
        manifest = json.load(f)
    print(f"pack id:    {manifest.get('id')}")
    print(f"pack name:  {manifest.get('name')}")
    print(f"stickers:   {len(manifest.get('stickers', []))}")
    print()
    for s in manifest.get("stickers", []):
        print(f"  {s['hash'][:16]}…  {s['label']:<24} ({s['mime']})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="SHROUD sticker pack authoring")
    sub = ap.add_subparsers(dest="command", required=True)

    bp = sub.add_parser("build", help="pack a directory of images into a sticker pack")
    bp.add_argument("--input", "-i", required=True, help="dir of source images")
    bp.add_argument("--output", "-o", required=True, help="dir to write manifest.json + cdn/")
    bp.add_argument("--pack-id", required=True, help="opaque pack id; clients address by this")
    bp.add_argument("--pack-name", required=True, help="human-readable name for the UI")
    bp.set_defaults(fn=cmd_build)

    ip = sub.add_parser("inspect", help="dump a manifest's contents")
    ip.add_argument("--manifest", "-m", required=True)
    ip.set_defaults(fn=cmd_inspect)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
