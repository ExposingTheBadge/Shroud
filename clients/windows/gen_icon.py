"""
GHOSTLINK icon generator — lattice-based cryptography motif.

Produces ghostlink.png (256x256) and ghostlink.ico (multi-resolution).
Design: hexagonal lattice cluster with glowing central core suggesting
ML-KEM-1024 (lattice-based post-quantum) key encapsulation.
"""
from PIL import Image, ImageDraw, ImageFilter
import math, os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
MASTER = 1024  # supersample for crisp downscale

BG_TOP    = (20,  10,  4,   255)
BG_BOT    = (40,  22,  10,  255)
ORANGE    = (255, 140, 30,  255)   # #ff8c1e — brand orange, matches client UI
ORANGE_DIM= (200, 110, 25,  255)   # darker shade of same hue
AMBER     = (255, 170, 60,  255)   # lighter shade of same hue, inner glyph
WHITE     = (255, 230, 200, 255)
GLOW      = (255, 140, 30,  110)


def hex_points(cx, cy, r, rot_deg=30):
    pts = []
    for i in range(6):
        a = math.radians(60 * i + rot_deg)
        pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
    return pts


def rounded_square_mask(size, radius):
    m = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(m)
    d.rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=255)
    return m


def vertical_gradient(size, top, bot):
    img = Image.new("RGBA", (size, size), top)
    px = img.load()
    for y in range(size):
        t = y / (size - 1)
        c = (
            int(top[0] + (bot[0] - top[0]) * t),
            int(top[1] + (bot[1] - top[1]) * t),
            int(top[2] + (bot[2] - top[2]) * t),
            255,
        )
        for x in range(size):
            px[x, y] = c
    return img


def draw_icon_small(size):
    """Simplified variant for 16/24/32 px — drops the outer lattice so the
    central hex + key glyph is recognizable at favicon scale."""
    s = size
    img = vertical_gradient(s, BG_TOP, BG_BOT)
    mask = rounded_square_mask(s, int(s * 0.18))
    img.putalpha(mask)
    d = ImageDraw.Draw(img, "RGBA")

    cx, cy = s / 2, s / 2
    R = s * 0.42

    # Glow layer behind core
    glow_layer = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow_layer)
    gd.polygon(hex_points(cx, cy, R, rot_deg=30), fill=(255, 140, 30, 160))
    glow = glow_layer.filter(ImageFilter.GaussianBlur(s * 0.04))
    img.alpha_composite(glow)

    # Core hex
    core = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    cd = ImageDraw.Draw(core)
    cd.polygon(
        hex_points(cx, cy, R, rot_deg=30),
        fill=(40, 20, 8, 255),
        outline=ORANGE,
        width=max(2, int(s * 0.04)),
    )
    # Centre key glyph — mint square + tooth notch.
    inner = R * 0.5
    cd.rectangle(
        (cx - inner * 0.5, cy - inner * 0.5, cx + inner * 0.5, cy + inner * 0.5),
        fill=AMBER,
    )
    notch = inner * 0.3
    cd.rectangle(
        (cx + inner * 0.5 - notch * 0.4, cy - notch * 0.3,
         cx + inner * 0.5 + notch * 0.7, cy + notch * 0.3),
        fill=AMBER,
    )
    img.alpha_composite(core)

    # Border
    border = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    bd = ImageDraw.Draw(border)
    bd.rounded_rectangle(
        (1, 1, s - 2, s - 2),
        radius=int(s * 0.18) - 1,
        outline=(255, 140, 30, 200),
        width=max(2, int(s * 0.025)),
    )
    img.alpha_composite(border)
    return img


def draw_icon(size):
    s = size
    img = vertical_gradient(s, BG_TOP, BG_BOT)
    mask = rounded_square_mask(s, int(s * 0.18))
    img.putalpha(mask)

    d = ImageDraw.Draw(img, "RGBA")

    # Background lattice — faint hex grid behind the main cluster.
    bg_layer = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    bgd = ImageDraw.Draw(bg_layer)
    step = s * 0.075
    r_bg = step * 0.46
    rows = int(s / step) + 2
    cols = int(s / step) + 2
    for row in range(-1, rows):
        for col in range(-1, cols):
            cx = col * step * 1.5
            cy = row * step * math.sqrt(3) + (step * math.sqrt(3) / 2 if col % 2 else 0)
            pts = hex_points(cx, cy, r_bg, rot_deg=0)
            bgd.polygon(pts, outline=(255, 140, 30, 32), width=max(1, int(s * 0.0035)))
    bg_layer.putalpha(mask)
    img.alpha_composite(bg_layer)

    # Main cluster — 7-hex flower (1 center + 6 surrounding).
    cx, cy = s / 2, s / 2
    R = s * 0.18           # outer hex radius
    spacing = R * math.sqrt(3) * 1.02

    # Outer six — drawn first, dim glow
    outer_layer = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    od = ImageDraw.Draw(outer_layer)
    for i in range(6):
        a = math.radians(60 * i - 30)
        ox = cx + spacing * math.cos(a)
        oy = cy + spacing * math.sin(a)
        pts = hex_points(ox, oy, R * 0.78, rot_deg=30)
        od.polygon(pts, outline=ORANGE_DIM, width=max(2, int(s * 0.008)))
        # Small filled dot at each hex center suggesting lattice vertices.
        rd = R * 0.10
        od.ellipse((ox - rd, oy - rd, ox + rd, oy + rd), fill=ORANGE)
    glow = outer_layer.filter(ImageFilter.GaussianBlur(s * 0.012))
    img.alpha_composite(glow)
    img.alpha_composite(outer_layer)

    # Connection lines from outer dots to center — lattice edges.
    line_layer = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    ld = ImageDraw.Draw(line_layer)
    for i in range(6):
        a = math.radians(60 * i - 30)
        ox = cx + spacing * math.cos(a)
        oy = cy + spacing * math.sin(a)
        ld.line((cx, cy, ox, oy), fill=(255, 160, 50, 90), width=max(1, int(s * 0.005)))
    img.alpha_composite(line_layer)

    # Central hex — bright core
    core_layer = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    cd = ImageDraw.Draw(core_layer)
    core_pts = hex_points(cx, cy, R, rot_deg=30)
    cd.polygon(core_pts, fill=(40, 20, 8, 255), outline=ORANGE, width=max(3, int(s * 0.012)))
    # Inner stylized "key bit" — a small cyan square inside, slightly offset.
    inner = R * 0.42
    cd.rectangle(
        (cx - inner * 0.5, cy - inner * 0.5, cx + inner * 0.5, cy + inner * 0.5),
        fill=AMBER,
    )
    # Dim notch on the right of the inner square — gives it a "key tooth" feel.
    notch = inner * 0.3
    cd.rectangle(
        (cx + inner * 0.5 - notch * 0.4, cy - notch * 0.25,
         cx + inner * 0.5 + notch * 0.6, cy + notch * 0.25),
        fill=AMBER,
    )
    core_glow = core_layer.filter(ImageFilter.GaussianBlur(s * 0.014))
    img.alpha_composite(core_glow)
    img.alpha_composite(core_layer)

    # Outer border highlight for crisp edge
    border = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    bd = ImageDraw.Draw(border)
    bd.rounded_rectangle(
        (1, 1, s - 2, s - 2),
        radius=int(s * 0.18) - 1,
        outline=(255, 140, 30, 180),
        width=max(2, int(s * 0.006)),
    )
    img.alpha_composite(border)
    return img


def main():
    large = draw_icon(MASTER)
    small = draw_icon_small(MASTER)

    png_path = os.path.join(OUT_DIR, "ghostlink.png")
    large.resize((256, 256), Image.LANCZOS).save(png_path, "PNG")
    print(f"wrote {png_path}")

    # Small sizes use the simplified variant; large sizes use the full lattice.
    small_sizes = [16, 24, 32]
    large_sizes = [48, 64, 128, 256]
    ico_imgs = (
        [small.resize((n, n), Image.LANCZOS) for n in small_sizes]
        + [large.resize((n, n), Image.LANCZOS) for n in large_sizes]
    )
    all_sizes = small_sizes + large_sizes
    ico_path = os.path.join(OUT_DIR, "ghostlink.ico")
    # Build a proper multi-entry ICO manually. PIL 12's save() collapses to
    # a single entry whether or not append_images is set, so we hand-write
    # the ICONDIR/ICONDIRENTRY headers and embed each image as PNG.
    import io, struct
    entries = []
    blobs = []
    for im in ico_imgs:
        w, h = im.size
        buf = io.BytesIO()
        im.save(buf, format="PNG")
        blobs.append(buf.getvalue())
        entries.append((w if w < 256 else 0, h if h < 256 else 0, len(blobs[-1])))
    header = struct.pack("<HHH", 0, 1, len(entries))
    offset = 6 + 16 * len(entries)
    dir_entries = b""
    for (w, h, sz) in entries:
        # bWidth, bHeight, bColorCount, bReserved, wPlanes, wBitCount, dwBytesInRes, dwImageOffset
        dir_entries += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, sz, offset)
        offset += sz
    with open(ico_path, "wb") as f:
        f.write(header)
        f.write(dir_entries)
        for b in blobs:
            f.write(b)
    print(f"wrote {ico_path} ({', '.join(f'{n}x{n}' for n in all_sizes)})")


if __name__ == "__main__":
    main()
