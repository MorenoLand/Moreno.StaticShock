# extract_res.py: write the original PE's .rsrc section as a Win32 .res file so the host linker can embed forms,
# icons, bitmaps, cursors, menus and string tables. The host links at the original image base, so the guest
# HInstance is the host module handle and FindResource/LoadResource/LoadString find these resources unchanged.
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg
from pe_image import Image

im = Image(cfg.game_exe())
rva, size = struct.unpack_from("<II", im.d, im.opt + 96 + 2 * 8)
if not rva or not size:
    sys.exit("the image has no resource directory")
base = im.off(im.base + rva)
if base is None:
    sys.exit("resource directory is outside the mapped sections")


def u16(o): return struct.unpack_from("<H", im.d, o)[0]
def u32(o): return struct.unpack_from("<I", im.d, o)[0]


def entries(dir_off):
    n_named, n_id = u16(dir_off + 12), u16(dir_off + 14)
    for i in range(n_named + n_id):
        name, off = struct.unpack_from("<II", im.d, dir_off + 16 + 8 * i)
        if name & 0x80000000:
            so = base + (name & 0x7FFFFFFF)
            n = u16(so)
            key = im.d[so + 2:so + 2 + 2 * n].decode("utf-16-le")
        else:
            key = name
        yield key, (base + (off & 0x7FFFFFFF)), bool(off & 0x80000000)


def ident(v):
    if isinstance(v, int):
        return struct.pack("<HH", 0xFFFF, v)
    return v.encode("utf-16-le") + b"\0\0"


out = bytearray(b"\0\0\0\0\x20\0\0\0\xff\xff\0\0\xff\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")
count = 0
for typ, t_off, t_dir in entries(base):
    for name, n_off, n_dir in entries(t_off):
        for lang, l_off, l_dir in entries(n_off):
            rva_d, sz, cp, _ = struct.unpack_from("<IIII", im.d, l_off)
            data = im.read(im.base + rva_d, sz)
            hdr = ident(typ) + ident(name)
            while len(hdr) % 4: hdr += b"\0"
            hsize = 8 + len(hdr) + 16
            out += struct.pack("<II", sz, hsize) + hdr + struct.pack("<IHHII", 0, 0x30 if isinstance(typ, int) and typ in (3, 14, 12, 1, 2) else 0x1030, lang, 0, 0)
            out += data
            while len(out) % 4: out += b"\0"
            count += 1
os.makedirs(cfg.DATA, exist_ok=True)
path = os.path.join(cfg.DATA, os.path.splitext(os.path.basename(cfg.game_exe()))[0] + ".res")
open(path, "wb").write(out)
print("%d resources, %d bytes -> %s" % (count, len(out), path))
