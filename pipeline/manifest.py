# manifest.py: write or verify recomp/data/target.json.
# The manifest is the immutable identity of the target: digest, PE layout, imports and tool versions.
import hashlib
import json
import os
import platform
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg
from pe_image import Image

OUT = os.path.join(cfg.DATA, "target.json")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build():
    exe = Path(cfg.game_exe())
    if not exe.exists():
        sys.exit("target not found: %s" % exe.name)
    im = Image(exe)
    imports = [{"module": m, "slot": "0x%08x" % ea, "name": n} for m, ea, n in im.imports()]
    data = {
        "schema": 1,
        "project": cfg.NAME,
        "arch": cfg.ARCH,
        "target": {
            "file": exe.name,
            "size": exe.stat().st_size,
            "sha256": sha256(exe),
            "pe_arch": im.arch,
            "image_base": "0x%x" % im.base,
            "entry": "0x%x" % im.entry,
            "image_size": "0x%x" % im.image_size,
            "sections": [
                {"name": name, "va": "0x%x" % va, "vsize": "0x%x" % vsize,
                 "raw_size": "0x%x" % raw_size, "raw_offset": "0x%x" % raw_off}
                for name, vsize, va, raw_size, raw_off in im.secs
            ],
            "imports": sorted(imports, key=lambda x: (x["module"], x["name"])),
        },
        "config": {
            "image_base": "0x%x" % cfg.IMAGE_BASE,
            "entry": "0x%x" % cfg.OEP,
            "code_lo": "0x%x" % cfg.CODE_LO,
            "code_hi": "0x%x" % cfg.CODE_HI,
            "image_end": "0x%x" % cfg.IMAGE_END,
            "guest_size": "0x%x" % cfg.GUEST_SIZE,
            "tail_size": "0x%x" % cfg.TAIL_SIZE,
        },
        "tools": {
            "python": platform.python_version(),
            "capstone": _capstone_version(),
            "platform": platform.system(),
        },
        "analysis": {
            "functions": _count(os.path.join(cfg.DATA, "functions.tsv")),
            "unsupported": _count(os.path.join(cfg.SRC, "unsupported.txt")),
        },
    }
    os.makedirs(cfg.DATA, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")
    print("wrote %s (%s)" % (OUT, data["target"]["sha256"][:16]))
    return data


def _capstone_version():
    try:
        import capstone
        return capstone.__version__
    except Exception:
        return None


def _count(path):
    try:
        with open(path, encoding="utf-8") as f:
            return sum(1 for line in f
                       if line.strip() and not line.startswith("#") and not line.startswith("ea\t")
                       and not line.startswith("address\t"))
    except OSError:
        return None


def verify():
    if not os.path.exists(OUT):
        sys.exit("target.json is missing; run: python pipeline/manifest.py")
    data = json.load(open(OUT, encoding="utf-8"))
    exe = Path(cfg.game_exe())
    if not exe.exists():
        sys.exit("target not found: %s" % exe.name)
    digest = sha256(exe)
    want = data.get("target", {}).get("sha256")
    if digest != want:
        sys.exit("target digest mismatch: manifest %s, file %s" % (want, digest))
    if exe.stat().st_size != data["target"].get("size"):
        sys.exit("target size mismatch")
    print("target ok: %s" % digest[:16])
    return 0


if __name__ == "__main__":
    if "--verify" in sys.argv:
        sys.exit(verify())
    build()
