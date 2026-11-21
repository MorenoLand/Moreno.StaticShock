# inventory.py: write recomp/data/inventory.json, a machine-readable map of the project.
# It records what is known, how it is known, and what remains limited. Agents can query it instead
# of re-reading the whole tree.
import csv
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg
from pe_image import Image

OUT = os.path.join(cfg.DATA, "inventory.json")


def read_functions():
    path = os.path.join(cfg.DATA, "functions.tsv")
    if not os.path.exists(path):
        sys.exit("functions.tsv is missing; run: python pipeline/make_functions.py")
    rows = []
    for r in csv.DictReader(open(path, encoding="utf-8"), delimiter="\t"):
        rows.append({
            "address": "0x%08x" % int(r["ea"], 16),
            "name": r["name"],
            "size": int(r["size"]),
            "category": r.get("category", "app"),
        })
    return rows


def read_imports():
    path = os.path.join(cfg.ida_dump(), "imports.txt")
    if os.path.exists(path):
        out = []
        for line in open(path, encoding="utf-8"):
            p = line.rstrip("\n").split("\t")
            if len(p) >= 3:
                out.append({"module": p[0], "slot": "0x" + p[1], "name": p[2]})
        return out
    return [{"module": m, "slot": "0x%08x" % ea, "name": n} for m, ea, n in Image(cfg.game_exe()).imports()]


def read_unsupported():
    path = os.path.join(cfg.SRC, "unsupported.txt")
    out = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            p = line.split(None, 2)
            if len(p) >= 2:
                out.setdefault("0x%08x" % int(p[1], 16), []).append(p[2].strip() if len(p) > 2 else "")
    return out


def read_rtti():
    path = os.path.join(cfg.DATA, "rtti_names.tsv")
    out = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            p = line.rstrip("\n").split("\t")
            if len(p) >= 3 and p[2] == "vfunc":
                out.setdefault("0x" + p[0].lower(), []).append(p[1])
    return out


def name_confidence(name):
    return "none" if name.startswith(("sub_", "f_", "loc_", "nullsub_", "j_sub_")) else "observed"


def build():
    rows = read_functions()
    unsupported = read_unsupported()
    rtti = read_rtti()
    rtti_meta = None
    rtti_path = os.path.join(cfg.DATA, "rtti.json")
    if os.path.exists(rtti_path):
        try:
            rtti_meta = json.load(open(rtti_path, encoding="utf-8"))
        except Exception:
            rtti_meta = None
    manifest = os.path.join(cfg.DATA, "target.json")
    digest = None
    if os.path.exists(manifest):
        digest = json.load(open(manifest, encoding="utf-8")).get("target", {}).get("sha256")
    functions = []
    for r in rows:
        limitations = []
        if r["address"] in unsupported:
            limitations.append("contains unsupported instructions")
        names = sorted(set(rtti.get(r["address"], [])))
        entry = {
            "address": r["address"],
            "name": r["name"],
            "name_confidence": name_confidence(r["name"]),
            "size": r["size"],
            "category": r["category"],
            "confidence": "observed",
            "authority": "shipped-artifact",
            "evidence": ["function table"],
            "limitations": limitations,
        }
        if names:
            entry["rtti_names"] = names
            entry["evidence"].append("rtti")
        functions.append(entry)
    data = {
        "schema": 1,
        "project": cfg.NAME,
        "target_sha256": digest,
        "functions": functions,
        "imports": sorted(read_imports(), key=lambda x: (x["module"], x["name"])),
        "coverage": {
            "functions": len(functions),
            "bytes": sum(f["size"] for f in functions),
            "with_unsupported": len(unsupported),
            "imports": len(read_imports()),
            "rtti_functions": len(rtti),
            "rtti_classes": (rtti_meta or {}).get("counts", {}).get("classes"),
        },
        "limitations": [
            "Names are observations from the analysis export; address-derived names are not claims.",
            "Unsupported instructions are listed per function and must be implemented, not stubbed.",
            "RTTI vfuncN names are positional slots, not semantic method names.",
        ],
    }
    os.makedirs(cfg.DATA, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")
    print("wrote %s (%d functions, %d imports, %d with unsupported)"
          % (OUT, len(functions), data["coverage"]["imports"], len(unsupported)))


def check():
    if not os.path.exists(OUT):
        sys.exit("inventory.json is missing; run: python pipeline/inventory.py")
    data = json.load(open(OUT, encoding="utf-8"))
    known = {f["address"] for f in data["functions"]}
    unsupported = read_unsupported()
    missing = sorted(set(unsupported) - known)
    if missing:
        sys.exit("unsupported addresses not in inventory: %s" % ", ".join(missing))
    if data.get("target_sha256") and os.path.exists(os.path.join(cfg.DATA, "target.json")):
        import hashlib
        h = hashlib.sha256()
        with open(cfg.game_exe(), "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != data["target_sha256"]:
            sys.exit("inventory target digest does not match the current target")
    print("inventory ok: %d functions" % len(known))
    return 0


if __name__ == "__main__":
    if "--check" in sys.argv:
        sys.exit(check())
    build()
