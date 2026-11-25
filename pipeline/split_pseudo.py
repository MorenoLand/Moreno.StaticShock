#!/usr/bin/env python3
"""Split the IDA Hex-Rays chunks in ida/ into one readable file per function in pseudo/.

The chunks are the raw IDA export.  A per-function copy makes the pseudocode easy to read next to
the matching asm/ listing and src/ file.  The files are analysis material: they are not compiled.
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def safe(name):
    name = re.sub(r"[^A-Za-z0-9_.@$+-]+", "_", name).strip("_")
    return name or "unnamed"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ida", default=str(ROOT / "ida"))
    ap.add_argument("--out", default=str(ROOT / "pseudo"))
    args = ap.parse_args()
    ida = Path(args.ida)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    header = re.compile(
        r"^//={70}\n// (?P<name>.*)\n// entry (?P<ea>[0-9a-fA-F]+)  size (?P<size>\d+)  status (?P<status>\w+)\n//={70}\n",
        re.MULTILINE)
    rows = []
    for chunk in sorted(ida.glob("chunk_*.c")):
        text = chunk.read_text(encoding="utf-8", errors="replace")
        matches = list(header.finditer(text))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            ea = match.group("ea").lower()
            name = match.group("name")
            body = text[match.end():end].rstrip() + "\n"
            filename = "%s_%s.c" % (ea, safe(name))
            (out / filename).write_text(
                "/* %s  entry %s  size %s  status %s\n"
                " * Hex-Rays pseudocode from IDA, for reading only.  Not compiled.\n"
                " * Original bytes: %s\n */\n\n%s" % (
                    name, ea, match.group("size"), match.group("status"),
                    chunk.name, body),
                encoding="utf-8", newline="\n")
            rows.append((ea, name, match.group("size"), match.group("status"), filename, chunk.name))

    rows.sort()
    with open(out / "index.tsv", "w", encoding="utf-8", newline="\n") as f:
        f.write("address\tname\tsize\tstatus\tfile\tchunk\n")
        for row in rows:
            f.write("\t".join(row) + "\n")
    print("%d functions -> %s" % (len(rows), out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
