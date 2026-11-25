#!/usr/bin/env python3
"""Compare the original program and the lifted host over a folder of inputs.

Every input runs in a fresh folder on both sides. Compared: exit code, stdout, stderr and every
file left behind (name, size, SHA-256).

usage: diff_corpus.py --original PATH --host PATH --corpus DIR [--pattern "*.bin"]
                      [--arg "{file}"] [--limit N] [--timeout SEC]
"""
import argparse
import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def snapshot(folder):
    return {str(p.relative_to(folder)): (p.stat().st_size, digest(p))
            for p in sorted(Path(folder).rglob("*")) if p.is_file()}


def run(exe, args, work, timeout):
    try:
        p = subprocess.run([str(exe)] + args, cwd=work, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr, snapshot(work)
    except subprocess.TimeoutExpired:
        return "timeout", b"", b"", snapshot(work)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--original", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--pattern", default="*")
    ap.add_argument("--arg", default="{file}")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=30)
    args = ap.parse_args()
    files = sorted(Path(args.corpus).glob(args.pattern))
    if args.limit:
        files = files[:args.limit]
    failures = 0
    for src in files:
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            for work in (a, b):
                shutil.copyfile(src, Path(work) / src.name)
            argv = [args.arg.replace("{file}", src.name)] if "{file}" in args.arg else args.arg.split()
            ra = run(args.original, argv, a, args.timeout)
            rb = run(args.host, argv, b, args.timeout)
        ok = ra == rb
        print("%-48s %s" % (src.name, "pass" if ok else "FAIL"))
        if not ok:
            failures += 1
            for label, x, y in (("exit", ra[0], rb[0]), ("stdout", ra[1], rb[1]),
                                ("stderr", ra[2], rb[2]), ("files", ra[3], rb[3])):
                if x != y:
                    print("  %s: original=%r host=%r" % (label, x, y))
    print("%d/%d inputs passed" % (len(files) - failures, len(files)))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
