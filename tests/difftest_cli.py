#!/usr/bin/env python3
"""Compare the original program and the lifted host on fixed CLI cases.

Each case runs in its own empty folder; the fixture files it names are copied in. Compared:
exit code, stdout, stderr and every file left behind (name, size, SHA-256).

usage: difftest_cli.py --original PATH --host PATH --fixtures DIR [--cases cases.json]

cases.json is a list of {"name": str, "args": [str], "copy": [str]}; without it the template
only checks the no-argument case.
"""
import argparse
import hashlib
import json
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


def run(exe, args, work, copies, fixtures, timeout):
    for name in copies:
        shutil.copyfile(Path(fixtures) / name, Path(work) / name)
    try:
        p = subprocess.run([str(exe)] + args, cwd=work, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr, snapshot(work)
    except subprocess.TimeoutExpired:
        return "timeout", b"", b"", snapshot(work)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--original", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--fixtures", default="")
    ap.add_argument("--cases", default="")
    ap.add_argument("--timeout", type=float, default=30)
    args = ap.parse_args()
    cases = [{"name": "no arguments", "args": [], "copy": []}]
    if args.cases:
        cases = json.loads(Path(args.cases).read_text(encoding="utf-8"))
    failures = 0
    for case in cases:
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            ra = run(args.original, case["args"], a, case.get("copy", []), args.fixtures, args.timeout)
            rb = run(args.host, case["args"], b, case.get("copy", []), args.fixtures, args.timeout)
        ok = ra == rb
        print("%-32s %s" % (case["name"], "pass" if ok else "FAIL"))
        if not ok:
            failures += 1
            for label, x, y in (("exit", ra[0], rb[0]), ("stdout", ra[1], rb[1]),
                                ("stderr", ra[2], rb[2]), ("files", ra[3], rb[3])):
                if x != y:
                    print("  %s: original=%r host=%r" % (label, x, y))
    print("%d/%d cases passed" % (len(cases) - failures, len(cases)))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
