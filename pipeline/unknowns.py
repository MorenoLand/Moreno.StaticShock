# unknowns.py: record unresolved questions and close them only with evidence.
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg

PATH = os.path.join(cfg.DATA, "unknowns.json")


def load():
    try:
        with open(PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"schema": 1, "unknowns": []}


def save(data):
    os.makedirs(cfg.DATA, exist_ok=True)
    with open(PATH, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")


def add(args):
    data = load()
    n = 1 + max([int(u["id"][1:]) for u in data["unknowns"] if u["id"][1:].isdigit()] or [0])
    data["unknowns"].append({
        "id": "U%d" % n,
        "question": args.question,
        "status": "open",
        "supporting": args.evidence or [],
        "contradicting": args.contradicting or [],
        "authority_needed": args.authority_needed or "",
        "resolution": None,
    })
    save(data)
    print("U%d" % n)


def resolve(args):
    data = load()
    for u in data["unknowns"]:
        if u["id"] == args.id:
            if not args.evidence:
                sys.exit("a resolution needs at least one evidence location")
            u["status"] = "resolved"
            u["resolution"] = {"evidence": args.evidence}
            save(data)
            print("resolved %s" % args.id)
            return
    sys.exit("unknown id: %s" % args.id)


def check():
    data = load()
    ids = [u["id"] for u in data["unknowns"]]
    if len(ids) != len(set(ids)):
        sys.exit("duplicate unknown ids")
    for u in data["unknowns"]:
        if not u.get("question"):
            sys.exit("%s has no question" % u["id"])
        if u.get("status") == "resolved" and not (u.get("resolution") or {}).get("evidence"):
            sys.exit("%s is resolved without evidence" % u["id"])
    open_count = sum(1 for u in data["unknowns"] if u.get("status") != "resolved")
    print("unknowns: %d open, %d resolved" % (open_count, len(ids) - open_count))
    return 0


def listing():
    data = load()
    for u in data["unknowns"]:
        print("%s\t%s\t%s" % (u["id"], u["status"], u["question"]))
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("check")
    a = sub.add_parser("add")
    a.add_argument("--question", required=True)
    a.add_argument("--evidence", action="append")
    a.add_argument("--contradicting", action="append")
    a.add_argument("--authority-needed")
    r = sub.add_parser("resolve")
    r.add_argument("--id", required=True)
    r.add_argument("--evidence", action="append", required=True)
    args = ap.parse_args()
    if args.cmd == "add":
        add(args)
    elif args.cmd == "resolve":
        resolve(args)
    elif args.cmd == "check":
        sys.exit(check())
    else:
        sys.exit(listing())


if __name__ == "__main__":
    main()
