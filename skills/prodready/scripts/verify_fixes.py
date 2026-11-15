#!/usr/bin/env python3
"""Re-run the scan and compare it with a baseline, finding by finding.

Each baseline finding becomes ``fixed`` (fingerprint gone), ``still-present``,
``moved`` (same fingerprint, different line) or ``changed`` (same check and
file, different snippet; needs a look). Findings that were not in the baseline
are listed as ``new`` so a fix that creates another problem is caught.
Writes ``.prodready/verification.json`` and prints a before and after table.

What it deliberately does not do: it does not decide that a fix is correct,
only that the scanner no longer sees the problem. Owner actions such as key
rotation stay open until the owner confirms them.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_all  # noqa: E402
from lib import findings  # noqa: E402


def compare(baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    now = {f["fingerprint"]: f for f in current["findings"]}
    by_key: Dict[tuple, List[Dict[str, Any]]] = {}
    for f in current["findings"]:
        by_key.setdefault((f["check_id"], f.get("file")), []).append(f)
    base_fps = {f["fingerprint"] for f in baseline["findings"]}
    rows = []
    for f in baseline["findings"]:
        if f.get("status") == "ignored":
            continue
        cur = now.get(f["fingerprint"])
        if cur is None:
            peers = [c for c in by_key.get((f["check_id"], f.get("file")), []) if c["fingerprint"] not in base_fps]
            state = "changed" if peers else "fixed"
        else:
            state = "still-present" if cur.get("line") == f.get("line") else "moved"
        rows.append({"id": f["id"], "check_id": f["check_id"], "severity": f["severity"], "file": f.get("file"), "state": state})
    new = [{"id": f["id"], "check_id": f["check_id"], "severity": f["severity"], "file": f.get("file")} for f in current["findings"] if f["fingerprint"] not in base_fps and f.get("status") != "ignored"]
    return {"results": rows, "new": new, "counts": {s: sum(1 for r in rows if r["state"] == s) for s in ("fixed", "still-present", "moved", "changed")}}


def table(result: Dict[str, Any]) -> str:
    lines = ["| Finding | Severity | Result |", "|---|---|---|"]
    for r in result["results"]:
        lines.append("| %s | %s | %s |" % (r["id"], r["severity"], r["state"]))
    for r in result["new"]:
        lines.append("| %s | %s | new since baseline |" % (r["id"], r["severity"]))
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    p = findings.base_parser("verify_fixes.py", __doc__ or "")
    p.add_argument("--baseline", required=True, metavar="PATH")
    p.add_argument("--targets", nargs="*", default=[], metavar="ID", help="finding IDs or check IDs that must be fixed")
    p.add_argument("--strict", action="store_true", help="exit 1 when any targeted finding is not fixed")
    p.add_argument("--allow-network", action="store_true")
    p.add_argument("--history", action="store_true")
    p.add_argument("--only", action="append", default=[])
    p.add_argument("--skip", action="append", default=[])
    p.add_argument("--max-commits", type=int, default=2000)
    p.add_argument("--since", default=None)
    args = p.parse_args(argv)
    root = os.path.abspath(args.app_root)
    if not os.path.isdir(root):
        sys.stderr.write("prodready: app root not found or unreadable: %s\n" % args.app_root)
        return findings.EXIT_NO_ROOT
    baseline = findings.load(args.baseline)
    current = run_all.run(root, args)
    result = compare(baseline, current)
    out = args.out or os.path.join(root, ".prodready", "verification.json")
    findings.write_text(out, findings.dumps(result))
    findings.emit_text(table(result))
    if args.strict and args.targets:
        bad = [r for r in result["results"] if (r["id"] in args.targets or r["check_id"] in args.targets) and r["state"] != "fixed"]
        if bad:
            return 1
    return findings.EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
