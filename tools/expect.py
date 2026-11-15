#!/usr/bin/env python3
"""Maintainer tool: run scanners on the fixtures and compare with each expected.json.

Usage:
  python tools/expect.py                 all fixtures, all scanners that exist
  python tools/expect.py NAME [NAME...]  only these fixtures
  python tools/expect.py --scanner scan_secrets   restrict must_find to checks one scanner owns or also emits
  python tools/expect.py --list NAME     print every finding for a fixture

Prints a recall and false-positive table. Exit code 1 when any expectation fails.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "skills", "prodready", "scripts")
sys.path.insert(0, SCRIPTS)
os.environ.setdefault("PRODREADY_FIXED_TIME", "2026-01-01T00:00:00Z")

from lib import catalog, findings, walker  # noqa: E402

SCANNERS = [
    "scan_secrets", "scan_env", "scan_supabase", "scan_firebase", "scan_routes", "scan_payments", "scan_llm",
    "scan_frontend", "scan_config", "scan_deps", "scan_launch", "scan_laravel", "scan_tenancy", "scan_logic", "scan_performance", "scan_infra", "scan_authz", "scan_ledger",
]
FIXTURES = [
    "lovable-supabase-vite", "nextjs-supabase-stripe", "nextjs-prisma-authjs", "firebase-react", "express-mongo-jwt",
    "nextjs-ai-chat", "expo-supabase", "clean-nextjs-supabase", "clean-vite-firebase", "laravel-multitenant", "clean-laravel",
]


def available(only=None):
    out = []
    for name in SCANNERS:
        if only and name not in only:
            continue
        if os.path.isfile(os.path.join(SCRIPTS, name + ".py")):
            out.append(importlib.import_module(name))
    return out


def scan_fixture(name, modules):
    import detect_stack

    root = os.path.join(REPO, "fixtures", name)
    project = walker.Project(root)
    stack = detect_stack.detect(project)
    project.stack = stack
    docs = [m.scan(project.root, stack, project).to_dict() for m in modules]
    return findings.merge(docs)


def matches(entry, f):
    if f["check_id"] != entry["check_id"]:
        return False
    if entry.get("file") and f.get("file") != entry["file"]:
        return False
    if entry.get("subject") and (f.get("subject") or {}).get("name") != entry["subject"]:
        return False
    return True


def evaluate(name, doc, owned=None):
    with open(os.path.join(REPO, "fixtures", name, "expected.json"), "r", encoding="utf-8") as fh:
        exp = json.load(fh)
    fs = doc["findings"]
    must = [e for e in exp.get("must_find", []) if owned is None or e["check_id"] in owned]
    missing = [e for e in must if not any(matches(e, f) for f in fs)]
    forbidden = [(e, f) for e in exp.get("must_not_find", []) for f in fs if matches(e, f)]
    planted_criticals = {e["check_id"] for e in exp.get("must_find", []) + exp.get("review_only", [])}
    fp_crit = [f for f in fs if f["severity"] == "critical" and f["confidence"] != "possible" and f["check_id"] not in planted_criticals]
    over = []
    if exp.get("max_severity"):
        cap = findings.severity_rank(exp["max_severity"])
        over = [f for f in fs if findings.severity_rank(f["severity"]) > cap and f["confidence"] != "possible"]
    return {"must": len(must), "missing": missing, "forbidden": forbidden, "fp_crit": fp_crit, "over": over, "total": len(fs), "limit": exp.get("max_false_positive_criticals", 0)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("fixtures", nargs="*")
    ap.add_argument("--scanner", action="append")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    modules = available(args.scanner)
    owned = None
    if args.scanner:
        owned = set()
        for m in modules:
            owned.update(m.IMPLEMENTS)
            owned.update(getattr(m, "ALSO_EMITS", []))
    failed = False
    print("%-26s %8s %8s %9s %8s %7s" % ("fixture", "must", "found", "forbidden", "fp-crit", "total"))
    for name in args.fixtures or FIXTURES:
        doc = scan_fixture(name, modules)
        if args.list:
            for f in doc["findings"]:
                print("  %-10s %-8s %-9s %s:%s  %s" % (f["check_id"], f["severity"], f["confidence"], f.get("file") or "-", f.get("line") or "", f["snippet"][:70]))
            for w in doc["warnings"]:
                print("  WARNING", w)
        r = evaluate(name, doc, owned)
        print("%-26s %8d %8d %9d %8d %7d" % (name, r["must"], r["must"] - len(r["missing"]), len(r["forbidden"]), len(r["fp_crit"]), r["total"]))
        for e in r["missing"]:
            print("    MISSING   %s %s %s" % (e["check_id"], e.get("file", ""), e.get("subject", "")))
        for e, f in r["forbidden"]:
            print("    FORBIDDEN %s %s:%s %s" % (f["check_id"], f.get("file"), f.get("line"), f["snippet"][:60]))
        for f in r["fp_crit"]:
            print("    FP-CRIT   %s %s:%s %s" % (f["check_id"], f.get("file"), f.get("line"), f["snippet"][:60]))
        for f in r["over"]:
            print("    OVER-CAP  %s %s %s:%s %s" % (f["check_id"], f["severity"], f.get("file"), f.get("line"), f["snippet"][:60]))
        if r["missing"] or r["forbidden"] or len(r["fp_crit"]) > r["limit"] or r["over"]:
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
