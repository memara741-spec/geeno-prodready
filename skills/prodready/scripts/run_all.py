#!/usr/bin/env python3
"""Run detect_stack and every applicable scanner, then merge the results into one findings document.

Scanners run in-process so they share one file cache. The merged document
lists which scanners ran and which were skipped. Honours ``.prodready.json``
(exclude, ignore with reasons, public_tables, severity_overrides).

Extra options: --only/--skip (check ID or category prefix, repeatable),
--baseline PATH (mark findings new or existing), --fail-on SEVERITY (exit 1 on
a confirmed finding at or above it, for CI), --format json|sarif|summary,
--history (include git history), --allow-network (let scan_deps run an audit).

What it deliberately does not do: it never uses the network without
--allow-network, never writes outside --out, and never runs probe_live.py.
"""
from __future__ import annotations

import importlib
import os
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detect_stack  # noqa: E402
from lib import catalog, findings, walker  # noqa: E402

SCANNERS = ["scan_secrets", "scan_env", "scan_supabase", "scan_firebase", "scan_routes", "scan_payments", "scan_llm", "scan_frontend", "scan_config", "scan_deps", "scan_launch", "scan_laravel", "scan_tenancy", "scan_logic", "scan_performance", "scan_infra"]
IMPLEMENTS: List[str] = []
ALSO_EMITS: List[str] = []
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def selected(check_id: str, only: List[str], skip: List[str]) -> bool:
    def hit(pats: List[str]) -> bool:
        return any(check_id == p or check_id.split("-")[0] == p or catalog.get(check_id).category == p for p in pats)
    return (not only or hit(only)) and not hit(skip)


def apply_config(doc: Dict[str, Any], config: Dict[str, Any]) -> None:
    ignores = {i.get("fingerprint"): i for i in config.get("ignore") or [] if isinstance(i, dict)}
    overrides = config.get("severity_overrides") or {}
    for f in doc["findings"]:
        if f["check_id"] in overrides and overrides[f["check_id"]] in findings.SEVERITIES:
            f["severity"] = overrides[f["check_id"]]
        ign = ignores.get(f["fingerprint"])
        if ign:
            f["status"] = "ignored"
            f["status_reason"] = ign.get("reason") or ""
            if not ign.get("reason"):
                doc["warnings"].append("an ignore entry for %s has no reason" % f["fingerprint"][:19])


def apply_baseline(doc: Dict[str, Any], baseline: Dict[str, Any]) -> None:
    old = {f["fingerprint"] for f in baseline["findings"]}
    for f in doc["findings"]:
        if "status" not in f:
            f["status"] = "existing" if f["fingerprint"] in old else "new"


def to_sarif(doc: Dict[str, Any]) -> Dict[str, Any]:
    rules, results = {}, []
    for f in doc["findings"]:
        if f.get("status") == "ignored":
            continue
        rules[f["check_id"]] = {"id": f["check_id"], "name": f["title"], "shortDescription": {"text": f["title"]}, "helpUri": "https://github.com/GITHUB_USER/geeno-prodready/blob/main/skills/prodready/" + f["references"][0]}
        res: Dict[str, Any] = {"ruleId": f["check_id"], "level": SARIF_LEVEL[f["severity"]], "message": {"text": f["message"]}, "partialFingerprints": {"prodready/v1": f["fingerprint"]}}
        if f.get("file"):
            res["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": f["file"]}, "region": {"startLine": f.get("line") or 1}}}]
        results.append(res)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "prodready", "version": findings.__version__, "rules": sorted(rules.values(), key=lambda r: r["id"])}}, "results": results}]}


def summary_text(doc: Dict[str, Any]) -> str:
    s = findings.summarise(doc["findings"])
    lines = ["prodready %s: %d finding(s)" % (doc["version"], s["total"]), "  " + "  ".join("%s %d" % (k, v) for k, v in s["by_severity"].items())]
    for f in doc["findings"]:
        if f.get("status") != "ignored" and findings.severity_rank(f["severity"]) >= 3:
            lines.append("  [%s/%s] %s %s:%s" % (f["severity"].upper(), f["confidence"], f["check_id"], f.get("file") or "-", f.get("line") or ""))
    return "\n".join(lines) + "\n"


def run(root: str, args: Any) -> Dict[str, Any]:
    project = walker.Project(root, include=args.include, exclude=args.exclude, max_size=args.max_file_size)
    project.options = args
    stack = detect_stack.detect(project)
    project.stack = stack
    docs: List[Dict[str, Any]] = []
    ran: List[Dict[str, Any]] = []
    names = SCANNERS + (["scan_git_history"] if args.history else [])
    for name in names:
        mod = importlib.import_module(name)
        owned = [c for c in mod.IMPLEMENTS if selected(c, args.only, args.skip)]
        if (args.only or args.skip) and not owned and not any(selected(c, args.only, args.skip) for c in getattr(mod, "ALSO_EMITS", [])):
            ran.append({"scanner": name, "status": "skipped", "reason": "no selected check"})
            continue
        try:
            doc = mod.scan(project.root, stack, project).to_dict()
        except Exception as exc:  # a scanner crash must not lose the other results
            ran.append({"scanner": name, "status": "failed", "reason": type(exc).__name__ + ": " + str(exc)[:120]})
            continue
        doc["findings"] = [f for f in doc["findings"] if selected(f["check_id"], args.only, args.skip)]
        docs.append(doc)
        ran.append({"scanner": name, "status": "ran", "findings": len(doc["findings"])})
    if not args.history:
        ran.append({"scanner": "scan_git_history", "status": "skipped", "reason": "off by default; pass --history"})
    merged = findings.merge(docs)
    merged["stack"] = stack
    merged["scanners"] = ran
    merged["warnings"] = list(dict.fromkeys(merged["warnings"] + project.warnings))
    apply_config(merged, project.config)
    return merged


def main(argv: Optional[List[str]] = None) -> int:
    p = findings.base_parser("run_all.py", __doc__ or "")
    p.add_argument("--only", action="append", default=[])
    p.add_argument("--skip", action="append", default=[])
    p.add_argument("--baseline", metavar="PATH")
    p.add_argument("--fail-on", choices=findings.SEVERITIES)
    p.add_argument("--format", choices=["json", "sarif", "summary"], default="json")
    p.add_argument("--history", action="store_true")
    p.add_argument("--allow-network", action="store_true")
    p.add_argument("--max-commits", type=int, default=2000)
    p.add_argument("--since", default=None)
    args = p.parse_args(argv)
    project_root = os.path.abspath(args.app_root)
    if not os.path.isdir(project_root):
        sys.stderr.write("prodready: app root not found or unreadable: %s\n" % args.app_root)
        return findings.EXIT_NO_ROOT
    findings.log("run_all: scanning %s" % args.app_root, args.quiet)
    doc = run(project_root, args)
    if args.baseline:
        apply_baseline(doc, findings.load(args.baseline))
    if args.format == "sarif":
        findings.emit(to_sarif(doc), args.out)
    elif args.format == "summary":
        findings.emit_text(summary_text(doc), args.out)
    else:
        findings.emit(doc, args.out)
    if args.fail_on:
        floor = findings.severity_rank(args.fail_on)
        if any(f["confidence"] == "confirmed" and f.get("status") != "ignored" and findings.severity_rank(f["severity"]) >= floor for f in doc["findings"]):
            return 1
    return findings.EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
