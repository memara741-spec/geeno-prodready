#!/usr/bin/env python3
"""Render a findings document as a plain-language report (Markdown or self-contained HTML).

Sections follow references/report/template.md: header, verdict, the three
things to do first, summary, who can access what, findings by severity, owner
actions, questions, what looks good, verification, launch checklist, appendix.
Claude supplies judgement through ``--narrative`` (Markdown inserted after the
verdict) and ``--extra-findings`` (review-only findings in the same schema).

All text that comes from the scanned project is escaped in HTML output. The
HTML has inline CSS only, no external requests, and works without JavaScript.
Pass ``--lang ar`` (or another RTL code) for right-to-left layout.

What it deliberately does not do: it does not write the narrative itself and
does not change severities; those are the reviewer's decisions.
"""
from __future__ import annotations

import html
import json
import os
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import findings  # noqa: E402

RTL = {"ar", "he", "fa", "ur"}
EFFORT = {"auto": "small", "assisted": "medium", "owner": "owner", "none": "-"}
WHO = {"auto": "Claude can fix this", "assisted": "Claude can fix this; you review and apply", "owner": "You need to do this in a dashboard", "none": "Nothing to fix"}


def verdict(fs: List[Dict[str, Any]], accepted: Optional[List[str]] = None, scanners: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    accepted = accepted or []
    failed = [x["scanner"] for x in scanners or [] if x.get("status") == "failed"]
    note = (" The audit is incomplete: %s failed to run." % ", ".join(failed)) if failed else ""
    live = [f for f in fs if f.get("status") not in ("ignored", "fixed", "dismissed") and f["confidence"] != "possible" or (f["severity"] in ("critical", "high") and f.get("status") not in ("ignored", "fixed", "dismissed"))]
    crit = [f for f in live if f["severity"] == "critical"]
    high = [f for f in live if f["severity"] == "high" and f["id"] not in accepted]
    med = [f for f in live if f["severity"] == "medium"]
    if crit:
        return {"verdict": "BLOCKED", "why": "%d critical finding(s) are open: anyone can reach other people's data, spend your money or take over accounts.%s" % (len(crit), note), "blocking": crit + high, "incomplete": failed}
    if high:
        return {"verdict": "BLOCKED", "why": "%d high-severity finding(s) are open and not accepted in writing.%s" % (len(high), note), "blocking": high, "incomplete": failed}
    if failed:
        return {"verdict": "INCOMPLETE", "why": "The audit did not finish, so no READY or LAUNCH WITH CAUTION verdict can be given.%s Fix the failure and run it again." % note, "blocking": [], "incomplete": failed}
    if med:
        return {"verdict": "LAUNCH WITH CAUTION", "why": "%d medium finding(s) remain; none blocks launch." % len(med), "blocking": []}
    return {"verdict": "READY", "why": "No open critical, high or medium findings.", "blocking": []}


def top_three(fs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # A leaked or browser-exposed key costs money immediately and cannot be fixed in code alone, so secrets come first.
    order = sorted([f for f in fs if f.get("status") not in ("ignored", "fixed", "dismissed") and f["severity"] in ("critical", "high")],
                   key=lambda f: (0 if f["check_id"] in ("SEC-001", "SEC-002", "SEC-013", "SEC-014", "SEC-015") and f["severity"] == "critical" else 1,
                                  -findings.severity_rank(f["severity"]), -findings.confidence_rank(f["confidence"]), f["check_id"]))
    seen, out = set(), []
    for f in order:
        if f["check_id"] not in seen:
            seen.add(f["check_id"])
            out.append(f)
        if len(out) == 3:
            break
    return out


def md_escape(s: Any) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def _matrix_rows(inv: Dict[str, Any]) -> List[str]:
    rows = []
    for table, m in sorted((inv.get("access_matrix") or {}).items()):
        a, u = m["anon"], m["authenticated"]
        rows.append("| %s | %s | %s | %s | %s |" % (md_escape(table), "**yes**" if a["select"] == "all rows" else a["select"], "**yes**" if a["insert"] == "all rows" or a["update"] == "all rows" or a["delete"] == "all rows" else "no", u["select"], u["update"]))
    return rows


def render_md(doc: Dict[str, Any], extra: List[Dict[str, Any]], narrative: str, app_name: str, verification: Optional[Dict[str, Any]], accepted: List[str]) -> str:
    fs = findings.dedupe_dicts(doc["findings"] + extra)
    v = verdict(fs, accepted, doc.get("scanners"))
    inv = doc.get("inventory") or {}
    stack = doc.get("stack") or {}
    s = findings.summarise(fs)
    L: List[str] = []
    L += ["# prodready report: %s" % app_name, "",
          "**Date:** %s · **Tool version:** %s · **Files scanned:** %s" % (doc.get("generated_at", "")[:10], doc.get("version"), (doc.get("stats") or {}).get("files_scanned", "?")),
          "**Audited:** automated scan of source files and configuration, plus code review. **Not audited:** anything configured only in dashboards, the live site, and areas listed in the appendix.", "",
          "## Verdict", "", "# %s" % v["verdict"], "", v["why"], ""]
    if narrative.strip():
        L += [narrative.strip(), ""]
    L += ["## The three things to do first", ""]
    for i, f in enumerate(top_three(fs), 1):
        L.append("%d. %s (`%s`)" % (i, f["message"], f["id"]))
    if not top_three(fs):
        L.append("Nothing urgent. See the owner actions below.")
    L += ["", "## Summary", "", "| Severity | Open |", "|---|---|"] + ["| %s | %d |" % (k, c) for k, c in s["by_severity"].items()]
    L += ["", "By category: " + (", ".join("%s %d" % (k, c) for k, c in s["by_category"].items()) or "none"), ""]
    L += ["## Who can access what", ""]
    rows = _matrix_rows(inv)
    if rows:
        L += ["| Table | Anyone can read | Anyone can change | Signed-in users can read | Signed-in users can change |", "|---|---|---|---|---|"] + rows + [""]
    fb = inv.get("firebase_access") or {}
    for f, m in sorted(fb.items()):
        L += ["**%s**" % f, "", "| Path | Anonymous | Signed-in |", "|---|---|---|"]
        for path, e in sorted(m.items()):
            L.append("| %s | read: %s, write: %s | read: %s, write: %s |" % (md_escape(path), e["anonymous"]["read"], e["anonymous"]["write"], e["signed-in"]["read"], e["signed-in"]["write"]))
        L.append("")
    routes = inv.get("routes") or []
    if routes:
        L += ["| Route | Who can call it | Touches |", "|---|---|---|"]
        for r in routes:
            who = {"present": "signed-in users", "none": "**anyone**", "middleware-only": "signed-in users (middleware only)"}.get(r["auth"]["status"], "unknown")
            if r.get("is_webhook"):
                who = "the provider (signature %s)" % ("verified" if r.get("verifies_signature") else "**not verified**")
            L.append("| %s | %s | %s |" % (md_escape(r["id"]), who, md_escape(", ".join(r["privileged_access"]) or "-")))
        L.append("")
    if not rows and not fb and not routes:
        L += ["Neither a table access matrix nor a route inventory could be built from the repository (for example, the database rules live only in a dashboard).", ""]
    L += ["## Findings", ""]
    for sev in ("critical", "high", "medium", "low", "info"):
        group = [f for f in fs if f["severity"] == sev and f.get("status") not in ("ignored", "fixed", "dismissed")]
        if not group:
            continue
        if sev in ("low", "info"):
            L += ["### %s (batched)" % sev.capitalize(), ""]
            for f in group:
                L.append("- `%s` %s %s" % (f["check_id"], f["message"], ("(%s:%s)" % (f["file"], f["line"])) if f.get("file") else ""))
            L.append("")
            continue
        for f in group:
            loc = "%s:%s" % (f["file"], f["line"]) if f.get("file") and f.get("line") else (f.get("file") or "project-level")
            L += ["### [%s] %s: %s" % (sev.upper(), f["check_id"], f["title"]), "",
                  "**In plain words:** %s" % f["message"], "**Where:** `%s`" % loc]
            if f.get("snippet"):
                L += ["**Evidence:**", "", "```", f["snippet"], "```"]
            L += ["**Why it matters:** %s" % (f.get("detail") or ""), "**Fix:** %s" % (f.get("fix_hint") or ""),
                  "**Effort:** %s · **Who:** %s" % (EFFORT.get(f["fix_type"].split("+")[0].split("/")[0], "medium"), WHO.get(f["fix_type"].split("+")[0].split("/")[0], "")),
                  "**Confidence:** %s" % f["confidence"], ""]
    owner = [f for f in fs if (f.get("owner_action") or "owner" in f["fix_type"]) and f.get("status") not in ("ignored", "fixed", "dismissed")]
    L += ["## Owner actions", ""]
    for f in owner[:30]:
        L.append("- [ ] `%s` %s%s" % (f["check_id"], f["title"], (" (guide: `%s`)" % f["owner_action"]) if f.get("owner_action") else ""))
    if not owner:
        L.append("None open.")
    L += ["", "## Questions for you", ""]
    for q in inv.get("owner_questions") or []:
        L.append("- `%s` %s" % (q["check"], q["question"]))
    L += ["", "## What looks good", "", "<!-- The reviewer fills in three to six specific strengths with evidence. -->", ""]
    if verification:
        L += ["## Verification", "", "| Finding | Severity | Result |", "|---|---|---|"]
        for r in verification["results"]:
            L.append("| %s | %s | %s |" % (md_escape(r["id"]), r["severity"], r["state"]))
        for r in verification["new"]:
            L.append("| %s | %s | new since baseline |" % (md_escape(r["id"]), r["severity"]))
        L.append("")
    L += ["## Launch checklist", "", "See `references/checks/launch.md`. Status of each item is filled in at the launch gate.", "",
          "## Appendix", "", "**Detected stack:** framework %s, database %s, auth %s, payments %s, AI %s, hosting %s." % (
              (stack.get("framework") or {}).get("name"), ", ".join(d["name"] for d in stack.get("database") or []) or "none", ", ".join(d["name"] for d in stack.get("auth") or []) or "none",
              ", ".join(d["name"] for d in stack.get("payments") or []) or "none", ", ".join(d["name"] for d in stack.get("llm") or []) or "none", ", ".join(d["name"] for d in stack.get("hosting") or []) or "unknown"), ""]
    tp = inv.get("third_parties") or []
    if tp:
        L += ["**Third parties that receive user data:**", ""] + ["- %s (%s): %s" % (t["name"], t["category"], t["data"]) for t in tp] + [""]
    L += ["**Scanners:** " + ", ".join("%s (%s)" % (x["scanner"], x["status"]) for x in doc.get("scanners") or []), ""]
    ign = [f for f in doc["findings"] if f.get("status") == "ignored"]
    if ign:
        L += ["**Ignored findings:**"] + ["- `%s`: %s" % (f["id"], f.get("status_reason") or "no reason given") for f in ign] + [""]
    if doc.get("warnings"):
        L += ["**Warnings:**"] + ["- %s" % w for w in doc["warnings"]] + [""]
    L += ["**Limits of this audit.** This review is automated and based on source code. Settings that exist only in provider dashboards (backups, email domain, billing limits, auth options) could not be seen unless stated. It is not a penetration test and not a compliance certification, and it does not replace a professional audit for health, financial or children's data.", ""]
    return "\n".join(L)


CSS = ("body{font:16px/1.55 system-ui,sans-serif;max-width:60rem;margin:0 auto;padding:1rem 1rem 4rem;background:#fff;color:#1a1a1a}"
       "@media(prefers-color-scheme:dark){body{background:#14161a;color:#e8e8e8}pre,code{background:#23262d!important}th{background:#23262d!important}}"
       "h1,h2,h3{line-height:1.2}.v{font-size:2rem;font-weight:800;padding:.4rem 1rem;border-radius:.4rem;display:inline-block}"
       ".BLOCKED{background:#b42318;color:#fff}.READY{background:#067647;color:#fff}.LAUNCH{background:#b54708;color:#fff}.INCOMPLETE{background:#475467;color:#fff}"
       "pre,code{background:#f3f4f6;padding:.1rem .3rem;border-radius:.2rem;overflow-x:auto}pre{padding:.6rem}table{border-collapse:collapse;display:block;overflow-x:auto}"
       "td,th{border:1px solid #8884;padding:.3rem .6rem;text-align:start}th{background:#f3f4f6}.sev{font-weight:700;margin-inline-end:.4rem}"
       "@media print{body{max-width:none}}")


def render_html(md: str, lang: str, title: str) -> str:
    """Minimal Markdown-to-HTML for the report's own syntax. Everything is escaped first."""
    out: List[str] = []
    in_code = in_table = in_list = False
    for raw in md.split("\n"):
        line = html.escape(raw, quote=True)
        if raw.startswith("```"):
            out.append("</pre>" if in_code else "<pre>")
            in_code = not in_code
            continue
        if in_code:
            out.append(line)
            continue
        def inline(t: str) -> str:
            import re
            t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
            return re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
        if raw.startswith("|"):
            if set(raw.replace("|", "").strip()) <= set("-: "):
                continue
            cells = [inline(c.strip()) for c in html.escape(raw.strip().strip("|"), quote=True).replace("\\|", "&#124;").split("|")]
            tag = "th" if not in_table else "td"
            if not in_table:
                out.append("<table>")
                in_table = True
            out.append("<tr>" + "".join("<%s>%s</%s>" % (tag, c, tag) for c in cells) + "</tr>")
            continue
        if in_table:
            out.append("</table>")
            in_table = False
        if raw.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append("<li>%s</li>" % inline(line[2:]))
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if raw.startswith("# ") and raw[2:] in ("BLOCKED", "READY", "LAUNCH WITH CAUTION", "INCOMPLETE"):
            out.append('<div class="v %s">%s</div>' % (raw[2:].split()[0], line[2:]))
        elif raw.startswith("#"):
            n = len(raw) - len(raw.lstrip("#"))
            out.append("<h%d>%s</h%d>" % (min(n, 4), inline(line[n + 1:]), min(n, 4)))
        elif raw.strip().startswith("<!--"):
            continue
        elif raw.strip():
            out.append("<p>%s</p>" % inline(line))
    if in_table:
        out.append("</table>")
    if in_list:
        out.append("</ul>")
    return '<!doctype html><html lang="%s" dir="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title><style>%s</style></head><body>%s</body></html>\n' % (
        html.escape(lang), "rtl" if lang.split("-")[0] in RTL else "ltr", html.escape(title), CSS, "\n".join(out))


def main(argv: Optional[List[str]] = None) -> int:
    p = findings.base_parser("render_report.py", __doc__ or "")
    p.add_argument("--format", choices=["md", "html"], default="md")
    p.add_argument("--narrative", metavar="PATH")
    p.add_argument("--extra-findings", metavar="PATH")
    p.add_argument("--verification", metavar="PATH")
    p.add_argument("--findings", metavar="PATH", help="findings JSON (default: <app_root>/.prodready/findings.json)")
    p.add_argument("--accept", action="append", default=[], help="finding ID the owner accepted in writing")
    p.add_argument("--lang", default="en")
    p.add_argument("--name", default=None)
    args = p.parse_args(argv)
    root = os.path.abspath(args.app_root)
    path = args.findings or os.path.join(root, ".prodready", "findings.json")
    if not os.path.isfile(path):
        sys.stderr.write("prodready: findings file not found: %s (run run_all.py first)\n" % path)
        return findings.EXIT_USAGE
    doc = findings.load(path)
    rd = lambda p_: open(p_, encoding="utf-8").read() if p_ else ""
    extra = json.loads(rd(args.extra_findings))["findings"] if args.extra_findings else []
    ver = json.loads(rd(args.verification)) if args.verification else None
    md = render_md(doc, extra, rd(args.narrative), args.name or os.path.basename(root), ver, args.accept)
    findings.emit_text(render_html(md, args.lang, "prodready report") if args.format == "html" else md + "\n", args.out)
    return findings.EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
