"""Finding schema, envelope, and the command-line plumbing shared by every scanner.

A finding is one occurrence of a check failing, with evidence. The constructor
redacts secrets in every free-text field, so a finding cannot carry a secret.
Scanners build an ``Envelope``, add findings and inventory to it, and hand it
to ``emit``. The tool version lives here and nowhere else.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from . import catalog
from .redact import redact_text

__version__ = "1.0.0"
TOOL = "prodready"

SEVERITIES = ["info", "low", "medium", "high", "critical"]
CONFIDENCES = ["possible", "likely", "confirmed"]
MAX_SNIPPET = 240

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_NO_ROOT = 3


def severity_rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0


def confidence_rank(conf: str) -> int:
    return CONFIDENCES.index(conf) if conf in CONFIDENCES else 0


def _one_line(text: str, limit: int = 0) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    if limit and len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def norm_path(path: Optional[str]) -> Optional[str]:
    if path is None:
        return None
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def fingerprint(check_id: str, path: Optional[str], snippet: str, subject: Optional[Dict[str, str]]) -> str:
    """Stable identity of a finding: check, path and collapsed snippet. No line number."""
    basis = _one_line(snippet)
    if not basis and subject:
        basis = "%s:%s" % (subject.get("kind", ""), subject.get("name", ""))
    raw = "\x1f".join([check_id, norm_path(path) or "", basis])
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


class Finding:
    """One occurrence of a check failing. All text fields are redacted on construction."""

    __slots__ = (
        "check_id", "title", "severity", "confidence", "category", "file", "line", "end_line", "snippet",
        "message", "detail", "subject", "fix_type", "fix_hint", "owner_action", "references", "fingerprint",
        "status", "status_reason",
    )

    def __init__(
        self,
        check_id: str,
        message: str,
        file: Optional[str] = None,
        line: Optional[int] = None,
        snippet: str = "",
        detail: str = "",
        confidence: str = "likely",
        subject: Optional[Dict[str, str]] = None,
        end_line: Optional[int] = None,
        severity: Optional[str] = None,
        title: Optional[str] = None,
        fix_hint: str = "",
        owner_action: Optional[str] = None,
    ) -> None:
        check = catalog.get(check_id)  # KeyError on an unknown check is deliberate
        if confidence not in CONFIDENCES:
            raise ValueError("unknown confidence: %s" % confidence)
        if severity is not None and severity not in SEVERITIES:
            raise ValueError("unknown severity: %s" % severity)
        self.check_id = check_id
        self.title = _one_line(redact_text(title or check.title))
        self.severity = severity or check.severity
        self.confidence = confidence
        self.category = check.category
        self.file = norm_path(file)
        self.line = int(line) if line else None
        self.end_line = int(end_line) if end_line else self.line
        self.snippet = _one_line(redact_text(snippet), MAX_SNIPPET)
        self.message = _one_line(redact_text(message))
        self.detail = _one_line(redact_text(detail))
        self.subject = dict(subject) if subject else None
        self.fix_type = check.fix_type
        self.fix_hint = _one_line(redact_text(fix_hint))
        self.owner_action = owner_action
        self.references = [check.reference]
        self.fingerprint = fingerprint(check_id, self.file, self.snippet, self.subject)
        self.status = None  # type: Optional[str]
        self.status_reason = None  # type: Optional[str]

    @property
    def id(self) -> str:
        if self.file:
            return "%s:%s:%s" % (self.check_id, self.file, self.line or 0)
        if self.subject and self.subject.get("name"):
            return "%s:%s" % (self.check_id, self.subject["name"])
        return "%s:project" % self.check_id

    def sort_key(self) -> tuple:
        return (self.check_id, self.file or "", self.line or 0, self.snippet, (self.subject or {}).get("name", ""))

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.id,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "snippet": self.snippet,
            "message": self.message,
            "detail": self.detail,
            "subject": self.subject,
            "fix_type": self.fix_type,
            "fix_hint": self.fix_hint,
            "owner_action": self.owner_action,
            "references": list(self.references),
            "fingerprint": self.fingerprint,
        }
        if self.status:
            d["status"] = self.status
            if self.status_reason:
                d["status_reason"] = self.status_reason
        return d


def generated_at() -> str:
    fixed = os.environ.get("PRODREADY_FIXED_TIME")
    if fixed:
        return fixed
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Envelope:
    """The JSON document a scanner emits."""

    def __init__(self, scanner: str, stack: Optional[Dict[str, Any]] = None) -> None:
        self.scanner = scanner
        self.stack = stack
        self.findings: List[Finding] = []
        self.inventory: Dict[str, Any] = {}
        self.warnings: List[str] = []
        self.files_scanned = 0
        self.files_skipped = 0
        self._started = time.time()

    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def warn(self, message: str) -> None:
        msg = _one_line(redact_text(message))
        if msg not in self.warnings:
            self.warnings.append(msg)

    def to_dict(self) -> Dict[str, Any]:
        duration = 0 if os.environ.get("PRODREADY_FIXED_TIME") else int((time.time() - self._started) * 1000)
        return {
            "tool": TOOL,
            "version": __version__,
            "scanner": self.scanner,
            "generated_at": generated_at(),
            "app_root": ".",
            "stack": self.stack,
            "findings": [f.to_dict() for f in sort_findings(dedupe(self.findings))],
            "inventory": self.inventory,
            "warnings": list(self.warnings),
            "stats": {"files_scanned": self.files_scanned, "files_skipped": self.files_skipped, "duration_ms": duration},
        }


def sort_findings(findings: Iterable[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: f.sort_key())


def dedupe(findings: Iterable[Finding]) -> List[Finding]:
    """Findings with the same fingerprint collapse to the one with the higher confidence."""
    best: Dict[str, Finding] = {}
    for f in findings:
        cur = best.get(f.fingerprint)
        if cur is None or confidence_rank(f.confidence) > confidence_rank(cur.confidence):
            best[f.fingerprint] = f
    return list(best.values())


# --- Working with emitted JSON documents -----------------------------------

def load(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or "findings" not in doc:
        raise ValueError("%s is not a prodready findings document" % path)
    return doc


def dedupe_dicts(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    best: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        cur = best.get(f["fingerprint"])
        if cur is None or confidence_rank(f.get("confidence", "")) > confidence_rank(cur.get("confidence", "")):
            best[f["fingerprint"]] = f
    return sorted(best.values(), key=lambda f: (f["check_id"], f.get("file") or "", f.get("line") or 0, f.get("snippet") or "", f["fingerprint"]))


def merge(envelopes: Sequence[Dict[str, Any]], scanner: str = "run_all") -> Dict[str, Any]:
    """Merge several scanner documents into one. Inventory keys are namespaced by scanner on collision."""
    findings: List[Dict[str, Any]] = []
    inventory: Dict[str, Any] = {}
    warnings: List[str] = []
    stats = {"files_scanned": 0, "files_skipped": 0, "duration_ms": 0}
    stack = None
    for env in envelopes:
        findings.extend(env.get("findings", []))
        for key, value in (env.get("inventory") or {}).items():
            if key in inventory and inventory[key] != value:
                inventory["%s.%s" % (env.get("scanner", "scanner"), key)] = value
            else:
                inventory[key] = value
        for w in env.get("warnings", []):
            if w not in warnings:
                warnings.append(w)
        s = env.get("stats") or {}
        stats["files_scanned"] = max(stats["files_scanned"], int(s.get("files_scanned", 0)))
        stats["files_skipped"] = max(stats["files_skipped"], int(s.get("files_skipped", 0)))
        stats["duration_ms"] += int(s.get("duration_ms", 0))
        stack = stack or env.get("stack")
    return {
        "tool": TOOL,
        "version": __version__,
        "scanner": scanner,
        "generated_at": generated_at(),
        "app_root": ".",
        "stack": stack,
        "findings": dedupe_dicts(findings),
        "inventory": inventory,
        "warnings": warnings,
        "stats": stats,
    }


def summarise(findings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Counts by severity and by category. Ignored and fixed findings are not counted."""
    by_sev = {s: 0 for s in reversed(SEVERITIES)}
    by_cat: Dict[str, int] = {}
    total = 0
    for f in findings:
        if f.get("status") in ("ignored", "fixed", "dismissed"):
            continue
        total += 1
        by_sev[f.get("severity", "info")] = by_sev.get(f.get("severity", "info"), 0) + 1
        by_cat[f.get("category", "other")] = by_cat.get(f.get("category", "other"), 0) + 1
    return {"total": total, "by_severity": by_sev, "by_category": dict(sorted(by_cat.items()))}


# --- Command line ----------------------------------------------------------

def log(message: str, quiet: bool = False) -> None:
    if not quiet:
        sys.stderr.write("prodready: %s\n" % message)
        sys.stderr.flush()


def dumps(doc: Any) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def write_text(path: str, text: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def emit_text(text: str, out: Optional[str] = None) -> None:
    """Write to ``out`` or to stdout as UTF-8 bytes with \\n line endings on every platform."""
    if out:
        write_text(out, text)
        return
    buf = getattr(sys.stdout, "buffer", None)
    if buf is not None:
        buf.write(text.encode("utf-8"))
        buf.flush()
    else:  # pragma: no cover - stdout replaced by a text-only stream
        sys.stdout.write(text)


def emit(doc: Dict[str, Any], out: Optional[str] = None) -> None:
    emit_text(dumps(doc), out)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # exit code 2 on usage errors
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, "%s: error: %s\n" % (self.prog, message))


def base_parser(prog: str, description: str) -> argparse.ArgumentParser:
    p = _Parser(prog=prog, description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("app_root", help="path to the root of the app to scan")
    p.add_argument("--json", action="store_true", help="print the JSON document to stdout (default)")
    p.add_argument("--out", metavar="PATH", help="write the JSON document to PATH instead of stdout")
    p.add_argument("--stack", metavar="PATH", help="path to a detect_stack result, to avoid re-detecting")
    p.add_argument("--include", action="append", default=[], metavar="GLOB", help="only scan paths matching GLOB (repeatable)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching GLOB (repeatable)")
    p.add_argument("--max-file-size", type=int, default=1500000, metavar="BYTES", help="skip larger files (default 1500000)")
    p.add_argument("--quiet", action="store_true", help="no progress on stderr")
    p.add_argument("--version", action="version", version="%s %s" % (TOOL, __version__))
    return p


def open_project(args: argparse.Namespace) -> Any:
    """Build the shared file cache for a scanner run, or exit with code 3."""
    from . import walker

    root = os.path.abspath(args.app_root)
    if not os.path.isdir(root) or not os.access(root, os.R_OK):
        sys.stderr.write("prodready: app root not found or unreadable: %s\n" % args.app_root)
        raise SystemExit(EXIT_NO_ROOT)
    return walker.Project(root, include=args.include, exclude=args.exclude, max_size=args.max_file_size)


def load_stack(args: argparse.Namespace, project: Any) -> Dict[str, Any]:
    if getattr(args, "stack", None):
        with open(args.stack, "r", encoding="utf-8") as fh:
            stack = json.load(fh)
    else:
        import detect_stack  # scripts/ is on sys.path when a scanner runs standalone

        stack = detect_stack.detect(project)
    project.stack = stack
    return stack


def run_scanner_cli(
    name: str,
    description: str,
    scan: Callable[[str, Dict[str, Any], Any], Envelope],
    argv: Optional[Sequence[str]] = None,
    configure: Optional[Callable[[argparse.ArgumentParser], None]] = None,
) -> int:
    """Standard main() for a scanner: parse, scan, print. Exit 0 with or without findings."""
    parser = base_parser(name + ".py", description)
    if configure:
        configure(parser)
    args = parser.parse_args(argv)
    project = open_project(args)
    project.options = args
    stack = load_stack(args, project)
    log("%s: scanning %s" % (name, args.app_root), args.quiet)
    env = scan(project.root, stack, project)
    for w in project.warnings:
        env.warn(w)
    doc = env.to_dict()
    emit(doc, args.out)
    log("%s: %d finding(s)" % (name, len(doc["findings"])), args.quiet)
    return EXIT_OK
