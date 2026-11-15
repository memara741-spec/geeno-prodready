#!/usr/bin/env python3
"""Check that a database backup can really be used, and optionally rehearse the restore.

A backup nobody has restored is a hope. This script checks the backup file itself
and, when you ask, runs YOUR restore command against a scratch database.

Checks (no network, nothing leaves the machine): the file exists and is not empty,
is not older than ``--max-age-hours`` (default 36), is readable (zip CRC test, gzip
end-of-stream), contains the completion marker the dump tools write at the end, and
contains every table in ``--expect-tables`` or the tables defined by the migrations of
``--app-root``. Findings: PROD-005 for a missing, stale, damaged or incomplete backup.

Restore rehearsal: with ``--restore-cmd "<command with {file}>" --run-restore
--i-own-this`` it runs exactly that command (for example
``mysql -h scratch -u root scratch_db < {file}``) and, if given, ``--verify-cmd``
(for example a query that must exit 0). A non-zero exit gives PROD-006. Point it at a
scratch database only; the script cannot know which database your command targets.

What it deliberately does not do: it never runs a command you did not write, never
connects to a database itself, and cannot prove the restored data is correct, only
that the restore runs and your own verification passes.
"""
from __future__ import annotations

import argparse
import gzip
import os
import re
import subprocess
import sys
import time
import zipfile
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import catalog, findings, phpscan, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("restore_drill")
ALSO_EMITS: List[str] = []
MARKERS = re.compile(r"Dump completed|PostgreSQL database dump complete|-- End of dump|\bCOMMIT;\s*$", re.I | re.M)
MAX_READ = 64 * 1024 * 1024


def read_dump(path: str) -> Dict[str, Any]:
    """Return {'text': str, 'problem': str|None} for a .sql, .sql.gz, .gz, .dump or .zip backup."""
    low = path.lower()
    try:
        if low.endswith(".zip"):
            with zipfile.ZipFile(path) as z:
                bad = z.testzip()
                if bad:
                    return {"text": "", "problem": "the zip archive is damaged (bad CRC in %s)" % bad}
                names = [n for n in z.namelist() if re.search(r"\.(sql|sql\.gz|dump)$", n, re.I)]
                if not names:
                    return {"text": "", "problem": "the zip contains no .sql or .dump file (files: %s)" % ", ".join(z.namelist()[:5])}
                data = z.read(names[0])[:MAX_READ]
                if names[0].lower().endswith(".gz"):
                    data = gzip.decompress(data)
                return {"text": data.decode("utf-8", "replace"), "problem": None}
        if low.endswith(".gz"):
            with gzip.open(path, "rb") as fh:
                return {"text": fh.read(MAX_READ).decode("utf-8", "replace"), "problem": None}
        with open(path, "rb") as fh:
            head = fh.read(MAX_READ)
        if head.startswith(b"PGDMP"):
            return {"text": "", "problem": None, "binary": True}
        return {"text": head.decode("utf-8", "replace"), "problem": None}
    except (EOFError, OSError, zipfile.BadZipFile, ValueError) as exc:
        return {"text": "", "problem": "the file cannot be read to the end (%s); it is probably truncated" % type(exc).__name__}


def tables_from_app(root: str) -> List[str]:
    project = walker.Project(root)
    names: List[str] = []
    for pf in phpscan.php_files(project):
        if "/migrations/" in "/" + pf.rel:
            names += re.findall(r"Schema::create\(\s*['\"](\w+)['\"]", pf.code)
    return sorted(set(names))


def check_backup(path: str, max_age_h: float, expect: List[str]) -> Envelope:
    env = Envelope("restore_drill")
    sub = {"kind": "backup", "name": os.path.basename(path)}

    def bad(msg: str, sev: str = "high") -> None:
        env.add(Finding("PROD-005", msg, file=None, subject=sub, confidence="confirmed", severity=sev, owner_action="Fix the backup job, take a fresh backup and repeat this check.",
                        fix_hint="Make sure the backup job runs, writes to storage away from the server, and is monitored (spatie/laravel-backup `backup:monitor`, or your host's backup alerts)."))

    if not os.path.isfile(path):
        bad("No backup file at `%s`." % path, "critical")
        return env
    size = os.path.getsize(path)
    age_h = (time.time() - os.path.getmtime(path)) / 3600
    env.inventory["backup"] = {"file": os.path.basename(path), "bytes": size, "age_hours": round(age_h, 1)}
    if size == 0:
        bad("The backup file is empty.", "critical")
        return env
    if age_h > max_age_h:
        bad("The newest backup is %.0f hours old (limit %.0f). The backup job has probably stopped." % (age_h, max_age_h))
    dump = read_dump(path)
    if dump["problem"]:
        bad("The backup cannot be used: %s." % dump["problem"], "critical")
        return env
    text = dump["text"]
    if dump.get("binary"):
        env.warn("PostgreSQL custom-format dump: completeness and table names were not checked; use pg_restore --list on it")
        return env
    if not MARKERS.search(text[-4000:]):
        bad("The dump has no completion marker at the end, so it was probably cut short while being written.")
    found = set(re.findall(r"CREATE TABLE(?: IF NOT EXISTS)?\s+[`\"]?(?:\w+\.)?[`\"]?(\w+)[`\"]?", text, re.I))
    missing = [t for t in expect if t not in found]
    env.inventory["backup"]["tables_found"] = len(found)
    if missing:
        bad("The backup is missing %d expected table(s): %s. A restore would lose them." % (len(missing), ", ".join(missing[:12])))
    return env


def rehearse(env: Envelope, path: str, restore_cmd: str, verify_cmd: Optional[str], timeout: int) -> None:
    def run(cmd: str) -> int:
        return subprocess.run(cmd, shell=True, timeout=timeout, capture_output=True, text=True).returncode

    sub = {"kind": "restore", "name": os.path.basename(path)}
    try:
        code = run(restore_cmd.replace("{file}", path))
    except subprocess.TimeoutExpired:
        code = -1
    env.inventory["restore"] = "restore command exited %s" % code
    if code != 0:
        env.add(Finding("PROD-006", "The restore rehearsal failed: your restore command exited with %s. A real emergency would fail the same way." % code, subject=sub, confidence="confirmed",
                        fix_hint="Run the command by hand against the scratch database, fix the error, and keep the working command in your runbook.", owner_action="Write down and test the restore procedure."))
        return
    if verify_cmd:
        try:
            vcode = run(verify_cmd)
        except subprocess.TimeoutExpired:
            vcode = -1
        env.inventory["restore"] += "; verify command exited %s" % vcode
        if vcode != 0:
            env.add(Finding("PROD-006", "The restore ran but your verification command failed (exit %s), so the restored data is not what you expected." % vcode, subject=sub, confidence="confirmed",
                            fix_hint="Check row counts and recent records in the restored database against production.", owner_action="Find out what is missing from the backup."))


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="restore_drill.py", description=(__doc__ or "").split("\n\n")[0])
    p.add_argument("--backup", required=True, help="path to the newest backup file")
    p.add_argument("--max-age-hours", type=float, default=36)
    p.add_argument("--expect-tables", help="comma-separated table names that must be in the dump")
    p.add_argument("--app-root", help="take the expected tables from this Laravel app's migrations")
    p.add_argument("--restore-cmd", help="your restore command; {file} is replaced by the backup path")
    p.add_argument("--verify-cmd", help="a command that must exit 0 after the restore")
    p.add_argument("--run-restore", action="store_true")
    p.add_argument("--i-own-this", action="store_true")
    p.add_argument("--timeout", type=int, default=3600)
    p.add_argument("--out")
    p.add_argument("--version", action="version", version="prodready %s" % findings.__version__)
    args = p.parse_args(argv)
    if args.restore_cmd and not (args.run_restore and args.i_own_this):
        sys.stderr.write("prodready: --restore-cmd runs your command. Add --run-restore and --i-own-this, and point it at a scratch database.\n")
        return findings.EXIT_USAGE
    expect = [t.strip() for t in (args.expect_tables or "").split(",") if t.strip()]
    if args.app_root:
        expect += [t for t in tables_from_app(os.path.abspath(args.app_root)) if t not in expect]
    env = check_backup(args.backup, args.max_age_hours, expect)
    if args.restore_cmd and os.path.isfile(args.backup):
        rehearse(env, os.path.abspath(args.backup), args.restore_cmd, args.verify_cmd, args.timeout)
    findings.emit(env.to_dict(), args.out)
    return findings.EXIT_FINDINGS if env.findings else findings.EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
