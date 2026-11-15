#!/usr/bin/env python3
"""Find secrets that were committed in the past, even if they are gone from the current files.

Detects: a credential that appears in an added line of any commit (SEC-003),
and env files that were ever tracked. Each distinct secret is reported once,
with the first commit that introduced it, redacted. Whether the repository is
public cannot be known offline, so the finding says so.

What it deliberately does not do: it never prints a secret, never rewrites
history, and never contacts the remote. It reads ``git log`` output only.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import catalog, findings, patterns, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402
from lib.redact import redact  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_git_history")
ALSO_EMITS: List[str] = []


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_git_history", stack)
    opts = getattr(project, "options", None)
    max_commits = int(getattr(opts, "max_commits", 2000) or 2000)
    since = getattr(opts, "since", None)
    if not project.is_git_repo:
        env.warn("scan_git_history: not a git repository; history was not checked")
        return env
    cmd = ["git", "-C", project.root, "log", "--all", "-p", "--no-color", "--no-ext-diff", "-n", str(max_commits), "--format=@@commit %H"]
    if since:
        cmd.append("--since=%s" % since)
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=300)
    except (OSError, subprocess.SubprocessError):
        env.warn("scan_git_history: git is not available or timed out")
        return env
    if proc.returncode != 0:
        env.warn("scan_git_history: git log failed (empty repository?)")
        return env
    text = proc.stdout.decode("utf-8", errors="replace")[:60_000_000]
    commit, file = "", ""
    seen: Dict[str, bool] = {}
    ever_env: Dict[str, str] = {}
    remote = ""
    try:
        cfg = open(os.path.join(project.root, ".git", "config"), encoding="utf-8", errors="replace").read()
        m = re.search(r"url\s*=\s*(\S+)", cfg)
        remote = m.group(1) if m else ""
    except OSError:
        pass
    host = re.search(r"(?:@|//)([\w.-]+)[:/]", remote)
    public_host = bool(host and host.group(1) in ("github.com", "gitlab.com", "bitbucket.org"))
    current = {rel for rel in project.all_paths()}
    for line in text.split("\n"):
        if line.startswith("@@commit "):
            commit = line[9:17]
        elif line.startswith("+++ b/"):
            file = line[6:]
            if walker.is_env_file(file) and not walker.is_env_example(file):
                ever_env.setdefault(file, commit)
        elif line.startswith("+") and not line.startswith("+++"):
            if len(line) > 2000 or not file or file.endswith(tuple(walker.ASSET_EXTS)) or file.rsplit("/", 1)[-1] in walker.LOCKFILES:
                continue
            for m in patterns.find_secrets(line[1:]):
                if m.public or m.pattern.generic or (m.pattern.id == "jwt" and m.label != "supabase-service-role"):
                    continue
                key = hashlib.sha256(m.value.encode()).hexdigest()
                if key in seen:
                    continue
                seen[key] = True
                still = False
                tf = project.get(file)
                if tf and m.value in project.text(tf):
                    still = True
                provider = m.pattern.description.split(" (")[0]
                env.add(Finding(
                    "SEC-003", "A %s was saved in your repository's history (commit %s, %s). Deleting the file later does not remove it: anyone who can clone the repository can still read it." % (provider, commit, file),
                    file=file, snippet="%s (%s) first seen in commit %s" % (provider, redact(m.value), commit), confidence="confirmed",
                    severity="critical" if public_host else "high", subject={"kind": "history-secret", "name": key[:12]},
                    detail="%s, %s. %s%s Repository visibility cannot be determined offline; if it is public the key must be treated as compromised." % (
                        redact(m.value), "still present in the working tree" if still else "removed from the current files", "Remote host: %s. " % host.group(1) if host else "No remote configured. ", ""),
                    fix_hint="Rotate the key first; that is what makes it safe. Rewriting history is optional and disruptive.",
                    owner_action="references/owner-actions/rotate-keys.md",
                ))
    for f, c in sorted(ever_env.items()):
        env.add(Finding(
            "SEC-003", "The settings file `%s` was committed (commit %s). Everything that was in it at that time is in the history." % (f, c),
            file=f, snippet="env file tracked in commit %s" % c, confidence="confirmed", severity="high", subject={"kind": "history-env", "name": f},
            detail="Env file appears in git history%s." % ("" if f not in current else " and still exists in the working tree"),
            fix_hint="Rotate every key that file ever held, then see references/owner-actions/purge-git-history.md.",
            owner_action="references/owner-actions/purge-git-history.md",
        ))
    env.inventory["git_history"] = {"commits_scanned_limit": max_commits, "remote_host": host.group(1) if host else None, "visibility": "unknown offline"}
    env.files_scanned, env.files_skipped = 0, 0
    return env


def main(argv: Optional[List[str]] = None) -> int:
    def configure(p: Any) -> None:
        p.add_argument("--max-commits", type=int, default=2000)
        p.add_argument("--since", default=None)

    return findings.run_scanner_cli("scan_git_history", __doc__ or "", scan, argv, configure)


if __name__ == "__main__":
    raise SystemExit(main())
