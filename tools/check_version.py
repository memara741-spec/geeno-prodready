#!/usr/bin/env python3
"""Check that manifests and the changelog agree with lib/findings.py __version__."""
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "skills", "prodready", "scripts"))
from lib import findings  # noqa: E402


def main():
    v = findings.__version__
    bad = []
    plugin = json.load(open(os.path.join(REPO, ".claude-plugin", "plugin.json"), encoding="utf-8"))
    if plugin.get("version") != v:
        bad.append("plugin.json version %s != %s" % (plugin.get("version"), v))
    market = json.load(open(os.path.join(REPO, ".claude-plugin", "marketplace.json"), encoding="utf-8"))
    for p in market.get("plugins", []):
        if p.get("version") not in (None, v):
            bad.append("marketplace.json version %s != %s" % (p.get("version"), v))
    if not re.search(r"^## \[%s\]" % re.escape(v), open(os.path.join(REPO, "CHANGELOG.md"), encoding="utf-8").read(), re.M):
        bad.append("CHANGELOG.md has no section for %s" % v)
    for b in bad:
        print("MISMATCH:", b)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
