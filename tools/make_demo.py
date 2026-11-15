#!/usr/bin/env python3
"""Regenerate docs/demo/sample-report.md and .html from the lovable-supabase-vite fixture."""
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = os.path.join(REPO, "skills", "prodready", "scripts")
FIX = os.path.join(REPO, "fixtures", "lovable-supabase-vite")
OUT = os.path.join(REPO, "docs", "demo")
os.environ["PRODREADY_FIXED_TIME"] = "2026-01-01T00:00:00Z"


def run(*args):
    subprocess.run([sys.executable, os.path.join(S, args[0])] + list(args[1:]), check=True)


def main():
    os.makedirs(OUT, exist_ok=True)
    findings = os.path.join(OUT, "findings.json")
    run("run_all.py", FIX, "--quiet", "--out", findings)
    run("render_report.py", FIX, "--findings", findings, "--name", "Souq Local (fixture)", "--out", os.path.join(OUT, "sample-report.md"))
    run("render_report.py", FIX, "--findings", findings, "--name", "Souq Local (fixture)", "--format", "html", "--out", os.path.join(OUT, "sample-report.html"))
    os.remove(findings)
    print("demo written to docs/demo")


if __name__ == "__main__":
    main()
