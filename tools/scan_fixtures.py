#!/usr/bin/env python3
"""Scan every fixture into dist/fixture-findings/<name>.json."""
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN = os.path.join(REPO, "skills", "prodready", "scripts", "run_all.py")
OUT = os.path.join(REPO, "dist", "fixture-findings")


def main():
    os.makedirs(OUT, exist_ok=True)
    for name in sorted(os.listdir(os.path.join(REPO, "fixtures"))):
        path = os.path.join(REPO, "fixtures", name)
        if os.path.isdir(path):
            subprocess.run([sys.executable, RUN, path, "--quiet", "--out", os.path.join(OUT, name + ".json")], check=True)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
