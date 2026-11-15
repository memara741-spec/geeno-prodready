#!/usr/bin/env python3
"""Build dist/prodready-skill.zip containing exactly the skills/prodready folder (SKILL.md at prodready/SKILL.md)."""
import os
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "skills", "prodready")
OUT = os.path.join(REPO, "dist", "prodready-skill.zip")


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for dirpath, dirnames, filenames in os.walk(SRC):
            dirnames[:] = sorted(d for d in dirnames if d not in ("__pycache__", ".pytest_cache"))
            for name in sorted(filenames):
                if name.endswith((".pyc", ".pyo")):
                    continue
                full = os.path.join(dirpath, name)
                arc = "prodready/" + os.path.relpath(full, SRC).replace(os.sep, "/")
                info = zipfile.ZipInfo(arc, (2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                with open(full, "rb") as fh:
                    z.writestr(info, fh.read())
    print("wrote", os.path.relpath(OUT, REPO))


if __name__ == "__main__":
    main()
