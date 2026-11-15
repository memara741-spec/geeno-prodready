# Security policy

To report a vulnerability in prodready, or a dangerous false negative (a serious problem the tool should have found and did not), email **the repository owner (MOHAMED IBRAHEM) via a private GitHub security advisory** with the version (`python3 skills/prodready/scripts/run_all.py --version`), what you ran, and a minimal reproduction with fake secrets. Please do not open a public issue for a vulnerability. We aim to acknowledge reports within a few days.

Scope: the scripts in `skills/prodready/scripts/`, the skill instructions, and the packaging. The scripts are read-only on the scanned app, use only the Python standard library, and make no network requests except `probe_live.py` with explicit consent flags.
