# Contributing

- **Add a check:** follow `docs/CHECK_AUTHORING.md`. A scan check needs a fixture that triggers it and a clean fixture that does not.
- **Add a fixture:** a small realistic app under `fixtures/<name>/` with `expected.json` (`must_find`, `review_only`, `must_not_find`, `max_false_positive_criticals`). Planted secrets must be obviously fake and marked `prodready-fixture: fake`.
- **Report a false positive:** open the "false positive" issue with the redacted snippet, the stack and its version, and a minimal reproduction. A false critical costs every user's trust, so these get priority.
- **Standard library only.** Scanners must run with `python3 script.py --help` and no install. This is what lets people run them on private code without trusting a dependency tree.
- **Style:** type hints, a module docstring saying what the script detects and what it deliberately does not, deterministic output (sorted, no timestamps in findings), and never print a secret.
- **Before a pull request:** `python3 -m unittest discover -s tests -t tests`, and `python3 tools/gen_checks.py` if you changed `tools/check_text.py` or the catalog.
- **Outdated platform fact?** Open an issue with the vendor documentation URL.
- **No `make`?** (for example on Windows) run the python commands from the Makefile directly.
