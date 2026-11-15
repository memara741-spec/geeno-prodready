# Authoring a check

Worked example: adding `API-020 Logout redirects to a caller-supplied URL`.

1. **Catalog.** Add a row to `skills/prodready/scripts/lib/catalog.py` (next free number in the category; never reuse an ID): `API-020|medium|scan|assisted|all backends|scan_routes|Logout redirects to a caller-supplied URL`.
2. **Prose.** Add an entry to `tools/check_text.py` (plain words, why, fix, verify), then run `python3 tools/gen_checks.py` to regenerate the reference files and the index.
3. **Pattern.** Put new regular expressions in `lib/patterns.py` with a positive and a negative example, or keep the logic next to the scanner when it is specific to one check.
4. **Scanner.** Emit `Finding("API-020", message, file=..., line=..., snippet=..., confidence=...)` in the owning scanner. Prefer `likely` unless the pattern is unambiguous; explain in `detail`; give a `fix_hint`.
5. **Fixtures.** Plant the issue in a vulnerable fixture and list it in that fixture's `expected.json` under `must_find`; make sure the clean fixtures do not trigger it (`must_not_find` if it is a likely false positive).
6. **Test.** Run `python3 tools/expect.py` and `python3 -m unittest discover -s tests -t tests`.
7. **Changelog.** Adding a check is a minor version: note it in `CHANGELOG.md`.

A check must be specific enough that two reviewers would agree whether an app fails it. The catalog count is asserted by `tests/test_lib.py`; update it when you add a check.
