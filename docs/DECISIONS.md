# Decisions and deviations from the specification

- **Skill frontmatter** uses only `name` and `description` (portable across Claude Code and the Claude apps). Claude Code's docs recommend keeping SKILL.md under 500 lines; ours is under 400 as specified.
- **Name.** No skill or plugin named exactly `prodready` was found on 2026-11-13; similar names exist (`prod-ready`, `production-audit`). Kept `prodready`. The plugin name is not one of the reserved names.
- **Plugin layout.** Manifests are in `.claude-plugin/`; `skills/`, `commands/` and `agents/` are at the repository root; the marketplace entry uses `source: "./"`.
- **DB-004 narrowed.** PostgreSQL reuses USING as WITH CHECK for UPDATE and ALL policies when WITH CHECK is absent (https://www.postgresql.org/docs/current/sql-createpolicy.html), so the spec's detection would be a false positive. The check covers insert policies without WITH CHECK and explicitly weak WITH CHECK expressions.
- **Catalog as data.** Added `lib/catalog.py` and `tools/check_text.py` as the single source for IDs, severities and prose; the reference files and index are generated from them.
- **Prose depth.** Each check has plain words, why, fix and verify. Stack-specific code examples live in the playbooks, not per check.
- **Fixtures.** The clean fixtures carry stub lockfiles because a real `npm ci` lockfile needs a networked install. The build-after-fix end-to-end test is therefore not done.
- **`probe_live.py`** implements headers, exposed files and the Supabase anonymous read check; the Firebase probe and the DNS lookup are not implemented (see `ROADMAP.md`).
- **Evals** are provided as data and a rubric; the scenarios were not run in fresh Claude sessions.
- **README.ar.md** is not written yet.
