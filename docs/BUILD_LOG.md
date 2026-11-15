# Build log

One dated line per meaningful decision or deviation. Terse by design; the reasoning is in `DECISIONS.md`.

- 2026-11-13 Phase 0. Read the Claude Code skills, plugin manifest and marketplace docs. Skill frontmatter limited to the portable fields (`name`, `description`); description kept under 1,024 characters.
- 2026-11-13 Phase 0. Name check: no skill or plugin named exactly `prodready` found; several named `prod-ready` or `production-audit` exist. Kept `prodready`.
- 2026-11-13 Phase 0. Competition survey written from public listings (see `COMPETITION.md`).
- 2026-11-13 Phase 0. Platform facts confirmed against vendor docs today: Supabase key types, PostgreSQL policy semantics, Supabase server-side auth calls, Next.js advisories (CVE-2025-29927, CVE-2025-66478, CVE-2025-55183/55184/67779), Next.js and Django support windows, Stripe webhook signing, jsonwebtoken and mongoose advisories.
- 2026-11-13 Phase 0. PostgreSQL docs contradict the spec's DB-004 detection for UPDATE and ALL policies (USING is reused as WITH CHECK when WITH CHECK is absent). DB-004 narrowed to the cases that are actually exploitable.
- 2026-11-13 Phase 1. Added `lib/catalog.py` as the single machine-readable check list. Core library and its tests green.
- 2026-11-15 Phase 2-4. Nine fixtures built; detect_stack and eleven scanners written; every `must_find` across the fixtures is found, no `must_not_find` fires, no critical false positives. Speculative expectations (REL-001, REL-006, DEP-012 on the Lovable fixture) were removed because the scanners cannot support them honestly.
- 2026-11-15 Phase 5 (part). run_all (json, sarif, summary, baseline, fail-on, ignore config) and verify_fixes written. SKILL.md, three commands and two agents written.
- 2026-11-15 Clean fixtures carry stub lockfiles: `npm ci` needs a real lockfile from a networked install, which was not possible here, so the end-to-end build test is not done.
- 2026-11-15 Phase 5-10. render_report and probe_live written; reference playbooks, owner actions, report guides and check files (generated from catalog and prose) written; assets, manifests, README (English and Arabic), docs, evals data, CI workflows and packaging written. 49 tests pass on Windows.
- 2026-11-15 Not done: `claude plugin validate` (CLI not available here), evals run in fresh sessions, Linux and macOS runs, `npm ci` build of the clean fixture, Firebase probe and DNS lookup in probe_live.
