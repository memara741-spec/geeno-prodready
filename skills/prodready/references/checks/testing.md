# Tests and CI (TEST)

What this covers: the 4 TEST checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### TEST-001 — No automated test for the critical paths
**Severity:** medium · **Mode:** scan · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** There are no automated tests, so any later change can silently break sign-up or payment.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Especially risky with AI-agent edits.

**Fix:** Add a small set: sign-in, the core action, cross-user denial, payment webhook handling.

**Verify:** Tests run and pass in CI.

### TEST-002 — No access-rule tests
**Severity:** medium · **Mode:** scan · **Applies to:** supabase, firebase, any
**Auto-fix:** assisted

**In plain words:** Nothing tests the access rules, which are your main security boundary.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** One edit can open the database.

**Fix:** Generate tests from assets/sql/rls_test.sql.tmpl or emulator rule tests.

**Verify:** Tests pass and fail when a policy is deliberately loosened.

### TEST-003 — No CI pipeline running checks before deploy
**Severity:** medium · **Mode:** scan · **Applies to:** github, gitlab
**Auto-fix:** auto

**In plain words:** Nothing checks changes before they go live.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Broken and insecure changes ship unchecked.

**Fix:** Install assets/ci/prodready.yml and add install, typecheck, test, build and audit steps.

**Verify:** The workflow runs green.

### TEST-004 — Secret scanning not enabled on the repository
**Severity:** low · **Mode:** review · **Applies to:** github
**Auto-fix:** owner

**In plain words:** Your repository does not block the next leaked key before it is pushed.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Secret scanning and push protection prevent leaks.

**Fix:** Enable secret scanning and push protection; optional pre-commit hook.

**Verify:** Owner confirmation.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.


