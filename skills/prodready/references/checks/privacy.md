# Privacy and data protection (PRIV)

What this covers: the 8 PRIV checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### PRIV-001 — No privacy policy or terms where personal data is collected
**Severity:** medium · **Mode:** scan · **Applies to:** web, mobile
**Auto-fix:** owner/assisted

**In plain words:** The app collects accounts but has no privacy policy or terms.

**How to detect:** Run `scripts/scan_launch.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Required by law in most markets, by app stores, payment providers and sign-in screens.

**Fix:** Add pages linked from sign-up and the footer; draft a factual data inventory for your lawyer. This is not legal advice.

**Verify:** Pages exist and are linked.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### PRIV-002 — Trackers load before consent where consent is required
**Severity:** medium · **Mode:** scan+review · **Applies to:** web
**Auto-fix:** assisted

**In plain words:** Tracking scripts load before visitors are asked.

**How to detect:** `scripts/scan_frontend.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Regulatory exposure and ad-platform policy violations where consent is required.

**Fix:** Gate non-essential scripts behind consent or use privacy-friendly analytics.

**Verify:** Scripts absent before consent.

### PRIV-003 — Users cannot delete their account or export their data
**Severity:** medium · **Mode:** scan+review · **Applies to:** all with accounts
**Auto-fix:** assisted

**In plain words:** Users cannot delete their account or export their data.

**How to detect:** `scripts/scan_launch.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** A legal right in many regions and an app store requirement.

**Fix:** A deletion endpoint that removes rows, files and third-party records, with a confirmation step and a data export.

**Verify:** After deletion no rows or objects for the user remain.

### PRIV-004 — Personal data in logs, analytics events or error reports
**Severity:** medium · **Mode:** scan+review · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** Personal data appears in logs, analytics events or error reports.

**How to detect:** `scripts/scan_secrets.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Copies spread to systems with weaker controls and longer retention.

**Fix:** Log IDs, scrub in the tracker's before-send hook, mask inputs in session replay.

**Verify:** Scanner clean; tracker configuration reviewed.

### PRIV-005 — Sensitive data stored unprotected or collected without need
**Severity:** high · **Mode:** scan+review · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** Sensitive data is stored unprotected, or passwords use a fast hash.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** A breach causes real harm to people and severe consequences for you.

**Fix:** Collect less; use argon2id, scrypt or bcrypt; encrypt sensitive fields; get a professional audit for regulated data.

**Verify:** Scanner clean; schema review.

### PRIV-006 — No list of third parties that receive user data
**Severity:** low · **Mode:** scan · **Applies to:** all
**Auto-fix:** auto

**In plain words:** You need a list of outside services that receive your users' data.

**How to detect:** Run `scripts/scan_launch.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** For the privacy policy, customer questionnaires and incident response.

**Fix:** Copy the generated inventory into the report appendix and complete it.

**Verify:** Inventory present.

### PRIV-007 — Session replay or analytics captures form inputs
**Severity:** medium · **Mode:** scan · **Applies to:** web
**Auto-fix:** assisted

**In plain words:** Session recording captures what users type.

**How to detect:** Run `scripts/scan_frontend.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Passwords and private messages end up in a third party's recordings.

**Fix:** Mask all inputs by default and exclude sensitive pages.

**Verify:** Configuration review.

### PRIV-008 — No data retention or cleanup
**Severity:** low · **Mode:** review · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** Old data is kept forever.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Old data is pure liability.

**Fix:** Define retention periods and add cleanup jobs.

**Verify:** Jobs or policies present.


