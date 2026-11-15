# Launch polish (LAUNCH)

What this covers: the 10 LAUNCH checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### LAUNCH-001 — Default or missing page metadata
**Severity:** low · **Mode:** scan · **Applies to:** web
**Auto-fix:** assisted

**In plain words:** Shared links show a default title, description or someone else's image.

**How to detect:** Run `scripts/scan_frontend.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Default or missing page metadata.

**Fix:** Set title, description, canonical URL and social image.

**Verify:** Scanner clean.

### LAUNCH-002 — Default favicon, missing app icons and manifest
**Severity:** low · **Mode:** scan · **Applies to:** web
**Auto-fix:** assisted

**In plain words:** The app's icons or web manifest are still the template's or missing.

**How to detect:** Run `scripts/scan_frontend.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A visible sign of an unfinished product.

**Fix:** Replace with your own assets.

**Verify:** Scanner clean.

### LAUNCH-003 — Search engine controls missing or wrong
**Severity:** low · **Mode:** scan · **Applies to:** web
**Auto-fix:** assisted

**In plain words:** Search engines get no guidance, or are told to ignore the site.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Missing or wrong robots and sitemap.

**Fix:** Correct robots rules and sitemap; noindex non-production environments.

**Verify:** Scanner clean.

### LAUNCH-004 — Placeholder content and mock data shipped
**Severity:** medium · **Mode:** scan · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** Placeholder content or fake testimonials are still in the app.

**How to detect:** Run `scripts/scan_frontend.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Destroys credibility; invented statistics can be unlawful advertising.

**Fix:** Replace or remove; wire or remove dead controls.

**Verify:** Scanner clean.

### LAUNCH-005 — Builder branding, badges and scaffolding left in place
**Severity:** low · **Mode:** scan · **Applies to:** lovable, bolt, v0, replit
**Auto-fix:** assisted

**In plain words:** The AI builder's badge, scripts or default README are still in the app.

**How to detect:** Run `scripts/scan_frontend.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Unprofessional, and some scaffolding adds scripts you do not control.

**Fix:** Remove where your plan permits and replace the README.

**Verify:** Scanner clean.

### LAUNCH-006 — No way for users to get help or report a problem
**Severity:** low · **Mode:** scan · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** Users cannot get help or report a security problem.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Problems go unreported or are reported publicly.

**Fix:** Add a support email or form and a security.txt.

**Verify:** Present.

### LAUNCH-007 — Custom domain, redirects and certificates not finalised
**Severity:** medium · **Mode:** review · **Applies to:** web
**Auto-fix:** owner

**In plain words:** Domain, redirects or certificates are not finalised.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Duplicate hosts split cookies and rankings; auth callbacks fail on the wrong host.

**Fix:** Choose a canonical host, redirect the other, update every provider's allowed URL list.

**Verify:** Owner confirmation.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### LAUNCH-008 — Mobile store requirements unmet
**Severity:** medium · **Mode:** scan+review · **Applies to:** expo, react-native, capacitor, flutter
**Auto-fix:** assisted+owner

**In plain words:** App store requirements are not met yet.

**How to detect:** `scripts/scan_config.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Store rejection delays launch by days or weeks.

**Fix:** Add permission descriptions, real bundle identifiers, HTTPS-only traffic and in-app account deletion.

**Verify:** Scanner clean for the automated items.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### LAUNCH-009 — No README or handover documentation
**Severity:** low · **Mode:** scan · **Applies to:** all
**Auto-fix:** auto

**In plain words:** There is no README explaining how to run and deploy the app.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Nobody else, including a future AI agent, can work on it safely.

**Fix:** Write what the app is, the stack, how to run it, environment variables, how to deploy, and where data lives.

**Verify:** File present and accurate.

### LAUNCH-010 — First-run experience untested with a fresh account
**Severity:** medium · **Mode:** review · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** A brand-new user's first run has never been tried on production.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** The first real user hits the path the builder never tested.

**Fix:** Run a ten-step manual smoke test on the production deployment before announcing.

**Verify:** Owner confirms completion.

## Launch checklist (phase 7)

Mark each item done, not done or not applicable; list owner actions still open; restate the verdict.

- [ ] No open critical or high findings (or accepted in writing).
- [ ] Every leaked key rotated and confirmed by the owner (SEC-001 to SEC-003, SEC-013).
- [ ] Row level security or rules verified with a cross-user test (DB-001 to DB-011).
- [ ] Payments: live keys only in production, verified webhook, one real low-value purchase refunded (PAY-001 to PAY-008).
- [ ] Backups on and one restore done (DB-016, REL-007).
- [ ] Error tracking and uptime monitoring alert someone (OBS-001, OBS-003).
- [ ] Email domain authenticated and sign-up email received (MAIL-001, MAIL-002).
- [ ] Privacy policy, terms, support contact and account deletion (PRIV-001, PRIV-003, LAUNCH-006).
- [ ] Production domain, redirects and provider URL allow-lists updated (LAUNCH-007, MAIL-003).
- [ ] Budgets and alerts at pay-per-use providers (DEP-014).
- [ ] Code in the owner's own repository with branch protection (DEP-011, DEP-013).
- [ ] Ten-step smoke test with a fresh account on production (LAUNCH-010).

