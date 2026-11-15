# Frontend (FE)

What this covers: the 9 FE checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### FE-001 — User-controlled content inserted as HTML
**Severity:** high · **Mode:** scan+review · **Applies to:** react, vue, svelte, angular, plain js
**Auto-fix:** assisted

**In plain words:** Content users can write is inserted as live HTML, so a posted script runs in other visitors' browsers.

**How to detect:** `scripts/scan_frontend.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Cross-site scripting.

**Fix:** Render as text; sanitise with a maintained sanitiser when HTML is required; validate URL schemes.

**Verify:** Scanner clean or each remaining sink is a documented constant.

### FE-002 — Sensitive data kept in browser storage or client state longer than needed
**Severity:** medium · **Mode:** scan+review · **Applies to:** web, mobile
**Auto-fix:** assisted

**In plain words:** Personal data is kept in the browser's storage longer than needed.

**How to detect:** `scripts/scan_frontend.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Readable by any script, extension and the next person on a shared device.

**Fix:** Store the minimum and clear it on sign-out; use secure storage on mobile.

**Verify:** Review of persisted keys.

### FE-003 — Debug output in production builds
**Severity:** low · **Mode:** scan · **Applies to:** web, mobile
**Auto-fix:** auto

**In plain words:** Debug output is left in the app and is visible to anyone who opens the console.

**How to detect:** Run `scripts/scan_frontend.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Leaks data and signals an unfinished product.

**Fix:** Remove it or strip it at build time.

**Verify:** Scanner clean.

### FE-004 — No error boundary or global error handling
**Severity:** medium · **Mode:** scan · **Applies to:** react, nextjs, vue, svelte
**Auto-fix:** assisted

**In plain words:** One runtime error turns the whole app into a blank white page.

**How to detect:** Run `scripts/scan_frontend.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** No error boundary or global error handling.

**Fix:** Add boundaries with a recovery action and reporting to the tracker.

**Verify:** Files present; a forced error shows the fallback.

### FE-005 — Missing loading, empty and failure states on key screens
**Severity:** low · **Mode:** review · **Applies to:** web, mobile
**Auto-fix:** assisted

**In plain words:** Key screens have no loading, empty or failure state.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** First real users hit slow networks and empty accounts immediately.

**Fix:** Add the three states to sign-up, the core action and payment.

**Verify:** Review and manual check list.

### FE-006 — Forms can be submitted twice
**Severity:** low · **Mode:** review · **Applies to:** web, mobile
**Auto-fix:** assisted

**In plain words:** Forms can be submitted twice.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Duplicate records and charges.

**Fix:** Pending state in the UI plus server idempotency.

**Verify:** Review.

### FE-007 — Third-party scripts loaded without need or integrity
**Severity:** low · **Mode:** scan · **Applies to:** web
**Auto-fix:** assisted

**In plain words:** A script from another company's server loads with no integrity check.

**How to detect:** Run `scripts/scan_frontend.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A compromised third-party script runs with full access to the page.

**Fix:** Self-host or pin with an integrity hash, remove what is not needed, restrict with CSP.

**Verify:** Scanner clean.

### FE-008 — Basic accessibility and mobile layout gaps
**Severity:** low · **Mode:** scan+review · **Applies to:** web
**Auto-fix:** assisted

**In plain words:** Some visitors cannot use parts of the app: missing language, image descriptions or keyboard access.

**How to detect:** `scripts/scan_frontend.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Excludes users and in some markets creates legal exposure.

**Fix:** Fix the automated findings and do a keyboard-only pass.

**Verify:** Scanner counts drop to zero.

### FE-009 — Links opening new tabs without isolation, and unsafe external navigation
**Severity:** low · **Mode:** scan · **Applies to:** web
**Auto-fix:** auto

**In plain words:** Links that open a new tab do not isolate it from your page.

**How to detect:** Run `scripts/scan_frontend.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Minor tab-nabbing risk, cheap to fix.

**Fix:** Add rel="noopener noreferrer" and validate URLs.

**Verify:** Scanner clean.


