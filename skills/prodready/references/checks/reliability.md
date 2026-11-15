# Reliability and correctness (REL)

What this covers: the 8 REL checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### REL-001 — Unhandled failures in asynchronous code
**Severity:** medium · **Mode:** scan · **Applies to:** node, browser
**Auto-fix:** assisted

**In plain words:** Operations fail silently and the screen shows success.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Unawaited promises, ignored errors and unchecked responses.

**Fix:** Await and check; surface errors to the user and the tracker.

**Verify:** Scanner clean on changed files.

### REL-002 — External calls without timeouts or retry policy
**Severity:** medium · **Mode:** scan+review · **Applies to:** backends
**Auto-fix:** assisted

**In plain words:** A slow outside service can hang every request.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** No timeouts or retry policy on external calls.

**Fix:** Timeouts on every external call; bounded retries with backoff for idempotent operations only.

**Verify:** Review.

### REL-003 — Multi-step writes without a transaction
**Severity:** medium · **Mode:** review · **Applies to:** any database
**Auto-fix:** assisted

**In plain words:** A failure part-way through a multi-step write leaves inconsistent data.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** No transaction around related writes.

**Fix:** Use a database transaction or a single database function.

**Verify:** A forced failure at the second step leaves no partial data.

### REL-004 — State kept in process memory on serverless or multi-instance hosts
**Severity:** medium · **Mode:** scan · **Applies to:** serverless, autoscaled containers
**Auto-fix:** assisted

**In plain words:** State kept in server memory disappears or differs between instances.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** In-memory rate limits do not limit on serverless.

**Fix:** Use a shared store such as the database or a key-value service.

**Verify:** Scanner clean.

### REL-005 — Long-running work performed inside the request
**Severity:** medium · **Mode:** review · **Applies to:** serverless, any
**Auto-fix:** assisted

**In plain words:** Long work runs inside a request and can time out or be duplicated.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Timeouts, lost work and duplicated work on retry.

**Fix:** Use a queue or background function with status polling; make jobs idempotent.

**Verify:** Review.

### REL-006 — Date, time zone and locale handling errors
**Severity:** low · **Mode:** scan+review · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** Dates are handled in local time, causing off-by-one-day bugs.

**How to detect:** `scripts/scan_config.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** A large share of the world's users are affected.

**Fix:** Store UTC with zone-aware types and convert at the edges.

**Verify:** Tests around midnight and daylight saving changes.

### REL-007 — No tested path to restore service after data loss
**Severity:** high · **Mode:** review · **Applies to:** all
**Auto-fix:** owner

**In plain words:** An untested backup is a hope, not a backup.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Nobody has restored one.

**Fix:** Perform one restore into a scratch environment and record the steps and time taken.

**Verify:** Owner confirmation with a date.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### REL-008 — Hard dependency on a single third party in the critical path with no fallback
**Severity:** low · **Mode:** review · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** A non-essential outside service can take down sign-in or checkout.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Hard dependency on one third party with no fallback.

**Fix:** Load non-essential services asynchronously and fail open.

**Verify:** Blocking the vendor host leaves the core flow working.


