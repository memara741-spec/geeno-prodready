# Observability (OBS)

What this covers: the 6 OBS checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### OBS-001 — No error tracking
**Severity:** high · **Mode:** scan · **Applies to:** all
**Auto-fix:** assisted+owner

**In plain words:** If the app breaks for a user, you will not find out.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** The owner learns about failures from angry users, or never.

**Fix:** Add a tracker on client and server with release tagging, personal data scrubbing and private source maps.

**Verify:** A test error appears in the tracker.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### OBS-002 — No usable server logs
**Severity:** medium · **Mode:** scan+review · **Applies to:** backends
**Auto-fix:** assisted

**In plain words:** Errors are swallowed or logs are unusable, so incidents cannot be investigated.

**How to detect:** `scripts/scan_config.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Attacks leave no trace.

**Fix:** Structured logs with request ID, route, status, duration and user ID; never secrets; handle or rethrow every caught error.

**Verify:** Sample log line reviewed; empty catch blocks removed.

### OBS-003 — No uptime monitoring or alerting
**Severity:** medium · **Mode:** review · **Applies to:** all
**Auto-fix:** owner

**In plain words:** Downtime can go unnoticed for hours.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** No uptime monitoring or alerting.

**Fix:** An external check on the health endpoint and main page, alerting a channel someone watches.

**Verify:** Owner confirmation.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### OBS-004 — No audit trail for sensitive actions
**Severity:** medium · **Mode:** review · **Applies to:** admin, billing, roles, data export
**Auto-fix:** assisted

**In plain words:** After an incident nobody can say who did what.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** No audit trail for sensitive actions.

**Fix:** An append-only server-written audit table: actor, action, target, time, request ID.

**Verify:** Table and write calls present.

### OBS-005 — No visibility into the core funnel
**Severity:** low · **Mode:** review · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** You cannot tell whether launch is working.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** No visibility into sign-up, activation and payment.

**Fix:** A handful of server-side events for the key steps.

**Verify:** Events visible.

### OBS-006 — No incident plan
**Severity:** low · **Mode:** review · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** The first incident will be handled by improvisation.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** No runbook.

**Fix:** A one-page RUNBOOK.md: hosting, rollback, key rotation, restore, contacts, user notification.

**Verify:** RUNBOOK.md exists.


