# Record-level authorization (AUTHZ)

What this covers: the 4 AUTHZ checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### AUTHZ-001 — Policy exists but nothing enforces it
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A permission policy was written but no code ever asks it.

**How to detect:** Run `scripts/scan_authz.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A policy that is never called protects nothing; the app is as open as if it did not exist.

**Fix:** Call `$this->authorize()` in each action, add `authorizeResource()` to the controller, or use `can:` middleware on the routes.

**Verify:** A test as another user gets 403 on each action.

### AUTHZ-002 — Policy rule never compares the user with the record
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A policy rule never compares the signed-in user with the record, so it answers the same for everyone.

**How to detect:** Run `scripts/scan_authz.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Any user passes the check for any record.

**Fix:** Compare the record's owner or tenant with the user (`$user->id === $post->user_id`).

**Verify:** A test as a user who does not own the record gets 403.

### AUTHZ-003 — Some operations on a record are checked and others are not
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** This controller checks permission for some actions on a record but not for this one.

**How to detect:** Run `scripts/scan_authz.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Attackers use the unchecked action, for example delete, when view is protected.

**Fix:** Authorise every action, or use `authorizeResource()` so none can be forgotten.

**Verify:** Each action returns 403 for a user who may not do it.

### AUTHZ-004 — Policy rule always allows
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A policy rule always says yes.

**How to detect:** Run `scripts/scan_authz.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Every user is allowed to do that operation on every record.

**Fix:** Return a real condition, or remove the rule so the default (deny) applies.

**Verify:** A user without rights gets 403.


