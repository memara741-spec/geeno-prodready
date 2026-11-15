# Business logic and money (BIZ)

What this covers: the 7 BIZ checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### BIZ-001 — Balance or stock changed by read-then-write without a lock
**Severity:** critical · **Mode:** scan · **Applies to:** laravel, node
**Auto-fix:** assisted

**In plain words:** A balance or stock level is read, changed in PHP and written back without a lock.

**How to detect:** Run `scripts/scan_logic.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Two requests at once both read the old value, so money or stock is created or spent twice.

**Fix:** Use a transaction with `lockForUpdate()` or atomic `decrement()` with a condition.

**Verify:** A concurrency test firing two debits at once never overdraws.

### BIZ-002 — Availability checked and then acted on without a lock or unique constraint
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** The code checks that something is free and then books it in a separate step.

**How to detect:** Run `scripts/scan_logic.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Two buyers asking at the same moment both pass the check and the last seat is sold twice.

**Fix:** Check and write in one locked transaction and add a unique index on the slot.

**Verify:** Two simultaneous bookings for one slot: one succeeds, one gets 409.

### BIZ-003 — Money-moving endpoint has no protection against repeats
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A payment or transfer route does nothing about the same request arriving twice.

**How to detect:** Run `scripts/scan_logic.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Double clicks and retries after a timeout charge or pay twice.

**Fix:** Require an idempotency key stored in a unique column and return the saved result on a repeat.

**Verify:** Sending the same request twice moves money once.

### BIZ-004 — Amount from the request is not limited to a positive range
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** An amount is not limited to a positive range.

**How to detect:** Run `scripts/scan_logic.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A negative amount reverses a transfer and credits the sender.

**Fix:** Add `min:0.01` and a `max`, and prefer integer cents.

**Verify:** A request with -5 gets 422.

### BIZ-005 — Money stored in a floating-point column
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** Money is stored as a floating-point number.

**How to detect:** Run `scripts/scan_logic.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Floats cannot hold 0.10 exactly, so totals drift and balances stop matching.

**Fix:** Use decimal columns or integer cents.

**Verify:** Sum of ten 0.10 payments equals exactly 1.00.

### BIZ-006 — Client can set price, total, status or balance fields
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** The client can send a price, total, discount or paid status that the server saves.

**How to detect:** Run `scripts/scan_logic.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Customers can set their own price to zero or mark an order as paid.

**Fix:** Compute money fields on the server from product IDs and your own prices; change statuses only from verified events.

**Verify:** Posting `price=0` does not change the stored price.

### BIZ-007 — Queued money job can run twice
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A queued job that moves money can run twice.

**How to detect:** Run `scripts/scan_logic.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Queues re-deliver jobs after crashes and timeouts, so a payout can be paid twice.

**Fix:** Make the job unique or record a processed marker in the same transaction.

**Verify:** Dispatching the job twice changes the balance once.


