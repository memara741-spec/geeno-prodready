# Financial integrity (FIN)

What this covers: the 4 FIN checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### FIN-001 — Balance changed with no ledger entry
**Severity:** critical · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A balance is changed but no ledger or transaction row records why.

**How to detect:** Run `scripts/scan_ledger.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Without a record you cannot explain, reconcile or reverse a balance, and bugs or fraud leave no trace.

**Fix:** Write a ledger row (amount, direction, reason, reference) in the same database transaction as every balance change.

**Verify:** Sum of ledger rows equals the balance for every account.

### FIN-002 — Transfer takes money from one account without adding it to another
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A transfer takes money from one account and never adds it to another.

**How to detect:** Run `scripts/scan_ledger.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Money disappears, or is created, and the books stop balancing.

**Fix:** Debit and credit in one transaction, with matching ledger rows.

**Verify:** Total money before and after a transfer is equal.

### FIN-003 — Balance column can go negative
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A balance column can hold a negative number.

**How to detect:** Run `scripts/scan_ledger.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Any race or bug can overdraw an account and the database will not stop it.

**Fix:** Add a CHECK (balance >= 0) constraint or an unsigned column, in addition to the code check.

**Verify:** An insert that would go negative is rejected by the database.

### FIN-004 — Money table has no unique key against duplicates
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A payment, transfer or payout table has no unique key such as a reference or idempotency key.

**How to detect:** Run `scripts/scan_ledger.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** The same payment can be stored twice by a retry.

**Fix:** Add a unique index on the provider reference or idempotency key.

**Verify:** Inserting the same reference twice fails.


