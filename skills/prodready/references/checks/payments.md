# Payments and entitlements (PAY)

What this covers: the 11 PAY checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### PAY-001 — Amount, price or plan taken from the client
**Severity:** critical · **Mode:** scan+review · **Applies to:** stripe, paddle, lemon squeezy, paypal, razorpay
**Auto-fix:** assisted

**In plain words:** The buyer's browser decides the price or plan, so anyone can pay what they like.

**How to detect:** `scripts/scan_payments.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** The buyer sets their own price.

**Fix:** The client sends only product or plan identifiers; the server maps them to prices it controls and recomputes totals.

**Verify:** A tampered amount is ignored or rejected.

### PAY-002 — Payment webhook signature not verified
**Severity:** critical · **Mode:** scan · **Applies to:** all payment providers
**Auto-fix:** assisted

**In plain words:** Anyone can send a fake "payment succeeded" message and get paid access for free.

**How to detect:** Run `scripts/scan_payments.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A forged event grants paid access.

**Fix:** Verify with the provider library and the raw body; use separate secrets per environment.

**Verify:** An unsigned event returns 400.

### PAY-003 — Access granted on the success redirect instead of a verified event
**Severity:** critical · **Mode:** review · **Applies to:** all payment providers
**Auto-fix:** assisted

**In plain words:** Opening the success page grants paid access without any payment.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Real payments that complete after the tab closes are also lost.

**Fix:** Grant entitlements in the verified webhook; the success page only displays status.

**Verify:** Hitting the success URL without payment changes nothing.

### PAY-004 — Webhook handler is not idempotent or ignores event ordering
**Severity:** high · **Mode:** review · **Applies to:** all payment providers
**Auto-fix:** assisted

**In plain words:** Payment events can arrive twice or out of order, giving double credits or wrong states.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Providers retry and reorder events.

**Fix:** Store processed event IDs with a unique constraint; set state from the provider's current object.

**Verify:** Replaying the same event has no extra effect.

### PAY-005 — Paid features gated only in the client
**Severity:** high · **Mode:** review · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** Paid features are locked only in the interface, so free users can call them directly.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Server endpoints for paid features must check entitlement.

**Fix:** Check entitlement on the server for every paid action; store it in server-written data.

**Verify:** A free user receives 402 or 403.

### PAY-006 — Subscription lifecycle events are not handled
**Severity:** medium · **Mode:** review · **Applies to:** subscriptions
**Auto-fix:** assisted

**In plain words:** Cancelled, refunded or failed subscriptions may keep access, or paying customers may lose it.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Only the first checkout event is handled.

**Fix:** Handle renewal failure, cancellation, refund, dispute, plan change and trial end; derive access from current status.

**Verify:** Fixture-event tests for each transition.

### PAY-007 — Customer or subscription identifier accepted from the client
**Severity:** high · **Mode:** scan+review · **Applies to:** stripe and similar
**Auto-fix:** assisted

**In plain words:** A user can put someone else's customer or subscription ID into a billing request and open or change their billing.

**How to detect:** `scripts/scan_payments.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Identifiers must come from the session user's record.

**Fix:** Look up customer and subscription IDs on the server for the signed-in user.

**Verify:** Cross-user test.

### PAY-008 — Test mode in production, or live keys in development
**Severity:** high · **Mode:** scan · **Applies to:** all payment providers
**Auto-fix:** owner

**In plain words:** The wrong payment mode is configured: test keys in production or live keys in development.

**How to detect:** Run `scripts/scan_payments.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Launching with test keys means no revenue; developing with live keys means real charges.

**Fix:** Correct per-environment keys; restricted keys in production.

**Verify:** Owner confirms, then one real low-value transaction end to end, refunded.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### PAY-009 — Card data handled by the app's own server
**Severity:** critical · **Mode:** scan · **Applies to:** any
**Auto-fix:** assisted

**In plain words:** Card numbers pass through your own server, putting you in the strictest card-security scope.

**How to detect:** Run `scripts/scan_payments.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A breach would be catastrophic.

**Fix:** Use the provider's hosted checkout or embedded elements.

**Verify:** Scanner clean.

### PAY-010 — Credits or balances updated without atomicity
**Severity:** high · **Mode:** review · **Applies to:** credits, wallets, inventory, seats
**Auto-fix:** assisted

**In plain words:** Concurrent requests can spend the same credit many times.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Read-then-write balance updates are not atomic.

**Fix:** Use an atomic conditional update or a transaction with locking, plus a check constraint against negatives.

**Verify:** N parallel requests with balance 1 produce exactly one success.

### PAY-011 — Money stored or computed as floating point
**Severity:** medium · **Mode:** scan · **Applies to:** any
**Auto-fix:** assisted

**In plain words:** Money is stored or computed as a decimal-inexact number, so totals can be off by a cent.

**How to detect:** Run `scripts/scan_payments.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Rounding errors in totals, tax and refunds.

**Fix:** Use integer minor units or decimal types end to end.

**Verify:** Schema and code review.


