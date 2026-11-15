# Email and messaging (MAIL)

What this covers: the 5 MAIL checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### MAIL-001 — Sending domain not authenticated
**Severity:** high · **Mode:** review · **Applies to:** any email
**Auto-fix:** owner

**In plain words:** Your verification and reset emails may land in spam or be rejected.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** The sending domain lacks SPF, DKIM and DMARC.

**Fix:** Configure the records with your email provider (owner-actions/dns-and-email.md).

**Verify:** Records present; a test email passes authentication.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### MAIL-002 — Relying on the backend provider's built-in development email service
**Severity:** high · **Mode:** scan · **Applies to:** supabase auth
**Auto-fix:** owner

**In plain words:** Sign-up emails use the backend's test mail service, which is tightly rate limited.

**How to detect:** Run `scripts/scan_supabase.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Built-in senders are for testing; sign-ups fail once real traffic arrives.

**Fix:** Configure a transactional email provider as custom SMTP and brand the templates.

**Verify:** Owner confirmation.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### MAIL-003 — Emails and auth redirects point to localhost or preview URLs
**Severity:** high · **Mode:** scan · **Applies to:** all
**Auto-fix:** assisted+owner

**In plain words:** Links in emails, sign-in and payment redirects point to localhost or a preview address.

**How to detect:** Run `scripts/scan_env.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** They break in production.

**Fix:** Build the base URL from environment and update provider dashboards with the production domain.

**Verify:** Scanner clean; owner confirms dashboards.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### MAIL-004 — Email or SMS sending can be triggered without limit
**Severity:** high · **Mode:** scan+review · **Applies to:** any email/sms
**Auto-fix:** assisted

**In plain words:** Anyone can make the app send email or text messages to any address.

**How to detect:** `scripts/scan_launch.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** The app becomes a spam cannon; SMS fraud costs real money.

**Fix:** Authenticate where possible, rate limit per IP, account and recipient, CAPTCHA on public forms, fixed templates.

**Verify:** Limit test.

### MAIL-005 — Marketing email without unsubscribe
**Severity:** low · **Mode:** review · **Applies to:** any marketing email
**Auto-fix:** assisted

**In plain words:** Marketing email has no unsubscribe.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** A legal requirement in many regions and a deliverability requirement.

**Fix:** Add unsubscribe handling and honour it.

**Verify:** Review.


