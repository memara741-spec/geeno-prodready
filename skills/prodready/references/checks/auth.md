# Authentication and sessions (AUTH)

What this covers: the 18 AUTH checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### AUTH-001 — Page protection exists only in the user interface
**Severity:** high · **Mode:** review · **Applies to:** web, mobile
**Auto-fix:** assisted

**In plain words:** A page is hidden in the interface, but the data behind it can still be fetched directly by anyone.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Hiding a screen does not protect data; anyone can call the endpoint or query the table.

**Fix:** Enforce the rule on the server or in database policies; keep the UI check as a convenience.

**Verify:** A request without a session to each data endpoint returns 401 or an empty result.

### AUTH-002 — Data-returning or data-changing route has no authentication check
**Severity:** critical · **Mode:** scan+review · **Applies to:** all backends
**Auto-fix:** assisted

**In plain words:** Anyone on the internet can call this route; it reads or changes data and never checks who is asking.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** The route is callable by anyone and often runs with full database access.

**Fix:** Check the session at the top of the handler and return 401 when missing, then check ownership (API-005).

**Verify:** Scanner marks the route protected and a test without credentials gets 401.

### AUTH-003 — Middleware does not cover the routes it is assumed to cover
**Severity:** high · **Mode:** scan+review · **Applies to:** nextjs, express, hono, sveltekit
**Auto-fix:** assisted

**In plain words:** The login check in your middleware does not cover every route it is assumed to cover.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** A gap in the matcher is an open door, and frameworks have had middleware bypass bugs.

**Fix:** Verify the session inside each handler or a shared data layer; keep middleware as an optimisation and keep the framework patched.

**Verify:** Route inventory shows a per-handler check.

### AUTH-004 — Server trusts a user identifier supplied by the client
**Severity:** critical · **Mode:** scan+review · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** The server believes whichever user ID the caller sends, so changing one field lets a person act as anyone.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Identity read from the request is attacker-controlled.

**Fix:** Derive identity only from the verified session on the server and ignore identity fields from the client.

**Verify:** Test: signed in as A, send B's ID; get A's data or 403.

### AUTH-005 — Server code uses an unverified session read
**Severity:** high · **Mode:** scan · **Applies to:** supabase-ssr, custom-jwt
**Auto-fix:** auto/assisted

**In plain words:** The server trusts a login cookie or token it never verifies, so anyone can pose as another user.

**How to detect:** Run `scripts/scan_supabase.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Unverified session data comes from something the visitor controls.

**Fix:** Use the verifying call (getUser or getClaims for Supabase; jwt.verify with an algorithm allow-list for custom tokens).

**Verify:** Scanner clean.

### AUTH-006 — Session token stored where page scripts can read it
**Severity:** medium · **Mode:** scan+review · **Applies to:** custom auth
**Auto-fix:** assisted

**In plain words:** The login token is stored where any script on the page can read it.

**How to detect:** `scripts/scan_frontend.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** One injected script or browser extension then means account takeover.

**Fix:** Use HttpOnly, Secure, SameSite cookies on the web and secure storage on mobile.

**Verify:** Cookie attributes present; scanner clean.

### AUTH-007 — Session cookie lacks protective attributes
**Severity:** medium · **Mode:** scan · **Applies to:** custom auth, express-session
**Auto-fix:** auto

**In plain words:** The login cookie is missing protective flags, which makes it easier to steal or misuse.

**How to detect:** Run `scripts/scan_routes.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Without HttpOnly, Secure and SameSite it can be read by scripts, sent over plain HTTP or forged cross-site.

**Fix:** Set httpOnly, secure and sameSite (use the __Host- prefix where possible).

**Verify:** Scanner clean; response headers checked.

### AUTH-008 — Email addresses are not verified before the account is trusted
**Severity:** medium · **Mode:** review · **Applies to:** supabase, firebase, clerk, authjs, custom
**Auto-fix:** owner/assisted

**In plain words:** People can sign up with an email address they do not own.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Enables sign-up as someone else, invitation hijacking and account merging.

**Fix:** Enable email confirmation and check email_verified before privileged actions and before linking identities.

**Verify:** Dashboard shows it enabled.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### AUTH-009 — Weak password rules or leaked-password protection off
**Severity:** low · **Mode:** review · **Applies to:** all with passwords
**Auto-fix:** owner/assisted

**In plain words:** Weak passwords are allowed.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Credential stuffing works against weak and reused passwords.

**Fix:** Minimum length 8 or more, enable breach checking, offer social login or passkeys.

**Verify:** Config or owner confirmation.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### AUTH-010 — No rate limit on sign-in, sign-up, reset or code verification
**Severity:** high · **Mode:** scan+review · **Applies to:** custom auth
**Auto-fix:** assisted

**In plain words:** Nothing limits how many times someone can try to sign in or guess a code.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Enables password guessing, code brute force, email bombing and SMS cost attacks.

**Fix:** Per-IP and per-account limits in a shared store, lockout with backoff, CAPTCHA on sign-up.

**Verify:** Repeated attempts receive 429.

### AUTH-011 — Password reset or magic link flow is unsafe
**Severity:** high · **Mode:** review · **Applies to:** custom auth
**Auto-fix:** assisted

**In plain words:** The password reset flow can be abused to take over accounts.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** The reset flow is the easiest route to account takeover.

**Fix:** Random single-use tokens with short expiry stored hashed, uniform responses, a fixed base URL from config.

**Verify:** Tests for reuse, expiry and uniform response.

### AUTH-012 — Redirect after login accepts arbitrary destinations
**Severity:** medium · **Mode:** scan+review · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** After sign-in the app sends people wherever a link says, including to another website.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Used for phishing and, in OAuth flows, token theft.

**Fix:** Allow only same-origin relative paths (reject // and backslashes) or an explicit allow-list.

**Verify:** Test with https://evil.example and //evil.example; both rejected.

### AUTH-013 — Role or admin flag stored where the user can change it
**Severity:** critical · **Mode:** scan+review · **Applies to:** supabase, firebase, clerk, custom
**Auto-fix:** assisted

**In plain words:** Users can grant themselves a role, plan or credits because it is stored where they can edit it.

**How to detect:** `scripts/scan_supabase.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** The user promotes themselves to administrator with one request.

**Fix:** Store roles in server-controlled claims (app_metadata, custom claims) or a table users cannot write; restrict updatable columns.

**Verify:** Test: an ordinary user tries to set the role and is denied.

### AUTH-014 — Sessions never expire or sign-out does not end them
**Severity:** low · **Mode:** review · **Applies to:** custom auth
**Auto-fix:** assisted

**In plain words:** Sessions never expire, or signing out does not actually end them.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** A stolen token works forever.

**Fix:** Short-lived access tokens with refresh rotation and server-side revocation on sign-out and password change.

**Verify:** A token is rejected after sign-out.

### AUTH-015 — State-changing requests with cookie auth lack CSRF protection
**Severity:** medium · **Mode:** review · **Applies to:** custom cookie auth, express, flask, django
**Auto-fix:** assisted

**In plain words:** Another website can make a signed-in visitor's browser perform actions on your app.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Cookie-authenticated state-changing requests need a forgery defence.

**Fix:** SameSite cookies plus Origin or token validation; no state changes on GET.

**Verify:** A cross-origin POST is rejected.

### AUTH-016 — No second factor available for administrator accounts
**Severity:** low · **Mode:** review · **Applies to:** all
**Auto-fix:** owner

**In plain words:** Administrator accounts have no second factor.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** One phished admin password compromises all users.

**Fix:** Enable MFA for admin roles or restrict admin access by SSO.

**Verify:** Owner confirmation.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### AUTH-017 — Default, demo or seeded credentials present
**Severity:** critical · **Mode:** scan · **Applies to:** all
**Auto-fix:** assisted+owner

**In plain words:** A demo, seeded or shortcut login exists that anyone who reads the code can use.

**How to detect:** Run `scripts/scan_secrets.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Published credentials and bypasses are the first thing attackers try.

**Fix:** Remove them, restrict seeds to development, delete the accounts in production.

**Verify:** Scanner clean; owner confirms accounts removed.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### AUTH-018 — Token verification accepts unsafe algorithms or skips claims
**Severity:** critical · **Mode:** scan · **Applies to:** custom-jwt
**Auto-fix:** assisted

**In plain words:** Login tokens are checked too loosely, so forged or expired ones are accepted.

**How to detect:** Run `scripts/scan_routes.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Allows forged tokens.

**Fix:** Pin algorithms, validate exp, iss and aud, and use the provider's verification library.

**Verify:** Tests with a tampered and an expired token.


