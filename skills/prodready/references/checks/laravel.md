# Laravel deep scan (LARA)

What this covers: the 17 LARA checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### LARA-001 — Debug mode or a local environment enabled in production configuration
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted+owner

**In plain words:** Laravel is set to show detailed error pages in production, which print your settings and code to anyone who triggers an error.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Debug pages expose environment values, file paths and sometimes keys, and have been used to take over servers.

**Fix:** Set APP_DEBUG=false and APP_ENV=production in the host's settings, remove committed environment files, and clear the config cache.

**Verify:** Trigger a 500 on a staging copy: the page must show a plain error, not a stack trace.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### LARA-002 — Application key committed to the repository
**Severity:** critical · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted+owner

**In plain words:** The key Laravel uses to encrypt cookies and sign data is saved in the repository.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Anyone with APP_KEY can read encrypted values and forge signed ones; in older versions it leads to remote code execution.

**Fix:** Run `php artisan key:generate`, set the new key only in the host's secrets, remove the file from git and sign everyone out.

**Verify:** scan_laravel is clean and `git ls-files` lists no environment file with values.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### LARA-003 — Mass assignment is unguarded
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A model lets a request fill in any column, so a caller can add fields like `is_admin` or `company_id` to a normal form.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Mass assignment turns a profile update into a privilege escalation or a move into another tenant.

**Fix:** List only safe columns in `$fillable`, never roles or tenant IDs, and use validated data instead of `$request->all()`.

**Verify:** A test that posts an extra `is_admin=1` field and checks it is ignored.

### LARA-004 — Raw SQL built from variables
**Severity:** critical · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A raw SQL string contains a variable, so whoever controls the value can change the query.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** SQL injection reads or destroys the whole database and bypasses every access check.

**Fix:** Use bindings (`whereRaw('x = ?', [$v])`) or the query builder; never join variables into the string.

**Verify:** scan_laravel is clean; a test with a quote character in the input returns normally.

### LARA-005 — Variable printed into a page without escaping
**Severity:** high · **Mode:** scan · **Applies to:** laravel blade, livewire
**Auto-fix:** assisted

**In plain words:** A Blade view prints a variable without escaping it, so HTML or script typed by a user runs in other people's browsers.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Stored cross-site scripting steals sessions and acts as the visitor.

**Fix:** Use `{{ $value }}`. If HTML is needed, sanitise it on save with a library such as HTML Purifier.

**Verify:** Save `<script>alert(1)</script>` in the field and load the page: it must show as text.

### LARA-006 — API tokens issued with every ability or never expiring
**Severity:** high · **Mode:** scan · **Applies to:** laravel sanctum
**Auto-fix:** assisted

**In plain words:** API tokens can do everything and never expire.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A leaked token gives permanent, full access to the account.

**Fix:** Create tokens with a narrow ability list and expiry, set `expiration` in config/sanctum.php, and prune expired tokens.

**Verify:** Config shows an expiry; a token without the ability gets 403.

### LARA-007 — Livewire public property holds an identifier the browser can change
**Severity:** high · **Mode:** scan · **Applies to:** livewire 3
**Auto-fix:** assisted

**In plain words:** A Livewire property holding an ID travels to the browser and back, so a user can change it to someone else's record.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Livewire public properties are user-editable input, like form fields.

**Fix:** Add `#[Locked]`, or set it in `mount()` and authorise the record on every action.

**Verify:** A test that sets the property to another user's ID and calls the action gets 403.

### LARA-008 — Livewire action changes data without an authorisation check
**Severity:** high · **Mode:** scan · **Applies to:** livewire 3
**Auto-fix:** assisted

**In plain words:** A Livewire action changes data without asking whether the current user is allowed.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Livewire actions can be called directly; hiding the button does not protect them.

**Fix:** Call `$this->authorize()` first in every action that writes, and load records through the current user or tenant.

**Verify:** Livewire test: acting as another user and calling the action fails with 403.

### LARA-009 — Roles or permissions assigned from request input
**Severity:** critical · **Mode:** scan · **Applies to:** laravel spatie permission
**Auto-fix:** assisted

**In plain words:** Roles or permissions are given out from request input with no check that the caller is allowed to.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A normal user can make themselves an administrator.

**Fix:** Authorise with a Gate or policy, validate the role against a fixed list and never assign what the request names unchecked.

**Verify:** A non-admin posting a role gets 403 and the role is unchanged.

### LARA-010 — Controller writes request data without validation
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A controller saves request data without validating it.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Wrong types, huge values and unexpected fields reach the database and cause errors or corrupted data.

**Fix:** Use a Form Request with rules and `$request->validated()`.

**Verify:** A test with missing and oversized fields gets 422.

### LARA-011 — Uploaded file stored under a client-controlled name or extension
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** An uploaded file is saved with the name or extension the uploader chose.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A file called `shell.php` or with `../` in its name can overwrite files or be executed.

**Fix:** Use `->store()` so Laravel picks the name, validate `mimes` and `max`, and keep uploads outside the public web root.

**Verify:** Upload `a.php`: it is rejected or stored under a random safe name.

### LARA-012 — Request input reaches a command, eval or unserialize
**Severity:** critical · **Mode:** scan · **Applies to:** laravel, php
**Auto-fix:** assisted

**In plain words:** Request input is passed to a command, `eval` or `unserialize`.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** An attacker can run commands on your server or trigger code execution through crafted data.

**Fix:** Remove the call, or use a safe library API; use `json_decode`, and `escapeshellarg` only as a last resort.

**Verify:** scan_laravel is clean; a payload with `; id` in the input does nothing.

### LARA-013 — CSRF protection switched off for broad route patterns
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** auto/assisted

**In plain words:** Form protection against other websites is switched off for the whole app.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Another site can submit forms for a signed-in visitor.

**Fix:** Exempt only the exact webhook paths and verify those with a signature.

**Verify:** A cross-site form post to a protected route returns 419.

### LARA-014 — Cross-origin policy allows every site with credentials
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** auto/assisted

**In plain words:** Any website may call your API from a visitor's browser with their cookies.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A malicious page can read private data using the visitor's session.

**Fix:** List your real front-end origins in `allowed_origins`.

**Verify:** A request with an unknown Origin gets no CORS headers.

### LARA-015 — Laravel version no longer receives security fixes
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** The Laravel version in use no longer gets security fixes.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** New vulnerabilities are published and never patched for it.

**Fix:** Upgrade to a supported major version (Laravel 12 or later, support dates at laravel.com/docs/releases), then run the tests.

**Verify:** `composer show laravel/framework` shows a supported major.

### LARA-016 — Authorisation gate grants access to everyone
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A permission rule always says yes.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Every permission check in the app passes for everyone it covers.

**Fix:** Return true only for a specific super-admin check and null otherwise, so normal policies still run.

**Verify:** A normal user is denied an action protected by a policy.

### LARA-017 — Debugging tools installed as production dependencies
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** Debugging tools that record requests and data are installed on production.

**How to detect:** Run `scripts/scan_laravel.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Telescope, Debugbar and similar tools store sensitive requests and can expose them.

**Fix:** Install them with `--dev`, deploy with `--no-dev`, and gate Telescope with a Gate if it must stay.

**Verify:** `composer show --no-dev` does not list them.


