# Production infrastructure (INFRA)

What this covers: the 9 INFRA checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### INFRA-001 — Web server serves the project root or dotfiles
**Severity:** high · **Mode:** scan · **Applies to:** nginx, apache, docker
**Auto-fix:** assisted

**In plain words:** The web server serves the project folder, or lists folders.

**How to detect:** Run `scripts/scan_infra.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Visitors can request the environment file, logs and source code.

**Fix:** Point the web root at `public`, deny dotfiles and turn off directory listing.

**Verify:** `curl -I https://site/.env` returns 403 or 404.

### INFRA-002 — TLS misconfigured or certificate checks disabled
**Severity:** high · **Mode:** scan · **Applies to:** nginx, apache, any code
**Auto-fix:** assisted

**In plain words:** Encryption settings are old or certificate checks are off, or there is no HTTPS redirect.

**How to detect:** Run `scripts/scan_infra.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Passwords and sessions can be read or changed in transit.

**Fix:** Use TLS 1.2 and 1.3, redirect HTTP to HTTPS, and never disable certificate verification.

**Verify:** An SSL scan grades A and `http://` redirects.

### INFRA-003 — World-writable permissions in build or deploy scripts
**Severity:** high · **Mode:** scan · **Applies to:** docker, shell, ci
**Auto-fix:** assisted

**In plain words:** Build or deploy steps make files world-writable.

**How to detect:** Run `scripts/scan_infra.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Any process on the machine, including a hijacked web request, can change your code.

**Fix:** Give the web user write access only to `storage` and `bootstrap/cache`.

**Verify:** `find . -perm -o+w` lists nothing outside those folders.

### INFRA-004 — Scheduler or queue worker has no process that runs it
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted+owner

**In plain words:** The scheduler or queue worker has no process that runs it.

**How to detect:** Run `scripts/scan_infra.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Scheduled tasks and queued emails silently never run.

**Fix:** Run `schedule:run` from cron (or `schedule:work`) and `queue:work` under a process manager.

**Verify:** A test task and a test job run on the server.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### INFRA-005 — Scheduled tasks can overlap or fail silently
**Severity:** low · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** Scheduled tasks can overlap, or fail without anyone being told.

**How to detect:** Run `scripts/scan_infra.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Overlapping runs double work or corrupt data; silent failures go unnoticed for weeks.

**Fix:** Add `withoutOverlapping()`, `onOneServer()` and a failure hook or heartbeat.

**Verify:** A failing task sends an alert.

### INFRA-006 — No database backup job defined
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted+owner

**In plain words:** No database backup job is defined.

**How to detect:** Run `scripts/scan_infra.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Data loss then means starting from nothing.

**Fix:** Schedule daily backups stored off the server, monitor them and practise a restore.

**Verify:** A restored copy opens in a scratch database.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### INFRA-007 — Deploy builds without production optimisation
**Severity:** medium · **Mode:** scan · **Applies to:** laravel, php, node
**Auto-fix:** assisted

**In plain words:** The deploy installs development packages or skips Laravel's optimisation.

**How to detect:** Run `scripts/scan_infra.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Debug packages and their vulnerabilities reach production and every request is slower.

**Fix:** Use `composer install --no-dev --optimize-autoloader` and `php artisan optimize`.

**Verify:** `composer show --no-dev` lists no dev tools and caches exist.

### INFRA-008 — Database or cache port published to the internet, or default password
**Severity:** high · **Mode:** scan · **Applies to:** docker compose
**Auto-fix:** assisted+owner

**In plain words:** A database or cache port is open to the internet, or uses a default password.

**How to detect:** Run `scripts/scan_infra.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Attackers scan for these and log in or wipe the data.

**Fix:** Do not publish the port, firewall it and set long random passwords.

**Verify:** `nmap` from outside shows the port closed.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### INFRA-009 — Logs are never rotated
**Severity:** low · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** auto/assisted

**In plain words:** Logs go to one file that grows for ever.

**How to detect:** Run `scripts/scan_infra.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A noisy day can fill the disk and stop the server.

**Fix:** Use the `daily` channel with a retention, or ship logs elsewhere.

**Verify:** Old log files are removed after the retention period.


