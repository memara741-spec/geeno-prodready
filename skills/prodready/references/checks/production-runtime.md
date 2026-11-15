# Live production verification (PROD)

What this covers: the 4 PROD checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### PROD-001 — Certificate invalid or close to expiry
**Severity:** high · **Mode:** scan · **Applies to:** web
**Auto-fix:** owner

**In plain words:** The site's HTTPS certificate is invalid or about to expire.

**How to detect:** Run `scripts/verify_production.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Browsers will block the site and payment or login flows fail.

**Fix:** Renew the certificate and turn on automatic renewal.

**Verify:** The check reports more than 30 days left.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### PROD-002 — Plain HTTP not redirected to HTTPS, or old TLS accepted
**Severity:** high · **Mode:** scan · **Applies to:** web
**Auto-fix:** owner

**In plain words:** Plain HTTP is not redirected to HTTPS, or an outdated TLS version is accepted.

**How to detect:** Run `scripts/verify_production.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Passwords and sessions can be read in transit.

**Fix:** Redirect port 80 to HTTPS and allow TLS 1.2 and 1.3 only.

**Verify:** `http://` returns a redirect to `https://`.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### PROD-003 — Sensitive file or debug tool reachable on the live site
**Severity:** critical · **Mode:** scan · **Applies to:** web
**Auto-fix:** assisted+owner

**In plain words:** A sensitive file or debug tool answers on the live site.

**How to detect:** Run `scripts/verify_production.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Environment files, logs and debug dashboards hand out secrets and data.

**Fix:** Block the path at the web server, point the web root at `public`, remove the tool from production and rotate anything exposed.

**Verify:** The path returns 403 or 404.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### PROD-004 — Scheduler, queue or backup heartbeat is stale
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** owner

**In plain words:** The scheduler, queue or backup has not reported recently on the live server.

**How to detect:** Run `scripts/verify_production.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Scheduled work, queued mail or backups have stopped without anyone noticing.

**Fix:** Restart the process, then add alerting on the health report.

**Verify:** The health report shows recent activity.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.


