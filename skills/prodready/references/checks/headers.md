# Security headers and transport (HDR)

What this covers: the 6 HDR checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### HDR-001 — No Content Security Policy
**Severity:** medium · **Mode:** scan · **Applies to:** web
**Auto-fix:** assisted

**In plain words:** The site sends no Content Security Policy, so nothing limits what an injected script can do.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** CSP is the main backstop against script injection.

**Fix:** Start from assets/security-headers/ for your host, report-only first if needed, then tighten.

**Verify:** Config present; optional probe shows the header.

### HDR-002 — HTTPS not enforced with HSTS
**Severity:** medium · **Mode:** scan · **Applies to:** web
**Auto-fix:** auto/assisted

**In plain words:** Nothing makes browsers insist on HTTPS, so a visitor on a hostile network can be downgraded.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Allows downgrade to an unencrypted connection.

**Fix:** Add HSTS once HTTPS works everywhere and redirect HTTP to HTTPS.

**Verify:** Config or probe.

### HDR-003 — Pages can be framed by other sites
**Severity:** medium · **Mode:** scan · **Applies to:** web
**Auto-fix:** auto

**In plain words:** Other sites can embed your pages in an invisible frame and trick visitors into clicking.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Clickjacking.

**Fix:** frame-ancestors 'none' or 'self' unless embedding is a feature.

**Verify:** Config or probe.

### HDR-004 — Missing nosniff, referrer and permissions policies
**Severity:** low · **Mode:** scan · **Applies to:** web
**Auto-fix:** auto

**In plain words:** Small free protections (nosniff, referrer and permissions policies) are not switched on.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Prevents content-type confusion and URL leakage.

**Fix:** Add them from the template.

**Verify:** Config or probe.

### HDR-005 — Authenticated responses may be cached by shared caches
**Severity:** medium · **Mode:** scan+review · **Applies to:** web with cdn, nextjs caching
**Auto-fix:** assisted

**In plain words:** A page or response that depends on who is signed in may be cached and served to someone else.

**How to detect:** `scripts/scan_config.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** One user's page is served to another.

**Fix:** Cache-Control: private, no-store for personalised responses; mark dynamic routes dynamic.

**Verify:** Test two sessions against the same URL.

### HDR-006 — Server and framework versions disclosed
**Severity:** low · **Mode:** scan · **Applies to:** express, nextjs, custom servers
**Auto-fix:** auto

**In plain words:** The server announces which framework it runs.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A minor information leak, trivial to remove.

**Fix:** Disable the X-Powered-By header.

**Verify:** Config.


