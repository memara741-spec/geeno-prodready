# Deployment and configuration (DEP)

What this covers: the 14 DEP checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### DEP-001 — Development or debug mode enabled in production
**Severity:** high · **Mode:** scan · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** The app runs in development or debug mode in production.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Debug modes expose stack traces and dev servers are slow and unsafe.

**Fix:** Use proper build and start commands; debug flags default off.

**Verify:** Scanner clean; production start command documented.

### DEP-002 — Production and development share one backend
**Severity:** high · **Mode:** review · **Applies to:** all
**Auto-fix:** owner

**In plain words:** Production and development share one backend, so experiments run against real users' data.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** A bad migration is immediately a production outage.

**Fix:** Separate projects or databases; previews use the development backend.

**Verify:** Owner confirms; env files differ.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### DEP-003 — Environment variables are not validated at startup
**Severity:** medium · **Mode:** scan · **Applies to:** all
**Auto-fix:** assisted

**In plain words:** The app reads its settings in many places without validating them at startup.

**How to detect:** Run `scripts/scan_env.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A missing variable becomes a confusing failure or a silent insecure fallback.

**Fix:** One module that validates the environment with a schema and fails fast.

**Verify:** Starting without a required variable fails with a clear error.

### DEP-004 — No health check endpoint
**Severity:** low · **Mode:** scan · **Applies to:** backends, containers
**Auto-fix:** auto

**In plain words:** Monitors cannot tell whether the app is alive.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** No health check endpoint.

**Fix:** Add a cheap endpoint that returns status without details.

**Verify:** Endpoint returns 200.

### DEP-005 — No rollback path
**Severity:** medium · **Mode:** review · **Applies to:** all
**Auto-fix:** owner

**In plain words:** If a release breaks, recovery takes as long as debugging under pressure.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** No known rollback path.

**Fix:** Document the host's instant rollback; keep migrations backward compatible for one release.

**Verify:** Runbook section exists.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### DEP-006 — Builds are not reproducible
**Severity:** medium · **Mode:** scan · **Applies to:** node, python
**Auto-fix:** auto/assisted

**In plain words:** Tomorrow's deployment may install different code than today's.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** No lockfile, mixed package managers, unpinned versions or runtime.

**Fix:** One package manager, a committed lockfile, a pinned runtime, clean-install commands.

**Verify:** Scanner clean.

### DEP-007 — Preview or staging deployments are public and indexed
**Severity:** medium · **Mode:** review · **Applies to:** vercel, netlify, cloudflare pages, replit, builders
**Auto-fix:** owner

**In plain words:** Old preview or staging copies of the app stay public and may be indexed.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** They may reach production data and are unpatched.

**Fix:** Enable deployment protection, point previews at development data, unpublish stale previews.

**Verify:** Owner confirmation.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### DEP-008 — Build ignores type and lint errors
**Severity:** medium · **Mode:** scan · **Applies to:** nextjs, vite, typescript
**Auto-fix:** assisted

**In plain words:** The build ignores type and lint errors, so real bugs ship unnoticed.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** AI builders often switch these flags on to make a build pass.

**Fix:** Turn the flags off, fix what surfaces, enable strict mode gradually.

**Verify:** The build passes without the flags.

### DEP-009 — Container image runs as root or bakes in secrets
**Severity:** medium · **Mode:** scan · **Applies to:** docker
**Auto-fix:** assisted

**In plain words:** The container image runs as root or bakes in secrets.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Secrets live forever in image layers and root widens any compromise.

**Fix:** Multi-stage build, non-root user, .dockerignore, runtime secrets, pinned base image.

**Verify:** Scanner clean.

### DEP-010 — Function region far from the database, or timeouts too short for the work
**Severity:** low · **Mode:** review · **Applies to:** serverless
**Auto-fix:** owner/assisted

**In plain words:** Function region or timeouts do not match the database or the work.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Slow responses and random timeouts.

**Fix:** Co-locate regions; stream or move long work to background jobs.

**Verify:** Config review.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### DEP-011 — The project still lives only inside the AI builder
**Severity:** medium · **Mode:** review · **Applies to:** lovable, bolt, v0, replit, firebase studio
**Auto-fix:** owner

**In plain words:** The project lives only inside the AI builder, so you cannot back up, audit or move it.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** You depend on one vendor for recovery.

**Fix:** Connect to your own GitHub repository; own the backend project and domain; document how to build and deploy.

**Verify:** Owner confirmation; remote present.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### DEP-012 — Default error pages and missing not-found handling
**Severity:** low · **Mode:** scan · **Applies to:** web
**Auto-fix:** auto/assisted

**In plain words:** Reloading or sharing a link to an inner page shows the host's 404.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Single-page apps need a host rewrite to index.html.

**Fix:** Add the pages and rewrite rules for your host.

**Verify:** Files and rewrite config present.

### DEP-013 — Default branch unprotected and deploys on every push
**Severity:** low · **Mode:** review · **Applies to:** github + any host
**Auto-fix:** owner

**In plain words:** Anyone, including an AI agent, can push straight to the branch that deploys.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** An unreviewed change goes straight to production.

**Fix:** Branch protection with required checks; agents work on branches.

**Verify:** Owner confirmation.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### DEP-014 — Billing limits and usage alerts not configured on pay-per-use services
**Severity:** medium · **Mode:** review · **Applies to:** all cloud, llm, sms, email, maps
**Auto-fix:** owner

**In plain words:** A loop or abuse can become a surprise bill before anyone notices.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** No budgets or alerts on pay-per-use services.

**Fix:** Budgets, hard caps where offered, and alerts at several thresholds per provider.

**Verify:** Owner confirmation per provider.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.


