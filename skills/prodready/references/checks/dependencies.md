# Dependencies and supply chain (DEPS)

What this covers: the 7 DEPS checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### DEPS-001 — Dependencies with known vulnerabilities
**Severity:** high · **Mode:** scan · **Applies to:** node, python
**Auto-fix:** assisted

**In plain words:** A package you use has a known security hole that attackers scan for.

**How to detect:** Run `scripts/scan_deps.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Known vulnerabilities in frameworks and auth libraries are exploited at scale.

**Fix:** Update to patched versions, prioritising framework, auth, database and parsing libraries; test after each.

**Verify:** Audit shows no high or critical advisories for production dependencies.

### DEPS-002 — Framework version is past security support
**Severity:** high · **Mode:** scan · **Applies to:** nextjs, react, express, django, flask
**Auto-fix:** assisted

**In plain words:** Your framework version no longer receives security fixes.

**How to detect:** Run `scripts/scan_deps.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** New vulnerabilities will never be patched.

**Fix:** Plan the upgrade; apply the latest patch of the current major now.

**Verify:** Version bump present; build passes.

### DEPS-003 — Dependency that does not exist, is misspelled, or is suspicious
**Severity:** high · **Mode:** scan · **Applies to:** node, python
**Auto-fix:** assisted

**In plain words:** A package is imported but not declared, or its name looks like a misspelling of a popular one; invented names can be registered by attackers.

**How to detect:** Run `scripts/scan_deps.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** AI tools sometimes invent package names.

**Fix:** Replace with the intended real package after checking its registry page, and remove look-alikes.

**Verify:** Scanner clean.

### DEPS-004 — Unused, duplicated or abandoned dependencies
**Severity:** low · **Mode:** scan · **Applies to:** node, python
**Auto-fix:** assisted

**In plain words:** A listed package is never used.

**How to detect:** Run `scripts/scan_deps.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Each dependency is attack surface and upgrade work.

**Fix:** Remove it after confirming the build passes.

**Verify:** Build passes.

### DEPS-005 — Development tools shipped as production dependencies, or the reverse
**Severity:** low · **Mode:** scan · **Applies to:** node
**Auto-fix:** auto

**In plain words:** A development tool ships to production, or a runtime package is dev-only.

**How to detect:** Run `scripts/scan_deps.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Larger attack surface, or a production crash on a missing module.

**Fix:** Move entries to the right section.

**Verify:** Clean production install and start.

### DEPS-006 — No automated dependency update or alerting
**Severity:** low · **Mode:** scan · **Applies to:** github
**Auto-fix:** auto

**In plain words:** Nothing tells you when a new security fix is released for your packages.

**How to detect:** Run `scripts/scan_deps.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Vulnerabilities announced after launch go unnoticed.

**Fix:** Add Dependabot or Renovate with grouped weekly updates.

**Verify:** File present.

### DEPS-007 — Licence incompatible with commercial use
**Severity:** low · **Mode:** scan · **Applies to:** node, python
**Auto-fix:** owner

**In plain words:** A dependency's licence may oblige you to publish your code or forbid commercial use.

**How to detect:** Run `scripts/scan_deps.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Legal exposure for a commercial product. This is not legal advice.

**Fix:** Flag it for the owner's decision and consider alternatives.

**Verify:** Owner decision recorded.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

## Offline advisory table (safety net, not an audit)

Last checked 2026-11-13. Mirrored in `scripts/scan_deps.py`. The full audit needs `npm audit` or `--allow-network`.

| Package | Advisory | Affected | Fixed in | Source |
|---|---|---|---|---|
| next | CVE-2025-29927 middleware authorization bypass | 12.0.0 to before 12.3.5, 13.0.0 to before 13.5.9, 14.0.0 to before 14.2.25, 15.0.0 to before 15.2.3 | 12.3.5, 13.5.9, 14.2.25, 15.2.3 | https://github.com/advisories/GHSA-f82v-jwr5-mffw |
| next | CVE-2025-66478 React Server Components remote code execution (App Router) | 15.x and 16.0.x before the listed fixes | 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7 | https://nextjs.org/blog/CVE-2025-66478 |
| next | CVE-2025-55184, CVE-2025-67779 (denial of service), CVE-2025-55183 (source exposure) | App Router, 13.3 and later before the listed fixes | 14.2.35, 15.0.7, 15.1.11, 15.2.8, 15.3.8, 15.4.10, 15.5.9, 16.0.10 | https://nextjs.org/blog/security-update-2025-12-11 |
| jsonwebtoken | CVE-2022-23540 | before 9.0.0 | 9.0.0 | https://github.com/advisories/GHSA-qwph-4952-7xr6 |
| mongoose | CVE-2025-23061 | before 6.13.6; 7.0.0 to before 7.8.4; 8.0.0 to before 8.9.5 | 6.13.6, 7.8.4, 8.9.5 | https://github.com/advisories/GHSA-vg7j-7cwx-8wgw |

Support windows (https://endoflife.date, 2026-11-13): Next.js 15 until 2027-01-31, 16 current, 14 ended 2025-10-26. Django supported: 5.2 LTS, 6.0, 6.1.

