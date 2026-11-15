#!/usr/bin/env python3
"""Generate references/checks/*.md and INDEX.md from lib/catalog.py and tools/check_text.py."""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "skills", "prodready", "scripts"))
sys.path.insert(0, os.path.join(REPO, "tools"))

from lib import catalog  # noqa: E402
from check_text import T  # noqa: E402

OUT = os.path.join(REPO, "skills", "prodready", "references", "checks")
MODE_HELP = {
    "scan": "Run `scripts/{s}.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.",
    "scan+review": "`scripts/{s}.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.",
    "review": "No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.",
}

EXTRA = {
"launch": """## Launch checklist (phase 7)

Mark each item done, not done or not applicable; list owner actions still open; restate the verdict.

- [ ] No open critical or high findings (or accepted in writing).
- [ ] Every leaked key rotated and confirmed by the owner (SEC-001 to SEC-003, SEC-013).
- [ ] Row level security or rules verified with a cross-user test (DB-001 to DB-011).
- [ ] Payments: live keys only in production, verified webhook, one real low-value purchase refunded (PAY-001 to PAY-008).
- [ ] Backups on and one restore done (DB-016, REL-007).
- [ ] Error tracking and uptime monitoring alert someone (OBS-001, OBS-003).
- [ ] Email domain authenticated and sign-up email received (MAIL-001, MAIL-002).
- [ ] Privacy policy, terms, support contact and account deletion (PRIV-001, PRIV-003, LAUNCH-006).
- [ ] Production domain, redirects and provider URL allow-lists updated (LAUNCH-007, MAIL-003).
- [ ] Budgets and alerts at pay-per-use providers (DEP-014).
- [ ] Code in the owner's own repository with branch protection (DEP-011, DEP-013).
- [ ] Ten-step smoke test with a fresh account on production (LAUNCH-010).
""",
"dependencies": """## Offline advisory table (safety net, not an audit)

Last checked 2026-11-13. Mirrored in `scripts/scan_deps.py`. The full audit needs `npm audit` or `--allow-network`.

| Package | Advisory | Affected | Fixed in | Source |
|---|---|---|---|---|
| next | CVE-2025-29927 middleware authorization bypass | 12.0.0 to before 12.3.5, 13.0.0 to before 13.5.9, 14.0.0 to before 14.2.25, 15.0.0 to before 15.2.3 | 12.3.5, 13.5.9, 14.2.25, 15.2.3 | https://github.com/advisories/GHSA-f82v-jwr5-mffw |
| next | CVE-2025-66478 React Server Components remote code execution (App Router) | 15.x and 16.0.x before the listed fixes | 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7 | https://nextjs.org/blog/CVE-2025-66478 |
| next | CVE-2025-55184, CVE-2025-67779 (denial of service), CVE-2025-55183 (source exposure) | App Router, 13.3 and later before the listed fixes | 14.2.35, 15.0.7, 15.1.11, 15.2.8, 15.3.8, 15.4.10, 15.5.9, 16.0.10 | https://nextjs.org/blog/security-update-2025-12-11 |
| jsonwebtoken | CVE-2022-23540 | before 9.0.0 | 9.0.0 | https://github.com/advisories/GHSA-qwph-4952-7xr6 |
| mongoose | CVE-2025-23061 | before 6.13.6; 7.0.0 to before 7.8.4; 8.0.0 to before 8.9.5 | 6.13.6, 7.8.4, 8.9.5 | https://github.com/advisories/GHSA-vg7j-7cwx-8wgw |

Support windows (https://endoflife.date, 2026-11-13): Next.js 15 until 2027-01-31, 16 current, 14 ended 2025-10-26. Django supported: 5.2 LTS, 6.0, 6.1.
""",
}


def main():
    os.makedirs(OUT, exist_ok=True)
    for prefix, meta in catalog.CATEGORIES.items():
        checks = catalog.by_category(prefix)
        lines = ["# %s (%s)" % (meta["name"], prefix), "",
                 "What this covers: the %d %s checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix." % (len(checks), prefix),
                 "Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.", ""]
        for c in checks:
            plain, why, fix, verify = T[c.id]
            detect = MODE_HELP[c.mode].format(s=c.scanner or "")
            lines += ["### %s — %s" % (c.id, c.title),
                      "**Severity:** %s · **Mode:** %s · **Applies to:** %s" % (c.severity, c.mode, c.stacks),
                      "**Auto-fix:** %s" % c.fix_type, "",
                      "**In plain words:** %s" % plain, "",
                      "**How to detect:** %s" % detect, "",
                      "**Why it matters:** %s" % why, "",
                      "**Fix:** %s" % fix, "",
                      "**Verify:** %s" % verify, ""]
            if "owner" in c.fix_type:
                lines += ["**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.", ""]
        lines += [EXTRA.get(meta["slug"], "")]
        with open(os.path.join(OUT, meta["slug"] + ".md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
    idx = ["# Check index", "", "Last checked: 2026-11-13.", "",
           "Every check, with default severity, mode and the script that implements it. Generated from `scripts/lib/catalog.py`; do not edit by hand. Severity here is the default; adjust it in the report as described in `references/severity.md`.", "",
           "| ID | Title | Severity | Mode | Applies to | Script |", "|---|---|---|---|---|---|"]
    for c in catalog.CHECKS.values():
        idx.append("| [%s](%s.md#%s) | %s | %s | %s | %s | %s |" % (c.id, c.category, c.id.lower(), c.title, c.severity, c.mode, c.stacks, c.scanner or "review"))
    idx += ["", "## Review-only checks", "", "Read the code for these; no script can judge them: " + ", ".join(c.id for c in catalog.CHECKS.values() if c.mode == "review") + "."]
    with open(os.path.join(OUT, "INDEX.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(idx) + "\n")
    print("wrote %d category files + INDEX.md" % len(catalog.CATEGORIES))


if __name__ == "__main__":
    main()
