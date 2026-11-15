# Roadmap

1. Run the eval scenarios in fresh Claude sessions and tune SKILL.md from the transcripts.
2. Finish `probe_live.py`: the Firebase open-rules probe and the SPF and DMARC lookup.
3. A real lockfile for `clean-nextjs-supabase` and an end-to-end "fix keeps the app building" test.
4. Stack-specific code examples inside each check entry, and more fixtures (many scan checks are not yet planted in any fixture).
5. A fuller offline advisory table, generated from vendor data at release time.

## Done in 1.2.0, and what is left

- PHP analysis: a token-level data-flow engine (`lib/phpflow.py`) is in. A full PHP AST (cross-class calls, container-resolved services, traits) is still open; a PHP-binary-backed `token_get_all` mode is one way to get there.
- Authorization: policies and per-action checks are in (`scan_authz`). Running the policies against seeded users is still open.
- Financial integrity: static ledger, transfer and uniqueness checks are in (`scan_ledger`) plus a generated double-spend test. Replaying real data to prove the books balance is open.
- Runtime profiling: query, repeat, time and memory measurement is in (`profile_runtime.py`, Laravel middleware). Node and Django profilers are open.
- Tenant isolation: a generated two-tenant test is in. Running it automatically against a disposable database is open.
- Production verification: certificate, redirect, TLS, exposed files and a health report are in (`verify_production.py`). Disk space, database dumps and process lists need an agent on the server and are open.

## Verification status (2026-11-15, version 1.2.0)

Only what has evidence is listed as verified.

**Verified**

- 82 automated tests pass in CI on Ubuntu, macOS and Windows with Python 3.9 and 3.13.
- Every planted problem in the eleven sample apps is found (63 in the Laravel multi-tenant app), and the three clean apps produce no critical, high or medium findings.
- No planted secret value appears in any scanner output; output is deterministic; scanners work with sockets disabled.
- Every generated PHP test and the two Laravel assets pass `php -l`.
- The runtime profiler and the live verifier were exercised against a local stub server: they flag the planted problems, send GET and HEAD only, and refuse to run without their ownership flags.
- The plugin installed and validated with Claude Code on version 1.0.0.

**Not verified yet**

- The generated PHPUnit tests have not been run inside a real Laravel project.
- `profile_runtime.py` and `verify_production.py` have not been run against a real Laravel app or a real production site.
- The scanners have not been compared with other tools on large real-world Laravel codebases, so false-positive and false-negative rates there are unknown.
- The PHP engine is token-level, not a full AST.
- A full headless Claude run on a real app, and the Claude-driven fix phase, have not been run.

### Update for 1.3.0

Verified by the automated suite (89 tests, CI on three operating systems): a failed scanner gives `INCOMPLETE` and exit code 4; data flow crosses classes, traits and typed properties; the restore drill passes a good backup, rejects a backup with missing tables and refuses to run a restore command without its flags; every generated PHP test passes `php -l`.

Still not verified, and the reason a "95 out of 100" claim would be premature:

- `ProdreadyPolicyTest.php` and `ProdreadyConcurrencyTest.php` have not been executed inside a real Laravel project against a real MySQL database.
- `verify_production.py`, `profile_runtime.py` and `restore_drill.py` have not been run against a real staging environment or a hosted backup.
- The PHP engine is still not a full AST.
- No benchmark against other tools on large public Laravel projects.
