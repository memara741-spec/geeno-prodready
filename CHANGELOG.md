# Changelog

All notable changes. Format: Keep a Changelog. Changing a check's default severity or removing a check is noted prominently.

## [1.2.0] - 2026-11-15

### Added
- `lib/phpflow.py`: a token-level data-flow engine for PHP. It follows request input through assignments, loops, string building and calls between methods of one class, and clears it at casts and sanitisers. `scan_laravel` now uses it for LARA-004, LARA-009 and LARA-012. It is not a full PHP AST (see ROADMAP).
- `scan_authz` (AUTHZ-001 to AUTHZ-004): record-level authorization. Policies that nothing calls, policy rules that never look at the record or always return true, and controller actions that skip the check their siblings make. Writes an action-by-action matrix to `inventory.authorization`.
- `scan_ledger` (FIN-001 to FIN-004): balance changes with no ledger row, transfers that debit without crediting, balance columns that can go negative, payment tables with no unique key.
- `profile_runtime.py` (PERF-013 to PERF-015): measures queries per page, repeated queries (real N+1), time and memory on a running copy of the app, with `assets/laravel/ProdreadyProfile.php`.
- `verify_production.py` (PROD-001 to PROD-004): read-only checks of the live site (certificate, HTTP to HTTPS redirect, old TLS, exposed `.env`, logs and debug tools) and of a token-protected health report (`assets/laravel/prodready-health.php`) for the scheduler, queue and backups.
- `generate_regression_tests.py` also writes `ProdreadyTenantIsolationTest.php` (two tenants, mutual access attempts) and `ProdreadyFinancialIntegrityTest.php` (the same money request twice, then no negative balance and an unchanged total for transfers).
- 250 checks in 25 categories, 82 tests.

## [1.1.0] - 2026-11-15

### Added
- Five scanners and 48 checks (now 235 checks in 22 categories): `scan_laravel` (LARA-001 to LARA-017, API-020, API-021), `scan_tenancy` (TEN-001 to TEN-007), `scan_logic` (BIZ-001 to BIZ-007), `scan_performance` (PERF-007 to PERF-012, PERF-001 for PHP loops) and `scan_infra` (INFRA-001 to INFRA-009).
- Laravel 11, 12 and later: Eloquent mass assignment, raw SQL, Blade escaping, Livewire 3 properties and actions, Sanctum tokens, Spatie permissions, CSRF and CORS, support status, a route inventory with middleware, authentication and throttling per route.
- Multi-tenant isolation for Laravel and Prisma: tenant tables, missing scopes, lookups by ID without a tenant, tenant taken from the request, shared cache keys, unique rules, nullable tenant columns.
- Business logic checks: read-then-write balances, check-then-act bookings, repeated money requests, negative amounts, float money, client-set prices, queued jobs that can run twice.
- `generate_regression_tests.py`: a stack-independent guard test, Laravel route-contract and behaviour tests (PHPUnit), and Node tests that prove a fix worked and did not remove or loosen routes.
- Two fixtures (`laravel-multitenant`, `clean-laravel`), `lib/phpscan.py`, a Laravel playbook and 22 more tests (71 in total).

### Changed
- `detect_stack` recognises Laravel (version from `composer.lock`), Sanctum, Passport, Fortify and Laravel error trackers.
- The `nextjs-prisma-authjs` fixture now expects the unscoped Prisma queries that TEN-003 finds in it.

## [1.0.0] - 2026-11-15

### Added
- 187 checks in 18 categories, 12 scanners, `run_all`, `verify_fixes`, `render_report`, `probe_live`.
- Skill, three commands, two agents, reference playbooks, nine fixtures.
