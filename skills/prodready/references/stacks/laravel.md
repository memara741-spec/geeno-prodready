# Laravel playbook

Last checked: 2026-11-15. Support dates come from laravel.com/docs/releases on that date: Laravel 11 stopped receiving security fixes on 2026-03-12, Laravel 12 receives them until 2027-02-24, Laravel 13 is current. Check the page again before telling a user a version is unsupported.

What this covers: how to review a Laravel 11, 12 or 13 app after `scan_laravel`, `scan_tenancy`, `scan_logic`, `scan_performance` and `scan_infra` have run. After reading it you can explain each Laravel finding, fix it with framework features and verify the fix with a test.

## Where things live

| Question | Look at |
|---|---|
| Which routes exist and who may call them | `routes/web.php`, `routes/api.php`, `bootstrap/app.php` (middleware), the `inventory.laravel_routes` list in the scan output |
| Who the current user is | `auth()->user()`, `$request->user()`, guards in `config/auth.php`; Sanctum tokens in `config/sanctum.php` |
| What a user may do | Policies in `app/Policies`, `Gate::define`, Spatie `can:`/`role:` middleware |
| What a request may write | Form Requests in `app/Http/Requests`, `$fillable` on models |
| Tenant separation | Global scopes or a `BelongsToTenant` trait on models, `stancl/tenancy` or `spatie/laravel-multitenancy` |
| Background work | `app/Jobs`, `routes/console.php`, Supervisor or container commands |

## Laravel 11 and later notes

- There is no `app/Http/Kernel.php`. Middleware, CSRF exceptions and rate limiting are configured in `bootstrap/app.php` (`$middleware->throttleApi()`, `validateCsrfTokens(except: [...])`). A project with no `throttleApi()` call has no default API rate limit.
- API routes are not installed by default; `php artisan install:api` adds Sanctum and `routes/api.php`.
- Scheduled tasks live in `routes/console.php` with `Schedule::command(...)`. Nothing runs them until the server calls `php artisan schedule:run` every minute (or `schedule:work` runs as a process).
- `APP_DEBUG=true` in production shows the full error page with environment values. `APP_KEY` leaks allow reading encrypted cookies and forging signed values.

## Review order

1. Run the scanners, then open every `AUTH-002`, `API-021`, `TEN-003` and `LARA-008` location. These are the "anyone can reach someone else's data" findings.
2. For each tenant table in `inventory.tenancy.tables`, confirm one scope applies on read and on create, and ask whether jobs, listeners and artisan commands run without a user (they bypass a scope that reads `auth()`).
3. Read money code: transfers, withdrawals, credits, bookings. The question is always "what if this request arrives twice at the same moment?".
4. Check the infrastructure files and ask the owner how the scheduler, queue worker and backups run in production (`INFRA-004`, `INFRA-006`).

## Fix patterns

| Finding | Fix |
|---|---|
| `LARA-003` | `$fillable` with safe fields; a Form Request and `$request->validated()` |
| `LARA-004` | bindings: `whereRaw('x = ?', [$v])` |
| `LARA-007`, `LARA-008` | `#[Locked]` on ID properties, `$this->authorize()` in each action |
| `API-021` | `php artisan make:policy`, `$this->authorize('view', $model)` or `$request->user()->things()->findOrFail($id)` |
| `TEN-001` | trait with `addGlobalScope` and a `creating` hook; test with two tenants |
| `BIZ-001`, `BIZ-002` | `DB::transaction` with `lockForUpdate()`; unique index on the slot |
| `BIZ-003` | idempotency key column with a unique index, checked inside the transaction |
| `PERF-007` | `with()`, and `Model::preventLazyLoading(! app()->isProduction())` in `AppServiceProvider::boot()` |
| `INFRA-001` | nginx `root /var/www/html/public;` and `location ~ /\.(?!well-known) { deny all; }` |

## Verification

Run `scripts/generate_regression_tests.py`, copy the PHP tests into `tests/Feature/`, run them before the fix (they must fail) and after (they must pass), then run the app's own `php artisan test`. If PHP is not installed, say which tests could not run.

## Limits

The scanners read PHP with regular expressions and brace matching, not a parser. They do not follow routes registered in service providers or packages, `Route::macro` helpers, or tenancy done only through database connections. State that in the report when the app uses them.
