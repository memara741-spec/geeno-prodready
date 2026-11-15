# Fixture: clean-nextjs-supabase

**Story.** The same product as `nextjs-supabase-stripe` (FocusBoard), after a careful engineer finished it.
This fixture is the negative control: the scanners must report no critical, high or medium findings here.
It is also the one fixture that installs and builds (`npm ci && npm run build`), so the end-to-end test can
check that an app still builds after fixes.

**What it does right.** Owner-scoped policies with `with check`, indexes and policy tests; the price comes
from a server-side allow-list; the webhook verifies the signature on the raw body and records event IDs;
every handler verifies the user with `getUser()`; environment variables are validated in one module;
security headers are set; errors are reported through `instrumentation.ts`; the cron route requires a
secret; rate limiting is stored in Postgres; there is account deletion, a privacy page, a runbook, CI and
automated dependency updates.
