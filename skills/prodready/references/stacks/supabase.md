# Supabase

What this covers: key types, row level security, policies, functions, views, storage, edge functions and auth settings.
Read it when: the app uses Supabase (`database: supabase*`).
After reading you can: explain who can read and write each table and fix open policies.
Last checked: 2026-11-13.
Sources: https://supabase.com/docs/guides/api/api-keys, https://www.postgresql.org/docs/current/sql-createpolicy.html

## How this stack works
The browser talks to Postgres through an auto-generated REST and realtime API. Tables in an exposed schema (default `public`) are reachable with the public key, so **row level security (RLS) policies are the only access control** for client queries. Server code can use a secret key that bypasses RLS entirely.

## What is public and what is secret
- **Publishable key** (`sb_publishable_...`) and the legacy `anon` JWT: low privilege, safe in the browser, run as `anon` or `authenticated`.
- **Secret key** (`sb_secret_...`) and the legacy `service_role` JWT: elevated, bypass RLS, never in a browser. Supabase says legacy keys are being deprecated by the end of 2026 and creating new keys does not revoke them; they stay valid until you disable them.
- Source: https://supabase.com/docs/guides/api/api-keys
- Finding a publishable or anon key in client code is expected (SEC-016, info), not a leak.

## The failure modes AI tools produce here
- RLS off, or on with `using (true)` (DB-001, DB-002).
- "Authenticated" treated as "owner" (DB-003).
- Roles read from `user_metadata`, which users can edit (DB-005, AUTH-013).
- Service-role client used in server routes with an ID from the request (API-005).
- `security definer` functions and views without `security_invoker` (DB-007, DB-008).
- Public storage buckets for private files (DB-009).
- `getSession()` trusted on the server (AUTH-005).

## How to review it
1. `supabase/migrations/*.sql`: replay in order (the scanner does); read `inventory.access_matrix`.
2. `supabase/config.toml`: email confirmations, `verify_jwt` per function.
3. Edge functions in `supabase/functions/*`: who can call them, which key they use.
4. Server code using the service-role key.
If there are no migrations, report DB-015 and ask for `supabase db pull`.

## Correct patterns
```sql
-- Owner-scoped table
alter table public.notes enable row level security;
create policy "own_select" on public.notes for select to authenticated using ((select auth.uid()) = user_id);
create policy "own_insert" on public.notes for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "own_update" on public.notes for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "own_delete" on public.notes for delete to authenticated using ((select auth.uid()) = user_id);
create index on public.notes (user_id);
```
PostgreSQL semantics (https://www.postgresql.org/docs/current/sql-createpolicy.html): with RLS enabled and no policy, access is denied; permissive policies combine with OR, restrictive with AND; the default role is PUBLIC; for UPDATE and ALL, USING is reused as WITH CHECK when WITH CHECK is absent. Wrap `auth.uid()` in `(select ...)` and index policy columns for performance.
Server-side identity: never trust `supabase.auth.getSession()` in server code; use `getClaims()` (verifies the token signature) or `getUser()` (asks the Auth server). Source: https://supabase.com/docs/guides/auth/server-side/nextjs

## How to test it
Use `assets/sql/rls_test.sql.tmpl` with `supabase test db` (pgTAP): as user A, B's rows are invisible and unwritable; as anon, nothing is readable.

## Owner dashboard settings to confirm
Authentication: email confirmation, redirect URL allow-list, custom SMTP, leaked-password protection and rate limits <!-- unverified -->; Database: backups and point-in-time recovery by plan <!-- unverified -->; API keys: legacy keys disabled when new ones are in use.

## Checks this playbook supports
DB-001 to DB-009, DB-015, DB-017, DB-020, DB-021, DB-024, AUTH-005, AUTH-008, AUTH-013, API-013, MAIL-002.
