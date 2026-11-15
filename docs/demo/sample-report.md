# prodready report: Souq Local (fixture)

**Date:** 2026-01-01 · **Tool version:** 1.0.0 · **Files scanned:** 25
**Audited:** automated scan of source files and configuration, plus code review. **Not audited:** anything configured only in dashboards, the live site, and areas listed in the appendix.

## Verdict

# BLOCKED

11 critical finding(s) are open: anyone can reach other people's data, spend your money or take over accounts.

## The three things to do first

1. Anyone on the internet can read and change every row in `profiles`, because the table has no access rules switched on. (`DB-001:supabase/migrations/20240101000000_init.sql:3`)
2. Anyone on the internet can read, add, change and delete rows in `orders` without signing in. The access rule is switched on but lets everyone through. (`DB-002:supabase/migrations/20240101000000_init.sql:35`)
3. The rule on `reviews` decides access from profile data that users can edit themselves, so any user can grant themselves that access. (`DB-005:supabase/migrations/20240110000000_accounts.sql:19`)

## Summary

| Severity | Open |
|---|---|
| critical | 11 |
| high | 15 |
| medium | 25 |
| low | 17 |
| info | 3 |

By category: api 6, auth 4, database 16, dependencies 1, deploy 4, email 2, frontend 7, headers 4, launch 7, observability 1, payments 1, performance 3, privacy 3, reliability 1, secrets 7, testing 3, uploads 1

## Who can access what

| Table | Anyone can read | Anyone can change | Signed-in users can read | Signed-in users can change |
|---|---|---|---|---|
| public.accounts | none | no | own rows | own rows |
| public.listings | **yes** | no | all rows | own rows |
| public.messages | none | no | all rows | none |
| public.orders | **yes** | **yes** | all rows | all rows |
| public.profiles | **yes** | **yes** | all rows | all rows |
| public.reviews | none | no | own rows | own rows |

| Route | Who can call it | Touches |
|---|---|---|
| FUNCTION get-order | **anyone** | supabase-service-role |
| FUNCTION send-invite | **anyone** | - |

## Findings

### [CRITICAL] AUTH-002: Data-returning or data-changing route has no authentication check

**In plain words:** Anyone on the internet can call `FUNCTION get-order`. It reads or changes data with full access and never checks who is asking.
**Where:** `supabase/functions/get-order/index.ts:1`
**Evidence:**

```
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
```
**Why it matters:** Handler uses supabase-service-role and has no recognised authentication call.
**Fix:** Check the session at the top of the handler and return 401 when it is missing. Then check that the caller owns the record (API-005).
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [CRITICAL] AUTH-004: Server trusts a user identifier supplied by the client

**In plain words:** `FUNCTION get-order` believes whatever user ID the caller sends. Changing one field in the request lets a person act as any other user.
**Where:** `supabase/functions/get-order/index.ts:10`
**Evidence:**

```
const { user_id, order_id } = await req.json();
```
**Why it matters:** `user_id` comes from the request and is used with supabase-service-role. Identity must come from the verified session, not from the request body, query or headers.
**Fix:** Derive the user ID from the verified session on the server and ignore identity fields sent by the client.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [CRITICAL] AUTH-013: Role or admin flag stored where the user can change it

**In plain words:** Users can edit their own row in `accounts`, and that row also stores plan, is_admin, credits. A user can promote or credit themselves with one request.
**Where:** `supabase/migrations/20240110000000_accounts.sql:9`
**Evidence:**

```
create policy "Users can update own account" on public.accounts for update using (auth.uid() = user_id)
```
**Why it matters:** The update policy on public.accounts does not restrict which columns change, and the table has privileged column(s): plan, is_admin, credits.
**Fix:** Move these columns to a table users cannot write, or revoke UPDATE on them and grant UPDATE only on the safe columns.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [CRITICAL] DB-001: Row level security disabled on a client-reachable table

**In plain words:** Anyone on the internet can read and change every row in `profiles`, because the table has no access rules switched on.
**Where:** `supabase/migrations/20240101000000_init.sql:3`
**Evidence:**

```
create table public.profiles ( id uuid primary key references auth.users(id), full_name text, email text, phone text, role text default 'user', created_at timestamp default now() )
```
**Why it matters:** Table public.profiles is in an exposed schema and row level security is never enabled in the migrations. It holds columns that look sensitive: full_name, email, phone. The publishable key that ships in the app is enough to query it.
**Fix:** Write a new migration that enables row level security and adds per-operation policies scoped to the row owner.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** confirmed

### [CRITICAL] DB-002: Policy allows everyone

**In plain words:** Anyone on the internet can read, add, change and delete rows in `orders` without signing in. The access rule is switched on but lets everyone through.
**Where:** `supabase/migrations/20240101000000_init.sql:35`
**Evidence:**

```
create policy "Enable all" on public.orders for all using (true)
```
**Why it matters:** Policy "Enable all" applies to all roles for all with an unconditional expression.
**Fix:** Replace it with per-operation policies scoped to authenticated users and to the row owner.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** confirmed

### [CRITICAL] DB-003: Authenticated-only policy without ownership scoping

**In plain words:** Any signed-up user can read every row in `messages`, not just their own. Signing up is open to anyone, so this protects nothing.
**Where:** `supabase/migrations/20240101000000_init.sql:45`
**Evidence:**

```
create policy "Authenticated users can read messages" on public.messages for select using (auth.role() = 'authenticated')
```
**Why it matters:** Policy "Authenticated users can read messages" only checks that the caller is signed in.
**Fix:** Add an ownership or membership condition, for example (select auth.uid()) = sender_id.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [CRITICAL] DB-005: Policy trusts user-editable metadata

**In plain words:** The rule on `reviews` decides access from profile data that users can edit themselves, so any user can grant themselves that access.
**Where:** `supabase/migrations/20240110000000_accounts.sql:19`
**Evidence:**

```
create policy "Verified sellers can moderate reviews" on public.reviews for delete using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'moderator')
```
**Why it matters:** Policy "Verified sellers can moderate reviews" reads user_metadata, which a signed-in user can change with one API call.
**Fix:** Use app_metadata (server-controlled) or a roles table that users cannot write.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** confirmed

### [CRITICAL] DB-009: Storage bucket is public or has no access policies

**In plain words:** Every file in the `id-documents` storage bucket can be downloaded by anyone who has or guesses its link.
**Where:** `supabase/migrations/20240105000000_storage.sql:1`
**Evidence:**

```
insert into storage.buckets (id, name, public) values ('id-documents', 'id-documents', true)
```
**Why it matters:** Bucket "id-documents" is created with public = true. Its name suggests private documents.
**Fix:** Make the bucket private, add policies on storage.objects scoped to the user's folder, and serve files with short-lived signed URLs.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [CRITICAL] SEC-002: Secret committed in the current working tree

**In plain words:** A real-looking OpenAI project, service account or admin key is saved in .env, a file that is part of the repository. Anyone who can see the repository has this key.
**Where:** `.env:4`
**Evidence:**

```
VITE_OPENAI_API_KEY="sk-p…5v (56 chars)"
```
**Why it matters:** VITE_OPENAI_API_KEY = sk-p…5v (56 chars) in an env file that is not covered by .gitignore. The variable name starts with VITE_, so the value is also built into the browser bundle (SEC-005).
**Fix:** Remove the value from the file, add the file to .gitignore, keep an .env.example with empty values, and rotate the key.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [CRITICAL] SEC-005: Secret stored in a browser-exposed environment variable

**In plain words:** VITE_OPENAI_API_KEY is set up to hold an AI provider key, but its name starts with VITE_, which tells the build tool to copy the value into the code sent to every visitor.
**Where:** `.env:4`
**Evidence:**

```
VITE_OPENAI_API_KEY=[value present]
```
**Why it matters:** Variable VITE_OPENAI_API_KEY in .env. Its value matches a private key format. Variables with this prefix are inlined into the browser bundle at build time.
**Fix:** Rename it without the public prefix, move the code that uses it to the server, and rotate the key if a real value was ever deployed.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** confirmed

### [CRITICAL] SEC-013: AI provider key used directly from the browser or mobile client

**In plain words:** The AI provider is called straight from the browser, so the key that pays for it is in every visitor's hands.
**Where:** `src/lib/ai.ts:6`
**Evidence:**

```
dangerouslyAllowBrowser: true,
```
**Why it matters:** AI SDK constructed in client-bundled code with dangerouslyAllowBrowser: true.
**Fix:** Create a server endpoint that holds the key, checks who is calling and enforces limits. Rotate the key and set a provider spending limit.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** confirmed

### [HIGH] API-002: No rate limiting on expensive or abusable endpoints

**In plain words:** Nothing limits how often the app's costly endpoints can be called. One script can run up your bills, exhaust quotas or take the app down.
**Where:** `supabase/functions/send-invite/index.ts:1`
**Evidence:**

```
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
```
**Why it matters:** No rate limiting library or code was found. Endpoints that should be limited: FUNCTION send-invite.
**Fix:** Add per-user and per-IP limits backed by a shared store or the host's firewall rules, stricter on the costly endpoints.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [HIGH] API-013: Edge or cloud functions deployed with JWT verification disabled

**In plain words:** The server function `get-order` accepts calls from anyone, with no check that the caller is signed in.
**Where:** `supabase/config.toml:11`
**Evidence:**

```
[functions.get-order] verify_jwt = false
```
**Why it matters:** verify_jwt = false for function get-order, and its code does not verify the caller or a webhook signature itself.
**Fix:** Remove verify_jwt = false, or verify the bearer token in the function. For webhooks, verify the provider's signature.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [HIGH] API-013: Edge or cloud functions deployed with JWT verification disabled

**In plain words:** The server function `send-invite` accepts calls from anyone, with no check that the caller is signed in.
**Where:** `supabase/config.toml:14`
**Evidence:**

```
[functions.send-invite] verify_jwt = false
```
**Why it matters:** verify_jwt = false for function send-invite, and its code does not verify the caller or a webhook signature itself.
**Fix:** Remove verify_jwt = false, or verify the bearer token in the function. For webhooks, verify the provider's signature.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [HIGH] DB-004: Write policy missing an effective WITH CHECK condition

**In plain words:** A signed-in user can add rows to `listings` that claim to belong to someone else.
**Where:** `supabase/migrations/20240101000000_init.sql:22`
**Evidence:**

```
create policy "Users can create listings" on public.listings for insert to authenticated with check (true)
```
**Why it matters:** Insert policy "Users can create listings" has a WITH CHECK that does not compare the owner column with auth.uid(), so nothing ties the new row's user_id to the caller.
**Fix:** Add WITH CHECK ((select auth.uid()) = user_id).
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** confirmed

### [HIGH] DB-007: Privileged function callable through the API

**In plain words:** The database function `promote_to_admin` runs with full rights and can be called by anyone through the API, skipping the access rules.
**Where:** `supabase/migrations/20240110000000_accounts.sql:24`
**Evidence:**

```
create or replace function public.promote_to_admin(target uuid) returns void language sql security definer as $$ update public.accounts set is_admin = true where user_id = target; $$
```
**Why it matters:** public.promote_to_admin is SECURITY DEFINER in an exposed schema: no fixed search_path; EXECUTE is not revoked from anon/public; it takes a user ID argument and never checks auth.uid().
**Fix:** Move it to a private schema or revoke EXECUTE from anon and public, set search_path = '', and check auth.uid() inside the function.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [HIGH] DB-008: View bypasses row level security

**In plain words:** The view `order_summaries` shows rows to every caller regardless of the access rules on the tables behind it.
**Where:** `supabase/migrations/20240110000000_accounts.sql:32`
**Evidence:**

```
create view public.order_summaries as select o.id, o.total, o.shipping_address, p.email from public.orders o join public.profiles p on p.id = o.buyer_id
```
**Why it matters:** public.order_summaries is created without security_invoker in an exposed schema. Views run with their owner's rights unless created with security_invoker = true.
**Fix:** Recreate it WITH (security_invoker = true), or move it out of the exposed schema.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [HIGH] DB-020: Realtime channels deliver data without authorisation

**In plain words:** Live updates from `messages` are broadcast to everyone who can read the table, and the table's read rule lets everyone in.
**Where:** `supabase/migrations/20240101000000_init.sql:50`
**Evidence:**

```
alter publication supabase_realtime add table public.messages
```
**Why it matters:** public.messages is in the supabase_realtime publication and its SELECT access is not scoped to the row owner.
**Fix:** Fix the SELECT policy first; realtime follows it.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** possible

### [HIGH] DB-021: Anonymous role holds broad grants or can call sensitive RPCs

**In plain words:** Visitors who are not signed in are granted write access, and 2 table(s) have no rule to stop them.
**Where:** `supabase/migrations/20240110000000_accounts.sql:36`
**Evidence:**

```
grant all on all tables in schema public to anon
```
**Why it matters:** Grant to anon combined with missing or permissive row level security on: public.orders, public.profiles.
**Fix:** Fix the row level security on those tables, and grant anon only what public pages need.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [HIGH] DB-024: Public profile data exposes private fields

**In plain words:** Anyone on the internet can download every user's full_name, email, phone from `profiles`.
**Where:** `supabase/migrations/20240101000000_init.sql:3`
**Evidence:**

```
create table public.profiles ( id uuid primary key references auth.users(id), full_name text, email text, phone text, role text default 'user', created_at timestamp default now() )
```
**Why it matters:** public.profiles is readable in full by anon and authenticated and contains: full_name, email, phone.
**Fix:** Split public and private columns into separate tables, or expose a restricted view, and select explicit columns.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [HIGH] MAIL-002: Relying on the backend provider's built-in development email service

**In plain words:** Sign-up and password reset emails go through the provider's built-in test mail service, which is tightly rate limited. Once real users arrive, some of them will never receive their email.
**Where:** `supabase/config.toml:7`
**Evidence:**

```
[auth.email] (no [auth.email.smtp] section)
```
**Why it matters:** No custom SMTP is configured in supabase/config.toml. Confirm in the dashboard under Authentication, SMTP settings.
**Fix:** Configure a transactional email provider as custom SMTP and authenticate the sending domain.
**Effort:** owner · **Who:** You need to do this in a dashboard
**Confidence:** possible

### [HIGH] MAIL-004: Email or SMS sending can be triggered without limit

**In plain words:** Anyone can make `FUNCTION send-invite` send email or text messages to any address, as often as they like. Your sending domain will be blacklisted and SMS fraud costs real money.
**Where:** `supabase/functions/send-invite/index.ts:1`
**Evidence:**

```
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
```
**Why it matters:** Message-sending handler with no authentication, rate limit or CAPTCHA, and a recipient taken from the request.
**Fix:** Require sign-in where possible, rate limit per IP, account and recipient, add a CAPTCHA to public forms, and send fixed templates only.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [HIGH] OBS-001: No error tracking

**In plain words:** If the app breaks for a user, you will not find out unless they tell you. Nothing records errors.
**Where:** `package.json:1`
**Why it matters:** No error tracking SDK (Sentry, Bugsnag, Rollbar and similar) or custom error hook was found on the client or the server.
**Fix:** Add an error tracker on both client and server, scrub personal data, and upload source maps privately.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [HIGH] SEC-004: Environment files are not ignored by git

**In plain words:** Your .gitignore does not exclude .env files, so the file that holds your keys will be published with the next commit.
**Where:** `.gitignore:1`
**Evidence:**

```
node_modules
```
**Why it matters:** .gitignore has no pattern that matches .env; env files present: .env.
**Fix:** Add .env and .env.* to .gitignore, keep !.env.example, and run `git rm --cached .env` if it is already tracked.
**Effort:** small · **Who:** Claude can fix this
**Confidence:** confirmed

### [HIGH] SEC-007: Secrets or server code visible in published source maps or build output

**In plain words:** The app publishes its original source code (source maps) to every visitor, including comments and any value that was inlined at build time.
**Where:** `vite.config.ts:10`
**Evidence:**

```
build: { sourcemap: true },
```
**Why it matters:** Production source maps are enabled.
**Fix:** Disable public source maps, or upload them privately to your error tracker.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [HIGH] UP-004: Private files exposed through permanent public URLs

**In plain words:** Private documents in `id-documents` are shared through permanent public links. Anyone who gets a link has the file forever.
**Where:** `src/pages/Profile.tsx:12`
**Evidence:**

```
const { data } = supabase.storage.from("id-documents").getPublicUrl(path);
```
**Why it matters:** getPublicUrl() on bucket "id-documents", whose name suggests private files.
**Fix:** Make the bucket private and issue short-lived signed URLs after checking that the caller may see the file.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] API-001: Request input is not validated

**In plain words:** `FUNCTION get-order` uses what the caller sends without checking its type or size. Unexpected input can crash it or store bad data.
**Where:** `supabase/functions/get-order/index.ts:1`
**Evidence:**

```
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
```
**Why it matters:** Handler reads body with no schema validation (zod, valibot, yup, joi, pydantic) and no manual type checks.
**Fix:** Parse the input with a schema at the top of the handler, return 400 on failure, and use only the parsed result.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** possible

### [MEDIUM] API-001: Request input is not validated

**In plain words:** `FUNCTION send-invite` uses what the caller sends without checking its type or size. Unexpected input can crash it or store bad data.
**Where:** `supabase/functions/send-invite/index.ts:1`
**Evidence:**

```
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
```
**Why it matters:** Handler reads body with no schema validation (zod, valibot, yup, joi, pydantic) and no manual type checks.
**Fix:** Parse the input with a schema at the top of the handler, return 400 on failure, and use only the parsed result.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** possible

### [MEDIUM] API-004: Errors return internal details to the client

**In plain words:** When something fails, the server sends the internal error text to the caller. That can reveal table names, file paths and sometimes secrets.
**Where:** `supabase/functions/get-order/index.ts:14`
**Evidence:**

```
return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: corsHeaders });
```
**Why it matters:** Response body includes the error's message or stack.
**Fix:** Return a generic message with a request ID, and send the full error to server logs and the error tracker.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] AUTH-008: Email addresses are not verified before the account is trusted

**In plain words:** Email addresses are not confirmed in this configuration, so someone can sign up with an address they do not own.
**Where:** `supabase/config.toml:8`
**Evidence:**

```
enable_confirmations = false
```
**Why it matters:** [auth.email] enable_confirmations = false in supabase/config.toml. This file configures local development; the hosted project may differ, so confirm in the dashboard under Authentication.
**Fix:** Enable email confirmation in the hosted project and in config.toml.
**Effort:** owner · **Who:** You need to do this in a dashboard
**Confidence:** possible

### [MEDIUM] DB-017: Missing indexes on columns used by policies and foreign keys

**In plain words:** The access rules on `listings` will make every query slower as the table grows.
**Where:** `supabase/migrations/20240101000000_init.sql:21`
**Evidence:**

```
create policy "Anyone can view listings" on public.listings for select using (true)
```
**Why it matters:** Policies on public.listings: no index on user_id.
**Fix:** Add an index on the policy column(s) and wrap auth.uid() in a sub-select.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] DB-017: Missing indexes on columns used by policies and foreign keys

**In plain words:** The access rules on `messages` will make every query slower as the table grows.
**Where:** `supabase/migrations/20240101000000_init.sql:45`
**Evidence:**

```
create policy "Authenticated users can read messages" on public.messages for select using (auth.role() = 'authenticated')
```
**Why it matters:** Policies on public.messages: no index on sender_id.
**Fix:** Add an index on the policy column(s) and wrap auth.uid() in a sub-select.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] DB-017: Missing indexes on columns used by policies and foreign keys

**In plain words:** The access rules on `accounts` will make every query slower as the table grows.
**Where:** `supabase/migrations/20240110000000_accounts.sql:8`
**Evidence:**

```
create policy "Users can view own account" on public.accounts for select using (auth.uid() = user_id)
```
**Why it matters:** Policies on public.accounts: auth.uid() is called per row instead of once via (select auth.uid()).
**Fix:** Add an index on the policy column(s) and wrap auth.uid() in a sub-select.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] DB-017: Missing indexes on columns used by policies and foreign keys

**In plain words:** The access rules on `reviews` will make every query slower as the table grows.
**Where:** `supabase/migrations/20240110000000_accounts.sql:19`
**Evidence:**

```
create policy "Verified sellers can moderate reviews" on public.reviews for delete using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'moderator')
```
**Why it matters:** Policies on public.reviews: no index on author_id; auth.uid() is called per row instead of once via (select auth.uid()).
**Fix:** Add an index on the policy column(s) and wrap auth.uid() in a sub-select.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] DEP-003: Environment variables are not validated at startup

**In plain words:** The app reads its settings in 3 different files without checking them at startup. A missing setting shows up later as a confusing failure.
**Where:** `src/lib/ai.ts:5`
**Evidence:**

```
apiKey: import.meta.env.VITE_OPENAI_API_KEY,
```
**Why it matters:** Environment variables are read directly in: src/lib/ai.ts, supabase/functions/get-order/index.ts, supabase/functions/send-invite/index.ts. No validation module was found.
**Fix:** Add one module that validates the environment with a schema and fails fast, and read settings only through it.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] DEP-006: Builds are not reproducible

**In plain words:** Tomorrow's deployment may install different code than today's: no lockfile; no pinned Node version.
**Where:** `package.json:1`
**Evidence:**

```
{
```
**Why it matters:** Reproducibility review: no lockfile; no pinned Node version.
**Fix:** Use one package manager, commit its lockfile, pin the runtime and install with `npm ci`.
**Effort:** small · **Who:** Claude can fix this
**Confidence:** confirmed

### [MEDIUM] DEP-008: Build ignores type and lint errors

**In plain words:** TypeScript's safety checks are turned off, so many bugs are invisible until a user hits them.
**Where:** `tsconfig.json:9`
**Evidence:**

```
"noImplicitAny": false,
```
**Why it matters:** strict, strictNullChecks or noImplicitAny is false in tsconfig.json.
**Fix:** Enable strict mode gradually and fix what surfaces.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] FE-002: Sensitive data kept in browser storage or client state longer than needed

**In plain words:** A copy of the user's personal data is kept in the browser's storage, where it stays after sign-out and is readable by any script on the page.
**Where:** `src/pages/Profile.tsx:15`
**Evidence:**

```
localStorage.setItem("user_profile", JSON.stringify(profile));
```
**Why it matters:** localStorage.setItem('user_profile', ...) persists a user record.
**Fix:** Store the minimum needed, and clear it on sign-out.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] FE-004: No error boundary or global error handling

**In plain words:** If any part of the page hits an error, the whole app turns into a blank white screen with no way forward.
**Where:** `src/App.tsx:1`
**Evidence:**

```
import { BrowserRouter, Routes, Route } from "react-router-dom";
```
**Why it matters:** No error boundary, error route file or global error handler was found.
**Fix:** Add an error boundary (for Next.js: app/error.tsx and app/global-error.tsx) with a retry action, and report the error to your tracker.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] HDR-001: No Content Security Policy

**In plain words:** The site sends no Content Security Policy. If an attacker ever gets a script onto a page, nothing limits what it can do.
**Where:** `package.json:1`
**Evidence:**

```
{
```
**Why it matters:** No Content-Security-Policy header or meta tag in framework, host or middleware configuration.
**Fix:** Start from assets/security-headers/ for your host, in report-only mode first if the app has inline scripts.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] HDR-002: HTTPS not enforced with HSTS

**In plain words:** Nothing makes browsers insist on HTTPS for this site, so a visitor on a hostile network can be downgraded to an unencrypted connection.
**Where:** `package.json:1`
**Why it matters:** No Strict-Transport-Security header configured and the host is not known to add it.
**Fix:** Add Strict-Transport-Security: max-age=63072000; includeSubDomains once HTTPS works everywhere.
**Effort:** small · **Who:** Claude can fix this
**Confidence:** likely

### [MEDIUM] HDR-003: Pages can be framed by other sites

**In plain words:** Other sites can embed your pages in an invisible frame and trick visitors into clicking.
**Where:** `package.json:1`
**Why it matters:** No frame-ancestors directive and no X-Frame-Options header.
**Fix:** Add frame-ancestors 'none' (or 'self') to the CSP and X-Frame-Options: DENY.
**Effort:** small · **Who:** Claude can fix this
**Confidence:** likely

### [MEDIUM] LAUNCH-004: Placeholder content and mock data shipped

**In plain words:** Placeholder content is still in the app: "coming soon" text, a button or link that does nothing, placeholder person name, placeholder text (lorem ipsum). Visitors read this as an unfinished or untrustworthy product.
**Where:** `src/pages/Index.tsx:5`
**Evidence:**

```
{ name: "John Doe", text: "Lorem ipsum dolor sit amet, consectetur adipiscing elit." },
```
**Why it matters:** 9 placeholder item(s) in user-visible text in this file.
**Fix:** Replace with real content or remove it. Invented testimonials and statistics should be deleted, not reworded.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] PAY-011: Money stored or computed as floating point

**In plain words:** The `price` amount is stored as a floating point number, which cannot represent most decimal amounts exactly.
**Where:** `supabase/migrations/20240101000000_init.sql:17`
**Evidence:**

```
price real not null,
```
**Why it matters:** Column price has type real.
**Fix:** Store integer minor units (cents) or use numeric(12,2).
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] PERF-002: Whole tables fetched to the client and filtered there

**In plain words:** The app downloads the whole `messages` table to the browser and then picks out what it needs. That is slow, costs money, and hands every visitor rows they should not receive.
**Where:** `src/pages/Messages.tsx:12`
**Evidence:**

```
const { data } = await supabase.from("messages").select("*");
```
**Why it matters:** Unfiltered fetch followed by client-side .filter within the same component.
**Fix:** Filter, sort and paginate in the query, and let the access rules return only the caller's rows.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] PRIV-001: No privacy policy or terms where personal data is collected

**In plain words:** Your app collects people's accounts but has no privacy policy or terms. App stores, payment providers and sign-in screens require them, and most countries do too.
**Where:** `project-level`
**Why it matters:** Accounts are present (supabase-auth) but no privacy or terms page, route or link was found. This is a factual finding, not legal advice.
**Fix:** Add privacy and terms pages linked from sign-up and the footer. Use the data inventory from this report to draft the policy with a lawyer or a policy generator.
**Effort:** owner · **Who:** You need to do this in a dashboard
**Confidence:** likely

### [MEDIUM] PRIV-003: Users cannot delete their account or export their data

**In plain words:** Users cannot delete their account or their data. That is a legal right in many places and a requirement of both app stores for apps with sign-up.
**Where:** `project-level`
**Why it matters:** No account deletion endpoint, function or screen was found.
**Fix:** Add a confirmed deletion flow that removes the user's rows, files and third-party records (database cascades help), plus an export of their data.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] REL-002: External calls without timeouts or retry policy

**In plain words:** A call to another service has no time limit. If that service hangs, every request that depends on it hangs too.
**Where:** `supabase/functions/send-invite/index.ts:6`
**Evidence:**

```
const res = await fetch("https://api.resend.com/emails", {
```
**Why it matters:** fetch() without an abort signal or timeout.
**Fix:** Pass signal: AbortSignal.timeout(ms) and handle the timeout.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** possible

### [MEDIUM] TEST-001: No automated test for the critical paths

**In plain words:** There are no automated tests. Every later change, especially one made by an AI tool, can silently break sign-up or payment.
**Where:** `package.json:1`
**Why it matters:** No test files or test script found.
**Fix:** Add a small set of tests: sign-in, the core action, cross-user access denial and payment webhook handling.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** confirmed

### [MEDIUM] TEST-002: No access-rule tests

**In plain words:** The access rules are the main security boundary, and nothing tests them. One careless edit can open the whole database.
**Where:** `supabase/config.toml:1`
**Why it matters:** Policies or rules exist but no emulator, pgTAP or SQL tests reference them.
**Fix:** Generate tests from assets/sql/rls_test.sql.tmpl or add Firebase emulator rules tests: user A cannot read or write user B's data, and anonymous cannot read private data.
**Effort:** medium · **Who:** Claude can fix this; you review and apply
**Confidence:** likely

### [MEDIUM] TEST-003: No CI pipeline running checks before deploy

**In plain words:** Nothing checks changes before they go live, so broken or insecure code ships unreviewed.
**Where:** `project-level`
**Why it matters:** No CI workflow that runs tests, type checks, a build or an audit.
**Fix:** Install assets/ci/prodready.yml and add install, typecheck, test, build and an audit step.
**Effort:** small · **Who:** Claude can fix this
**Confidence:** confirmed

### Low (batched)

- `DEP-004` There is no simple address a monitoring service can call to check whether the app is alive. (package.json:1)
- `DEPS-006` Nothing tells you when a new security fix is released for the packages you use. 
- `FE-003` Debug output is left in the app. Anyone who opens the browser console sees it, and it can include user data. (src/pages/Index.tsx:14)
- `FE-007` The page loads a script from another company's server with no integrity check. If that server is compromised, the attacker's code runs on your site with full access to the page. (index.html:13)
- `FE-007` The page loads a script from another company's server with no integrity check. If that server is compromised, the attacker's code runs on your site with full access to the page. (index.html:14)
- `FE-008` Some visitors cannot use parts of the app: the page does not declare its language; 1 image(s) without a text description; 1 clickable element(s) that keyboards and screen readers cannot use. (index.html:2)
- `FE-009` Links that open a new tab do not isolate it from your page. Older browsers let the new page redirect yours. (src/pages/Index.tsx:27)
- `HDR-004` Small free protections are not switched on: x-content-type-options, referrer-policy, permissions-policy. (package.json:1)
- `LAUNCH-001` When someone shares a link to the app, it shows up with the title is still the template default ("Lovable App"); the description is the template default; the social preview image is the builder's default. (index.html:6)
- `LAUNCH-002` The app's icons are not finished: no browser tab icon; no home-screen icon; no web app manifest. (index.html:1)
- `LAUNCH-003` There is no robots.txt or sitemap, so search engines get no guidance about what to index. (package.json:1)
- `LAUNCH-005` The AI builder's branding and tooling are still in the app: a "Edit with Lovable" badge, the Lovable default social image, the Lovable editor script, the Lovable tagger plugin. (index.html:9)
- `LAUNCH-006` Users have no way to ask for help or report a problem, and there is no address for reporting security issues. 
- `LAUNCH-009` There is no README that explains how to run, configure and deploy the app, so nobody else, including a future AI assistant, can safely work on it. (README.md:1)
- `PERF-004` A large library is loaded in full for every visitor, which slows the first page load on phones. (src/pages/Listings.tsx:2)
- `PERF-006` A live data subscription is opened every time this screen appears and never closed. Over time that means duplicate updates, memory leaks and rising costs. (src/pages/Messages.tsx:22)
- `SEC-008` There is no .env.example listing the settings this app needs, so setting it up elsewhere is guesswork. 

### Info (batched)

- `DB-002` Everyone can read `listings`. If this is public reference data that is fine; confirm that it is intended. (supabase/migrations/20240101000000_init.sql:21)
- `PRIV-006` 3 outside services receive your users' data. You need this list for your privacy policy and for customers who ask. 
- `SEC-016` This Supabase key is designed to be public. It is not a leak; what protects your data is the access rules behind it. (.env:3)

## Owner actions

- [ ] `AUTH-008` Email addresses are not verified before the account is trusted
- [ ] `DB-009` Storage bucket is public or has no access policies
- [ ] `MAIL-002` Relying on the backend provider's built-in development email service (guide: `references/owner-actions/dns-and-email.md`)
- [ ] `OBS-001` No error tracking (guide: `references/checks/observability.md#obs-001`)
- [ ] `PRIV-001` No privacy policy or terms where personal data is collected
- [ ] `SEC-002` Secret committed in the current working tree (guide: `references/owner-actions/rotate-keys.md`)
- [ ] `SEC-005` Secret stored in a browser-exposed environment variable (guide: `references/owner-actions/rotate-keys.md`)
- [ ] `SEC-013` AI provider key used directly from the browser or mobile client (guide: `references/owner-actions/rotate-keys.md`)

## Questions for you

- `DB-016` Are automated database backups switched on, and have you ever restored one to a scratch project?
- `REL-007` When did you last test restoring from a backup?
- `OBS-003` Is an uptime monitor checking the site and alerting someone who will see it?
- `DEP-005` Do you know how to roll back a bad release on your host?
- `LAUNCH-007` Which is the production domain, and do www and the bare domain redirect to one of them?
- `DEP-014` Have you set budgets and usage alerts at each pay-per-use provider (openai, resend, supabase)?
- `MAIL-001` Is the sending domain authenticated with SPF, DKIM and DMARC?
- `DEP-011` Is the code in a GitHub repository you own, and is the backend project under your own account?
- `DEP-002` Are development and production using separate databases or backend projects?
- `DEP-013` Is the default branch protected, so changes need a review or passing checks?

## What looks good

<!-- The reviewer fills in three to six specific strengths with evidence. -->

## Launch checklist

See `references/checks/launch.md`. Status of each item is filled in at the launch gate.

## Appendix

**Detected stack:** framework vite-react, database supabase-postgres, auth supabase-auth, payments none, AI openai, hosting lovable.

**Third parties that receive user data:**

- openai (AI provider): prompts and uploaded content
- resend (email): email addresses and message content
- supabase (database and auth): accounts, all app data

**Scanners:** scan_secrets (ran), scan_env (ran), scan_supabase (ran), scan_firebase (ran), scan_routes (ran), scan_payments (ran), scan_llm (ran), scan_frontend (ran), scan_config (ran), scan_deps (ran), scan_launch (ran), scan_git_history (skipped)

**Warnings:**
- scan_deps: full vulnerability audit skipped (offline). Only the bundled advisory table was used; run `npm audit` or pass --allow-network.

**Limits of this audit.** This review is automated and based on source code. Settings that exist only in provider dashboards (backups, email domain, billing limits, auth options) could not be seen unless stated. It is not a penetration test and not a compliance certification, and it does not replace a professional audit for health, financial or children's data.

