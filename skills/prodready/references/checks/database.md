# Database, storage and access rules (DB)

What this covers: the 24 DB checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### DB-001 — Row level security disabled on a client-reachable table
**Severity:** critical · **Mode:** scan · **Applies to:** supabase, postgrest
**Auto-fix:** assisted

**In plain words:** Anyone on the internet can read and change every row in this table, because access rules are not switched on.

**How to detect:** Run `scripts/scan_supabase.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** With the public key that ships in every client, the auto-generated API exposes the whole table.

**Fix:** Write a migration that enables RLS and adds least-privilege policies from assets/sql/ templates; you apply it.

**Verify:** Scanner clean on migrations; the RLS test passes; an anonymous request returns no rows.

### DB-002 — Policy allows everyone
**Severity:** critical · **Mode:** scan · **Applies to:** supabase
**Auto-fix:** assisted

**In plain words:** A policy lets everyone read or change every row, so the access rule is on but protects nothing.

**How to detect:** Run `scripts/scan_supabase.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** RLS is technically enabled, but USING (true) opens the table.

**Fix:** Scope to authenticated users and to the row owner or tenant; separate policies per operation.

**Verify:** Scanner clean; the RLS test proves user A cannot read user B's rows.

### DB-003 — Authenticated-only policy without ownership scoping
**Severity:** critical · **Mode:** scan+review · **Applies to:** supabase
**Auto-fix:** assisted

**In plain words:** Any signed-up user can read or change every row; since anyone can sign up, that means anyone.

**How to detect:** `scripts/scan_supabase.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Authenticated-only is not ownership.

**Fix:** Add (select auth.uid()) = user_id or a tenant membership condition.

**Verify:** Cross-user RLS test.

### DB-004 — Write policy missing an effective WITH CHECK condition
**Severity:** high · **Mode:** scan · **Applies to:** supabase, postgres
**Auto-fix:** assisted

**In plain words:** A user can add rows that claim to belong to someone else, or hand their rows to another user.

**How to detect:** Run `scripts/scan_supabase.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A missing or weak WITH CHECK lets ownership be forged. (PostgreSQL reuses USING for UPDATE and ALL when WITH CHECK is absent; the exposure is insert policies without it and weak explicit ones.)

**Fix:** Add WITH CHECK mirroring the ownership condition; make ownership columns immutable where possible.

**Verify:** Test: insert with another user's ID fails.

### DB-005 — Policy trusts user-editable metadata
**Severity:** critical · **Mode:** scan · **Applies to:** supabase
**Auto-fix:** assisted

**In plain words:** A rule decides access from profile data users can edit themselves, so any user can grant themselves access.

**How to detect:** Run `scripts/scan_supabase.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** user_metadata is writable by the signed-in user.

**Fix:** Use app_metadata or a roles table with its own policies.

**Verify:** Scanner clean.

### DB-006 — Table has no ownership or tenant column to scope by
**Severity:** high · **Mode:** review · **Applies to:** supabase, postgres, any
**Auto-fix:** assisted

**In plain words:** A table has no column saying who owns each row, so no rule can keep users apart.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Without an ownership column no rule can separate users; client-side filtering is a filter, not protection.

**Fix:** Add the column with a default of the current user, backfill, then add policies.

**Verify:** Migration present; cross-user test.

### DB-007 — Privileged function callable through the API
**Severity:** high · **Mode:** scan · **Applies to:** supabase, postgres
**Auto-fix:** assisted

**In plain words:** A database function runs with full rights and anyone can call it through the API, skipping the access rules.

**How to detect:** Run `scripts/scan_supabase.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** SECURITY DEFINER functions run with their owner's rights and can bypass RLS for any caller.

**Fix:** Move to a private schema or revoke EXECUTE from anon and public, set search_path = '', check auth.uid() inside.

**Verify:** Scanner clean.

### DB-008 — View bypasses row level security
**Severity:** high · **Mode:** scan · **Applies to:** supabase, postgres 15+
**Auto-fix:** assisted

**In plain words:** A view shows rows to every caller regardless of the access rules on the tables behind it.

**How to detect:** Run `scripts/scan_supabase.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** By default a view runs with its creator's rights.

**Fix:** Recreate with WITH (security_invoker = true) or move it out of the exposed schema.

**Verify:** Scanner clean.

### DB-009 — Storage bucket is public or has no access policies
**Severity:** high · **Mode:** scan+review · **Applies to:** supabase storage, firebase storage, s3, r2
**Auto-fix:** assisted+owner

**In plain words:** Files in a storage bucket can be downloaded by anyone who has or guesses a link.

**How to detect:** `scripts/scan_supabase.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** A public bucket serves every uploaded file; listing may also be possible.

**Fix:** Make the bucket private, add policies scoped by user folder, use short-lived signed URLs.

**Verify:** Scanner clean; an anonymous fetch of a test object fails.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### DB-010 — Firebase rules allow open access
**Severity:** critical · **Mode:** scan · **Applies to:** firebase
**Auto-fix:** assisted

**In plain words:** Anyone on the internet can read and change your Firebase data without signing in.

**How to detect:** Run `scripts/scan_firebase.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** The whole database is readable and writable by anyone with the project ID, which is in the client.

**Fix:** Deny by default, write per-collection rules scoped by request.auth.uid, keep rules in the repository and deploy them from it.

**Verify:** Scanner clean; emulator rules tests added and passing.

### DB-011 — Firebase rules check sign-in but not ownership or shape
**Severity:** critical · **Mode:** scan+review · **Applies to:** firebase
**Auto-fix:** assisted

**In plain words:** Any signed-up user can read or edit other people's Firebase data, or edit fields that should be server-controlled.

**How to detect:** `scripts/scan_firebase.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** A signed-in check without ownership or field validation is open to every user.

**Fix:** Scope by request.auth.uid and validate writable fields with hasOnly; move privileged fields to server-written documents.

**Verify:** Emulator tests for cross-user read, cross-user write and privileged field write.

### DB-012 — SQL built by string concatenation with request data
**Severity:** critical · **Mode:** scan · **Applies to:** any sql
**Auto-fix:** assisted

**In plain words:** A database query is built by pasting request text into SQL, so a crafted input can read or destroy the whole database.

**How to detect:** Run `scripts/scan_routes.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** SQL injection.

**Fix:** Use parameterised queries or tagged templates and allow-list identifiers.

**Verify:** Scanner clean; test with a quote character.

### DB-013 — Request body written to the database without field selection
**Severity:** high · **Mode:** scan · **Applies to:** prisma, drizzle, mongoose, supabase-js, any orm
**Auto-fix:** assisted

**In plain words:** The whole request body is written to the database, so the caller can set fields like role, owner or price.

**How to detect:** Run `scripts/scan_routes.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Mass assignment.

**Fix:** Validate with a schema, pick allowed fields explicitly, set ownership from the session.

**Verify:** Test: an extra privileged field in the body is ignored.

### DB-014 — Database reachable directly from the browser with privileged credentials
**Severity:** critical · **Mode:** scan · **Applies to:** any
**Auto-fix:** assisted+owner

**In plain words:** Browser code connects straight to the database, which requires shipping the database password to every visitor.

**How to detect:** Run `scripts/scan_routes.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Full database credentials are published.

**Fix:** Move data access behind server routes and rotate the database password.

**Verify:** Scanner clean.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### DB-015 — Schema and policies exist only in the hosted dashboard
**Severity:** medium · **Mode:** scan · **Applies to:** supabase, firebase
**Auto-fix:** assisted+owner

**In plain words:** The rules that protect your data exist only in a dashboard, so they cannot be reviewed, tested or restored from code.

**How to detect:** Run `scripts/scan_supabase.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Security rules cannot be versioned or tested; this audit cannot see them.

**Fix:** Pull the schema and policies into the repository with the vendor CLI and re-run the scan.

**Verify:** Files present; scanner processes them.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### DB-016 — No backups or no tested restore
**Severity:** high · **Mode:** review · **Applies to:** all
**Auto-fix:** owner

**In plain words:** If data is lost or deleted, you may have no way to get it back.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** One bad migration, bug or attacker deletes everything permanently.

**Fix:** Enable automated backups or point-in-time recovery, schedule an export, and perform one restore to a scratch project.

**Verify:** Owner confirms the backup setting and one successful restore.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### DB-017 — Missing indexes on columns used by policies and foreign keys
**Severity:** medium · **Mode:** scan · **Applies to:** postgres, supabase
**Auto-fix:** assisted

**In plain words:** The access rules will make every query slower as data grows.

**How to detect:** Run `scripts/scan_supabase.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Unindexed policy columns and per-row auth.uid() calls cause full scans.

**Fix:** Add indexes on policy columns and wrap auth.uid() in a sub-select.

**Verify:** Scanner clean.

### DB-018 — Serverless functions open direct database connections without pooling
**Severity:** medium · **Mode:** scan+review · **Applies to:** prisma, drizzle, pg on serverless
**Auto-fix:** assisted

**In plain words:** Under real traffic the app will run out of database connections and go down.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Serverless functions that open a connection per request exhaust the pool.

**Fix:** Use the provider's pooler URL and one client instance per runtime.

**Verify:** Config review.

### DB-019 — Multi-tenant data not isolated by tenant in rules or queries
**Severity:** critical · **Mode:** review · **Applies to:** any multi-tenant
**Auto-fix:** assisted

**In plain words:** One customer may be able to see another customer's data.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** The worst incident for a B2B product.

**Fix:** Enforce tenant membership in policies or a shared data layer; never accept a tenant ID without checking membership.

**Verify:** Cross-tenant tests.

### DB-020 — Realtime channels deliver data without authorisation
**Severity:** high · **Mode:** review · **Applies to:** supabase realtime, firebase, pusher, ably, socket.io
**Auto-fix:** assisted

**In plain words:** Anyone can subscribe to live updates and watch private changes as they happen.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Realtime follows the table's read rules and channel authorisation.

**Fix:** Use private channels with authorisation and sound RLS; authorise socket rooms on the server.

**Verify:** An unauthenticated subscription receives nothing.

### DB-021 — Anonymous role holds broad grants or can call sensitive RPCs
**Severity:** high · **Mode:** scan · **Applies to:** supabase, postgres
**Auto-fix:** assisted

**In plain words:** Visitors who are not signed in have broad database grants.

**How to detect:** Run `scripts/scan_supabase.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Grants plus a permissive policy expose data to anonymous callers.

**Fix:** Revoke, grant minimal rights, check auth.uid() in functions.

**Verify:** Scanner clean.

### DB-022 — Guessable identifiers combined with weak authorisation
**Severity:** medium · **Mode:** review · **Applies to:** any
**Auto-fix:** assisted

**In plain words:** Record IDs are guessable, which makes enumeration trivial where authorisation is weak.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Random IDs mitigate but do not fix missing authorisation.

**Fix:** Fix authorisation first, then consider UUIDs for public identifiers.

**Verify:** See API-005.

### DB-023 — Application connects to the database as a superuser
**Severity:** medium · **Mode:** review · **Applies to:** postgres, mysql, mongo self-managed
**Auto-fix:** owner

**In plain words:** The app connects to the database as a superuser, so any bug has unlimited reach and RLS is skipped.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** A least-privilege role limits the blast radius.

**Fix:** Create a dedicated least-privilege application role.

**Verify:** Owner confirms the connection user changed.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### DB-024 — Public profile data exposes private fields
**Severity:** high · **Mode:** scan+review · **Applies to:** supabase, firebase, any
**Auto-fix:** assisted

**In plain words:** Anyone, or any signed-up user, can download every user's private details such as email or phone.

**How to detect:** `scripts/scan_supabase.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Mass scraping of personal data.

**Fix:** Split public and private columns into separate tables or expose a restricted view; select explicit columns.

**Verify:** Anonymous and cross-user reads return only public columns.


