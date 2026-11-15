# Lovable

What this covers: what Lovable projects look like and what to check first.
Read it when: `builder: lovable` is detected.
After reading you can find the data access code fast and explain how to apply fixes without the builder overwriting them.
Last checked: 2026-11-13. 

## What this builder generates
A Vite, React, TypeScript, Tailwind and shadcn single-page app with a generated Supabase client and types under `src/integrations/supabase/`, plus Supabase migrations and edge functions.

## What it tends to get right
Clean component structure and a working happy path.

## What it tends to leave unsafe
RLS missing or `using (true)` (DB-001, DB-002); public storage buckets (DB-009); secrets in `VITE_` variables (SEC-005); client-side admin pages (AUTH-001); edge functions with `verify_jwt = false` (API-013); default title, badge and README (LAUNCH-001, LAUNCH-005).

## Where things live
`supabase/migrations`, `supabase/functions`, `src/integrations/supabase/client.ts` (the publishable key there is public by design), `src/pages`.

## Getting the code and backend under the owner's control (DEP-011)
Connect the project to your own GitHub repository and make sure the Supabase project is in your own account. Lovable also offers its own security scan; use prodready as the deeper, independent second review. <!-- unverified -->

## Builder-specific cleanup (LAUNCH-005)
Remove `lovable-tagger`, the `gptengineer.js` script, the default social image and README text where your plan allows.

## How to apply fixes
Edit in the repository and push; when the builder syncs from GitHub, check that your manual fixes survive. Database fixes are migration files you apply with the Supabase CLI.

## Prompts the owner can paste into the builder
"Enable row level security on every table in `supabase/migrations` and restrict each policy to the row owner using auth.uid()."
"Move the OpenAI call into a Supabase edge function that requires a signed-in user and reads the key from a secret."
