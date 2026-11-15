# FocusBoard

A subscription productivity board.

## Stack

Next.js App Router, Supabase (auth and Postgres with row level security), Stripe Checkout, hosted on Vercel.

## Run locally

1. `nvm use` and `npm ci`
2. Copy `.env.example` to `.env.local` and fill in the values from your development Supabase and Stripe test projects.
3. `supabase start` and `supabase db reset` to apply the migrations.
4. `npm run dev`

## Checks

`npm run typecheck`, `npm test`, `supabase test db` (policy tests), `npm run build`.

## Deploy

Pushes to `main` run CI. Vercel deploys after CI passes. Production and preview use separate Supabase projects.
See `RUNBOOK.md` for rollback, key rotation and restore steps.

## Where data lives

User accounts and boards are in Supabase. Payments are in Stripe; this app stores only Stripe identifiers.
Third parties that receive user data are listed in `app/privacy/page.tsx` under "subprocessors".
