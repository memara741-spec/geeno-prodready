# Fixture: nextjs-supabase-stripe

**Story.** Omar, a freelance designer, used Cursor to build "FocusBoard", a subscription productivity board:
Next.js App Router, Supabase for sign-in and data, Stripe for the Pro plan, deployed on Vercel. The database
policies are actually fine, because he copied them from a tutorial. Everything around payments and the
server routes was generated in a hurry to make the demo work.

**What is planted.** The checkout route trusts `priceId` and `amount` from the browser; the Stripe webhook
accepts unsigned events; the success page upgrades the plan; a server action uses the service-role client
with no session check; an invoice route loads any invoice by ID; server code decides on `getSession()`; the
middleware matcher skips `/api`; the plan lives in `user_metadata`; the build ignores type errors; one route
reflects the request origin with credentials and a public cache header; the cron route is open; redirect
URLs point to localhost; a client file expects a service-role key in a `NEXT_PUBLIC_` variable. See
`expected.json`.
