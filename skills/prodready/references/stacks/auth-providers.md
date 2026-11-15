# Authentication providers

What this covers: the server call that verifies the user and where roles should live, per provider.
Read it when: any `auth:` entry.
After reading you can: pick the right verification call and role storage.
Last checked: 2026-11-13.

## How this stack works
Managed providers verify sign-in; your server must still verify the caller on every request.

## What is public and what is secret
Client IDs and publishable keys are public; secrets and signing keys are not.

## The failure modes AI tools produce here
Trusting a user ID from the client (AUTH-004); roles in user-editable metadata (AUTH-013); unverified token reads (AUTH-005); no rate limits on hand-rolled login (AUTH-010).

## How to review it
Where the session is read on the server, and where roles are stored.

## Correct patterns
- **Supabase:** `getClaims()` or `getUser()`; roles in `app_metadata` or a table. https://supabase.com/docs/guides/auth/server-side/nextjs
- **Firebase:** `verifyIdToken()`; custom claims.
- **Clerk:** `auth()` from the server package; roles in organisation membership or private metadata. <!-- unverified -->
- **Auth.js:** `getServerSession` / `auth()`; keep a strong `NEXTAUTH_SECRET` with no fallback.
- **Better Auth, Auth0, Lucia-style and hand-rolled JWT:** verify signature, issuer, audience and expiry; short-lived tokens; server-side revocation.

## How to test it
Test a request with a tampered token and an expired token.

## Owner dashboard settings to confirm
Email confirmation, redirect allow-list, MFA for admins.

## Checks this playbook supports
AUTH-001 to AUTH-018.
