# Next.js

What this covers: server and client components, env prefixes, route handlers, server actions, middleware, caching, headers and build flags.
Read it when: `framework: nextjs`.
After reading you can: review each server entry point and the settings that hide problems.
Last checked: 2026-11-13.
Sources: https://nextjs.org/blog/CVE-2025-66478, https://github.com/advisories/GHSA-f82v-jwr5-mffw

## How this stack works
App Router code runs on the server by default; files with `"use client"` are bundled for the browser, and props passed to client components are serialised and visible. Route handlers and server actions are public HTTP endpoints.

## What is public and what is secret
- `NEXT_PUBLIC_*` variables are inlined into the browser bundle at build time; never put secrets there (SEC-005).
- Everything not prefixed is server-only.

## The failure modes AI tools produce here
- Server actions and route handlers with no session check, relying on the page being protected (AUTH-002, API-010).
- Middleware as the only gate; its matcher excluding `/api` (AUTH-003). CVE-2025-29927 allowed middleware authorization bypass in versions before 12.3.5, 13.5.9, 14.2.25 and 15.2.3 (https://github.com/advisories/GHSA-f82v-jwr5-mffw).
- `typescript.ignoreBuildErrors` and `eslint.ignoreDuringBuilds` (DEP-008).
- Personalised responses cached publicly (HDR-005).
- Out-of-support or vulnerable versions: see DEPS-001 and DEPS-002 (CVE-2025-66478, CVE-2025-55183, CVE-2025-55184, CVE-2025-67779; https://nextjs.org/blog/CVE-2025-66478, https://nextjs.org/blog/security-update-2025-12-11).

## How to review it
`app/**/route.ts`, `"use server"` files, `middleware.ts` (or `proxy.ts`), `lib/` data access, `next.config.*`.

## Correct patterns
```ts
// Verify inside the handler, not only in middleware
export async function POST(req: Request) {
  const user = await getVerifiedUser();            // supabase.auth.getUser() or your auth library
  if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  const body = schema.parse(await req.json());      // validate
  // query with the session user's id in the WHERE clause
}
```
Use `import 'server-only'` in data-access modules. Set `poweredByHeader: false` and security headers in `next.config` (see `assets/security-headers/`). A nonce-based CSP through middleware lets you drop `'unsafe-inline'`.

## How to test it
Call every route without a session and expect 401; call with user A and user B's ID and expect 404; build with the ignore flags removed.

## Owner dashboard settings to confirm
Environment variables per scope (production, preview); deployment protection for previews.

## Checks this playbook supports
AUTH-002, AUTH-003, API-010, SEC-005, HDR-001 to HDR-006, DEP-008, DEPS-001, DEPS-002, PERF-005.
