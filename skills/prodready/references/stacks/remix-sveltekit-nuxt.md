# Remix, SvelteKit and Nuxt

What this covers: server-file conventions, env exposure, loaders, actions and CSRF in the three frameworks.
Read it when: `framework: remix`, `sveltekit` or `nuxt`.
After reading you can: find the server entry points and check each one.
Last checked: 2026-11-13.

## How this stack works
Each framework splits server and client code by file convention and exposes loaders/actions/endpoints as HTTP handlers.

## What is public and what is secret
- Remix: `*.server.*` is server-only. SvelteKit: `$env/static/private` and `+server.ts` are server-only; `PUBLIC_` is exposed. Nuxt: `runtimeConfig` outside `public` is server-only; `NUXT_PUBLIC_` is exposed. <!-- unverified -->

## The failure modes AI tools produce here
Loaders and actions that read data with no session check; trusting an ID from the URL; disabled CSRF protection on form actions.

## How to review it
Remix `app/routes/*` loader/action; SvelteKit `+page.server.ts`, `+server.ts`, `hooks.server.ts`; Nuxt `server/api/**`.

## Correct patterns
Verify the session at the top of every loader, action or handler and scope queries by the session user. SvelteKit form actions have origin checks by default; do not turn them off. <!-- unverified -->

## How to test it
Request each endpoint without a session.

## Owner dashboard settings to confirm
Host environment variables per scope.

## Checks this playbook supports
AUTH-002, AUTH-003, AUTH-004, API-010, SEC-005.
