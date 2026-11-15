# Vite and other single-page apps

What this covers: why everything in a SPA is public and what that means for data access and hosting.
Read it when: `framework: vite-*` or `cra`.
After reading you can: decide what must move to a backend and review the access rules the app depends on.
Last checked: 2026-11-13.

## How this stack works
A SPA is static files plus a backend-as-a-service. Every file, every route component and every env variable with the public prefix (`VITE_`, `REACT_APP_`) ships to the visitor.

## What is public and what is secret
Everything in `src/` is public, including admin pages. Secrets must never appear in `VITE_*` variables or literals (SEC-001, SEC-005, SEC-013).

## The failure modes AI tools produce here
AI calls from the browser with `dangerouslyAllowBrowser`; service keys in `VITE_` variables; admin screens protected only by a client redirect (AUTH-001); builder defaults left in `index.html`.

## How to review it
`src/integrations/*` or wherever the data client is created, every `supabase.from(...)` / Firestore call site, `index.html`, `vite.config.*`.

## Correct patterns
Move privileged calls to an edge function or server route; rely on database rules for everything else. Add a host rewrite so deep links work (`/* /index.html`).

## How to test it
Search the `dist/` output for key prefixes; open a deep link directly.

## Owner dashboard settings to confirm
Host rewrite rules and headers (see the hosting playbooks); disable public source maps (SEC-007).

## Checks this playbook supports
SEC-001, SEC-005, SEC-007, SEC-013, AUTH-001, DEP-012, FE-004, LAUNCH-001, LAUNCH-005.
