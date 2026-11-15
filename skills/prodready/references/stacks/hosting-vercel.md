# Vercel

What this covers: where settings live, headers, cron, limits, logs and rollback on Vercel.
Read it when: `hosting: vercel`.
After reading you can: configure headers and secrets and know how to roll back.
Last checked: 2026-11-13.

## How this stack works
Environment variables have scopes (production, preview, development). Enable deployment protection for previews. Vercel's own docs recommend a Content Security Policy starting in report-only mode and avoiding `unsafe-inline` (https://vercel.com/docs/cdn-security/security-headers). Cron routes receive a secret: set `CRON_SECRET` and check the Authorization header. Instant rollback: Deployments, pick the last good one. <!-- unverified -->

## What is public and what is secret
Host environment variables are secret server-side unless prefixed for the browser.

## The failure modes AI tools produce here
Previews pointing at production data (DEP-002, DEP-007); no security headers (HDR-001 to HDR-004); open cron routes (API-014).

## How to review it
Host config files in the repository and the dashboard settings below.

## Correct patterns
Start from `assets/security-headers/vercel.json`.

## How to test it
Request the live site and compare headers (`probe_live.py` with consent).

## Owner dashboard settings to confirm
Production versus preview variables; deployment protection; spend limits and alerts (DEP-014); rollback steps (DEP-005).

## Checks this playbook supports
HDR-001 to HDR-006, DEP-005, DEP-007, DEP-014, API-014.
