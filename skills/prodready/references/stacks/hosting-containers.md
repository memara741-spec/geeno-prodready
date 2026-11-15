# Containers, Fly, Render and Railway

What this covers: where settings live, headers, cron, limits, logs and rollback on Containers, Fly, Render and Railway.
Read it when: `hosting: containers`.
After reading you can: configure headers and secrets and know how to roll back.
Last checked: 2026-11-13.

## How this stack works
Use multi-stage builds, a non-root `USER`, a `.dockerignore` that excludes `.env` and `.git`, a pinned base image, and runtime secrets; never `ENV` a secret (DEP-009). Each platform has secret storage, health checks (use `/health`), logs and instant rollback; confirm the current steps in its docs. <!-- unverified -->

## What is public and what is secret
Host environment variables are secret server-side unless prefixed for the browser.

## The failure modes AI tools produce here
Previews pointing at production data (DEP-002, DEP-007); no security headers (HDR-001 to HDR-004); open cron routes (API-014).

## How to review it
Host config files in the repository and the dashboard settings below.

## Correct patterns
Start from a `Dockerfile` with a non-root user and `HEALTHCHECK`.

## How to test it
Request the live site and compare headers (`probe_live.py` with consent).

## Owner dashboard settings to confirm
Production versus preview variables; deployment protection; spend limits and alerts (DEP-014); rollback steps (DEP-005).

## Checks this playbook supports
HDR-001 to HDR-006, DEP-005, DEP-007, DEP-014, API-014.
