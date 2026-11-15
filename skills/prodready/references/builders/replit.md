# Replit

What this covers: what Replit projects look like and what to check first.
Read it when: `builder: replit` is detected.
After reading you can find the data access code fast and explain how to apply fixes without the builder overwriting them.
Last checked: 2026-11-13. 

## What this builder generates
A project with `.replit` and `replit.nix`, often Node or Python, hosted on Replit domains.

## What it tends to get right
Everything runs out of the box.

## What it tends to leave unsafe
Dev servers as production (DEP-001); secrets pasted into code instead of Replit Secrets (SEC-006); public preview URLs (DEP-007).

## Where things live
`.replit`, `replit.nix`, `main.py` or `index.js`.

## Getting the code and backend under the owner's control (DEP-011)
Connect to your own GitHub and document how to run and deploy outside Replit. <!-- unverified -->

## Builder-specific cleanup (LAUNCH-005)
Remove Replit-specific scaffolding and badges.

## How to apply fixes
Edit in the repository or the workspace; confirm secrets are in the Secrets tool.

## Prompts the owner can paste into the builder
"Move all API keys into Secrets and read them from environment variables."
