# Bolt

What this covers: what Bolt projects look like and what to check first.
Read it when: `builder: bolt` is detected.
After reading you can find the data access code fast and explain how to apply fixes without the builder overwriting them.
Last checked: 2026-11-13. 

## What this builder generates
A StackBlitz-style project, usually Vite and React, often with Supabase or Firebase, with a `.bolt/` directory.

## What it tends to get right
Fast scaffolding.

## What it tends to leave unsafe
Test-mode Firebase rules left on (DB-010); keys in client code; builder badge and default metadata (LAUNCH-005); no tests or CI.

## Where things live
`.bolt/`, `src/`, `firebase.json`, `firestore.rules`.

## Getting the code and backend under the owner's control (DEP-011)
Export or connect to GitHub, and move the backend project to your own account. <!-- unverified -->

## Builder-specific cleanup (LAUNCH-005)
Remove the "Made with Bolt" badge and default title and icon.

## How to apply fixes
Fix in the repository; re-import carefully so the builder does not overwrite rules files.

## Prompts the owner can paste into the builder
"Replace the Firestore rules with owner-scoped rules and add emulator tests."
