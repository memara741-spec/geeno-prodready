# Firebase

What this covers: web config, Firestore, Storage and Realtime Database rules, Cloud Functions auth, App Check and the Admin SDK.
Read it when: the app uses Firebase (`database: firebase*`).
After reading you can: read rules, spot open access and write owner-scoped rules with tests.
Last checked: 2026-11-13.

## How this stack works
Clients talk straight to Firestore, Storage and the Realtime Database. **Security rules are the only barrier for client access.** The Admin SDK used in functions bypasses rules.

## What is public and what is secret
- The web config (apiKey, projectId, appId) is public by design (SEC-016). Restrict the API key by referrer in Google Cloud (SEC-012).
- Service account JSON and Admin credentials are secret (SEC-015).

## The failure modes AI tools produce here
- Test-mode rules left on (`allow read, write: if request.time < timestamp.date(...)`) (DB-010).
- `if request.auth != null` treated as ownership (DB-011).
- Users able to write `role` or `credits` on their own profile (AUTH-013).
- `onRequest` functions with no token check; Admin key file committed.

## How to review it
`firestore.rules`, `storage.rules`, `database.rules.json`, `firebase.json`, then `functions/`. Read `inventory.firebase_access`.

## Correct patterns
```
match /users/{userId} {
  allow read: if request.auth != null && request.auth.uid == userId;
  allow update: if request.auth != null && request.auth.uid == userId
    && request.resource.data.diff(resource.data).affectedKeys().hasOnly(['displayName']);
}
// Storage: per-user folder, size and type limits
match /users/{userId}/{file} {
  allow write: if request.auth.uid == userId && request.resource.size < 5 * 1024 * 1024
    && request.resource.contentType.matches('image/(png|jpeg|webp)');
}
```
Use custom claims for roles. In functions, verify with `admin.auth().verifyIdToken()` for `onRequest` and read `request.auth` for `onCall`.

## How to test it
Firebase emulator suite with `@firebase/rules-unit-testing`: owner can read, another signed-in user cannot, anonymous cannot, a user cannot set `role`.

## Owner dashboard settings to confirm
Budgets and alerts; App Check (an extra layer, not a replacement for rules); scheduled exports for backups; API key restrictions.

## Checks this playbook supports
DB-009 to DB-011, DB-015, API-013, SEC-012, SEC-015.
