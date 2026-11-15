# Notely

Short notes for friends.

## Stack

React with Vite, Firebase Authentication, Firestore, Storage and Hosting. Errors go to Sentry.

## Run locally

1. `nvm use` and `npm ci`
2. Copy `.env.example` to `.env.local` and paste the web config of your development Firebase project.
3. `npm run dev`

## Checks

`npm test` for unit tests and `npm run test:rules` for the security rules tests (needs the Firebase emulators).

## Deploy

CI runs on every pull request. `firebase deploy` publishes hosting and the rules files in this repository.
The rules are the security boundary: change them only together with `tests/rules.test.ts`.
