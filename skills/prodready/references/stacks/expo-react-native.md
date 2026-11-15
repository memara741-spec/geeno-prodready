# Expo and React Native

What this covers: what ships in the app binary, secure storage, deep links and store requirements.
Read it when: `mobile: expo` or `react-native`.
After reading you can: separate what may live in the app from what needs a backend.
Last checked: 2026-11-13.

## How this stack works
The app package is downloadable and easily unpacked; nothing inside it is secret.

## What is public and what is secret
`EXPO_PUBLIC_*` and everything in `app.json` `extra` are public. Only public keys belong in the app (SEC-014).

## The failure modes AI tools produce here
A secret key put in `extra` to make a request work; tokens in plain AsyncStorage (AUTH-006); no account deletion; missing permission descriptions; cleartext traffic allowed; placeholder bundle identifiers (LAUNCH-008).

## How to review it
`app.json` or `app.config.*`, `eas.json`, the client creation file, storage calls.

## Correct patterns
Use the publishable key plus database rules, or call a backend that holds the secret. Store tokens with `expo-secure-store`. Validate deep link parameters.

## How to test it
Unpack a build or inspect `app.json` and confirm no secret remains.

## Owner dashboard settings to confirm
Store listings: privacy details, data safety, account deletion path.

## Checks this playbook supports
SEC-014, AUTH-006, FE-002, LAUNCH-008, PRIV-003.
