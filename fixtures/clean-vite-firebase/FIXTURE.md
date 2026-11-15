# Fixture: clean-vite-firebase

**Story.** The same product as `firebase-react` (Notely), done correctly. This fixture is a negative
control: the scanners must report no critical, high or medium findings here. It is a static input and is
not installed by the test suite.

**What it does right.** Deny-by-default Firestore rules scoped by owner with field validation; Storage
rules with a per-user folder, a size limit and a content-type allow-list; emulator rules tests; the
realtime listener is narrowed with a query and unsubscribed on cleanup; an error boundary and an error
tracker; security headers and SPA rewrites in `firebase.json`; account deletion; a privacy page; CI and
automated dependency updates.
