# Fixture: firebase-react

**Story.** Sara, a student, built "Notely" in Bolt: a social notes app where friends share short formatted
notes. React with Vite, Firebase Auth, Firestore, Storage and two Cloud Functions. She started the database
in test mode "to get it working" and later added one rule for user profiles.

**What is planted.** Firestore still has the time-boxed test-mode rule; Storage rules allow everything; the
`users` rule lets any signed-in user write any profile (including `role` and `credits`); an `onRequest`
function changes credits with no token check and an `onCall` function never reads the caller; an Admin
service account key file is in the repository; note content is rendered as raw HTML; the feed listener is
never unsubscribed; the whole `notes` collection is downloaded and filtered in the browser; an ID token is
copied into local storage; the builder's title, icon and badge are still in place. See `expected.json`.
