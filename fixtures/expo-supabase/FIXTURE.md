# Fixture: expo-supabase

**Story.** Two friends built "TrailMates" with an IDE agent: a mobile app for finding hiking partners and
checking in on a trail with your location. Expo Router on the client, Supabase behind it. The agent could
not get the insert to work with the anon key, so it switched the app to the secret key.

**What is planted.** The Supabase secret key is in `app.json` under `extra` and the client is built with
it; session tokens are also copied into plain AsyncStorage; there is no way to delete an account; the iOS
permission descriptions for camera and location are missing; cleartext traffic is allowed on Android; the
bundle identifiers are placeholders; the `checkins` table, which holds precise locations, has row level
security off. See `expected.json`.
