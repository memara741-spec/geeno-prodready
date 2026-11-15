# Runbook

- **Hosting:** Vercel project `focusboard`. Roll back: Deployments, pick the last good one, "Instant Rollback".
- **Database:** Supabase project `focusboard-prod`. Daily backups; restore drill last done on a scratch project.
- **Keys:** rotate in the provider dashboard, update the Vercel environment variable, redeploy, revoke the old key.
- **Errors:** server errors are sent to the error tracker through `instrumentation.ts`.
- **Contact:** security@focusboard.example
