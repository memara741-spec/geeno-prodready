# Rotate a leaked key

What this covers: the safe order for replacing a key that was exposed, and where to do it for common providers. Read it whenever a finding says a key is in code, history, a public variable or a build. After reading you can walk a non-engineer through it step by step.
Last checked: 2026-11-13. Provider menu names change; if a step does not match what you see, use the provider's own rotation documentation.

## The order that matters

1. Create the new key in the provider dashboard. Do not delete the old one yet.
2. Put the new key in your host's environment variables (production, and preview if used).
3. Redeploy and confirm the app works.
4. Revoke the old key. A key that was public must be revoked; removing it from code does not un-leak it.
5. Check the provider's logs and usage for the period the key was exposed. Look for requests you do not recognise and for unexpected cost.
6. Tell Claude it is done. The finding closes as "rotated", with the date.

## Per provider

- **Supabase.** Secret and publishable keys are in Project Settings, API Keys. Creating new keys does not disable the legacy `anon` and `service_role` keys; they remain valid until you disable them in the same section. Supabase says a secret key does not work in a browser, but a leaked one can still be used from other tools, so rotate it. Source: https://supabase.com/docs/guides/api/api-keys
- **Stripe.** Developers, API keys: "Roll key" lets the old key expire later. Webhook signing secrets: Webhooks, your endpoint, "Roll secret"; you can keep the old secret active for up to 7 days while you deploy the new one. Source: https://docs.stripe.com/webhooks
- **OpenAI, Anthropic, Google AI and other AI providers.** Create a new key in the provider's API keys page, delete the old one, then set a monthly spending limit and an alert. <!-- unverified: exact menu names -->
- **Firebase and Google Cloud service accounts.** In the Google Cloud console, IAM, Service Accounts, Keys: create a new key, then delete the exposed one. Prefer workload identity or the host's secret manager so no key file exists.
- **Database passwords.** Change the password in the database provider, update the connection string everywhere, redeploy.
- **Anything else.** Find "revoke" or "regenerate" in the provider's API settings and follow the same order.

## After a public exposure

If the key was in a public repository or a live bundle, assume it was used. Read `incident-first-hour.md`. Next.js's own advisory for CVE-2025-66478 recommended rotating all secrets after patching an exposed app: https://nextjs.org/blog/CVE-2025-66478
