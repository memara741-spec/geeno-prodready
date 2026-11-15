# Check index

Last checked: 2026-11-13.

Every check, with default severity, mode and the script that implements it. Generated from `scripts/lib/catalog.py`; do not edit by hand. Severity here is the default; adjust it in the report as described in `references/severity.md`.

| ID | Title | Severity | Mode | Applies to | Script |
|---|---|---|---|---|---|
| [SEC-001](secrets.md#sec-001) | Admin-level backend key reachable from client code | critical | scan | all | scan_secrets |
| [SEC-002](secrets.md#sec-002) | Secret committed in the current working tree | critical | scan | all | scan_secrets |
| [SEC-003](secrets.md#sec-003) | Secret present in git history | high | scan | all | scan_git_history |
| [SEC-004](secrets.md#sec-004) | Environment files are not ignored by git | high | scan | all | scan_env |
| [SEC-005](secrets.md#sec-005) | Secret stored in a browser-exposed environment variable | critical | scan | nextjs, vite, cra, expo, sveltekit, nuxt, astro | scan_env |
| [SEC-006](secrets.md#sec-006) | Hard-coded credential in source code | high | scan | all | scan_secrets |
| [SEC-007](secrets.md#sec-007) | Secrets or server code visible in published source maps or build output | high | scan | web | scan_secrets |
| [SEC-008](secrets.md#sec-008) | No .env.example or documentation of required variables | low | scan | all | scan_env |
| [SEC-009](secrets.md#sec-009) | Secrets, tokens or passwords written to logs | medium | scan+review | all | scan_secrets |
| [SEC-010](secrets.md#sec-010) | Weak, default or placeholder signing secret | critical | scan | custom-jwt, authjs, express-session, django, flask | scan_secrets |
| [SEC-011](secrets.md#sec-011) | Test and live credentials mixed, or one set shared by all environments | medium | review | all | review |
| [SEC-012](secrets.md#sec-012) | Browser-visible third-party key has no restrictions | medium | review | firebase, google-maps, mapbox, algolia | review |
| [SEC-013](secrets.md#sec-013) | AI provider key used directly from the browser or mobile client | critical | scan | any llm | scan_secrets |
| [SEC-014](secrets.md#sec-014) | Secrets embedded in a mobile app configuration | critical | scan | expo, react-native, capacitor, flutter | scan_secrets |
| [SEC-015](secrets.md#sec-015) | Private key or service account file in the repository | critical | scan | all | scan_secrets |
| [SEC-016](secrets.md#sec-016) | Public key found in client code (not a leak) | info | scan | supabase, firebase, stripe, clerk | scan_secrets |
| [AUTH-001](auth.md#auth-001) | Page protection exists only in the user interface | high | review | web, mobile | review |
| [AUTH-002](auth.md#auth-002) | Data-returning or data-changing route has no authentication check | critical | scan+review | all backends | scan_routes |
| [AUTH-003](auth.md#auth-003) | Middleware does not cover the routes it is assumed to cover | high | scan+review | nextjs, express, hono, sveltekit | scan_routes |
| [AUTH-004](auth.md#auth-004) | Server trusts a user identifier supplied by the client | critical | scan+review | all | scan_routes |
| [AUTH-005](auth.md#auth-005) | Server code uses an unverified session read | high | scan | supabase-ssr, custom-jwt | scan_supabase |
| [AUTH-006](auth.md#auth-006) | Session token stored where page scripts can read it | medium | scan+review | custom auth | scan_frontend |
| [AUTH-007](auth.md#auth-007) | Session cookie lacks protective attributes | medium | scan | custom auth, express-session | scan_routes |
| [AUTH-008](auth.md#auth-008) | Email addresses are not verified before the account is trusted | medium | review | supabase, firebase, clerk, authjs, custom | review |
| [AUTH-009](auth.md#auth-009) | Weak password rules or leaked-password protection off | low | review | all with passwords | review |
| [AUTH-010](auth.md#auth-010) | No rate limit on sign-in, sign-up, reset or code verification | high | scan+review | custom auth | scan_routes |
| [AUTH-011](auth.md#auth-011) | Password reset or magic link flow is unsafe | high | review | custom auth | review |
| [AUTH-012](auth.md#auth-012) | Redirect after login accepts arbitrary destinations | medium | scan+review | all | scan_routes |
| [AUTH-013](auth.md#auth-013) | Role or admin flag stored where the user can change it | critical | scan+review | supabase, firebase, clerk, custom | scan_supabase |
| [AUTH-014](auth.md#auth-014) | Sessions never expire or sign-out does not end them | low | review | custom auth | review |
| [AUTH-015](auth.md#auth-015) | State-changing requests with cookie auth lack CSRF protection | medium | review | custom cookie auth, express, flask, django | review |
| [AUTH-016](auth.md#auth-016) | No second factor available for administrator accounts | low | review | all | review |
| [AUTH-017](auth.md#auth-017) | Default, demo or seeded credentials present | critical | scan | all | scan_secrets |
| [AUTH-018](auth.md#auth-018) | Token verification accepts unsafe algorithms or skips claims | critical | scan | custom-jwt | scan_routes |
| [DB-001](database.md#db-001) | Row level security disabled on a client-reachable table | critical | scan | supabase, postgrest | scan_supabase |
| [DB-002](database.md#db-002) | Policy allows everyone | critical | scan | supabase | scan_supabase |
| [DB-003](database.md#db-003) | Authenticated-only policy without ownership scoping | critical | scan+review | supabase | scan_supabase |
| [DB-004](database.md#db-004) | Write policy missing an effective WITH CHECK condition | high | scan | supabase, postgres | scan_supabase |
| [DB-005](database.md#db-005) | Policy trusts user-editable metadata | critical | scan | supabase | scan_supabase |
| [DB-006](database.md#db-006) | Table has no ownership or tenant column to scope by | high | review | supabase, postgres, any | review |
| [DB-007](database.md#db-007) | Privileged function callable through the API | high | scan | supabase, postgres | scan_supabase |
| [DB-008](database.md#db-008) | View bypasses row level security | high | scan | supabase, postgres 15+ | scan_supabase |
| [DB-009](database.md#db-009) | Storage bucket is public or has no access policies | high | scan+review | supabase storage, firebase storage, s3, r2 | scan_supabase |
| [DB-010](database.md#db-010) | Firebase rules allow open access | critical | scan | firebase | scan_firebase |
| [DB-011](database.md#db-011) | Firebase rules check sign-in but not ownership or shape | critical | scan+review | firebase | scan_firebase |
| [DB-012](database.md#db-012) | SQL built by string concatenation with request data | critical | scan | any sql | scan_routes |
| [DB-013](database.md#db-013) | Request body written to the database without field selection | high | scan | prisma, drizzle, mongoose, supabase-js, any orm | scan_routes |
| [DB-014](database.md#db-014) | Database reachable directly from the browser with privileged credentials | critical | scan | any | scan_routes |
| [DB-015](database.md#db-015) | Schema and policies exist only in the hosted dashboard | medium | scan | supabase, firebase | scan_supabase |
| [DB-016](database.md#db-016) | No backups or no tested restore | high | review | all | review |
| [DB-017](database.md#db-017) | Missing indexes on columns used by policies and foreign keys | medium | scan | postgres, supabase | scan_supabase |
| [DB-018](database.md#db-018) | Serverless functions open direct database connections without pooling | medium | scan+review | prisma, drizzle, pg on serverless | scan_routes |
| [DB-019](database.md#db-019) | Multi-tenant data not isolated by tenant in rules or queries | critical | review | any multi-tenant | review |
| [DB-020](database.md#db-020) | Realtime channels deliver data without authorisation | high | review | supabase realtime, firebase, pusher, ably, socket.io | review |
| [DB-021](database.md#db-021) | Anonymous role holds broad grants or can call sensitive RPCs | high | scan | supabase, postgres | scan_supabase |
| [DB-022](database.md#db-022) | Guessable identifiers combined with weak authorisation | medium | review | any | review |
| [DB-023](database.md#db-023) | Application connects to the database as a superuser | medium | review | postgres, mysql, mongo self-managed | review |
| [DB-024](database.md#db-024) | Public profile data exposes private fields | high | scan+review | supabase, firebase, any | scan_supabase |
| [API-001](api.md#api-001) | Request input is not validated | medium | scan+review | all backends | scan_routes |
| [API-002](api.md#api-002) | No rate limiting on expensive or abusable endpoints | high | scan+review | all backends | scan_routes |
| [API-003](api.md#api-003) | Cross-origin policy allows any site with credentials | high | scan | all backends | scan_config |
| [API-004](api.md#api-004) | Errors return internal details to the client | medium | scan | all backends | scan_routes |
| [API-005](api.md#api-005) | Handler does not check that the resource belongs to the caller | critical | review | all backends | review |
| [API-006](api.md#api-006) | Server fetches a URL supplied by the user | high | scan+review | all backends | scan_routes |
| [API-007](api.md#api-007) | Incoming webhook is not authenticated | high | scan | any webhook provider | scan_routes |
| [API-008](api.md#api-008) | List endpoints return unbounded results | medium | scan+review | all backends | scan_routes |
| [API-009](api.md#api-009) | No limit on request body size | low | scan | express, fastify, custom servers | scan_routes |
| [API-010](api.md#api-010) | Server action or RPC callable without its own checks | critical | scan+review | nextjs server actions, trpc, remix, sveltekit | scan_routes |
| [API-011](api.md#api-011) | GraphQL endpoint exposed without limits | medium | scan | graphql | scan_routes |
| [API-012](api.md#api-012) | Debug, test or scaffolding endpoints left in the app | high | scan | all backends | scan_routes |
| [API-013](api.md#api-013) | Edge or cloud functions deployed with JWT verification disabled | high | scan | supabase edge functions, firebase functions, cloud run | scan_supabase |
| [API-014](api.md#api-014) | Scheduled or internal endpoints are publicly triggerable | high | scan+review | vercel cron, netlify scheduled, any | scan_routes |
| [API-015](api.md#api-015) | File path built from user input | critical | scan | node, python backends | scan_routes |
| [API-016](api.md#api-016) | User input reaches a shell, eval or dynamic code execution | critical | scan | node, python backends | scan_routes |
| [API-017](api.md#api-017) | Mutating endpoints are not idempotent where retries are expected | medium | review | payments, credits, orders, email sends | review |
| [API-018](api.md#api-018) | HTTP methods not restricted | low | scan | nextjs pages api, express, serverless functions | scan_routes |
| [API-019](api.md#api-019) | Response includes more fields than the client needs | medium | scan+review | all backends | scan_routes |
| [PAY-001](payments.md#pay-001) | Amount, price or plan taken from the client | critical | scan+review | stripe, paddle, lemon squeezy, paypal, razorpay | scan_payments |
| [PAY-002](payments.md#pay-002) | Payment webhook signature not verified | critical | scan | all payment providers | scan_payments |
| [PAY-003](payments.md#pay-003) | Access granted on the success redirect instead of a verified event | critical | review | all payment providers | review |
| [PAY-004](payments.md#pay-004) | Webhook handler is not idempotent or ignores event ordering | high | review | all payment providers | review |
| [PAY-005](payments.md#pay-005) | Paid features gated only in the client | high | review | all | review |
| [PAY-006](payments.md#pay-006) | Subscription lifecycle events are not handled | medium | review | subscriptions | review |
| [PAY-007](payments.md#pay-007) | Customer or subscription identifier accepted from the client | high | scan+review | stripe and similar | scan_payments |
| [PAY-008](payments.md#pay-008) | Test mode in production, or live keys in development | high | scan | all payment providers | scan_payments |
| [PAY-009](payments.md#pay-009) | Card data handled by the app's own server | critical | scan | any | scan_payments |
| [PAY-010](payments.md#pay-010) | Credits or balances updated without atomicity | high | review | credits, wallets, inventory, seats | review |
| [PAY-011](payments.md#pay-011) | Money stored or computed as floating point | medium | scan | any | scan_payments |
| [UP-001](uploads.md#up-001) | Uploads accepted without type and size limits | high | scan+review | any with uploads | scan_routes |
| [UP-002](uploads.md#up-002) | Uploaded files served from the application's origin as active content | high | review | any | review |
| [UP-003](uploads.md#up-003) | Storage path or filename controlled by the user | high | scan | any | scan_routes |
| [UP-004](uploads.md#up-004) | Private files exposed through permanent public URLs | high | scan+review | supabase storage, firebase storage, s3, r2 | scan_routes |
| [UP-005](uploads.md#up-005) | No per-user quota on uploads or storage | medium | review | any | review |
| [UP-006](uploads.md#up-006) | Image or document processing of untrusted files without limits | medium | review | sharp, imagemagick, pdf libraries, ffmpeg | review |
| [LLM-001](llm.md#llm-001) | AI endpoint callable without authentication | critical | scan | any llm | scan_llm |
| [LLM-002](llm.md#llm-002) | No per-user limit or spending cap on AI usage | high | scan+review | any llm | scan_llm |
| [LLM-003](llm.md#llm-003) | Client controls the model, system prompt or generation parameters | high | scan | any llm | scan_llm |
| [LLM-004](llm.md#llm-004) | No output or input size limits and no timeout | medium | scan | any llm | scan_llm |
| [LLM-005](llm.md#llm-005) | Untrusted content can steer a model that has tools or data access | high | review | agents, rag, tool use, mcp | review |
| [LLM-006](llm.md#llm-006) | Model output rendered or executed without sanitising | high | scan | any llm with rich output | scan_llm |
| [LLM-007](llm.md#llm-007) | Secrets or private data placed in prompts | high | scan+review | any llm | scan_llm |
| [LLM-008](llm.md#llm-008) | Personal data sent to AI providers without disclosure or minimisation | medium | review | any llm | review |
| [LLM-009](llm.md#llm-009) | No abuse controls on user-generated AI content | low | review | public-facing generation | review |
| [LLM-010](llm.md#llm-010) | Instructions aimed at AI reviewers embedded in the project | medium | scan | all | scan_llm |
| [FE-001](frontend.md#fe-001) | User-controlled content inserted as HTML | high | scan+review | react, vue, svelte, angular, plain js | scan_frontend |
| [FE-002](frontend.md#fe-002) | Sensitive data kept in browser storage or client state longer than needed | medium | scan+review | web, mobile | scan_frontend |
| [FE-003](frontend.md#fe-003) | Debug output in production builds | low | scan | web, mobile | scan_frontend |
| [FE-004](frontend.md#fe-004) | No error boundary or global error handling | medium | scan | react, nextjs, vue, svelte | scan_frontend |
| [FE-005](frontend.md#fe-005) | Missing loading, empty and failure states on key screens | low | review | web, mobile | review |
| [FE-006](frontend.md#fe-006) | Forms can be submitted twice | low | review | web, mobile | review |
| [FE-007](frontend.md#fe-007) | Third-party scripts loaded without need or integrity | low | scan | web | scan_frontend |
| [FE-008](frontend.md#fe-008) | Basic accessibility and mobile layout gaps | low | scan+review | web | scan_frontend |
| [FE-009](frontend.md#fe-009) | Links opening new tabs without isolation, and unsafe external navigation | low | scan | web | scan_frontend |
| [HDR-001](headers.md#hdr-001) | No Content Security Policy | medium | scan | web | scan_config |
| [HDR-002](headers.md#hdr-002) | HTTPS not enforced with HSTS | medium | scan | web | scan_config |
| [HDR-003](headers.md#hdr-003) | Pages can be framed by other sites | medium | scan | web | scan_config |
| [HDR-004](headers.md#hdr-004) | Missing nosniff, referrer and permissions policies | low | scan | web | scan_config |
| [HDR-005](headers.md#hdr-005) | Authenticated responses may be cached by shared caches | medium | scan+review | web with cdn, nextjs caching | scan_config |
| [HDR-006](headers.md#hdr-006) | Server and framework versions disclosed | low | scan | express, nextjs, custom servers | scan_config |
| [DEP-001](deploy.md#dep-001) | Development or debug mode enabled in production | high | scan | all | scan_config |
| [DEP-002](deploy.md#dep-002) | Production and development share one backend | high | review | all | review |
| [DEP-003](deploy.md#dep-003) | Environment variables are not validated at startup | medium | scan | all | scan_env |
| [DEP-004](deploy.md#dep-004) | No health check endpoint | low | scan | backends, containers | scan_config |
| [DEP-005](deploy.md#dep-005) | No rollback path | medium | review | all | review |
| [DEP-006](deploy.md#dep-006) | Builds are not reproducible | medium | scan | node, python | scan_config |
| [DEP-007](deploy.md#dep-007) | Preview or staging deployments are public and indexed | medium | review | vercel, netlify, cloudflare pages, replit, builders | review |
| [DEP-008](deploy.md#dep-008) | Build ignores type and lint errors | medium | scan | nextjs, vite, typescript | scan_config |
| [DEP-009](deploy.md#dep-009) | Container image runs as root or bakes in secrets | medium | scan | docker | scan_config |
| [DEP-010](deploy.md#dep-010) | Function region far from the database, or timeouts too short for the work | low | review | serverless | review |
| [DEP-011](deploy.md#dep-011) | The project still lives only inside the AI builder | medium | review | lovable, bolt, v0, replit, firebase studio | review |
| [DEP-012](deploy.md#dep-012) | Default error pages and missing not-found handling | low | scan | web | scan_config |
| [DEP-013](deploy.md#dep-013) | Default branch unprotected and deploys on every push | low | review | github + any host | review |
| [DEP-014](deploy.md#dep-014) | Billing limits and usage alerts not configured on pay-per-use services | medium | review | all cloud, llm, sms, email, maps | review |
| [DEPS-001](dependencies.md#deps-001) | Dependencies with known vulnerabilities | high | scan | node, python | scan_deps |
| [DEPS-002](dependencies.md#deps-002) | Framework version is past security support | high | scan | nextjs, react, express, django, flask | scan_deps |
| [DEPS-003](dependencies.md#deps-003) | Dependency that does not exist, is misspelled, or is suspicious | high | scan | node, python | scan_deps |
| [DEPS-004](dependencies.md#deps-004) | Unused, duplicated or abandoned dependencies | low | scan | node, python | scan_deps |
| [DEPS-005](dependencies.md#deps-005) | Development tools shipped as production dependencies, or the reverse | low | scan | node | scan_deps |
| [DEPS-006](dependencies.md#deps-006) | No automated dependency update or alerting | low | scan | github | scan_deps |
| [DEPS-007](dependencies.md#deps-007) | Licence incompatible with commercial use | low | scan | node, python | scan_deps |
| [PRIV-001](privacy.md#priv-001) | No privacy policy or terms where personal data is collected | medium | scan | web, mobile | scan_launch |
| [PRIV-002](privacy.md#priv-002) | Trackers load before consent where consent is required | medium | scan+review | web | scan_frontend |
| [PRIV-003](privacy.md#priv-003) | Users cannot delete their account or export their data | medium | scan+review | all with accounts | scan_launch |
| [PRIV-004](privacy.md#priv-004) | Personal data in logs, analytics events or error reports | medium | scan+review | all | scan_secrets |
| [PRIV-005](privacy.md#priv-005) | Sensitive data stored unprotected or collected without need | high | scan+review | all | scan_routes |
| [PRIV-006](privacy.md#priv-006) | No list of third parties that receive user data | low | scan | all | scan_launch |
| [PRIV-007](privacy.md#priv-007) | Session replay or analytics captures form inputs | medium | scan | web | scan_frontend |
| [PRIV-008](privacy.md#priv-008) | No data retention or cleanup | low | review | all | review |
| [OBS-001](observability.md#obs-001) | No error tracking | high | scan | all | scan_config |
| [OBS-002](observability.md#obs-002) | No usable server logs | medium | scan+review | backends | scan_config |
| [OBS-003](observability.md#obs-003) | No uptime monitoring or alerting | medium | review | all | review |
| [OBS-004](observability.md#obs-004) | No audit trail for sensitive actions | medium | review | admin, billing, roles, data export | review |
| [OBS-005](observability.md#obs-005) | No visibility into the core funnel | low | review | all | review |
| [OBS-006](observability.md#obs-006) | No incident plan | low | review | all | review |
| [REL-001](reliability.md#rel-001) | Unhandled failures in asynchronous code | medium | scan | node, browser | scan_config |
| [REL-002](reliability.md#rel-002) | External calls without timeouts or retry policy | medium | scan+review | backends | scan_routes |
| [REL-003](reliability.md#rel-003) | Multi-step writes without a transaction | medium | review | any database | review |
| [REL-004](reliability.md#rel-004) | State kept in process memory on serverless or multi-instance hosts | medium | scan | serverless, autoscaled containers | scan_config |
| [REL-005](reliability.md#rel-005) | Long-running work performed inside the request | medium | review | serverless, any | review |
| [REL-006](reliability.md#rel-006) | Date, time zone and locale handling errors | low | scan+review | all | scan_config |
| [REL-007](reliability.md#rel-007) | No tested path to restore service after data loss | high | review | all | review |
| [REL-008](reliability.md#rel-008) | Hard dependency on a single third party in the critical path with no fallback | low | review | all | review |
| [PERF-001](performance.md#perf-001) | Query inside a loop | medium | scan+review | any database | scan_routes |
| [PERF-002](performance.md#perf-002) | Whole tables fetched to the client and filtered there | medium | scan+review | supabase-js, firebase, any | scan_frontend |
| [PERF-003](performance.md#perf-003) | Unoptimised images and assets | low | scan | web | scan_frontend |
| [PERF-004](performance.md#perf-004) | Oversized JavaScript bundle | low | scan | web | scan_frontend |
| [PERF-005](performance.md#perf-005) | No caching for static or public content | low | scan | web | scan_config |
| [PERF-006](performance.md#perf-006) | Realtime subscriptions and listeners are never cleaned up | low | scan | supabase realtime, firebase listeners, websockets | scan_frontend |
| [MAIL-001](email.md#mail-001) | Sending domain not authenticated | high | review | any email | review |
| [MAIL-002](email.md#mail-002) | Relying on the backend provider's built-in development email service | high | scan | supabase auth | scan_supabase |
| [MAIL-003](email.md#mail-003) | Emails and auth redirects point to localhost or preview URLs | high | scan | all | scan_env |
| [MAIL-004](email.md#mail-004) | Email or SMS sending can be triggered without limit | high | scan+review | any email/sms | scan_launch |
| [MAIL-005](email.md#mail-005) | Marketing email without unsubscribe | low | review | any marketing email | review |
| [TEST-001](testing.md#test-001) | No automated test for the critical paths | medium | scan | all | scan_config |
| [TEST-002](testing.md#test-002) | No access-rule tests | medium | scan | supabase, firebase, any | scan_config |
| [TEST-003](testing.md#test-003) | No CI pipeline running checks before deploy | medium | scan | github, gitlab | scan_config |
| [TEST-004](testing.md#test-004) | Secret scanning not enabled on the repository | low | review | github | review |
| [LAUNCH-001](launch.md#launch-001) | Default or missing page metadata | low | scan | web | scan_frontend |
| [LAUNCH-002](launch.md#launch-002) | Default favicon, missing app icons and manifest | low | scan | web | scan_frontend |
| [LAUNCH-003](launch.md#launch-003) | Search engine controls missing or wrong | low | scan | web | scan_config |
| [LAUNCH-004](launch.md#launch-004) | Placeholder content and mock data shipped | medium | scan | all | scan_frontend |
| [LAUNCH-005](launch.md#launch-005) | Builder branding, badges and scaffolding left in place | low | scan | lovable, bolt, v0, replit | scan_frontend |
| [LAUNCH-006](launch.md#launch-006) | No way for users to get help or report a problem | low | scan | all | scan_config |
| [LAUNCH-007](launch.md#launch-007) | Custom domain, redirects and certificates not finalised | medium | review | web | review |
| [LAUNCH-008](launch.md#launch-008) | Mobile store requirements unmet | medium | scan+review | expo, react-native, capacitor, flutter | scan_config |
| [LAUNCH-009](launch.md#launch-009) | No README or handover documentation | low | scan | all | scan_config |
| [LAUNCH-010](launch.md#launch-010) | First-run experience untested with a fresh account | medium | review | all | review |

## Review-only checks

Read the code for these; no script can judge them: SEC-011, SEC-012, AUTH-001, AUTH-008, AUTH-009, AUTH-011, AUTH-014, AUTH-015, AUTH-016, DB-006, DB-016, DB-019, DB-020, DB-022, DB-023, API-005, API-017, PAY-003, PAY-004, PAY-005, PAY-006, PAY-010, UP-002, UP-005, UP-006, LLM-005, LLM-008, LLM-009, FE-005, FE-006, DEP-002, DEP-005, DEP-007, DEP-010, DEP-011, DEP-013, DEP-014, PRIV-008, OBS-003, OBS-004, OBS-005, OBS-006, REL-003, REL-005, REL-007, REL-008, MAIL-001, MAIL-005, TEST-004, LAUNCH-007, LAUNCH-010.
