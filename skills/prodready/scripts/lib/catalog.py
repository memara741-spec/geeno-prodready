"""The check catalog as data: one row per check.

This is the single machine-readable list of checks. The prose for each check
lives in ``references/checks/<category>.md`` and the table in
``references/checks/INDEX.md``; ``tests/test_catalog_consistency.py`` asserts
that all three agree on IDs, titles, severities and modes.

Row format: ``id|severity|mode|fix|stacks|scanner|title``

- ``severity`` is the default severity. Context adjustments are made by the
  reviewer in the report, never here.
- ``mode`` is ``scan``, ``review`` or ``scan+review``.
- ``scanner`` is the one script that owns the check (``-`` for review-only
  checks). Other scripts may emit the check as a secondary signal; they list
  it in their ``ALSO_EMITS``.
"""
from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional

CATEGORIES: Dict[str, Dict[str, str]] = {
    "SEC": {"slug": "secrets", "name": "Secrets and keys"},
    "AUTH": {"slug": "auth", "name": "Authentication and sessions"},
    "DB": {"slug": "database", "name": "Database, storage and access rules"},
    "API": {"slug": "api", "name": "Server endpoints and input handling"},
    "PAY": {"slug": "payments", "name": "Payments and entitlements"},
    "UP": {"slug": "uploads", "name": "File uploads"},
    "LLM": {"slug": "llm", "name": "AI features"},
    "FE": {"slug": "frontend", "name": "Frontend"},
    "HDR": {"slug": "headers", "name": "Security headers and transport"},
    "DEP": {"slug": "deploy", "name": "Deployment and configuration"},
    "DEPS": {"slug": "dependencies", "name": "Dependencies and supply chain"},
    "PRIV": {"slug": "privacy", "name": "Privacy and data protection"},
    "OBS": {"slug": "observability", "name": "Observability"},
    "REL": {"slug": "reliability", "name": "Reliability and correctness"},
    "PERF": {"slug": "performance", "name": "Performance"},
    "MAIL": {"slug": "email", "name": "Email and messaging"},
    "TEST": {"slug": "testing", "name": "Tests and CI"},
    "LAUNCH": {"slug": "launch", "name": "Launch polish"},
}

_ROWS = """
SEC-001|critical|scan|assisted+owner|all|scan_secrets|Admin-level backend key reachable from client code
SEC-002|critical|scan|assisted+owner|all|scan_secrets|Secret committed in the current working tree
SEC-003|high|scan|owner|all|scan_git_history|Secret present in git history
SEC-004|high|scan|auto|all|scan_env|Environment files are not ignored by git
SEC-005|critical|scan|assisted+owner|nextjs, vite, cra, expo, sveltekit, nuxt, astro|scan_env|Secret stored in a browser-exposed environment variable
SEC-006|high|scan|assisted+owner|all|scan_secrets|Hard-coded credential in source code
SEC-007|high|scan|assisted|web|scan_secrets|Secrets or server code visible in published source maps or build output
SEC-008|low|scan|auto|all|scan_env|No .env.example or documentation of required variables
SEC-009|medium|scan+review|assisted|all|scan_secrets|Secrets, tokens or passwords written to logs
SEC-010|critical|scan|assisted+owner|custom-jwt, authjs, express-session, django, flask|scan_secrets|Weak, default or placeholder signing secret
SEC-011|medium|review|owner|all|-|Test and live credentials mixed, or one set shared by all environments
SEC-012|medium|review|owner|firebase, google-maps, mapbox, algolia|-|Browser-visible third-party key has no restrictions
SEC-013|critical|scan|assisted+owner|any llm|scan_secrets|AI provider key used directly from the browser or mobile client
SEC-014|critical|scan|assisted+owner|expo, react-native, capacitor, flutter|scan_secrets|Secrets embedded in a mobile app configuration
SEC-015|critical|scan|assisted+owner|all|scan_secrets|Private key or service account file in the repository
SEC-016|info|scan|none|supabase, firebase, stripe, clerk|scan_secrets|Public key found in client code (not a leak)
AUTH-001|high|review|assisted|web, mobile|-|Page protection exists only in the user interface
AUTH-002|critical|scan+review|assisted|all backends|scan_routes|Data-returning or data-changing route has no authentication check
AUTH-003|high|scan+review|assisted|nextjs, express, hono, sveltekit|scan_routes|Middleware does not cover the routes it is assumed to cover
AUTH-004|critical|scan+review|assisted|all|scan_routes|Server trusts a user identifier supplied by the client
AUTH-005|high|scan|auto/assisted|supabase-ssr, custom-jwt|scan_supabase|Server code uses an unverified session read
AUTH-006|medium|scan+review|assisted|custom auth|scan_frontend|Session token stored where page scripts can read it
AUTH-007|medium|scan|auto|custom auth, express-session|scan_routes|Session cookie lacks protective attributes
AUTH-008|medium|review|owner/assisted|supabase, firebase, clerk, authjs, custom|-|Email addresses are not verified before the account is trusted
AUTH-009|low|review|owner/assisted|all with passwords|-|Weak password rules or leaked-password protection off
AUTH-010|high|scan+review|assisted|custom auth|scan_routes|No rate limit on sign-in, sign-up, reset or code verification
AUTH-011|high|review|assisted|custom auth|-|Password reset or magic link flow is unsafe
AUTH-012|medium|scan+review|assisted|all|scan_routes|Redirect after login accepts arbitrary destinations
AUTH-013|critical|scan+review|assisted|supabase, firebase, clerk, custom|scan_supabase|Role or admin flag stored where the user can change it
AUTH-014|low|review|assisted|custom auth|-|Sessions never expire or sign-out does not end them
AUTH-015|medium|review|assisted|custom cookie auth, express, flask, django|-|State-changing requests with cookie auth lack CSRF protection
AUTH-016|low|review|owner|all|-|No second factor available for administrator accounts
AUTH-017|critical|scan|assisted+owner|all|scan_secrets|Default, demo or seeded credentials present
AUTH-018|critical|scan|assisted|custom-jwt|scan_routes|Token verification accepts unsafe algorithms or skips claims
DB-001|critical|scan|assisted|supabase, postgrest|scan_supabase|Row level security disabled on a client-reachable table
DB-002|critical|scan|assisted|supabase|scan_supabase|Policy allows everyone
DB-003|critical|scan+review|assisted|supabase|scan_supabase|Authenticated-only policy without ownership scoping
DB-004|high|scan|assisted|supabase, postgres|scan_supabase|Write policy missing an effective WITH CHECK condition
DB-005|critical|scan|assisted|supabase|scan_supabase|Policy trusts user-editable metadata
DB-006|high|review|assisted|supabase, postgres, any|-|Table has no ownership or tenant column to scope by
DB-007|high|scan|assisted|supabase, postgres|scan_supabase|Privileged function callable through the API
DB-008|high|scan|assisted|supabase, postgres 15+|scan_supabase|View bypasses row level security
DB-009|high|scan+review|assisted+owner|supabase storage, firebase storage, s3, r2|scan_supabase|Storage bucket is public or has no access policies
DB-010|critical|scan|assisted|firebase|scan_firebase|Firebase rules allow open access
DB-011|critical|scan+review|assisted|firebase|scan_firebase|Firebase rules check sign-in but not ownership or shape
DB-012|critical|scan|assisted|any sql|scan_routes|SQL built by string concatenation with request data
DB-013|high|scan|assisted|prisma, drizzle, mongoose, supabase-js, any orm|scan_routes|Request body written to the database without field selection
DB-014|critical|scan|assisted+owner|any|scan_routes|Database reachable directly from the browser with privileged credentials
DB-015|medium|scan|assisted+owner|supabase, firebase|scan_supabase|Schema and policies exist only in the hosted dashboard
DB-016|high|review|owner|all|-|No backups or no tested restore
DB-017|medium|scan|assisted|postgres, supabase|scan_supabase|Missing indexes on columns used by policies and foreign keys
DB-018|medium|scan+review|assisted|prisma, drizzle, pg on serverless|scan_routes|Serverless functions open direct database connections without pooling
DB-019|critical|review|assisted|any multi-tenant|-|Multi-tenant data not isolated by tenant in rules or queries
DB-020|high|review|assisted|supabase realtime, firebase, pusher, ably, socket.io|-|Realtime channels deliver data without authorisation
DB-021|high|scan|assisted|supabase, postgres|scan_supabase|Anonymous role holds broad grants or can call sensitive RPCs
DB-022|medium|review|assisted|any|-|Guessable identifiers combined with weak authorisation
DB-023|medium|review|owner|postgres, mysql, mongo self-managed|-|Application connects to the database as a superuser
DB-024|high|scan+review|assisted|supabase, firebase, any|scan_supabase|Public profile data exposes private fields
API-001|medium|scan+review|assisted|all backends|scan_routes|Request input is not validated
API-002|high|scan+review|assisted|all backends|scan_routes|No rate limiting on expensive or abusable endpoints
API-003|high|scan|auto/assisted|all backends|scan_config|Cross-origin policy allows any site with credentials
API-004|medium|scan|assisted|all backends|scan_routes|Errors return internal details to the client
API-005|critical|review|assisted|all backends|-|Handler does not check that the resource belongs to the caller
API-006|high|scan+review|assisted|all backends|scan_routes|Server fetches a URL supplied by the user
API-007|high|scan|assisted|any webhook provider|scan_routes|Incoming webhook is not authenticated
API-008|medium|scan+review|assisted|all backends|scan_routes|List endpoints return unbounded results
API-009|low|scan|auto|express, fastify, custom servers|scan_routes|No limit on request body size
API-010|critical|scan+review|assisted|nextjs server actions, trpc, remix, sveltekit|scan_routes|Server action or RPC callable without its own checks
API-011|medium|scan|assisted|graphql|scan_routes|GraphQL endpoint exposed without limits
API-012|high|scan|assisted|all backends|scan_routes|Debug, test or scaffolding endpoints left in the app
API-013|high|scan|assisted|supabase edge functions, firebase functions, cloud run|scan_supabase|Edge or cloud functions deployed with JWT verification disabled
API-014|high|scan+review|assisted|vercel cron, netlify scheduled, any|scan_routes|Scheduled or internal endpoints are publicly triggerable
API-015|critical|scan|assisted|node, python backends|scan_routes|File path built from user input
API-016|critical|scan|assisted|node, python backends|scan_routes|User input reaches a shell, eval or dynamic code execution
API-017|medium|review|assisted|payments, credits, orders, email sends|-|Mutating endpoints are not idempotent where retries are expected
API-018|low|scan|auto|nextjs pages api, express, serverless functions|scan_routes|HTTP methods not restricted
API-019|medium|scan+review|assisted|all backends|scan_routes|Response includes more fields than the client needs
PAY-001|critical|scan+review|assisted|stripe, paddle, lemon squeezy, paypal, razorpay|scan_payments|Amount, price or plan taken from the client
PAY-002|critical|scan|assisted|all payment providers|scan_payments|Payment webhook signature not verified
PAY-003|critical|review|assisted|all payment providers|-|Access granted on the success redirect instead of a verified event
PAY-004|high|review|assisted|all payment providers|-|Webhook handler is not idempotent or ignores event ordering
PAY-005|high|review|assisted|all|-|Paid features gated only in the client
PAY-006|medium|review|assisted|subscriptions|-|Subscription lifecycle events are not handled
PAY-007|high|scan+review|assisted|stripe and similar|scan_payments|Customer or subscription identifier accepted from the client
PAY-008|high|scan|owner|all payment providers|scan_payments|Test mode in production, or live keys in development
PAY-009|critical|scan|assisted|any|scan_payments|Card data handled by the app's own server
PAY-010|high|review|assisted|credits, wallets, inventory, seats|-|Credits or balances updated without atomicity
PAY-011|medium|scan|assisted|any|scan_payments|Money stored or computed as floating point
UP-001|high|scan+review|assisted|any with uploads|scan_routes|Uploads accepted without type and size limits
UP-002|high|review|assisted|any|-|Uploaded files served from the application's origin as active content
UP-003|high|scan|assisted|any|scan_routes|Storage path or filename controlled by the user
UP-004|high|scan+review|assisted|supabase storage, firebase storage, s3, r2|scan_routes|Private files exposed through permanent public URLs
UP-005|medium|review|assisted|any|-|No per-user quota on uploads or storage
UP-006|medium|review|assisted|sharp, imagemagick, pdf libraries, ffmpeg|-|Image or document processing of untrusted files without limits
LLM-001|critical|scan|assisted|any llm|scan_llm|AI endpoint callable without authentication
LLM-002|high|scan+review|assisted+owner|any llm|scan_llm|No per-user limit or spending cap on AI usage
LLM-003|high|scan|assisted|any llm|scan_llm|Client controls the model, system prompt or generation parameters
LLM-004|medium|scan|auto/assisted|any llm|scan_llm|No output or input size limits and no timeout
LLM-005|high|review|assisted|agents, rag, tool use, mcp|-|Untrusted content can steer a model that has tools or data access
LLM-006|high|scan|assisted|any llm with rich output|scan_llm|Model output rendered or executed without sanitising
LLM-007|high|scan+review|assisted|any llm|scan_llm|Secrets or private data placed in prompts
LLM-008|medium|review|owner/assisted|any llm|-|Personal data sent to AI providers without disclosure or minimisation
LLM-009|low|review|assisted|public-facing generation|-|No abuse controls on user-generated AI content
LLM-010|medium|scan|none|all|scan_llm|Instructions aimed at AI reviewers embedded in the project
FE-001|high|scan+review|assisted|react, vue, svelte, angular, plain js|scan_frontend|User-controlled content inserted as HTML
FE-002|medium|scan+review|assisted|web, mobile|scan_frontend|Sensitive data kept in browser storage or client state longer than needed
FE-003|low|scan|auto|web, mobile|scan_frontend|Debug output in production builds
FE-004|medium|scan|assisted|react, nextjs, vue, svelte|scan_frontend|No error boundary or global error handling
FE-005|low|review|assisted|web, mobile|-|Missing loading, empty and failure states on key screens
FE-006|low|review|assisted|web, mobile|-|Forms can be submitted twice
FE-007|low|scan|assisted|web|scan_frontend|Third-party scripts loaded without need or integrity
FE-008|low|scan+review|assisted|web|scan_frontend|Basic accessibility and mobile layout gaps
FE-009|low|scan|auto|web|scan_frontend|Links opening new tabs without isolation, and unsafe external navigation
HDR-001|medium|scan|assisted|web|scan_config|No Content Security Policy
HDR-002|medium|scan|auto/assisted|web|scan_config|HTTPS not enforced with HSTS
HDR-003|medium|scan|auto|web|scan_config|Pages can be framed by other sites
HDR-004|low|scan|auto|web|scan_config|Missing nosniff, referrer and permissions policies
HDR-005|medium|scan+review|assisted|web with cdn, nextjs caching|scan_config|Authenticated responses may be cached by shared caches
HDR-006|low|scan|auto|express, nextjs, custom servers|scan_config|Server and framework versions disclosed
DEP-001|high|scan|assisted|all|scan_config|Development or debug mode enabled in production
DEP-002|high|review|owner|all|-|Production and development share one backend
DEP-003|medium|scan|assisted|all|scan_env|Environment variables are not validated at startup
DEP-004|low|scan|auto|backends, containers|scan_config|No health check endpoint
DEP-005|medium|review|owner|all|-|No rollback path
DEP-006|medium|scan|auto/assisted|node, python|scan_config|Builds are not reproducible
DEP-007|medium|review|owner|vercel, netlify, cloudflare pages, replit, builders|-|Preview or staging deployments are public and indexed
DEP-008|medium|scan|assisted|nextjs, vite, typescript|scan_config|Build ignores type and lint errors
DEP-009|medium|scan|assisted|docker|scan_config|Container image runs as root or bakes in secrets
DEP-010|low|review|owner/assisted|serverless|-|Function region far from the database, or timeouts too short for the work
DEP-011|medium|review|owner|lovable, bolt, v0, replit, firebase studio|-|The project still lives only inside the AI builder
DEP-012|low|scan|auto/assisted|web|scan_config|Default error pages and missing not-found handling
DEP-013|low|review|owner|github + any host|-|Default branch unprotected and deploys on every push
DEP-014|medium|review|owner|all cloud, llm, sms, email, maps|-|Billing limits and usage alerts not configured on pay-per-use services
DEPS-001|high|scan|assisted|node, python|scan_deps|Dependencies with known vulnerabilities
DEPS-002|high|scan|assisted|nextjs, react, express, django, flask|scan_deps|Framework version is past security support
DEPS-003|high|scan|assisted|node, python|scan_deps|Dependency that does not exist, is misspelled, or is suspicious
DEPS-004|low|scan|assisted|node, python|scan_deps|Unused, duplicated or abandoned dependencies
DEPS-005|low|scan|auto|node|scan_deps|Development tools shipped as production dependencies, or the reverse
DEPS-006|low|scan|auto|github|scan_deps|No automated dependency update or alerting
DEPS-007|low|scan|owner|node, python|scan_deps|Licence incompatible with commercial use
PRIV-001|medium|scan|owner/assisted|web, mobile|scan_launch|No privacy policy or terms where personal data is collected
PRIV-002|medium|scan+review|assisted|web|scan_frontend|Trackers load before consent where consent is required
PRIV-003|medium|scan+review|assisted|all with accounts|scan_launch|Users cannot delete their account or export their data
PRIV-004|medium|scan+review|assisted|all|scan_secrets|Personal data in logs, analytics events or error reports
PRIV-005|high|scan+review|assisted|all|scan_routes|Sensitive data stored unprotected or collected without need
PRIV-006|low|scan|auto|all|scan_launch|No list of third parties that receive user data
PRIV-007|medium|scan|assisted|web|scan_frontend|Session replay or analytics captures form inputs
PRIV-008|low|review|assisted|all|-|No data retention or cleanup
OBS-001|high|scan|assisted+owner|all|scan_config|No error tracking
OBS-002|medium|scan+review|assisted|backends|scan_config|No usable server logs
OBS-003|medium|review|owner|all|-|No uptime monitoring or alerting
OBS-004|medium|review|assisted|admin, billing, roles, data export|-|No audit trail for sensitive actions
OBS-005|low|review|assisted|all|-|No visibility into the core funnel
OBS-006|low|review|assisted|all|-|No incident plan
REL-001|medium|scan|assisted|node, browser|scan_config|Unhandled failures in asynchronous code
REL-002|medium|scan+review|assisted|backends|scan_routes|External calls without timeouts or retry policy
REL-003|medium|review|assisted|any database|-|Multi-step writes without a transaction
REL-004|medium|scan|assisted|serverless, autoscaled containers|scan_config|State kept in process memory on serverless or multi-instance hosts
REL-005|medium|review|assisted|serverless, any|-|Long-running work performed inside the request
REL-006|low|scan+review|assisted|all|scan_config|Date, time zone and locale handling errors
REL-007|high|review|owner|all|-|No tested path to restore service after data loss
REL-008|low|review|assisted|all|-|Hard dependency on a single third party in the critical path with no fallback
PERF-001|medium|scan+review|assisted|any database|scan_routes|Query inside a loop
PERF-002|medium|scan+review|assisted|supabase-js, firebase, any|scan_frontend|Whole tables fetched to the client and filtered there
PERF-003|low|scan|assisted|web|scan_frontend|Unoptimised images and assets
PERF-004|low|scan|assisted|web|scan_frontend|Oversized JavaScript bundle
PERF-005|low|scan|assisted|web|scan_config|No caching for static or public content
PERF-006|low|scan|assisted|supabase realtime, firebase listeners, websockets|scan_frontend|Realtime subscriptions and listeners are never cleaned up
MAIL-001|high|review|owner|any email|-|Sending domain not authenticated
MAIL-002|high|scan|owner|supabase auth|scan_supabase|Relying on the backend provider's built-in development email service
MAIL-003|high|scan|assisted+owner|all|scan_env|Emails and auth redirects point to localhost or preview URLs
MAIL-004|high|scan+review|assisted|any email/sms|scan_launch|Email or SMS sending can be triggered without limit
MAIL-005|low|review|assisted|any marketing email|-|Marketing email without unsubscribe
TEST-001|medium|scan|assisted|all|scan_config|No automated test for the critical paths
TEST-002|medium|scan|assisted|supabase, firebase, any|scan_config|No access-rule tests
TEST-003|medium|scan|auto|github, gitlab|scan_config|No CI pipeline running checks before deploy
TEST-004|low|review|owner|github|-|Secret scanning not enabled on the repository
LAUNCH-001|low|scan|assisted|web|scan_frontend|Default or missing page metadata
LAUNCH-002|low|scan|assisted|web|scan_frontend|Default favicon, missing app icons and manifest
LAUNCH-003|low|scan|assisted|web|scan_config|Search engine controls missing or wrong
LAUNCH-004|medium|scan|assisted|all|scan_frontend|Placeholder content and mock data shipped
LAUNCH-005|low|scan|assisted|lovable, bolt, v0, replit|scan_frontend|Builder branding, badges and scaffolding left in place
LAUNCH-006|low|scan|assisted|all|scan_config|No way for users to get help or report a problem
LAUNCH-007|medium|review|owner|web|-|Custom domain, redirects and certificates not finalised
LAUNCH-008|medium|scan+review|assisted+owner|expo, react-native, capacitor, flutter|scan_config|Mobile store requirements unmet
LAUNCH-009|low|scan|auto|all|scan_config|No README or handover documentation
LAUNCH-010|medium|review|assisted|all|-|First-run experience untested with a fresh account
"""


@dataclasses.dataclass(frozen=True)
class Check:
    id: str
    severity: str
    mode: str
    fix_type: str
    stacks: str
    scanner: Optional[str]
    title: str

    @property
    def prefix(self) -> str:
        return self.id.split("-")[0]

    @property
    def category(self) -> str:
        return CATEGORIES[self.prefix]["slug"]

    @property
    def reference(self) -> str:
        return "references/checks/%s.md#%s" % (self.category, self.id.lower())

    @property
    def is_scan(self) -> bool:
        return "scan" in self.mode


def _load() -> Dict[str, Check]:
    out: Dict[str, Check] = {}
    for line in _ROWS.strip().splitlines():
        cid, sev, mode, fix, stacks, scanner, title = [p.strip() for p in line.split("|", 6)]
        out[cid] = Check(cid, sev, mode, fix, stacks, None if scanner == "-" else scanner, title)
    return out


CHECKS: Dict[str, Check] = _load()


def get(check_id: str) -> Check:
    return CHECKS[check_id]


def by_scanner(scanner: str) -> List[str]:
    """Check IDs owned by a scanner, in catalog order."""
    return [c.id for c in CHECKS.values() if c.scanner == scanner]


def by_category(prefix: str) -> List[Check]:
    return [c for c in CHECKS.values() if c.prefix == prefix]
