# Server endpoints and input handling (API)

What this covers: the 19 API checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### API-001 — Request input is not validated
**Severity:** medium · **Mode:** scan+review · **Applies to:** all backends
**Auto-fix:** assisted

**In plain words:** The route uses what the caller sends without checking its type or size.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Unexpected types and sizes cause crashes, bad data and injection paths.

**Fix:** Validate at the boundary with a schema, reject with 400, use only the parsed result.

**Verify:** Test with a wrong type and an oversized string.

### API-002 — No rate limiting on expensive or abusable endpoints
**Severity:** high · **Mode:** scan+review · **Applies to:** all backends
**Auto-fix:** assisted

**In plain words:** Nothing limits how often costly endpoints can be called, so one script can run up bills or take the app down.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Exhausted quotas and surprise costs.

**Fix:** Add limits backed by a shared store or the platform firewall, stricter on costly endpoints.

**Verify:** A test receives 429 after the threshold.

### API-003 — Cross-origin policy allows any site with credentials
**Severity:** high · **Mode:** scan · **Applies to:** all backends
**Auto-fix:** auto/assisted

**In plain words:** Any website can make requests to your API as the signed-in visitor and read the answers.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Wildcard or reflected origins with credentials defeat the browser's protection.

**Fix:** Use an explicit origin allow-list from configuration; credentials only for those origins.

**Verify:** Scanner clean; a request from a disallowed origin is refused.

### API-004 — Errors return internal details to the client
**Severity:** medium · **Mode:** scan · **Applies to:** all backends
**Auto-fix:** assisted

**In plain words:** When something fails, the server sends internal error text to the caller.

**How to detect:** Run `scripts/scan_routes.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Leaks schema, file paths and sometimes secrets.

**Fix:** Return a generic message plus a request ID; send details to logs and the error tracker.

**Verify:** A forced error shows no internals.

### API-005 — Handler does not check that the resource belongs to the caller
**Severity:** critical · **Mode:** review · **Applies to:** all backends
**Auto-fix:** assisted

**In plain words:** A signed-in user can change the ID in a request and read or change someone else's record.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Insecure direct object reference, the most common serious flaw in AI-built backends.

**Fix:** Put the ownership condition in the query itself and return 404 on mismatch.

**Verify:** Test: user A requests user B's resource and gets 404.

### API-006 — Server fetches a URL supplied by the user
**Severity:** high · **Mode:** scan+review · **Applies to:** all backends
**Auto-fix:** assisted

**In plain words:** The server fetches any web address the caller supplies, which lets outsiders reach internal systems through your server.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Server-side request forgery.

**Fix:** Allow-list hosts, or block private, loopback and link-local ranges, forbid redirects to them, require https, set timeouts and size limits.

**Verify:** Tests with http://169.254.169.254/, http://localhost and a redirecting URL.

### API-007 — Incoming webhook is not authenticated
**Severity:** high · **Mode:** scan · **Applies to:** any webhook provider
**Auto-fix:** assisted

**In plain words:** Anyone can send fake events to a webhook and the app believes them.

**How to detect:** Run `scripts/scan_routes.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Forged "payment succeeded" or "user created" events.

**Fix:** Verify the signature with the provider's library against the raw body and check the timestamp tolerance.

**Verify:** An unsigned payload returns 400.

### API-008 — List endpoints return unbounded results
**Severity:** medium · **Mode:** scan+review · **Applies to:** all backends
**Auto-fix:** assisted

**In plain words:** A list endpoint returns every row with no limit, which gets slow and hands scrapers a bulk export.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Slow responses, large bills and easy data export.

**Fix:** Enforce a maximum page size on the server and paginate with a cursor.

**Verify:** A huge limit request is capped.

### API-009 — No limit on request body size
**Severity:** low · **Mode:** scan · **Applies to:** express, fastify, custom servers
**Auto-fix:** auto

**In plain words:** The server accepts very large request bodies, so a few requests can exhaust memory.

**How to detect:** Run `scripts/scan_routes.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Memory exhaustion and cost.

**Fix:** Use small per-route limits; larger only for streaming upload routes.

**Verify:** An oversized request returns 413.

### API-010 — Server action or RPC callable without its own checks
**Severity:** critical · **Mode:** scan+review · **Applies to:** nextjs server actions, trpc, remix, sveltekit
**Auto-fix:** assisted

**In plain words:** A server action or procedure changes data without checking who calls it; every action is a public address.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Each is an HTTP endpoint regardless of where its button is rendered.

**Fix:** Authenticate and authorise inside every action; validate arguments.

**Verify:** Direct invocation without a session fails.

### API-011 — GraphQL endpoint exposed without limits
**Severity:** medium · **Mode:** scan · **Applies to:** graphql
**Auto-fix:** assisted

**In plain words:** The GraphQL API publishes its schema and accepts arbitrarily deep queries.

**How to detect:** Run `scripts/scan_routes.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Schema discovery and expensive nested queries.

**Fix:** Disable introspection and the playground in production for a private API, add depth and cost limits, authorise in resolvers.

**Verify:** Config check.

### API-012 — Debug, test or scaffolding endpoints left in the app
**Severity:** high · **Mode:** scan · **Applies to:** all backends
**Auto-fix:** assisted

**In plain words:** A leftover developer endpoint is part of the app; tools for the developer are tools for an attacker.

**How to detect:** Run `scripts/scan_routes.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Debug routes can dump environment variables or run queries.

**Fix:** Delete it, or guard with an environment check and admin authorisation.

**Verify:** Scanner clean.

### API-013 — Edge or cloud functions deployed with JWT verification disabled
**Severity:** high · **Mode:** scan · **Applies to:** supabase edge functions, firebase functions, cloud run
**Auto-fix:** assisted

**In plain words:** A server function accepts calls from anyone with no sign-in check, while holding privileged credentials.

**How to detect:** Run `scripts/scan_supabase.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** The function is a public endpoint.

**Fix:** Enable JWT verification or verify the token in code; verify signatures for webhooks.

**Verify:** Scanner clean; an unauthenticated call returns 401.

### API-014 — Scheduled or internal endpoints are publicly triggerable
**Severity:** high · **Mode:** scan+review · **Applies to:** vercel cron, netlify scheduled, any
**Auto-fix:** assisted

**In plain words:** Anyone can start a scheduled job by visiting its address, as often as they like.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Batch jobs, emails and billing runs can be triggered repeatedly.

**Fix:** Require the platform's cron secret header or a signed token; make jobs idempotent.

**Verify:** A call without the secret returns 401.

### API-015 — File path built from user input
**Severity:** critical · **Mode:** scan · **Applies to:** node, python backends
**Auto-fix:** assisted

**In plain words:** A file path is built from what the caller sends, so `../` can reach files such as your secret settings.

**How to detect:** Run `scripts/scan_routes.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Path traversal.

**Fix:** Resolve against a base directory and verify the result stays inside; prefer IDs mapped to stored paths.

**Verify:** Test with ../../.env.

### API-016 — User input reaches a shell, eval or dynamic code execution
**Severity:** critical · **Mode:** scan · **Applies to:** node, python backends
**Auto-fix:** assisted

**In plain words:** What the caller sends reaches a shell or code interpreter, letting an attacker run commands on your server.

**How to detect:** Run `scripts/scan_routes.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Remote code execution: complete server takeover.

**Fix:** Avoid shells, pass argument arrays, allow-list commands, use safe parsers.

**Verify:** Scanner clean.

### API-017 — Mutating endpoints are not idempotent where retries are expected
**Severity:** medium · **Mode:** review · **Applies to:** payments, credits, orders, email sends
**Auto-fix:** assisted

**In plain words:** Retries or double clicks can create duplicate orders, charges or messages.

**How to detect:** No script can see this. Read the code and configuration named in the stack playbook, and ask the owner where the answer is not in the repository.

**Why it matters:** Duplicate charges, orders and deductions.

**Fix:** Idempotency keys with a unique constraint; disable the button while pending as a convenience.

**Verify:** The same request twice produces one effect.

### API-018 — HTTP methods not restricted
**Severity:** low · **Mode:** scan · **Applies to:** nextjs pages api, express, serverless functions
**Auto-fix:** auto

**In plain words:** A route changes data on a plain link visit or accepts the wrong HTTP method.

**How to detect:** Run `scripts/scan_routes.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Crawlers, link previews and image tags can trigger it.

**Fix:** Restrict to the intended method and return 405 otherwise.

**Verify:** A request with the wrong method is refused.

### API-019 — Response includes more fields than the client needs
**Severity:** medium · **Mode:** scan+review · **Applies to:** all backends
**Auto-fix:** assisted

**In plain words:** The response includes more fields than the page needs, such as password hashes or other users' emails.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Data leaks through the network tab.

**Fix:** Select explicit fields or use response schemas.

**Verify:** A test asserts sensitive fields are absent.


