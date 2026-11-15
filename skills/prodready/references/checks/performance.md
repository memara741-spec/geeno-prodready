# Performance (PERF)

What this covers: the 12 PERF checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### PERF-001 — Query inside a loop
**Severity:** medium · **Mode:** scan+review · **Applies to:** any database
**Auto-fix:** assisted

**In plain words:** The code asks the database one question per item, so pages slow to seconds with real data.

**How to detect:** `scripts/scan_routes.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** N+1 queries.

**Fix:** Batch with `in`, joins or includes.

**Verify:** Query count drops; scanner clean.

### PERF-002 — Whole tables fetched to the client and filtered there
**Severity:** medium · **Mode:** scan+review · **Applies to:** supabase-js, firebase, any
**Auto-fix:** assisted

**In plain words:** The app downloads a whole table and filters it in the browser.

**How to detect:** `scripts/scan_frontend.py` finds candidates with file and line. Read each one: promote it to confirmed, keep it, or drop it with a reason. Then review the surrounding code for cases the scanner cannot see.

**Why it matters:** Slow, expensive, and hands visitors rows they should not receive.

**Fix:** Filter, sort and paginate in the query.

**Verify:** The network response contains only the needed page.

### PERF-003 — Unoptimised images and assets
**Severity:** low · **Mode:** scan · **Applies to:** web
**Auto-fix:** assisted

**In plain words:** Large images slow the first load on phones.

**How to detect:** Run `scripts/scan_frontend.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Where most launch traffic is lost.

**Fix:** Resize, compress, use modern formats and lazy loading.

**Verify:** Asset sizes under thresholds.

### PERF-004 — Oversized JavaScript bundle
**Severity:** low · **Mode:** scan · **Applies to:** web
**Auto-fix:** assisted

**In plain words:** A large JavaScript bundle slows interaction on mid-range phones.

**How to detect:** Run `scripts/scan_frontend.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Whole libraries imported for one function.

**Fix:** Per-module imports, dynamic import for heavy features, remove unused libraries.

**Verify:** Bundle size report before and after.

### PERF-005 — No caching for static or public content
**Severity:** low · **Mode:** scan · **Applies to:** web
**Auto-fix:** assisted

**In plain words:** Public pages are rendered on every visit although they are the same for everyone.

**How to detect:** Run `scripts/scan_config.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Unnecessary cost and fragility under a traffic spike.

**Fix:** Static generation or revalidation for public pages; immutable caching for hashed assets.

**Verify:** Config review.

### PERF-006 — Realtime subscriptions and listeners are never cleaned up
**Severity:** low · **Mode:** scan · **Applies to:** supabase realtime, firebase listeners, websockets
**Auto-fix:** assisted

**In plain words:** Live subscriptions are opened and never closed.

**How to detect:** Run `scripts/scan_frontend.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Memory leaks, duplicate events and growing read costs.

**Fix:** Unsubscribe in cleanup and narrow the listener's query.

**Verify:** Scanner clean.

### PERF-007 — Related records loaded one by one inside a loop (N+1)
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** Related records are fetched one row at a time inside a loop.

**How to detect:** Run `scripts/scan_performance.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A page with 100 rows runs 101 queries and slows with growth.

**Fix:** Eager load with `with()`, and enable `preventLazyLoading` in development.

**Verify:** Query count on the page is constant as rows grow.

### PERF-008 — Whole table loaded on a request path
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A whole table is loaded into memory on a web request.

**How to detect:** Run `scripts/scan_performance.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Fine with 50 rows and fatal with 500,000.

**Fix:** Use `paginate()`, `cursor()` or `chunk()` and select needed columns.

**Verify:** The response time and memory stay flat as the table grows.

### PERF-009 — Query shape that cannot use an index or loads everything into memory
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A query shape that cannot use an index or loads everything into PHP.

**How to detect:** Run `scripts/scan_performance.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** It reads whole tables on every request.

**Fix:** Aggregate in the database, avoid leading wildcards and random ordering, or use full-text search.

**Verify:** `EXPLAIN` shows an index, and the query count and memory fall.

### PERF-010 — Email or outside call made inside the request
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** An email or notification is sent while the visitor waits.

**How to detect:** Run `scripts/scan_performance.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A slow mail server hangs the page and an outage makes the request fail.

**Fix:** Queue the mail or notification and run a worker.

**Verify:** The request returns before the mail is sent.

### PERF-011 — Queue, cache or session driver unsuitable for production
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted+owner

**In plain words:** The queue, cache or session driver in production config is a development one.

**How to detect:** Run `scripts/scan_performance.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Queued jobs run inside the request, the cache caches nothing and sessions are lost.

**Fix:** Use redis or database drivers and run a queue worker.

**Verify:** A queued job is processed by the worker, not the request.

**Owner action:** a human must do part of this outside the code; see `references/owner-actions/` and give the exact steps for the detected platform.

### PERF-012 — Foreign key column without an index
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A column linking to another table has no index.

**How to detect:** Run `scripts/scan_performance.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Lookups, joins and deletes read the whole table.

**Fix:** Use `foreignId()->constrained()` or add an index.

**Verify:** `EXPLAIN` shows the index used.


