# Multi-tenant isolation (TEN)

What this covers: the 7 TEN checks. Read it when a finding in this category appears or when reviewing this area. After reading you can explain each finding in plain words, fix it and verify the fix.
Last checked: 2026-11-13. Platform claims were confirmed against vendor documentation on that date where a URL is given in the stack playbooks; claims without a URL are marked in the playbook.

### TEN-001 — Tenant-owned table has a model with no tenant scope
**Severity:** critical · **Mode:** scan · **Applies to:** laravel, prisma
**Auto-fix:** assisted

**In plain words:** A table belongs to one company, but its model does not filter by company.

**How to detect:** Run `scripts/scan_tenancy.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Every query returns every customer's rows unless each developer remembers the filter every time.

**Fix:** Add a global scope or trait that filters and fills the tenant column automatically.

**Verify:** Two-tenant test: tenant A never sees tenant B's rows through the model.

### TEN-002 — Tenant scope switched off in request-handling code
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A tenant filter is switched off in code that serves requests.

**How to detect:** Run `scripts/scan_tenancy.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** That query reads all customers' data.

**Fix:** Remove it or restrict it to an authorised, logged admin action.

**Verify:** scan_tenancy is clean; the two-tenant test still passes.

### TEN-003 — Record looked up by ID without a tenant filter
**Severity:** critical · **Mode:** scan · **Applies to:** laravel, prisma
**Auto-fix:** assisted

**In plain words:** A record is fetched by ID with no tenant condition.

**How to detect:** Run `scripts/scan_tenancy.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** A user can open another company's record by guessing its ID.

**Fix:** Look records up through the current tenant, or scope the model.

**Verify:** Requesting another tenant's record ID returns 404.

### TEN-004 — Tenant or company ID taken from the request
**Severity:** critical · **Mode:** scan · **Applies to:** laravel, express, nextjs
**Auto-fix:** assisted

**In plain words:** The company or tenant comes from something the caller sends.

**How to detect:** Run `scripts/scan_tenancy.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Anyone can pass another company's ID and work inside it.

**Fix:** Take the tenant from the signed-in user or a verified domain.

**Verify:** A request naming another tenant is ignored or rejected.

### TEN-005 — Cache keys or storage paths not separated by tenant
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A cached value comes from tenant data but its cache key is the same for everyone.

**How to detect:** Run `scripts/scan_tenancy.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** The first company to load it fills the cache and the others are served its data.

**Fix:** Include the tenant in the key or use per-tenant cache tags.

**Verify:** Two tenants requesting the page see their own data.

### TEN-006 — Unique or exists validation ignores the tenant
**Severity:** medium · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** A unique or exists rule checks the whole table, not the current tenant.

**How to detect:** Run `scripts/scan_tenancy.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** It reveals that a value exists in another company and blocks values that other company uses.

**Fix:** Add `->where('company_id', $tenantId)` to the rule.

**Verify:** The same value can exist in two tenants.

### TEN-007 — Tenant column is nullable or has no index
**Severity:** high · **Mode:** scan · **Applies to:** laravel
**Auto-fix:** assisted

**In plain words:** The tenant column can be empty or has no index.

**How to detect:** Run `scripts/scan_tenancy.py` (or `scripts/run_all.py`). It reports this check with file, line and a redacted snippet. Open each location before reporting it.

**Why it matters:** Rows without a tenant are visible to everyone or no one, and scoped queries scan all customers.

**Fix:** Make it NOT NULL with a foreign key and an index.

**Verify:** The migration runs and `EXPLAIN` shows the index used.


