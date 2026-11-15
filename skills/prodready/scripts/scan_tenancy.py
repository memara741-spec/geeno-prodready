#!/usr/bin/env python3
"""Multi-tenant isolation audit: can one company's users reach another company's data?

Works on Laravel (Eloquent models, migrations, controllers, Livewire) and on
Prisma schemas used from JavaScript or TypeScript servers. It first finds the
tenant-owned tables (those with a ``tenant_id``, ``company_id``, ``team_id``,
``organization_id`` or similar column), then checks how the code reaches them.

Detects: a tenant-owned table whose model has no tenant scope (TEN-001), a scope
switched off in request code (TEN-002), a record looked up by ID with no tenant
filter (TEN-003), a tenant ID read from the request (TEN-004), cached results
shared between tenants (TEN-005), unique or exists rules that ignore the tenant
(TEN-006) and tenant columns that are nullable or unindexed (TEN-007).

What it deliberately does not do: it cannot prove isolation. Apps that give each
tenant its own database (stancl/tenancy) are reported as such and not flagged for
missing row scopes. Read the report's table of tenant tables and confirm it.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional, Set

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import catalog, findings, phpscan, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_tenancy")
ALSO_EMITS: List[str] = []

TENANT_COLS = ("tenant_id", "company_id", "team_id", "organization_id", "organisation_id", "org_id", "account_id", "workspace_id", "business_id", "store_id", "client_id")
TENANT_RE = "|".join(TENANT_COLS)
PRISMA_TENANT = ("tenantId", "orgId", "organizationId", "companyId", "teamId", "workspaceId", "accountId", "businessId")
SCOPE_RE = re.compile(r"BelongsToTenant|HasTenant|TenantScoped|BelongsToTeam|BelongsToCompany|BelongsToOrganization|addGlobalScope|ScopedBy|MultiTenantable|UsesTenantConnection")
FILTER_RE = re.compile(r"(?:%s)|tenant|->(?:company|team|organization|account|workspace)\(\)|auth\(\)->user\(\)->\w+\(\)->|\$request->user\(\)->\w+\(\)->|Auth::user\(\)->\w+\(\)->|currentTenant|tenant\(\)" % TENANT_RE, re.I)


def _migrations(project: walker.Project) -> Dict[str, Dict[str, Any]]:
    """table -> {cols: {col: {chain, line, file}}, indexed: set, file}"""
    tables: Dict[str, Dict[str, Any]] = {}
    for pf in phpscan.php_files(project):
        if "/migrations/" not in "/" + pf.rel:
            continue
        for m in re.finditer(r"Schema::(?:create|table)\s*\(\s*['\"](\w+)['\"]", pf.code):
            tname = m.group(1)
            open_idx = pf.bare.find("{", m.end())
            if open_idx < 0:
                continue
            end = phpscan.match_brace(pf.bare, open_idx)
            body = pf.code[open_idx:end]
            t = tables.setdefault(tname, {"cols": {}, "indexed": set(), "file": pf.rel})
            for c in re.finditer(r"\$table->(\w+)\(\s*['\"](%s)['\"][^;]*;" % TENANT_RE, body):
                t["cols"][c.group(2)] = {"chain": c.group(0), "line": pf.line(open_idx + c.start()), "file": pf.rel, "type": c.group(1)}
                if re.search(r"->(?:index|constrained|foreign|references)\s*\(|foreignId|foreignUuid", c.group(0)):
                    t["indexed"].add(c.group(2))
            for c in re.finditer(r"\$table->(?:index|foreign|unique|primary)\s*\(\s*(\[[^\]]*\]|['\"][^'\"]+['\"])", body):
                for col in re.findall(r"['\"](\w+)['\"]", c.group(1)):
                    t["indexed"].add(col)
    return {k: v for k, v in tables.items() if v["cols"]}


def _prisma_tenant_models(project: walker.Project) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for sf in project.files:
        if not sf.rel.endswith(".prisma"):
            continue
        text = project.text(sf)
        for m in re.finditer(r"^model\s+(\w+)\s*\{(.*?)^\}", text, re.M | re.S):
            for col in PRISMA_TENANT:
                if re.search(r"^\s*%s\s+" % col, m.group(2), re.M):
                    out[m.group(1)[0].lower() + m.group(1)[1:]] = col
                    break
    return out


def _call_args(text: str, open_idx: int) -> str:
    depth = 0
    for i in range(open_idx, min(len(text), open_idx + 4000)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx:i + 1]
    return text[open_idx:open_idx + 400]


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_tenancy", stack)
    laravel = phpscan.is_laravel(project)
    prisma = _prisma_tenant_models(project)
    comp = phpscan.composer(project)
    db_per_tenant = "stancl/tenancy" in comp["require"]
    tables = _migrations(project) if laravel else {}
    models = phpscan.model_class_names(project) if laravel else {}
    tenant_models: Dict[str, phpscan.PhpFile] = {}
    for name, pf in models.items():
        if phpscan.table_of(pf) in tables:
            tenant_models[name] = pf
    env.inventory["tenancy"] = {
        "laravel_tenant_tables": sorted(tables), "prisma_tenant_models": sorted(prisma), "database_per_tenant": db_per_tenant,
        "tables": [{"table": t, "column": sorted(v["cols"])[0], "model": next((n for n, p in tenant_models.items() if phpscan.table_of(p) == t), None),
                    "scoped": bool(next((SCOPE_RE.search(p.code) or any(SCOPE_RE.search(x) for x in p.traits) for n, p in tenant_models.items() if phpscan.table_of(p) == t), False))} for t, v in sorted(tables.items())],
    }
    if not tables and not prisma:
        env.files_scanned, env.files_skipped = project.stats()
        return env

    pfs = [p for p in phpscan.php_files(project) if not walker.TEST_PATH_RE.search(p.rel) and "/migrations/" not in "/" + p.rel and not p.rel.startswith(("database/factories/", "database/seeders/"))]
    request_files = [p for p in pfs if re.search(r"app/(Http|Livewire)/", p.rel) or p.rel.startswith("routes/")]

    def scoped(pf: phpscan.PhpFile) -> bool:
        return bool(SCOPE_RE.search(pf.code)) or any(SCOPE_RE.search(t) for t in pf.traits)

    # TEN-001
    if not db_per_tenant:
        for name, pf in sorted(tenant_models.items()):
            if scoped(pf):
                continue
            t = phpscan.table_of(pf)
            col = sorted(tables[t]["cols"])[0]
            m = re.search(r"\bclass\s+\w+", pf.bare)
            env.add(Finding("TEN-001", "The `%s` table belongs to a specific %s (`%s`), but the `%s` model does not filter by it. Every query on it returns every customer's rows unless each call remembers to add the filter." % (t, col.replace("_id", ""), col, name),
                            file=pf.rel, line=pf.line(m.start()) if m else 1, snippet=pf.line_text(pf.line(m.start()) if m else 1), confidence="likely", subject={"kind": "model", "name": name},
                            detail="Migration %s defines `%s.%s`; the model has no global scope or tenant trait." % (tables[t]["file"], t, col),
                            fix_hint="Add a global scope (or a `BelongsToTenant` trait) that applies `where %s = current tenant` to every query and sets it when creating. Then test it with two tenants." % col))

    # TEN-002 and TEN-003 (Laravel)
    tenant_tables = set(tables)
    for pf in request_files:
        for m in re.finditer(r"(?:->|::)withoutGlobalScopes?\s*\(", pf.code):
            env.add(Finding("TEN-002", "A global scope is switched off in code that serves requests. If that scope is the tenant filter, this query reads every customer's data.", file=pf.rel, line=pf.line(m.start()), snippet=pf.line_text(pf.line(m.start())),
                            confidence="likely", fix_hint="Remove it, or limit it to an admin-only action that is explicitly authorised and logged."))
        for m in re.finditer(r"DB::table\s*\(\s*['\"](\w+)['\"]\s*\)([^;]*);", pf.code):
            if m.group(1) in tenant_tables and not FILTER_RE.search(m.group(2)):
                env.add(Finding("TEN-002", "`DB::table('%s')` skips the model and its tenant scope, and this query has no tenant filter." % m.group(1), file=pf.rel, line=pf.line(m.start()), snippet=pf.line_text(pf.line(m.start())), confidence="likely",
                                fix_hint="Query through the model so the scope applies, or add `->where('%s', $tenantId)`." % sorted(tables[m.group(1)]["cols"])[0]))
        if db_per_tenant:
            continue
        for meth in pf.methods():
            body = meth["body"]
            if FILTER_RE.search(body):
                continue
            for m in re.finditer(r"\b([A-Z]\w+)::(find|findOrFail|findOrNew|firstOrFail|findMany|destroy)\s*\(\s*(\$\w+|\$request->[^)]*|request\([^)]*\)[^)]*)\)", body):
                mod = m.group(1)
                if mod in tenant_models and not scoped(tenant_models[mod]):
                    env.add(Finding("TEN-003", "`%s::%s(%s)` picks a record by ID with no tenant filter. A user from one company can open another company's record by changing the number." % (mod, m.group(2), m.group(3)[:30]),
                                    file=pf.rel, line=pf.line(meth["body_start"] + m.start()), snippet=pf.line_text(pf.line(meth["body_start"] + m.start())), confidence="likely", subject={"kind": "model", "name": "%s in %s" % (mod, meth["name"])},
                                    fix_hint="Look the record up through the current tenant (`$request->user()->company->invoices()->findOrFail($id)`) or give the model a tenant scope."))
            for m in re.finditer(r"\b([A-Z]\w+)::where\s*\(\s*['\"]id['\"]", body):
                mod = m.group(1)
                if mod in tenant_models and not scoped(tenant_models[mod]):
                    env.add(Finding("TEN-003", "`%s::where('id', ...)` has no tenant filter." % mod, file=pf.rel, line=pf.line(meth["body_start"] + m.start()), snippet=pf.line_text(pf.line(meth["body_start"] + m.start())), confidence="likely", subject={"kind": "model", "name": "%s in %s" % (mod, meth["name"])},
                                    fix_hint="Add the tenant condition or a global scope."))

    # TEN-004 (Laravel and JavaScript servers)
    tenant_param = re.compile(r"\$request->(?:input|get|query|post|string|integer)\s*\(\s*['\"](?:%s)['\"]|\$request->(?:%s)\b|request\(\s*['\"](?:%s)['\"]|\$request->header\(\s*['\"]x-(?:tenant|company|team|org)[\w-]*['\"]" % (TENANT_RE, TENANT_RE, TENANT_RE), re.I)
    for pf in request_files:
        if db_per_tenant:
            break
        for meth in pf.methods():
            m = tenant_param.search(meth["body"])
            if m and not re.search(r"authorize\w*\s*\(|Gate::|abort_(?:if|unless)", meth["body"]):
                env.add(Finding("TEN-004", "`%s::%s()` takes the company or tenant from the request. Anyone can send another company's ID and work inside it." % (pf.class_name, meth["name"]), file=pf.rel, line=pf.line(meth["body_start"] + m.start()),
                                snippet=pf.line_text(pf.line(meth["body_start"] + m.start())), confidence="likely", subject={"kind": "method", "name": pf.rel + "::" + meth["name"]},
                                fix_hint="Take the tenant from the signed-in user (`$request->user()->tenant_id`) or from a verified domain, never from a field the caller controls."))
    js_tenant = re.compile(r"(?:(?:req|request)\.(?:body|query|params)|body|data|parsed)\??\.(?:tenantId|orgId|organizationId|companyId|teamId|workspaceId)\b|(?:headers\.get|header)\(\s*['\"]x-(?:tenant|org|company|team)[\w-]*['\"]", re.I)
    for sf in project.code_files({".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}):
        if project.classify(sf) not in ("server", "shared"):
            continue
        text = project.text(sf)
        if not (prisma or re.search(r"tenant|organization|company", text, re.I)):
            continue
        m = js_tenant.search(text)
        if m and not re.search(r"session\.(?:user\.)?(?:tenantId|orgId)|membership|requireOrg|assertMember|isMember", text):
            line = sf.line_of(m.start())
            env.add(Finding("TEN-004", "This handler takes the tenant or organisation ID from the request. Anyone can send another organisation's ID.", file=sf.rel, line=line, snippet=sf.line_text(line), confidence="possible",
                            fix_hint="Derive it from the verified session or a membership lookup, and reject IDs the user does not belong to."))

    # TEN-003 for Prisma
    if prisma and not any(re.search(r"\$extends\s*\(", project.text(sf)) and re.search(r"tenantId|orgId|organizationId", project.text(sf)) for sf in project.code_files()):
        pat = re.compile(r"\bprisma\.(%s)\.(findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findMany|update|updateMany|delete|deleteMany|count|aggregate)\s*\(" % "|".join(prisma))
        for sf in project.code_files({".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}):
            if project.classify(sf) not in ("server", "shared"):
                continue
            text = project.text(sf)
            for m in pat.finditer(text):
                args = _call_args(text, m.end() - 1)
                if m.group(2) in ("findUnique", "findUniqueOrThrow") and re.search(r"where\s*:\s*\{\s*(?:email|username|token|slug|stripeCustomerId|providerAccountId|sessionToken|identifier)", args):
                    continue  # natural-key lookups such as sign-in by email
                if not re.search(r"\b(?:%s)\b" % "|".join(PRISMA_TENANT), args):
                    line = sf.line_of(m.start())
                    env.add(Finding("TEN-003", "`prisma.%s.%s` has no `%s` in its filter. It can return or change another tenant's rows." % (m.group(1), m.group(2), prisma[m.group(1)]), file=sf.rel, line=line, snippet=sf.line_text(line),
                                    confidence="likely", subject={"kind": "model", "name": "%s.%s" % (m.group(1), m.group(2))}, fix_hint="Add the tenant to every `where` (or use a Prisma client extension that injects it) and take the tenant from the session."))

    # TEN-005 cached results shared between tenants
    if tenant_models and not db_per_tenant:
        for pf in pfs:
            for m in re.finditer(r"Cache::(?:remember|rememberForever|sear)\s*\(\s*(['\"])([^'\"]*)\1\s*,", pf.code):
                key = m.group(2)
                stmt_end = pf.bare.find(";", m.end())
                stmt = pf.code[m.start():stmt_end if stmt_end > 0 else m.end() + 600]
                body_end = phpscan.match_brace(pf.bare, pf.bare.find("{", m.end())) if "{" in pf.bare[m.end():m.end() + 200] else m.end() + 400
                stmt = pf.code[m.start():max(body_end, m.end())]
                if re.search(r"tenant|%s" % TENANT_RE, key, re.I) or "$" in key:
                    continue
                if any(re.search(r"\b%s::" % n, stmt) for n in tenant_models):
                    env.add(Finding("TEN-005", "The cache key `%s` is the same for every tenant, but the cached value comes from tenant data. The first company to load it fills the cache and every other company is served that company's data." % key, file=pf.rel, line=pf.line(m.start()),
                                    snippet=pf.line_text(pf.line(m.start())), confidence="likely", fix_hint="Put the tenant in the key (`\"invoices:{$tenantId}\"`) or use cache tags per tenant."))

    # TEN-006 unique/exists rules
    for pf in pfs:
        for m in re.finditer(r"(?<=['\"|])(unique|exists):(\w+)(?:,(\w+))?(?:,[^'\"|]*)?(?=['\"|])", pf.code):
            table = m.group(2)
            full = pf.code[m.start():m.start() + 120].split("'")[1] if False else m.group(0)
            if table in tenant_tables and not re.search(r"(?:%s)" % TENANT_RE, full):
                env.add(Finding("TEN-006", "The `%s:%s` rule checks the whole table, not just the current tenant. It lets someone learn whether a value exists in another company, or blocks a value another company already uses." % (m.group(1), table), file=pf.rel,
                                line=pf.line(m.start()), snippet=pf.line_text(pf.line(m.start())), confidence="likely", fix_hint="Use `Rule::%s('%s', 'col')->where('%s', $tenantId)`." % (m.group(1), table, sorted(tables[table]["cols"])[0])))
        for m in re.finditer(r"Rule::(unique|exists)\s*\(\s*['\"](\w+)['\"][^)]*\)([^,\]]*)", pf.code):
            if m.group(2) in tenant_tables and not re.search(r"->(?:where|scope|when)\s*\(", m.group(3)):
                env.add(Finding("TEN-006", "`Rule::%s('%s')` is not limited to the current tenant." % (m.group(1), m.group(2)), file=pf.rel, line=pf.line(m.start()), snippet=pf.line_text(pf.line(m.start())), confidence="likely",
                                fix_hint="Chain `->where('%s', $tenantId)`." % sorted(tables[m.group(2)]["cols"])[0]))

    # TEN-007 migrations
    for t, info in sorted(tables.items()):
        for col, d in sorted(info["cols"].items()):
            if re.search(r"->nullable\s*\(", d["chain"]):
                env.add(Finding("TEN-007", "`%s.%s` is allowed to be empty. A row with no tenant is visible to everyone or to no one, and is easy to create by accident." % (t, col), file=d["file"], line=d["line"], snippet=d["chain"][:160], confidence="confirmed", subject={"kind": "column", "name": "%s.%s" % (t, col)},
                                fix_hint="Make the column NOT NULL with a foreign key, after backfilling existing rows."))
            elif col not in info["indexed"]:
                env.add(Finding("TEN-007", "`%s.%s` has no index. Every tenant-scoped query on this table scans all customers' rows, and it gets slower with every new customer." % (t, col), file=d["file"], line=d["line"], snippet=d["chain"][:160], confidence="confirmed", severity="medium", subject={"kind": "column", "name": "%s.%s" % (t, col)},
                                fix_hint="Add `->index()` or `->constrained()` (or a composite index starting with the tenant column)."))
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_tenancy", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
