#!/usr/bin/env python3
"""Laravel deep scanner: Laravel 11 and later, Livewire 3, Eloquent, Sanctum and Spatie permissions.

Detects: committed or debug configuration (LARA-001/002), mass assignment
(LARA-003), raw SQL built from variables (LARA-004), unescaped Blade output
(LARA-005), Sanctum tokens with every ability or no expiry (LARA-006), Livewire
properties and actions that trust the browser (LARA-007/008), Spatie roles set
from request input (LARA-009), unvalidated writes (LARA-010), client-named
uploads (LARA-011), request input reaching a command, eval or unserialize
(LARA-012), CSRF and CORS gaps (LARA-013/014), unsupported Laravel versions
(LARA-015), blanket Gate rules (LARA-016), debug packages in production
(LARA-017), routes with no rate limit (API-020) and route-bound records with no
ownership check (API-021). It also builds ``inventory.laravel_routes``: every
route with its middleware, whether it is authenticated and whether it is
throttled.

What it deliberately does not do: it does not run PHP or artisan, does not read
``vendor/``, and does not follow dynamic route registration. A route it cannot
read is skipped, not guessed.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import catalog, findings, phpflow, phpscan, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_laravel")
ALSO_EMITS = ["AUTH-002"]

GUARD_RE = re.compile(r"authorize\w*\s*\(|Gate::|->can\s*\(|->cannot\s*\(|\$this->authorizeResource|abort_if\s*\(|abort_unless\s*\(|Policy|auth\(\)->(?:id|user)\b|Auth::(?:id|user)\b|\$request->user\(\)|->user\(\)->\w+\(\)|\bhasRole\b|hasPermissionTo|->tenant\b|currentTenant|tenant\(\)")
CLASS_AUTH_RE = re.compile(r"middleware\(\s*\[?\s*['\"](?:auth|can:)|new\s+Middleware\(\s*['\"](?:auth|can:)|#\[Middleware\(\s*['\"](?:auth|can:)|authorizeResource\s*\(")
MUTATE_RE = re.compile(r"->(?:update|delete|forceDelete|save|fill|restore|attach|detach|sync|increment|decrement)\s*\(|::(?:create|destroy|insert|upsert|updateOrCreate)\s*\(|DB::table\([^)]*\)(?:->\w+\([^)]*\))*->(?:update|delete|insert)\s*\(")
EXEMPT_URI_RE = re.compile(r"(?i)login|logout|register|sign-?up|sign-?in|password|forgot|reset|verify|webhook|callback|sanctum/csrf|broadcasting|oauth|socialite|stripe|paddle|health|up$|auth/|two-factor|confirm|contact|subscribe|newsletter|unsubscribe")
SENSITIVE_URI_RE = re.compile(r"(?i)login|register|sign-?in|sign-?up|password|forgot|reset|otp|verify|token|code|2fa|two-factor|auth")
DATA_URI_RE = re.compile(r"(?i)admin|report|export|user|invoice|order|customer|payment|wallet|account|booking|tenant|project|billing")
PRIVILEGED = {"is_admin", "isadmin", "is_super_admin", "is_superadmin", "role", "roles", "role_id", "permissions", "tenant_id", "company_id", "organization_id", "team_id", "balance", "credits", "is_staff", "email_verified_at", "stripe_id", "plan", "is_paid", "is_verified"}
ENV_NAMES = re.compile(r"(^|/)\.env(\.(production|prod|staging|live))?$")
LIVEWIRE_SKIP = {"render", "mount", "boot", "booted", "hydrate", "dehydrate", "rendering", "rendered", "placeholder", "paginationView", "queryString", "rules", "messages", "validationAttributes", "updating", "updated", "title", "layout"}


def _env_value(text: str, key: str) -> Optional[str]:
    m = re.search(r"^\s*%s\s*=\s*(.*)$" % re.escape(key), text, re.M)
    return m.group(1).strip().strip("'\"") if m else None


def _env_line(text: str, key: str) -> int:
    m = re.search(r"^\s*%s\s*=" % re.escape(key), text, re.M)
    return text.count("\n", 0, m.start()) + 1 if m else 1


def _scope_traits(pf: phpscan.PhpFile) -> bool:
    return bool(re.search(r"BelongsToTenant|HasTenant|TenantScoped|BelongsToTeam|BelongsToCompany|addGlobalScope|ScopedBy|#\[ScopedBy", pf.code)) or any(re.search(r"Tenant|Scoped|Team|Company", t) for t in pf.traits)


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_laravel", stack)
    if not phpscan.is_laravel(project):
        env.inventory["laravel"] = {"detected": False}
        env.files_scanned, env.files_skipped = project.stats()
        return env
    major = phpscan.laravel_major(project)
    comp = phpscan.composer(project)
    env.inventory["laravel"] = {"detected": True, "major": major, "livewire": "livewire/livewire" in comp["require"], "sanctum": "laravel/sanctum" in comp["require"], "spatie_permission": "spatie/laravel-permission" in comp["require"]}
    pfs = [p for p in phpscan.php_files(project) if not walker.TEST_PATH_RE.search(p.rel) and not p.rel.startswith(("database/factories/", "database/seeders/"))]
    models = phpscan.model_class_names(project)
    _ct: Dict[str, Any] = {}

    def ct_of(pf: phpscan.PhpFile) -> Dict[str, Any]:
        if pf.rel not in _ct:
            _ct[pf.rel] = phpflow.class_taint(pf)
        return _ct[pf.rel]

    def add(check: str, pf: phpscan.PhpFile, offset: int, message: str, confidence: str = "likely", detail: str = "", fix: str = "", severity: Optional[str] = None, subject: Optional[Dict[str, str]] = None) -> None:
        line = pf.line(offset)
        env.add(Finding(check, message, file=pf.rel, line=line, snippet=pf.line_text(line), confidence=confidence, detail=detail, fix_hint=fix, severity=severity, subject=subject))

    # LARA-001 / LARA-002: environment files that would be committed
    for sf in project.files:
        if not ENV_NAMES.search(sf.rel) or walker.is_env_example(sf.rel):
            continue
        text = project.text(sf)
        committed = project.will_be_committed(sf.rel)
        if not committed:
            continue
        env_name = (_env_value(text, "APP_ENV") or "").lower()
        if (_env_value(text, "APP_DEBUG") or "").lower() in ("true", "1") and (env_name in ("production", "prod", "staging", "live") or re.search(r"production|prod|live", sf.name)):
            env.add(Finding("LARA-001", "`%s` turns debug mode on for a production environment. Laravel then shows stack traces, configuration and environment values to every visitor who triggers an error." % sf.rel,
                            file=sf.rel, line=_env_line(text, "APP_DEBUG"), snippet="APP_DEBUG=true", confidence="confirmed" if re.search(r"production|prod|live", sf.name) else "likely",
                            detail="APP_DEBUG=true with APP_ENV=%s in a file that is committed." % (env_name or "unset"), fix_hint="Set APP_DEBUG=false and APP_ENV=production in the host's own settings, and remove environment files from the repository."))
        key = _env_value(text, "APP_KEY") or ""
        if re.match(r"^(base64:)?[A-Za-z0-9+/=]{32,}$", key) and not re.search(r"(?i)changeme|your|example|random|placeholder|xxxx|secret", key):
            env.add(Finding("LARA-002", "`%s` contains the real application key. With it, anyone can decrypt your session cookies and forge signed data, and older Laravel versions allow code execution through it." % sf.rel,
                            file=sf.rel, line=_env_line(text, "APP_KEY"), snippet="APP_KEY=<redacted>", confidence="confirmed", detail="A 32-byte application key is stored in a committed environment file.",
                            fix_hint="Generate a new key with `php artisan key:generate`, set it only in the host's secret settings, remove the file from git, and treat the old key as leaked (all sessions will end).",
                            owner_action="Rotate APP_KEY on every environment and sign everyone out."))
    for pf in pfs:
        if pf.rel == "config/app.php":
            m = re.search(r"['\"]debug['\"]\s*=>\s*true\b", pf.code)
            if m:
                add("LARA-001", pf, m.start(), "`config/app.php` hard-codes debug mode on, so it stays on in production whatever the environment file says.", "confirmed", fix="Use `'debug' => (bool) env('APP_DEBUG', false)`.")
            m = re.search(r"['\"]key['\"]\s*=>\s*['\"]([A-Za-z0-9+/=:]{32,})['\"]", pf.code)
            if m and not re.search(r"(?i)changeme|your|example|random", m.group(1)):
                env.add(Finding("LARA-002", "`config/app.php` contains a literal application key.", file=pf.rel, line=pf.line(m.start()), snippet="'key' => <redacted>", confidence="confirmed", fix_hint="Read it with env('APP_KEY') and rotate it.", owner_action="Rotate APP_KEY."))

    # LARA-015 / LARA-017: dependencies
    if major is not None and major < 12:
        env.add(Finding("LARA-015", "This app runs Laravel %d, which no longer receives security fixes. New vulnerabilities in it will stay open." % major, file="composer.json",
                        line=1, snippet=comp["require"].get("laravel/framework", ""), confidence="confirmed" if project.exists("composer.lock") else "likely",
                        detail="Laravel 11 security support ended on 2026-03-12; Laravel 12 receives security fixes until 2027-02-24 (laravel.com/docs/releases, checked 2026-11-15).",
                        fix_hint="Upgrade to the current Laravel release with Laravel Shift or the upgrade guide, then run the tests."))
    for pkg in ("laravel/telescope", "barryvdh/laravel-debugbar", "spatie/laravel-ray", "spatie/laravel-web-tinker", "laravel/tinker"):
        if pkg in comp["require"]:
            env.add(Finding("LARA-017", "`%s` is installed as a production dependency. Debugging tools record requests, queries and data, and some give shell access, so on a live site they leak what they collect." % pkg,
                            file="composer.json", line=1, snippet='"%s": "%s"' % (pkg, comp["require"][pkg]), confidence="likely", subject={"kind": "package", "name": pkg},
                            fix_hint="Move it to require-dev (`composer require --dev %s`) and deploy with `composer install --no-dev`. If you need Telescope in production, gate it with Gate::define('viewTelescope', ...)." % pkg))

    # Model-level checks
    for pf in models.values():
        guarded = re.search(r"\$guarded\s*=\s*\[\s*\]", pf.code)
        if guarded:
            add("LARA-003", pf, guarded.start(), "`%s` accepts every field in mass assignment (`$guarded = []`). A request that adds `is_admin` or `tenant_id` can set it." % pf.class_name, "confirmed", fix="List the safe fields in `$fillable` and never include roles, balances or tenant IDs.")
        fill = pf.array_prop("fillable") or []
        bad = sorted(f for f in fill if f.lower() in PRIVILEGED)
        if bad:
            m = re.search(r"\$fillable\s*=", pf.code)
            add("LARA-003", pf, m.start() if m else 0, "`%s` lets requests set protected fields through mass assignment: %s." % (pf.class_name, ", ".join(bad)), "likely", fix="Remove %s from `$fillable` and set them in code." % ", ".join(bad))
    for pf in pfs:
        for m in re.finditer(r"\b(?:Model|Eloquent)::unguard\s*\(", pf.code):
            add("LARA-003", pf, m.start(), "Mass-assignment protection is switched off for every model (`Model::unguard()`).", "confirmed", fix="Remove the call and use `$fillable` on each model.")
        for m in re.finditer(r"->(?:create|update|fill|forceFill|firstOrCreate|updateOrCreate|insert)\s*\(\s*\$request->(?:all|input)\s*\(\s*\)\s*\)", pf.code):
            add("LARA-003", pf, m.start(), "The whole request body is written to the database with `%s`. Extra fields sent by the caller are saved too." % m.group(0).split("(")[0].strip("->"), "likely", fix="Use `$request->validated()` from a Form Request, or `$request->only([...])`.")

    # LARA-004 raw SQL with interpolation
    raw_re = re.compile(r"(?:DB::(?:select|statement|insert|update|delete|unprepared|raw)|->(?:whereRaw|orWhereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw|joinRaw|fromRaw))\s*\(")
    for pf in pfs:
        for m in raw_re.finditer(pf.bare):
            open_idx = m.end() - 1
            depth, k, first_end = 0, open_idx, None
            while k < len(pf.bare):
                ch = pf.bare[k]
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    depth -= 1
                    if depth == 0:
                        break
                elif ch == "," and depth == 1 and first_end is None:
                    first_end = k
                k += 1
            arg = pf.code[open_idx + 1:first_end if first_end else k]
            interpolated = bool(re.search(r"\"[^\"]*\$[\w{]|[\"']\s*\.\s*\$|\$\w+(?:->\w+|\[[^\]]*\])*\s*\.\s*[\"']|sprintf\s*\(|implode\s*\(", arg))
            meth = pf.method_at(m.start())
            tv = ct_of(pf).get(meth["name"], set()) if meth else set()
            via_var = False
            if not interpolated and meth and re.fullmatch(r"\s*\$\w+\s*", arg) and arg.strip() in phpflow.built_vars(meth["body"]):
                interpolated, via_var = True, True
            if interpolated:
                taint = phpflow.reaches(arg, tv) or bool(re.search(r"\$request|\$_(GET|POST|REQUEST)|request\(", arg))
                add("LARA-004", pf, m.start(), "A raw SQL string is built from a variable, so whoever controls that value can run their own SQL against your database.", ("confirmed" if taint and not via_var else "likely") if taint else "possible",
                    detail="The first argument of `%s` contains a variable instead of a `?` placeholder." % m.group(0).strip("( ").strip(">-"), fix="Pass values as bindings: `whereRaw('name like ?', [\"%$q%\"])`, or use the query builder.")

    # Blade: LARA-005 and Volt components
    safe = re.compile(r"\$slot|\$attributes|->links\(|->render\(|->toHtml\(|json_encode|csrf_field|method_field|\$errors|vite\(|Js::from|htmlspecialchars|\be\(|__\(|trans\(|trans_choice\(|->withQueryString|\$paginator|<\?|\bviteReactRefresh|Vite::")
    for sf in project.files:
        if not sf.rel.endswith(".blade.php"):
            continue
        text = project.text(sf)
        for m in re.finditer(r"\{!!\s*(.+?)\s*!!\}", text, re.S):
            expr = m.group(1)
            if "$" in expr and not safe.search(expr):
                line = text.count("\n", 0, m.start()) + 1
                env.add(Finding("LARA-005", "`%s` prints `%s` without escaping. If that value contains anything a user typed, their script runs in other visitors' browsers." % (sf.rel, " ".join(expr.split())[:60]),
                                file=sf.rel, line=line, snippet=text.splitlines()[line - 1].strip(), confidence="likely", fix_hint="Use `{{ $value }}` so Laravel escapes it. If you need HTML, sanitise it first with a library such as HTML Purifier."))

    # Sanctum
    for pf in pfs:
        for m in re.finditer(r"->createToken\s*\(([^;]*)\)", pf.code):
            args = m.group(1)
            if re.search(r"\[\s*['\"]\*['\"]\s*\]", args) or not re.search(r",\s*\[", args):
                add("LARA-006", pf, m.start(), "An API token is created with every ability (the default is `*`), so a leaked token can do everything its owner can.", "likely" if "," not in args else "confirmed", fix="Pass a narrow list: `createToken('app', ['invoices:read'], now()->addDays(30))` and check abilities with `tokenCan`.")
        if pf.rel == "config/sanctum.php" and re.search(r"['\"]expiration['\"]\s*=>\s*null", pf.code):
            m = re.search(r"['\"]expiration['\"]\s*=>\s*null", pf.code)
            add("LARA-006", pf, m.start() if m else 0, "Sanctum tokens never expire (`'expiration' => null`). A token stolen today works for ever.", "confirmed", fix="Set an expiry in minutes, for example `'expiration' => 60 * 24 * 30`, and prune expired tokens with `sanctum:prune-expired`.")

    # Livewire components (classes and Volt)
    lw_sources: List[Any] = []
    for pf in pfs:
        if re.search(r"\bextends\s+(?:\\?[\w\\]*\\)?Component\b", pf.bare) and ("Livewire" in pf.raw[:2000] or "/Livewire/" in pf.rel):
            lw_sources.append(pf)
    for sf in project.files:
        if sf.rel.endswith(".blade.php") and re.search(r"Livewire\\Volt|new\s+class\s+extends\s+Component", project.text(sf)):
            lw_sources.append(phpscan.PhpFile(sf, project.text(sf)))
    for pf in lw_sources:
        lines = pf.raw.splitlines()
        for m in re.finditer(r"^[ \t]*public\s+(?:\??(?:int|string|float)\s+)?\$(\w+)\b", pf.code, re.M):
            name = m.group(1)
            if not re.search(r"(?i)(^id$|[a-z]Id$|_id$)", name):
                continue
            ln = pf.line(m.start())
            prev = " ".join(lines[max(0, ln - 3):ln - 1])
            if "Locked" in prev or "Locked" in lines[ln - 1]:
                continue
            high = bool(re.search(r"(?i)^(user|tenant|company|team|owner|org|account)", name))
            add("LARA-007", pf, m.start(), "The Livewire property `$%s` is sent to the browser and back on every action, so a user can change it to another record's ID and act on that record." % name, "confirmed" if high else "likely",
                fix="Mark it `#[Locked]`, or load the record in `mount()` from the route and authorise it with `$this->authorize()`.")
        class_has_auth = bool(re.search(r"#\[Authorize|\$this->authorize|Gate::", pf.code[: pf.code.find("function render")] if "function render" in pf.code else ""))
        for meth in pf.methods():
            if meth["vis"] != "public" or meth["name"] in LIVEWIRE_SKIP or meth["name"].startswith(("__", "updated", "updating", "render")) or not MUTATE_RE.search(meth["body"]):
                continue
            if GUARD_RE.search(meth["body"]):
                continue
            add("LARA-008", pf, meth["start"], "The Livewire action `%s()` changes data and never checks that the current user may. Livewire actions can be called directly by anyone who can load the page." % meth["name"], "likely",
                subject={"kind": "livewire-action", "name": pf.rel + "::" + meth["name"]}, fix="Call `$this->authorize('update', $model)` (or Gate::authorize) at the top of the action and load the record scoped to the current user.")

    # Spatie roles from input, commands from input, uploads, validation
    taint_src = re.compile(r"\$request->|\brequest\s*\(|\$_(?:GET|POST|REQUEST|COOKIE)|\binput\s*\(")
    for pf in pfs:
        for meth in pf.methods():
            body = meth["body"]
            tainted = ct_of(pf).get(meth["name"], set())
            for m in re.finditer(r"->(?:assignRole|syncRoles|givePermissionTo|syncPermissions)\s*\(([^;]*)\)\s*;", body):
                a = m.group(1)
                if phpflow.reaches(a, tainted) and not re.search(r"authorize\w*\s*\(|Gate::|hasRole|hasPermissionTo|->can\s*\(|hasAnyRole", body):
                    add("LARA-009", pf, meth["body_start"] + m.start(), "A role or permission is handed out from request input with no check that the caller may do that. Any signed-in user can make themselves an administrator.", "likely",
                        subject={"kind": "method", "name": pf.rel + "::" + meth["name"]}, fix="Authorise the caller (`$this->authorize('assign-roles')`) and validate the role against a fixed list with `Rule::in([...])`.")
            for m in re.finditer(r"\b(shell_exec|exec|system|passthru|proc_open|popen|eval|unserialize|assert|Process::fromShellCommandline|Process::run)\s*\(([^;]*)\)", body):
                a = m.group(2)
                if taint_src.search(a) or any(re.search(re.escape(t) + r"\b", a) for t in tainted):
                    add("LARA-012", pf, meth["body_start"] + m.start(), "Request input reaches `%s()`. An attacker can run commands on your server or trigger code execution through crafted data." % m.group(1), "confirmed" if taint_src.search(a) else "likely",
                        fix="Never build commands or serialized data from input. Use `escapeshellarg` only as a last resort, prefer a library call, and use `json_decode` instead of `unserialize`.")
            for m in re.finditer(r"(\$\w+)\s*=\s*[^;]*->getClientOriginal(?:Name|Extension)\s*\(", body):
                var = m.group(1)
                if re.search(r"(?:storeAs|putFileAs|move|put)\s*\([^;]*" + re.escape(var) + r"\b", body):
                    add("LARA-011", pf, meth["body_start"] + m.start(), "An uploaded file is saved under the name or extension the uploader chose. A file called `shell.php` or `../../x` can end up where the server will run or serve it.", "likely", fix="Store with `->store('dir')` (Laravel picks a safe random name) and validate with `mimes:` and `max:`.")
            for m in re.finditer(r"(?:storeAs|putFileAs|move)\s*\([^;]*getClientOriginal(?:Name|Extension)\s*\(", body):
                add("LARA-011", pf, meth["body_start"] + m.start(), "An uploaded file is saved under the name or extension the uploader chose. A file called `shell.php` or `../../x` can end up where the server will run or serve it.", "confirmed", fix="Store with `->store('dir')` (Laravel picks a safe random name) and validate with `mimes:` and `max:`.")
            if "/Http/Controllers/" in pf.rel and meth["vis"] == "public" and re.search(r"\bRequest\s+\$request\b", meth["params"]) and not meth["name"].startswith("__"):
                writes = re.search(r"::create\s*\(|->(?:update|fill|save|insert|create|updateOrCreate)\s*\(|::insert\s*\(", meth["body"])
                uses = re.search(r"\$request->(?:all|input|only|except|post|get|query|\w+)\b", meth["body"])
                valid = re.search(r"validate\w*\s*\(|validated\s*\(|Validator::make|\$this->validate|safe\s*\(", meth["body"])
                if writes and uses and not valid:
                    add("LARA-010", pf, meth["start"], "`%s::%s()` saves data from the request without validating it. Wrong types, huge values and unexpected fields go straight to the database." % (pf.class_name, meth["name"]), "likely",
                        subject={"kind": "method", "name": pf.rel + "::" + meth["name"]}, fix="Create a Form Request (`php artisan make:request`) with rules and use `$request->validated()`.")

    # Gate rules, CSRF, CORS
    for pf in pfs:
        for m in re.finditer(r"Gate::(?:before|after)\s*\(\s*(?:static\s+)?(?:function|fn)\s*\([^)]*\)\s*(?:use\s*\([^)]*\)\s*)?(?::\s*\??\w+\s*)?(?:=>\s*true\b|\{\s*return\s+true\s*;)|Gate::define\s*\(\s*['\"][^'\"]+['\"]\s*,\s*(?:static\s+)?(?:fn\s*\([^)]*\)\s*=>\s*true\b|function\s*\([^)]*\)\s*\{\s*return\s+true\s*;)", pf.code):
            add("LARA-016", pf, m.start(), "A Gate rule always answers yes, so every signed-in user (or everyone, for `before`) passes every permission check in the app.", "confirmed", fix="Return true only for a specific super-admin check and `null` otherwise, so normal policies still run.")
        if pf.rel in ("bootstrap/app.php",) or pf.rel.endswith("VerifyCsrfToken.php"):
            for m in re.finditer(r"(?:validateCsrfTokens\s*\(\s*except\s*:\s*|\$except\s*=\s*)\[([^\]]*)\]", pf.code):
                if re.search(r"['\"]/?\*['\"]", m.group(1)):
                    add("LARA-013", pf, m.start(), "CSRF protection is switched off for every route (`*`). Another website can make a signed-in visitor's browser submit forms on your app.", "confirmed", fix="Exempt only the specific webhook paths that cannot send a token, and verify those with a signature.")
        if pf.rel == "config/cors.php":
            origins = re.search(r"['\"]allowed_origins['\"]\s*=>\s*\[([^\]]*)\]", pf.code)
            cred = re.search(r"['\"]supports_credentials['\"]\s*=>\s*true", pf.code)
            if origins and re.search(r"['\"]\*['\"]", origins.group(1)) and cred:
                add("LARA-014", pf, origins.start(), "Any website may call your API from a visitor's browser with their cookies attached (`allowed_origins ['*']` with credentials).", "confirmed", fix="List your real front-end origins in `allowed_origins`.")

    # Routes: inventory, AUTH-002, API-020, API-021
    routes = phpscan.route_inventory(project)
    env.inventory["laravel_routes"] = [{k: r[k] for k in ("method", "uri", "middleware", "auth", "throttle", "controller", "action", "file", "line")} for r in routes]
    global_throttle = any(re.search(r"throttleApi\s*\(|throttle:api|ThrottleRequests|RateLimiter::for\(\s*['\"]api", p.code) for p in pfs if p.rel in ("bootstrap/app.php", "app/Http/Kernel.php", "app/Providers/RouteServiceProvider.php", "app/Providers/AppServiceProvider.php")) \
        and any(re.search(r"throttleApi\s*\(|'api'\s*=>\s*\[[^\]]*throttle:api|\$middleware->api\([^)]*throttle", p.code) for p in pfs if p.rel in ("bootstrap/app.php", "app/Http/Kernel.php"))
    login_limited = any(re.search(r"RateLimiter::(?:tooManyAttempts|hit)|RateLimiter::for\(\s*['\"]login|Fortify::|ThrottlesLogins", p.code) for p in pfs)
    by_file = {p.rel: p for p in pfs}

    def handler(r: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        cf = phpscan.controller_file(project, r["controller"])
        if not cf:
            return None
        for m in cf.methods():
            if m["name"] == r["action"]:
                return {"file": cf, "method": m}
        return None

    class_auth: Dict[str, bool] = {}
    for r in routes:
        pf = by_file.get(r["file"])
        h = handler(r) if r["controller"] else None
        cf_name = r["controller"]
        if h and cf_name not in class_auth:
            class_auth[cf_name] = bool(CLASS_AUTH_RE.search(h["file"].code))
        authed = r["auth"] or class_auth.get(cf_name, False) or "guest" in [m.lower() for m in r["middleware"]]
        uri = r["uri"]
        if pf is None:
            continue
        verb = r["method"].lower()
        guard_in_body = False
        if h:
            guard_in_body = bool(re.search(r"auth\(\)|Auth::|\$request->user\(\)|authorize\w*\(|Gate::|abort_(?:if|unless)", h["method"]["body"]))
        elif r["closure"]:
            guard_in_body = bool(re.search(r"auth\(\)|Auth::|\$request->user\(\)|authorize\w*\(|Gate::", r["snippet"]))
        if not authed and not guard_in_body and not EXEMPT_URI_RE.search(uri):
            body = h["method"]["body"] if h else r["snippet"]
            returns_data = bool(re.search(r"::(?:all|paginate|get|find|findOrFail|where|query|with)\s*\(|->get\s*\(|->paginate\s*\(|->first\s*\(", body))
            if verb in phpscan.WRITE_VERBS and (h is None or MUTATE_RE.search(body) or returns_data) or (verb == "get" and returns_data and (uri.startswith("/api") or DATA_URI_RE.search(uri))):
                env.add(Finding("AUTH-002", "Anyone on the internet can call `%s %s`. It %s and the route has no `auth` middleware." % (r["method"], uri, "changes data" if verb in phpscan.WRITE_VERBS else "returns data"),
                                file=r["file"], line=r["line"], snippet=r["snippet"], confidence="likely", subject={"kind": "route", "name": "%s %s" % (r["method"], uri)},
                                detail="No `auth`, `auth:sanctum` or `can:` middleware on the route or its groups, and no authorisation call in the handler.", fix_hint="Wrap the route in `Route::middleware('auth:sanctum')->group(...)` and check ownership in the handler."))
        # API-020
        if r["throttle"] or global_throttle:
            continue
        sensitive = bool(SENSITIVE_URI_RE.search(uri))
        if verb in phpscan.WRITE_VERBS and sensitive and not (login_limited and re.search(r"(?i)login|sign-?in", uri)):
            env.add(Finding("API-020", "`%s %s` has no rate limit, so someone can try thousands of passwords or codes against it." % (r["method"], uri), file=r["file"], line=r["line"], snippet=r["snippet"], confidence="likely",
                            subject={"kind": "route", "name": "%s %s" % (r["method"], uri)}, fix_hint="Add `->middleware('throttle:5,1')` or a named limiter (`RateLimiter::for`) keyed by IP and email."))
    unthrottled_writes = [r for r in routes if r["method"].lower() in phpscan.WRITE_VERBS and not r["throttle"] and not SENSITIVE_URI_RE.search(r["uri"])]
    if unthrottled_writes and not global_throttle and not any(f.check_id == "API-020" for f in env.findings):
        first = unthrottled_writes[0]
        env.add(Finding("API-020", "None of the %d routes that change data has a rate limit, and Laravel does not add one by itself (`throttleApi()` is not enabled)." % len(unthrottled_writes), file=first["file"], line=first["line"], snippet=first["snippet"], confidence="possible", severity="medium",
                        subject={"kind": "project", "name": "laravel-throttle"}, fix_hint="Call `$middleware->throttleApi()` in bootstrap/app.php or add `throttle:` middleware to route groups."))

    # API-021 ownership
    seen = set()
    for r in routes:
        if "{" not in r["uri"] or not r["controller"] or (r["controller"], r["action"]) in seen:
            continue
        seen.add((r["controller"], r["action"]))
        h = handler(r)
        if not h:
            continue
        cf, m = h["file"], h["method"]
        if r["method"] == "GET" and False:
            continue
        param_models = [t for t in re.findall(r"\b([A-Z]\w+)\s+\$\w+", m["params"]) if t in models]
        by_id = bool(re.search(r"\$id\b|\$\w*[iI]d\b", m["params"])) or bool(re.search(r"::(?:find|findOrFail|firstOrFail)\s*\(\s*\$request->", m["body"]))
        if not (param_models or by_id):
            continue
        if not (MUTATE_RE.search(m["body"]) or re.search(r"\breturn\b", m["body"])):
            continue
        if GUARD_RE.search(m["body"]) or CLASS_AUTH_RE.search(cf.code) or any(x.startswith("can:") for x in r["middleware"]):
            continue
        if param_models and all(_scope_traits(models[t]) for t in param_models):
            continue
        env.add(Finding("API-021", "`%s::%s()` works on a record picked by its ID in the URL and never checks that it belongs to the caller. Any signed-in user can read or change other people's records by changing the number." % (cf.class_name, m["name"]),
                        file=cf.rel, line=m["line"], snippet=cf.line_text(m["line"]), confidence="likely", subject={"kind": "route", "name": "%s %s" % (r["method"], r["uri"])},
                        detail="Route `%s %s` binds `%s` and the handler has no authorize(), policy, Gate or owner filter." % (r["method"], r["uri"], ", ".join(param_models) or "an ID"),
                        fix_hint="Create a policy (`php artisan make:policy`) and call `$this->authorize('view', $record)`, or load the record through the user: `$request->user()->invoices()->findOrFail($id)`."))
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_laravel", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
