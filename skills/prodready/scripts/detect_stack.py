#!/usr/bin/env python3
"""Detect what an app is built with: framework, backend, database, auth, payments,
AI providers, hosting, and which AI builder produced it.

Sources, in order of reliability: manifests and lockfiles, config files,
directory conventions, then imports in source files. The result tells the
other scanners which checks apply and tells the reviewer which playbooks to
read.

What it deliberately does not do: it does not install or run anything, it does
not contact any registry, and it does not guess a component it has no evidence
for. Low-confidence guesses are labelled so the reviewer looks for themselves.
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Set

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import findings, patterns, walker  # noqa: E402

IMPLEMENTS: List[str] = []
ALSO_EMITS: List[str] = []

_SIGNALS: Dict[str, str] = {
    "supabase-auth": r"\.auth\.(?:signIn\w*|signUp|getUser|getSession|getClaims|onAuthStateChange|signOut)\(",
    "supabase-storage": r"\.storage\s*\.from\(",
    "supabase-realtime": r"postgres_changes|\.channel\(",
    "supabase-client": r"@supabase/supabase-js|@supabase/ssr|esm\.sh/@supabase",
    "firebase-auth": r"firebase/auth|getAuth\(|firebase\.auth\(",
    "firebase-firestore": r"firebase/firestore|getFirestore\(|\.firestore\(\)",
    "firebase-rtdb": r"firebase/database|getDatabase\(",
    "firebase-storage": r"firebase/storage|getStorage\(",
    "firebase-admin": r"firebase-admin",
    "s3": r"@aws-sdk/client-s3|\bS3Client\b",
    "resend-host": r"api\.resend\.com",
    "sendgrid-host": r"api\.sendgrid\.com",
    "gtag": r"googletagmanager\.com|gtag\(",
    "facebook-pixel": r"connect\.facebook\.net|fbq\(",
    "hotjar": r"static\.hotjar\.com|hotjar",
    "clarity": r"clarity\.ms",
    "plausible": r"plausible\.io",
    "custom-error-reporting": r"\bonRequestError\b|captureException\(|reportError\(",
    "jwt-custom": r"jsonwebtoken|\bjose\b|import\s+jwt\b|PyJWT",
    "stripe-host": r"api\.stripe\.com|js\.stripe\.com",
    "expo-api": r"\+api\.[jt]s",
}

_ANALYTICS_PKGS = {
    "posthog-js": "posthog", "posthog-node": "posthog", "@vercel/analytics": "vercel-analytics", "mixpanel-browser": "mixpanel",
    "@segment/analytics-next": "segment", "@amplitude/analytics-browser": "amplitude", "plausible-tracker": "plausible",
    "react-ga4": "google-analytics", "logrocket": "logrocket", "@fullstory/browser": "fullstory", "@hotjar/browser": "hotjar",
    "@microsoft/clarity": "clarity", "smartlook-client": "smartlook",
}
_ERROR_PKGS = {
    "@sentry/": "sentry", "sentry-sdk": "sentry", "@bugsnag/": "bugsnag", "bugsnag": "bugsnag", "rollbar": "rollbar",
    "@honeybadger-io/": "honeybadger", "@highlight-run/": "highlight", "@datadog/browser-rum": "datadog", "dd-trace": "datadog",
    "newrelic": "newrelic", "@appsignal/": "appsignal", "@rollbar/": "rollbar", "raygun": "raygun", "@logtail/": "logtail",
    "@axiomhq/": "axiom",
}
_EMAIL_PKGS = {
    "resend": "resend", "@sendgrid/mail": "sendgrid", "nodemailer": "nodemailer", "postmark": "postmark", "mailgun.js": "mailgun",
    "@aws-sdk/client-ses": "ses", "@react-email/components": "react-email", "twilio": "twilio", "sendgrid": "sendgrid",
    "@mailchimp/mailchimp_transactional": "mandrill", "loops": "loops",
}
_PAYMENT_PKGS = {
    "stripe": "stripe", "@stripe/stripe-js": "stripe", "@stripe/react-stripe-js": "stripe", "@paddle/paddle-js": "paddle",
    "@paddle/paddle-node-sdk": "paddle", "@lemonsqueezy/lemonsqueezy.js": "lemonsqueezy", "@paypal/checkout-server-sdk": "paypal",
    "@paypal/react-paypal-js": "paypal", "razorpay": "razorpay", "@polar-sh/sdk": "polar", "paddle-sdk": "paddle",
}
_AUTH_PKGS = {
    "@clerk/": "clerk", "next-auth": "authjs", "@auth/": "authjs", "better-auth": "better-auth", "@auth0/": "auth0", "auth0": "auth0",
    "lucia": "lucia", "passport": "passport", "@kinde-oss/": "kinde", "@workos-inc/": "workos", "express-session": "express-session",
    "iron-session": "iron-session", "flask-login": "flask-login", "djangorestframework-simplejwt": "custom-jwt",
}
_ORM_PKGS = {
    "@prisma/client": "prisma", "prisma": "prisma", "drizzle-orm": "drizzle", "mongoose": "mongoose", "typeorm": "typeorm",
    "sequelize": "sequelize", "kysely": "kysely", "knex": "knex", "sqlalchemy": "sqlalchemy", "@mikro-orm/core": "mikro-orm",
}
_TEST_PKGS = {"vitest": "vitest", "jest": "jest", "mocha": "mocha", "@playwright/test": "playwright", "cypress": "cypress", "ava": "ava", "pytest": "pytest"}


def _entry(name: str, **extra: Any) -> Dict[str, Any]:
    d: Dict[str, Any] = {"name": name}
    d.update(extra)
    return d


def _clean_version(spec: str) -> Optional[str]:
    m = re.search(r"(\d+(?:\.\d+){0,2})", spec or "")
    return m.group(1) if m else None


def _pkg_match(deps: Dict[str, str], table: Dict[str, str]) -> List[str]:
    out: List[str] = []
    for prefix, label in table.items():
        for dep in deps:
            if dep == prefix or (prefix.endswith("/") and dep.startswith(prefix)):
                if label not in out:
                    out.append(label)
    return out


def _git_info(root: str) -> Dict[str, Any]:
    git_dir = os.path.join(root, ".git")
    info: Dict[str, Any] = {"is_repo": os.path.exists(git_dir), "has_remote": False, "default_branch": None, "remote_host": None}
    if not os.path.isdir(git_dir):
        return info
    try:
        with open(os.path.join(git_dir, "config"), "r", encoding="utf-8", errors="replace") as fh:
            cfg = fh.read()
        m = re.search(r"\[remote \"[^\"]+\"\][^\[]*?url\s*=\s*(\S+)", cfg)
        if m:
            info["has_remote"] = True
            hm = re.search(r"(?:@|//)([\w.-]+)[:/]", m.group(1))
            info["remote_host"] = hm.group(1) if hm else None
        with open(os.path.join(git_dir, "HEAD"), "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read().strip()
        bm = re.match(r"ref: refs/heads/(.+)", head)
        info["default_branch"] = bm.group(1) if bm else None
    except OSError:
        pass
    return info


def _workspaces(project: walker.Project) -> List[str]:
    pats: List[str] = []
    ws = project.package.get("workspaces")
    if isinstance(ws, list):
        pats.extend(str(p) for p in ws)
    elif isinstance(ws, dict) and isinstance(ws.get("packages"), list):
        pats.extend(str(p) for p in ws["packages"])
    for line in project.read("pnpm-workspace.yaml").splitlines():
        m = re.match(r"\s*-\s*[\"']?([^\"'#]+?)[\"']?\s*$", line)
        if m:
            pats.append(m.group(1))
    roots: List[str] = []
    paths = project.all_paths()
    for pat in pats:
        base = pat.rstrip("/*").rstrip("/")
        for p in paths:
            if p.endswith("/package.json") and (p.startswith(base + "/") or p == base + "/package.json"):
                d = p.rsplit("/", 1)[0]
                depth_ok = d == base or d.count("/") == base.count("/") + 1 or "**" in pat
                if depth_ok and d not in roots:
                    roots.append(d)
    return sorted(roots)


def _scan_signals(project: walker.Project) -> Dict[str, List[str]]:
    """One pass over source files: which signals appear, and in which kinds of file."""
    compiled = {k: re.compile(v) for k, v in _SIGNALS.items()}
    hits: Dict[str, List[str]] = {}
    llm_where: Set[str] = set()
    llm_hosts: Set[str] = set()
    for sf in project.files:
        if sf.ext not in walker.CODE_EXTS and sf.ext != ".html":
            continue
        text = project.text(sf)
        if not text or sf.minified:
            continue
        for key, rx in compiled.items():
            if rx.search(text):
                hits.setdefault(key, []).append(sf.rel)
        if patterns.LLM_CALL_RE.search(text):
            kind = project.classify(sf)
            if kind != "test":
                llm_where.add("client" if kind == "client" else "server")
                hm = patterns.LLM_HOST_RE.search(text)
                if hm:
                    llm_hosts.add(hm.group(0))
    hits["__llm_where"] = sorted(llm_where)
    hits["__llm_hosts"] = sorted(llm_hosts)
    return hits


def detect_builder(project: walker.Project, deps: Dict[str, str]) -> Dict[str, Any]:
    ev: List[str] = []
    name = None
    confidence = "low"
    vite_cfg = "".join(project.read(p) for p in ("vite.config.ts", "vite.config.js", "vite.config.mts"))
    index_html = project.read("index.html")
    readme = project.read("README.md")
    paths = project.all_paths()
    if "lovable-tagger" in deps or "lovable-tagger" in vite_cfg:
        ev.append("lovable-tagger in the Vite config or dev dependencies")
    if "gptengineer.js" in index_html or "lovable.dev" in index_html:
        ev.append("Lovable script or metadata in index.html")
    if re.search(r"(?i)welcome to your lovable project|lovable\.dev/projects", readme):
        ev.append("Lovable default README")
    if ev:
        name, confidence = "lovable", "high" if len(ev) > 1 or "lovable-tagger" in deps else "medium"
    if not name and any(p.startswith(".bolt/") for p in paths):
        name, confidence = "bolt", "high"
        ev.append(".bolt/ directory")
    if not name and (re.search(r"(?i)bolt\.new|made with bolt|built with bolt", index_html + readme)):
        name, confidence = "bolt", "medium"
        ev.append("Bolt badge or link")
    if not name:
        pkg_name = str(project.package.get("name", ""))
        if re.search(r"(?i)^my-v0-project$|^v0-", pkg_name) or re.search(r"(?i)built with v0|v0\.dev|v0\.app|synced with your v0", readme) or re.search(r"generator:\s*[\"']v0", project.read("app/layout.tsx")):
            name, confidence = "v0", "medium"
            ev.append("v0 project name, README text or layout metadata")
    if not name and (project.exists(".replit") or project.exists("replit.nix") or any(d.startswith("@replit/") for d in deps)):
        name, confidence = "replit", "high"
        ev.append(".replit or replit.nix or @replit packages")
    if not name and any(p.startswith(".idx/") for p in paths):
        name, confidence = "firebase-studio", "high"
        ev.append(".idx/ workspace directory")
    agents: List[str] = []
    for marker, label in ((".cursorrules", "cursor"), (".windsurfrules", "windsurf"), ("CLAUDE.md", "claude-code"), ("AGENTS.md", "agents-md"), (".github/copilot-instructions.md", "copilot")):
        if project.exists(marker):
            agents.append(label)
    if any(p.startswith(".cursor/") for p in paths) and "cursor" not in agents:
        agents.append("cursor")
    if any(p.startswith(".claude/") for p in paths) and "claude-code" not in agents:
        agents.append("claude-code")
    if not name and agents:
        name, confidence = "ide-agent", "medium"
        ev.append("agent instruction files: " + ", ".join(agents))
    return {"name": name, "confidence": confidence if name else None, "evidence": ev, "agents": agents}


def summarise_root(project: walker.Project) -> Dict[str, Any]:
    deps = project.deps
    pydeps = project.python_deps
    alldeps = dict(deps)
    alldeps.update({k: v for k, v in pydeps.items() if k not in alldeps})
    paths = project.all_paths()
    sig = _scan_signals(project)
    notes: List[str] = []

    fw = project._guess_framework()
    fw_pkg = {"nextjs": "next", "vite-react": "vite", "vite-vue": "vite", "vite-svelte": "vite", "vite": "vite", "cra": "react-scripts", "sveltekit": "@sveltejs/kit", "nestjs": "@nestjs/core", "remix": "@remix-run/react", "angular": "@angular/core"}.get(fw, fw)
    version = _clean_version(deps.get(fw_pkg, "") or pydeps.get(fw, ""))
    comp: Dict[str, Any] = {"require": {}, "dev": {}}
    if fw == "laravel":
        from lib import phpscan
        comp = phpscan.composer(project)
        major = phpscan.laravel_major(project)
        version = str(major) if major else _clean_version(comp["require"].get("laravel/framework", ""))
    router = None
    if fw == "nextjs":
        has_app = any(re.match(r"(src/)?app/.*\.(tsx|jsx|ts|js)$", p) for p in paths)
        has_pages = any(re.match(r"(src/)?pages/.*\.(tsx|jsx|ts|js)$", p) for p in paths)
        router = "app" if has_app and not has_pages else "pages" if has_pages and not has_app else "app+pages" if has_app else None
    framework = {"name": fw, "version": version, "router": router, "confidence": "high" if fw != "unknown" else "low"}

    rendering = {
        "nextjs": ["server", "client"], "nuxt": ["server", "client"], "sveltekit": ["server", "client"], "remix": ["server", "client"],
        "astro": ["server", "client"], "express": ["server"], "fastify": ["server"], "hono": ["server"], "koa": ["server"],
        "nestjs": ["server"], "laravel": ["server"], "django": ["server"], "flask": ["server"], "fastapi": ["server"],
    }.get(fw, ["client"] if fw != "unknown" else [])

    languages: List[str] = []
    if project.exists("tsconfig.json") or any(p.endswith((".ts", ".tsx")) for p in paths):
        languages.append("typescript")
    if any(p.endswith((".js", ".jsx", ".mjs", ".cjs")) for p in paths):
        languages.append("javascript")
    if any(p.endswith(".py") for p in paths):
        languages.append("python")
    if any(p.endswith(".dart") for p in paths):
        languages.append("dart")
    if any(p.endswith(".php") for p in paths) or project.exists("composer.json"):
        languages.append("php")
    if any(p.endswith(".sql") for p in paths):
        languages.append("sql")

    pm = None
    for lock, label in (("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn"), ("bun.lockb", "bun"), ("bun.lock", "bun"), ("package-lock.json", "npm")):
        if project.exists(lock):
            pm = label
            break
    if pm is None and project.exists("package.json"):
        pm = "npm"
    if pm is None and (pydeps or project.exists("pyproject.toml")):
        pm = "poetry" if project.exists("poetry.lock") else "uv" if project.exists("uv.lock") else "pip"

    uses_supabase = any(d.startswith("@supabase/") for d in deps) or "supabase" in pydeps or "supabase-client" in sig or any(p.startswith("supabase/") for p in paths)
    uses_firebase = "firebase" in deps or "firebase-admin" in deps or "firebase-admin" in pydeps or project.exists("firebase.json") or project.exists("firestore.rules") or "@react-native-firebase/app" in deps

    backend: List[Dict[str, Any]] = []
    database: List[Dict[str, Any]] = []
    storage: List[Dict[str, Any]] = []
    auth: List[Dict[str, Any]] = []
    if uses_supabase:
        backend.append(_entry("supabase", confidence="high"))
        access: List[str] = []
        for rel in sig.get("supabase-client", []):
            sf = project.get(rel)
            kind = project.classify(sf) if sf else "shared"
            label = "client-sdk" if kind == "client" else "server-sdk"
            if label not in access:
                access.append(label)
        migrations = "supabase/migrations" if any(p.startswith("supabase/migrations/") for p in paths) else None
        database.append(_entry("supabase-postgres", access=sorted(access), migrations=migrations))
        if "supabase-storage" in sig or any("storage.buckets" in project.read(p) for p in paths if p.endswith(".sql")):
            storage.append(_entry("supabase-storage"))
        if "supabase-auth" in sig or "auth.users" in "".join(project.read(p) for p in paths if p.endswith(".sql"))[:200000]:
            auth.append(_entry("supabase-auth"))
        if any(p.startswith("supabase/functions/") for p in paths):
            backend.append(_entry("supabase-edge-functions", confidence="high"))
    if uses_firebase:
        backend.append(_entry("firebase", confidence="high"))
        if "firebase-firestore" in sig or project.exists("firestore.rules"):
            database.append(_entry("firebase-firestore", access=["client-sdk"], rules="firestore.rules" if project.exists("firestore.rules") else None))
        if "firebase-rtdb" in sig or project.exists("database.rules.json"):
            database.append(_entry("firebase-realtime-database", access=["client-sdk"], rules="database.rules.json" if project.exists("database.rules.json") else None))
        if "firebase-storage" in sig or project.exists("storage.rules"):
            storage.append(_entry("firebase-storage"))
        if "firebase-auth" in sig:
            auth.append(_entry("firebase-auth"))
        if any(p.startswith("functions/") for p in paths) and ("firebase-functions" in project.read("functions/package.json") or "firebase-functions" in deps):
            backend.append(_entry("firebase-functions", confidence="high"))
    if fw == "nextjs" and any(re.search(r"(^|/)(app/.*/route|pages/api/.*)\.[jt]sx?$", p) for p in paths):
        backend.append(_entry("next-route-handlers", confidence="high"))
    if fw == "laravel":
        extras = {k.split("/")[-1]: v for k, v in comp["require"].items() if k in ("livewire/livewire", "laravel/sanctum", "spatie/laravel-permission", "laravel/fortify", "laravel/breeze", "laravel/jetstream", "laravel/passport", "stancl/tenancy", "laravel/cashier", "laravel/horizon", "laravel/octane", "laravel/telescope")}
        backend.append(_entry("laravel", confidence="high", packages=sorted(extras)))
        for pkg, label in (("laravel/sanctum", "laravel-sanctum"), ("laravel/passport", "laravel-passport"), ("laravel/fortify", "laravel-fortify"), ("laravel/breeze", "laravel-breeze"), ("laravel/jetstream", "laravel-jetstream")):
            if pkg in comp["require"]:
                auth.append(_entry(label))
        if "laravel/cashier" in comp["require"]:
            pass
    if fw in ("express", "fastify", "hono", "koa", "nestjs", "django", "flask", "fastapi"):
        backend.append(_entry(fw, confidence="high"))
    elif any(k in deps for k in ("express", "fastify", "hono", "koa")):
        backend.append(_entry(next(k for k in ("express", "fastify", "hono", "koa") if k in deps), confidence="medium"))
    if any(p.startswith("netlify/functions/") for p in paths):
        backend.append(_entry("netlify-functions", confidence="high"))

    orms = _pkg_match(alldeps, _ORM_PKGS)
    orm = orms[0] if orms else None
    if "mongoose" in deps or "mongodb" in deps or "pymongo" in pydeps:
        database.append(_entry("mongodb", access=["server-sdk"]))
    prisma_schema = project.read("prisma/schema.prisma")
    pm_provider = re.search(r"provider\s*=\s*\"(postgresql|mysql|sqlite|mongodb|sqlserver|cockroachdb)\"", prisma_schema)
    if pm_provider and not uses_supabase:
        database.append(_entry(pm_provider.group(1).replace("postgresql", "postgres"), access=["server-sdk"], migrations="prisma/migrations" if any(p.startswith("prisma/migrations/") for p in paths) else None))
    elif any(k in deps for k in ("pg", "postgres", "@neondatabase/serverless", "@vercel/postgres")) and not uses_supabase and not pm_provider:
        database.append(_entry("postgres", access=["server-sdk"]))
    elif any(k in deps for k in ("mysql2", "@planetscale/database")):
        database.append(_entry("mysql", access=["server-sdk"]))
    if "psycopg2" in pydeps or "psycopg2-binary" in pydeps or "asyncpg" in pydeps or "psycopg" in pydeps:
        database.append(_entry("postgres", access=["server-sdk"]))
    if "convex" in deps:
        backend.append(_entry("convex", confidence="high"))
        database.append(_entry("convex", access=["client-sdk"]))

    for label in _pkg_match(alldeps, _AUTH_PKGS):
        auth.append(_entry(label))
    if "jwt-custom" in sig and not any(a["name"] in ("clerk", "authjs", "better-auth", "auth0", "supabase-auth", "firebase-auth") for a in auth):
        if any(k in alldeps for k in ("jsonwebtoken", "jose", "pyjwt", "python-jose")):
            auth.append(_entry("custom-jwt"))

    payments = [_entry(n) for n in _pkg_match(alldeps, _PAYMENT_PKGS)]
    if not payments and "stripe-host" in sig:
        payments.append(_entry("stripe"))

    llm_names: List[str] = []
    for dep, label in patterns.LLM_SDK_PACKAGES.items():
        if dep in alldeps and label not in llm_names:
            llm_names.append(label)
    for host in sig.get("__llm_hosts", []):
        label = host.split(".")[1] if host.startswith("api.") else host.split(".")[0]
        if label not in llm_names and not any(label in n for n in llm_names):
            llm_names.append(label)
    where = sig.get("__llm_where", [])
    llm = [_entry(n, where=where) for n in llm_names]

    email = [_entry(n) for n in _pkg_match(alldeps, _EMAIL_PKGS)]
    if "resend-host" in sig and not any(e["name"] == "resend" for e in email):
        email.append(_entry("resend"))
    if "sendgrid-host" in sig and not any(e["name"] == "sendgrid" for e in email):
        email.append(_entry("sendgrid"))
    if "s3" in sig:
        storage.append(_entry("s3"))
    for dep, label in (("uploadthing", "uploadthing"), ("cloudinary", "cloudinary"), ("@vercel/blob", "vercel-blob"), ("multer", "local-disk")):
        if dep in deps:
            storage.append(_entry(label))

    analytics = [_entry(n) for n in _pkg_match(alldeps, _ANALYTICS_PKGS)]
    for key, label in (("gtag", "google-analytics"), ("facebook-pixel", "facebook-pixel"), ("hotjar", "hotjar"), ("clarity", "clarity"), ("plausible", "plausible")):
        if key in sig and not any(a["name"] == label for a in analytics):
            analytics.append(_entry(label))
    error_tracking = [_entry(n) for n in _pkg_match(alldeps, _ERROR_PKGS)]
    for pkg, label in (("sentry/sentry-laravel", "sentry"), ("sentry/sentry", "sentry"), ("bugsnag/bugsnag-laravel", "bugsnag"), ("spatie/laravel-flare", "flare"), ("spatie/flare-client-php", "flare"), ("rollbar/rollbar-laravel", "rollbar"), ("honeybadger-io/honeybadger-laravel", "honeybadger"), ("laravel/nightwatch", "nightwatch")):
        if pkg in comp["require"] and not any(e["name"] == label for e in error_tracking):
            error_tracking.append(_entry(label))
    if not error_tracking and "custom-error-reporting" in sig:
        error_tracking.append(_entry("custom", evidence=sig["custom-error-reporting"][:3]))

    hosting: List[Dict[str, Any]] = []

    def host(name: str, confidence: str, evidence: str) -> None:
        for h in hosting:
            if h["name"] == name:
                h["evidence"].append(evidence)
                return
        hosting.append(_entry(name, confidence=confidence, evidence=[evidence]))

    if project.exists("vercel.json"):
        host("vercel", "high", "vercel.json")
    if any(d.startswith("@vercel/") for d in deps):
        host("vercel", "medium", "@vercel packages")
    if project.exists("netlify.toml") or any(p.startswith("netlify/") for p in paths):
        host("netlify", "high", "netlify.toml")
    if project.any_exists("wrangler.toml", "wrangler.jsonc", "wrangler.json"):
        host("cloudflare", "high", "wrangler config")
    if project.exists("fly.toml"):
        host("fly", "high", "fly.toml")
    if project.exists("render.yaml"):
        host("render", "high", "render.yaml")
    if project.any_exists("railway.json", "railway.toml"):
        host("railway", "high", "railway config")
    if any(p == "Dockerfile" or p.startswith("Dockerfile.") or p.endswith("/Dockerfile") for p in paths):
        host("docker", "high", "Dockerfile")
    if project.exists("Procfile"):
        host("heroku", "medium", "Procfile")
    if '"hosting"' in project.read("firebase.json"):
        host("firebase-hosting", "high", "firebase.json hosting")
    if project.exists(".replit"):
        host("replit", "medium", ".replit")
    if fw == "nextjs" and not hosting:
        host("vercel", "low", "Next.js with no other host configuration (assumption)")

    builder = detect_builder(project, deps)
    if builder["name"] == "lovable" and not hosting:
        host("lovable", "low", "builder-hosted preview (assumption)")

    mobile = None
    if "expo" in deps:
        mobile = {"name": "expo", "config": project.any_exists("app.json", "app.config.ts", "app.config.js")}
    elif "react-native" in deps:
        mobile = {"name": "react-native", "config": None}
    elif "@capacitor/core" in deps:
        mobile = {"name": "capacitor", "config": project.any_exists("capacitor.config.ts", "capacitor.config.json")}
    elif project.exists("pubspec.yaml"):
        mobile = {"name": "flutter", "config": "pubspec.yaml"}

    ci: List[Dict[str, Any]] = []
    workflows = [p for p in paths if re.match(r"\.github/workflows/[^/]+\.ya?ml$", p)]
    if workflows:
        ci.append(_entry("github-actions", files=workflows))
    if project.exists(".gitlab-ci.yml"):
        ci.append(_entry("gitlab-ci", files=[".gitlab-ci.yml"]))
    if project.exists(".circleci/config.yml"):
        ci.append(_entry("circleci", files=[".circleci/config.yml"]))

    test_files = [p for p in paths if walker.TEST_PATH_RE.search(p.lower()) and os.path.splitext(p)[1] in walker.CODE_EXTS | {".sql"}]
    runners = _pkg_match(alldeps, _TEST_PKGS)
    test_script = str((project.package.get("scripts") or {}).get("test", ""))
    if not runners and "node --test" in test_script:
        runners = ["node-test"]
    tests = {"present": bool(test_files), "runner": runners[0] if runners else None, "files": len(test_files)}

    if fw == "unknown":
        notes.append("No known framework found in the manifests; read the entry files before choosing a playbook.")
    if uses_supabase and not any(p.endswith(".sql") for p in paths):
        notes.append("Supabase is used but there are no SQL migrations in the repository; policies cannot be reviewed from code.")

    return {
        "package_manager": pm,
        "languages": languages,
        "framework": framework,
        "rendering": rendering,
        "backend": backend,
        "database": database,
        "orm": orm,
        "auth": auth,
        "payments": payments,
        "llm": llm,
        "email": email,
        "storage": storage,
        "analytics": analytics,
        "error_tracking": error_tracking,
        "hosting": hosting,
        "builder": builder,
        "mobile": mobile,
        "ci": ci,
        "tests": tests,
        "notes": notes,
    }


def detect(project: walker.Project) -> Dict[str, Any]:
    """Full stack summary for the app root, with one entry per workspace app in a monorepo."""
    if "stack" in project.cache:
        return project.cache["stack"]
    summary = summarise_root(project)
    ws = _workspaces(project)
    monorepo = bool(ws) or project.exists("turbo.json") or project.exists("nx.json") or project.exists("pnpm-workspace.yaml")
    roots: List[Dict[str, Any]] = []
    if ws:
        for rel in ws:
            try:
                sub = walker.Project(os.path.join(project.root, rel.replace("/", os.sep)), max_size=project.max_size)
            except OSError:
                continue
            sub_fw = sub._guess_framework()
            scripts = sub.package.get("scripts") or {}
            kind = "app" if sub_fw != "unknown" or "start" in scripts or "dev" in scripts else "package"
            roots.append({"path": rel, "kind": kind, "framework": sub_fw})
        if summary["framework"]["name"] != "unknown":
            roots.insert(0, {"path": ".", "kind": "app", "framework": summary["framework"]["name"]})
    else:
        roots.append({"path": ".", "kind": "app", "framework": summary["framework"]["name"]})
    stack: Dict[str, Any] = {"roots": roots, "monorepo": monorepo}
    stack.update(summary)
    stack["git"] = _git_info(project.root)
    project.cache["stack"] = stack
    return stack


def names(stack: Optional[Dict[str, Any]], key: str) -> Set[str]:
    """Names listed under a stack key, whatever its shape."""
    if not stack:
        return set()
    value = stack.get(key)
    if isinstance(value, dict):
        return {str(value.get("name"))} if value.get("name") else set()
    if isinstance(value, list):
        return {str(v.get("name")) for v in value if isinstance(v, dict) and v.get("name")}
    if isinstance(value, str):
        return {value}
    return set()


def has(stack: Optional[Dict[str, Any]], key: str, *fragments: str) -> bool:
    found = names(stack, key)
    return any(fr in n for n in found for fr in fragments)


def is_web(stack: Optional[Dict[str, Any]]) -> bool:
    fw = (stack or {}).get("framework", {}).get("name", "")
    return fw in ("nextjs", "nuxt", "sveltekit", "remix", "astro", "vite-react", "vite-vue", "vite-svelte", "vite", "cra", "angular")


def is_serverless(stack: Optional[Dict[str, Any]]) -> bool:
    fw = (stack or {}).get("framework", {}).get("name", "")
    return fw in ("nextjs", "nuxt", "sveltekit", "remix", "astro") or has(stack, "hosting", "vercel", "netlify", "cloudflare") or has(stack, "backend", "edge-functions", "firebase-functions", "netlify-functions")


def main(argv: Optional[List[str]] = None) -> int:
    parser = findings.base_parser("detect_stack.py", __doc__ or "")
    args = parser.parse_args(argv)
    project = findings.open_project(args)
    findings.log("detect_stack: reading %s" % args.app_root, args.quiet)
    stack = detect(project)
    findings.emit_text(findings.dumps(stack), args.out)
    return findings.EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
