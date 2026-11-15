#!/usr/bin/env python3
"""Check configuration: security headers, containers, build flags, CI, tests and project hygiene.

Detects: missing or weak security headers in framework and host config
(HDR-001 to HDR-006), permissive CORS (API-003), caching of personalised
responses (HDR-005), dev servers or debug mode in production (DEP-001),
missing health check (DEP-004), non-reproducible builds (DEP-006), build flags
that hide errors (DEP-008), container problems (DEP-009), SPA fallback and
error pages (DEP-012), source maps (SEC-007), tests and CI (TEST-001 to
TEST-003), error tracking and logging (OBS-001, OBS-002), unhandled async
errors and in-memory state (REL-001, REL-004), search engine files and
support contacts (LAUNCH-003, LAUNCH-006), store requirements for mobile apps
(LAUNCH-008), README (LAUNCH-009), caching (PERF-005) and date handling hints
(REL-006).

What it deliberately does not do: it cannot see headers a host adds on its
own. When a header may come from the host, the finding is ``possible`` and
says so. It never makes a request to the deployed site (see probe_live.py).
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detect_stack  # noqa: E402
from lib import catalog, findings, jsast, patterns, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_config")
ALSO_EMITS: List[str] = []

HEADER_FILES = ("next.config.js", "next.config.mjs", "next.config.ts", "vercel.json", "netlify.toml", "public/_headers", "_headers", "firebase.json", "nuxt.config.ts", "svelte.config.js", "wrangler.toml", "staticwebapp.config.json", "middleware.ts", "src/middleware.ts", "proxy.ts", "render.yaml", "Caddyfile", "nginx.conf")


def _lines(text: str, needle: str) -> int:
    i = text.lower().find(needle.lower())
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_config", stack)
    fw = project.framework
    deps = project.deps
    paths = project.all_paths()
    web = detect_stack.is_web(stack)
    backend = bool(detect_stack.names(stack, "backend") - {"supabase", "firebase"}) or fw in ("express", "fastify", "hono", "koa", "nestjs", "django", "flask", "fastapi")
    pkg_sf = project.get("package.json")
    scripts = project.package.get("scripts") or {}

    # --- security headers (web) -------------------------------------------
    header_text = ""
    header_src: Dict[str, str] = {}
    for rel in HEADER_FILES:
        if project.exists(rel):
            t = project.read(rel)
            header_text += "\n" + t
            header_src[rel] = t
    for sf in project.code_files():
        t = project.text(sf)
        if re.search(r"Content-Security-Policy|helmet\(", t) and sf.rel not in header_src:
            header_text += "\n" + t
            header_src[sf.rel] = t
    low = header_text.lower()
    host_adds_hsts = detect_stack.has(stack, "hosting", "vercel", "netlify", "firebase-hosting", "cloudflare")
    if web or (backend and "express" in deps):
        has_csp = "content-security-policy" in low or "helmet(" in low
        anchor_file = next(iter(header_src), None) or ("package.json" if pkg_sf else None)
        anchor_line = 1
        if not has_csp:
            env.add(Finding(
                "HDR-001", "The site sends no Content Security Policy. If an attacker ever gets a script onto a page, nothing limits what it can do.",
                file=anchor_file, line=anchor_line, snippet=(project.get(anchor_file).line_text(1) if anchor_file and project.get(anchor_file) else ""), confidence="likely",
                subject={"kind": "headers", "name": "content-security-policy"},
                detail="No Content-Security-Policy header or meta tag in framework, host or middleware configuration.",
                fix_hint="Start from assets/security-headers/ for your host, in report-only mode first if the app has inline scripts.",
            ))
        elif re.search(r"script-src[^;\"']*'unsafe-inline'[^;\"']*'unsafe-eval'|script-src[^;\"']*\*[^.]", low):
            env.add(Finding(
                "HDR-001", "The Content Security Policy allows inline and eval scripts, which removes most of its protection.",
                file=anchor_file, line=_lines(header_text, "script-src"), snippet="script-src ... 'unsafe-inline' 'unsafe-eval'", confidence="possible",
                detail="script-src allows unsafe-inline and unsafe-eval or a wildcard.",
                fix_hint="Use nonces or hashes for the scripts you need and drop unsafe-eval.",
            ))
        if "strict-transport-security" not in low and "hsts" not in low and not host_adds_hsts:
            env.add(Finding(
                "HDR-002", "Nothing makes browsers insist on HTTPS for this site, so a visitor on a hostile network can be downgraded to an unencrypted connection.",
                file=anchor_file, line=1, snippet="", confidence="likely", subject={"kind": "headers", "name": "strict-transport-security"},
                detail="No Strict-Transport-Security header configured and the host is not known to add it.",
                fix_hint="Add Strict-Transport-Security: max-age=63072000; includeSubDomains once HTTPS works everywhere.",
            ))
        elif "strict-transport-security" not in low and host_adds_hsts:
            env.add(Finding(
                "HDR-002", "No HSTS header is configured in the project. Your host may add one by default; confirm on the live site.",
                file=anchor_file, line=1, snippet="", confidence="possible", severity="low", subject={"kind": "headers", "name": "strict-transport-security"},
                detail="The detected host (%s) may add HSTS on its own domains only, not on custom domains." % ", ".join(sorted(detect_stack.names(stack, "hosting"))),
                fix_hint="Set the header explicitly.",
            ))
        if "frame-ancestors" not in low and "x-frame-options" not in low and "helmet(" not in low:
            env.add(Finding(
                "HDR-003", "Other sites can embed your pages in an invisible frame and trick visitors into clicking.",
                file=anchor_file, line=1, snippet="", confidence="likely", subject={"kind": "headers", "name": "frame-ancestors"},
                detail="No frame-ancestors directive and no X-Frame-Options header.",
                fix_hint="Add frame-ancestors 'none' (or 'self') to the CSP and X-Frame-Options: DENY.",
            ))
        missing = [h for h in ("x-content-type-options", "referrer-policy", "permissions-policy") if h not in low and "helmet(" not in low]
        if missing:
            env.add(Finding(
                "HDR-004", "Small free protections are not switched on: %s." % ", ".join(missing),
                file=anchor_file, line=1, snippet="", confidence="likely", subject={"kind": "headers", "name": "misc"},
                detail="Missing headers: %s." % ", ".join(missing),
                fix_hint="Add them from the template in assets/security-headers/.",
            ))
    if fw == "nextjs" and "poweredbyheader" not in low.replace(" ", ""):
        nc = next((r for r in ("next.config.js", "next.config.mjs", "next.config.ts") if project.exists(r)), None)
        env.add(Finding(
            "HDR-006", "The server announces that it runs Next.js in every response. It is a small hint that helps attackers pick exploits.",
            file=nc, line=1, snippet=project.get(nc).line_text(1) if nc else "", confidence="likely", subject={"kind": "headers", "name": "x-powered-by"},
            detail="poweredByHeader is not set to false.",
            fix_hint="Set poweredByHeader: false in the Next.js config.",
        )) if nc else None
    if "express" in deps:
        for sf in project.code_files():
            t = project.text(sf)
            if re.search(r"express\(\)", t) and not re.search(r"x-powered-by|helmet\(", t):
                line = _lines(t, "express()")
                env.add(Finding(
                    "HDR-006", "The server announces that it runs Express in every response.",
                    file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely",
                    detail="app.disable('x-powered-by') or helmet() is not used.",
                    fix_hint="Call app.disable('x-powered-by') or use helmet().",
                ))
                break

    # API-003: CORS.
    for sf in project.code_files():
        if project.classify(sf) in ("client", "test"):
            continue
        t = project.text(sf)
        src = jsast.lexed(t).nocomment if sf.ext != ".py" else t
        if sf.ext == ".py":
            m = re.search(r"CORS\(\s*\w+\s*\)|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|allow_origins\s*=\s*\[\s*[\"']\*[\"']", src)
            if m and re.search(r"supports_credentials\s*=\s*True|CORS_ALLOW_CREDENTIALS\s*=\s*True|allow_credentials\s*=\s*True", src):
                line = jsast.line_of(src, m.start())
                env.add(Finding("API-003", "Any website can make requests to this API as the signed-in visitor and read the answers.", file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", detail="Wildcard CORS together with credentials.", fix_hint="List the exact origins you trust."))
            continue
        for m in re.finditer(r"\bcors\(\s*\)|\bapp\.use\(\s*cors\(\s*\)\s*\)", src):
            line = jsast.line_of(src, m.start())
            cookies = re.search(r"cookie|credentials|session|jwt", t, re.I)
            env.add(Finding(
                "API-003", "The API accepts requests from any website. Because it also uses cookies, a hostile page can act as the signed-in visitor." if cookies else "The API accepts requests from any website.",
                file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely" if cookies else "possible",
                detail="cors() with default options allows every origin.",
                fix_hint="Pass an explicit origin allow-list from configuration and enable credentials only for those origins.",
            ))
            break
        m = re.search(r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*(?:req(?:uest)?\.headers(?:\.get\(\s*[\"']origin[\"']\s*\)|\.origin|\[\s*[\"']origin[\"']\s*\])|[^,\n]*\bget\(\s*[\"']origin[\"']\s*\))", src, re.I)
        if m and re.search(r"Access-Control-Allow-Credentials[\"']?\s*[:,]\s*[\"']?true", src, re.I):
            line = jsast.line_of(src, m.start())
            env.add(Finding(
                "API-003", "The API repeats back whatever website asks, and allows cookies. Any website can read a signed-in visitor's data.",
                file=sf.rel, line=line, snippet=sf.line_text(line), confidence="confirmed",
                detail="Access-Control-Allow-Origin reflects the request origin while Allow-Credentials is true.",
                fix_hint="Compare the origin with an allow-list and only then echo it.",
            ))
        # HDR-005: public caching of personalised responses.
        for m in re.finditer(r"[Cc]ache-[Cc]ontrol[\"']?\s*[:,]\s*[\"'`](?=[^\"'`]*public)[^\"'`]*[\"'`]", src):
            around = src[max(0, m.start() - 1500): m.end() + 300]
            if patterns.AUTH_CALL_RE.search(around):
                line = jsast.line_of(src, m.start())
                env.add(Finding(
                    "HDR-005", "A response that depends on who is signed in is marked as cacheable by shared caches. One user's data can be served to another.",
                    file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely",
                    detail="Cache-Control: public on a handler that reads the session.",
                    fix_hint="Use Cache-Control: private, no-store for personalised responses.",
                ))
                break

    # --- deployment ---------------------------------------------------------
    for name, cmd in sorted(scripts.items()):
        if name in ("start", "serve", "prod", "production") and re.search(r"\b(nodemon|next dev|vite(?!\s+build)\b(?!\s+preview)|ts-node-dev|--watch|flask run|--reload)\b", str(cmd)):
            line = next((i for i, l in enumerate(pkg_sf.lines, 1) if '"%s"' % name in l), 1) if pkg_sf else 1
            env.add(Finding(
                "DEP-001", "The command that starts the app in production (`%s`) runs a developer tool that restarts on file changes, shows debug output and is not built for real traffic." % cmd,
                file="package.json", line=line, snippet=pkg_sf.line_text(line) if pkg_sf else "", confidence="likely",
                detail="package.json script `%s` runs `%s`." % (name, cmd),
                fix_hint="Build the app and start the compiled output (for example `node src/server.js`) with NODE_ENV=production.",
            ))
    for sf in project.files:
        if sf.name.startswith("Dockerfile") or sf.name in ("docker-compose.yml", "docker-compose.yaml", "compose.yaml", "Procfile", "app.json") and False:
            t = project.text(sf)
            for m in re.finditer(r"(?im)^\s*(?:CMD|ENTRYPOINT)\b.*$", t):
                if re.search(r"nodemon|next dev|npm[\"',\s]+run[\"',\s]+dev|yarn[\"',\s]+dev|vite\b(?!\s+build)|--reload|--watch|flask run|runserver", m.group(0)):
                    line = t.count("\n", 0, m.start()) + 1
                    env.add(Finding("DEP-001", "The container starts a developer server instead of the production build.", file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", detail="Dockerfile start command runs a dev tool.", fix_hint="Run the compiled app with NODE_ENV=production."))
            if sf.name.startswith("Dockerfile"):
                issues = []
                if not re.search(r"(?im)^\s*USER\s+(?!root\b)\S+", t):
                    issues.append("runs as root (no USER instruction)")
                if re.search(r"(?im)^\s*COPY\s+\.\s+\.", t) and not project.exists(".dockerignore"):
                    issues.append("copies the whole folder with no .dockerignore, so .env and .git end up in the image")
                if re.search(r"(?im)^\s*(?:ENV|ARG)\s+\w*(?:SECRET|PASSWORD|TOKEN|KEY)\w*[= ]\s*\S+", t):
                    issues.append("bakes a secret into an ENV or ARG")
                fm = re.search(r"(?im)^\s*FROM\s+(\S+)", t)
                if fm and (fm.group(1).endswith(":latest") or ":" not in fm.group(1).split("/")[-1]) and fm.group(1) != "scratch":
                    issues.append("uses an unpinned base image (%s)" % fm.group(1))
                if issues:
                    line = _lines(t, "COPY") if "COPY" in t else 1
                    env.add(Finding(
                        "DEP-009", "The container image has problems: %s." % "; ".join(issues),
                        file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely",
                        detail="Dockerfile review: %s." % "; ".join(issues),
                        fix_hint="Use a pinned base image, a non-root USER, a .dockerignore that excludes .env and .git, and inject secrets at run time.",
                    ))

    # DEP-004: health endpoint.
    has_health = any(re.search(r"(^|/)(health|healthz|ready|readyz|ping|status)(/|\.|$)", p) for p in paths if p.endswith((".ts", ".js", ".tsx", ".py", ".mjs"))) or any(re.search(r"[\"']/(?:api/)?(?:health|healthz|ping|ready)\b", project.read(p)) for p in paths if p.endswith((".js", ".ts", ".py")) and project.classify(project.get(p)) == "server")
    if fw == "laravel" and (re.search(r"health\s*:\s*['\"]/", project.read("bootstrap/app.php")) or any(re.search(r"['\"]/(?:up|health|healthz)['\"]", project.read(p)) for p in paths if p.startswith("routes/") and p.endswith(".php"))):
        has_health = True
    if (backend or fw == "nextjs") and not has_health:
        first = next((p for p in paths if p in ("package.json", "requirements.txt")), None)
        env.add(Finding(
            "DEP-004", "There is no simple address a monitoring service can call to check whether the app is alive.",
            file=first, line=1, snippet="", confidence="likely", subject={"kind": "project", "name": "health-endpoint"},
            detail="No /health, /healthz or /api/health route found.",
            fix_hint="Add a cheap endpoint that returns {\"status\":\"ok\"} without exposing details.",
        ))

    # DEP-006: reproducible builds.
    if project.exists("package.json"):
        locks = [l for l in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock") if project.exists(l)]
        issues = []
        if not locks:
            issues.append("no lockfile")
        elif len(locks) > 1:
            issues.append("several lockfiles (%s)" % ", ".join(locks))
        loose = [k for k, v in deps.items() if v.strip() in ("latest", "*", "") or v.startswith(("http", "git"))]
        if loose:
            issues.append("unpinned versions (%s)" % ", ".join(loose[:4]))
        if not (project.package.get("engines") or project.any_exists(".nvmrc", ".node-version", ".tool-versions", "mise.toml")):
            issues.append("no pinned Node version")
        for sf in project.files:
            if sf.name.startswith("Dockerfile") and re.search(r"npm install\b", project.text(sf)) and not re.search(r"npm ci", project.text(sf)):
                issues.append("`npm install` instead of `npm ci` in %s" % sf.rel)
        if issues:
            line = 1
            env.add(Finding(
                "DEP-006", "Tomorrow's deployment may install different code than today's: %s." % "; ".join(issues),
                file="package.json", line=line, snippet=pkg_sf.line_text(1) if pkg_sf else "", confidence="confirmed" if not locks else "likely", subject={"kind": "project", "name": "reproducible-builds"},
                detail="Reproducibility review: %s." % "; ".join(issues),
                fix_hint="Use one package manager, commit its lockfile, pin the runtime and install with `npm ci`.",
            ))

    # DEP-008: flags that hide errors.
    for rel in ("next.config.js", "next.config.mjs", "next.config.ts", "vite.config.ts"):
        t = project.read(rel)
        for needle in ("ignoreBuildErrors: true", "ignoreDuringBuilds: true"):
            if needle in t:
                line = _lines(t, needle)
                env.add(Finding(
                    "DEP-008", "The build is told to ignore errors, so real bugs can ship without anyone noticing. AI builders often switch this on to make a build pass.",
                    file=rel, line=line, snippet=project.get(rel).line_text(line), confidence="confirmed",
                    detail="%s in %s." % (needle, rel),
                    fix_hint="Remove the flag, fix the errors it reveals, and enable strict mode step by step.",
                ))
    tsc = project.read("tsconfig.json")
    if tsc and re.search(r"\"strict\"\s*:\s*false|\"strictNullChecks\"\s*:\s*false|\"noImplicitAny\"\s*:\s*false", tsc):
        line = next((i for i, l in enumerate(tsc.split("\n"), 1) if re.search(r"strict|noImplicitAny", l)), 1)
        env.add(Finding(
            "DEP-008", "TypeScript's safety checks are turned off, so many bugs are invisible until a user hits them.",
            file="tsconfig.json", line=line, snippet=project.get("tsconfig.json").line_text(line), confidence="likely",
            detail="strict, strictNullChecks or noImplicitAny is false in tsconfig.json.",
            fix_hint="Enable strict mode gradually and fix what surfaces.",
        ))
    for sf in project.code_files():
        if "@ts-nocheck" in project.text(sf):
            env.add(Finding("DEP-008", "Type checking is switched off for this whole file.", file=sf.rel, line=_lines(project.text(sf), "@ts-nocheck"), snippet="// @ts-nocheck", confidence="likely", detail="@ts-nocheck directive.", fix_hint="Remove it and fix the errors."))
            break

    # DEP-012: SPA rewrites and error pages.
    if fw in ("vite-react", "vite-vue", "vite-svelte", "vite", "cra") and not project.exists("src/App.tsx") is None:
        pass
    if fw in ("vite-react", "vite-vue", "vite-svelte", "vite", "cra"):
        hosts = detect_stack.names(stack, "hosting")
        rewrites = bool(re.search(r"rewrites|\[\[redirects\]\]|/\*\s+/index\.html|try_files|fallback", header_text + project.read("_redirects") + project.read("public/_redirects") + project.read("netlify.toml")))
        if not rewrites and hosts - {"lovable"} and not ("firebase-hosting" in hosts and "rewrites" in project.read("firebase.json")):
            env.add(Finding(
                "DEP-012", "Reloading or sharing a link to any page other than the home page will show the host's 404 page, because the host does not know about the app's routes.",
                file="package.json", line=1, snippet="", confidence="possible", subject={"kind": "project", "name": "spa-fallback"},
                detail="Single-page app with no rewrite rule to index.html for the detected host.",
                fix_hint="Add a catch-all rewrite to /index.html in the host configuration.",
            ))

    # SEC-007: source maps.
    for rel, rx in (("vite.config.ts", r"sourcemap\s*:\s*true"), ("vite.config.js", r"sourcemap\s*:\s*true"), ("next.config.js", r"productionBrowserSourceMaps\s*:\s*true"), ("next.config.mjs", r"productionBrowserSourceMaps\s*:\s*true"), ("next.config.ts", r"productionBrowserSourceMaps\s*:\s*true")):
        t = project.read(rel)
        m = re.search(rx, t)
        if m:
            line = t.count("\n", 0, m.start()) + 1
            env.add(Finding(
                "SEC-007", "The app publishes its original source code (source maps) to every visitor, including comments and any value that was inlined at build time.",
                file=rel, line=line, snippet=project.get(rel).line_text(line), confidence="likely",
                detail="Production source maps are enabled.",
                fix_hint="Disable public source maps, or upload them privately to your error tracker.",
            ))

    # --- observability and reliability ---------------------------------------
    has_tracker = bool(detect_stack.names(stack, "error_tracking"))
    if (web or backend or fw == "nextjs") and not has_tracker:
        env.add(Finding(
            "OBS-001", "If the app breaks for a user, you will not find out unless they tell you. Nothing records errors.",
            file="package.json" if pkg_sf else None, line=1 if pkg_sf else None, snippet="", confidence="likely", subject={"kind": "project", "name": "error-tracking"},
            detail="No error tracking SDK (Sentry, Bugsnag, Rollbar and similar) or custom error hook was found on the client or the server.",
            fix_hint="Add an error tracker on both client and server, scrub personal data, and upload source maps privately.",
            owner_action="references/checks/observability.md#obs-001",
        ))
    for sf in project.code_files():
        if project.classify(sf) == "test":
            continue
        t = project.text(sf)
        src = jsast.lexed(t).code if sf.ext != ".py" else t
        m = re.search(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}|\.catch\(\s*\(\s*\w*\s*\)\s*=>\s*\{\s*\}\s*\)|except(?:\s+\w+(?:\s+as\s+\w+)?)?\s*:\s*\n\s*pass\b", src)
        if m:
            line = jsast.line_of(src, m.start())
            env.add(Finding(
                "OBS-002", "An error is caught and silently thrown away here, so when it fails nobody will ever know why.",
                file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely",
                detail="Empty catch block or except: pass.",
                fix_hint="Handle the error, or log it and report it to the tracker.",
            ))
            break
    for sf in project.code_files():
        if project.classify(sf) in ("test", "config"):
            continue
        t = project.text(sf)
        if sf.ext == ".py":
            continue
        src = jsast.lexed(t).code
        m = re.search(r"\.forEach\(\s*async\b", src)
        if m:
            line = jsast.line_of(src, m.start())
            env.add(Finding("REL-001", "Work started inside forEach(async ...) is not waited for, so failures vanish and the response is sent before the work finishes.", file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", detail="async callback passed to forEach.", fix_hint="Use for...of with await, or Promise.all over map."))
            break
        for call in jsast.find_calls(t, ["supabase.*", "supabaseAdmin.*", "admin.*"]):
            pre = src[max(0, call.start - 40): call.start]
            stmt_end = src.find(";", call.end)
            tail = src[call.end: stmt_end if stmt_end != -1 else call.end + 200]
            if re.search(r"\.from\(|\.rpc\(", call.name + call.args) and re.search(r"(?:insert|update|upsert|delete|rpc)$", call.name) and re.search(r"^\s*await\b", pre[-12:] + " ") and not re.search(r"(?:const|let|var)\s*(?:\{|\w+\s*=)[^;]*$", pre) and not re.search(r"\.then\(|error", tail):
                line = call.line
                env.add(Finding("REL-001", "The result of a database write is never checked, so a failed save looks like a success.", file=sf.rel, line=line, snippet=sf.line_text(line), confidence="possible", detail="SDK call whose { data, error } result is ignored.", fix_hint="Check error and surface it to the user and the tracker."))
                break
        else:
            m = re.search(r"(?<![\w$.])(?:const|let)\s+\w+\s*=\s*(?:new\s+)?Map\(\)", src)
            if m and project.classify(sf) == "server" and re.search(r"(?i)rate|limit|session|cache|usage", sf.rel + src[m.start(): m.start() + 200]) and detect_stack.is_serverless(stack):
                line = jsast.line_of(src, m.start())
                env.add(Finding("REL-004", "State is kept in the server's memory. On serverless hosting every request can land on a fresh instance, so counters and limits reset constantly.", file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", detail="Module-level Map used for rate limits, sessions, caches or usage counts.", fix_hint="Use a shared store such as the database or a key-value service."))
            continue
        break
    for sf in project.code_files():
        t = project.text(sf)
        if sf.ext != ".py" and project.classify(sf) == "server":
            src = jsast.lexed(t).code
            m = re.search(r"(?<![\w$.])(?:const|let)\s+(\w+)\s*=\s*new\s+Map(?:<[^>]*>)?\(\)", src)
            if m and re.search(r"(?i)rate|limit|session|cache|usage|counts?", m.group(1) + sf.rel) and detect_stack.is_serverless(stack) and not any(f.check_id == "REL-004" for f in env.findings):
                line = jsast.line_of(src, m.start())
                env.add(Finding("REL-004", "State is kept in the server's memory. On serverless hosting every request can land on a fresh instance, so counters and limits reset constantly.", file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", detail="Module-level Map holding rate limit, session, cache or usage state.", fix_hint="Use a shared store such as the database or a key-value service."))

    # --- tests and CI --------------------------------------------------------
    tests = (stack or {}).get("tests") or {}
    if not tests.get("present"):
        env.add(Finding(
            "TEST-001", "There are no automated tests. Every later change, especially one made by an AI tool, can silently break sign-up or payment.",
            file="package.json" if pkg_sf else None, line=1 if pkg_sf else None, snippet="", confidence="confirmed", subject={"kind": "project", "name": "tests"},
            detail="No test files or test script found.",
            fix_hint="Add a small set of tests: sign-in, the core action, cross-user access denial and payment webhook handling.",
        ))
    has_rules = bool(detect_stack.has(stack, "database", "firebase", "supabase"))
    if has_rules and (project.exists("firestore.rules") or any(p.endswith(".sql") for p in paths if "migrations" in p)):
        rule_tests = any(re.search(r"rules.*test|test.*rules|rls.*test|test.*rls|rules-unit-testing|pgtap|supabase/tests/", p + project.read(p)[:3000], re.I) for p in paths if walker.TEST_PATH_RE.search(p.lower()) or p.startswith("supabase/tests/"))
        if not rule_tests:
            env.add(Finding(
                "TEST-002", "The access rules are the main security boundary, and nothing tests them. One careless edit can open the whole database.",
                file="firestore.rules" if project.exists("firestore.rules") else "supabase/config.toml" if project.exists("supabase/config.toml") else None, line=1, snippet="", confidence="likely", subject={"kind": "project", "name": "access-rule-tests"},
                detail="Policies or rules exist but no emulator, pgTAP or SQL tests reference them.",
                fix_hint="Generate tests from assets/sql/rls_test.sql.tmpl or add Firebase emulator rules tests: user A cannot read or write user B's data, and anonymous cannot read private data.",
            ))
    workflows = [p for p in paths if re.match(r"\.github/workflows/[^/]+\.ya?ml$", p)]
    ci_ok = any(re.search(r"\b(test|build|lint|typecheck|audit)\b", project.read(w)) for w in workflows) or project.exists(".gitlab-ci.yml") or project.exists(".circleci/config.yml")
    if not ci_ok and (project.is_git_repo or True) and (pkg_sf or project.python_deps):
        env.add(Finding(
            "TEST-003", "Nothing checks changes before they go live, so broken or insecure code ships unreviewed.",
            file=None, line=None, snippet="", confidence="confirmed", subject={"kind": "project", "name": "ci"},
            detail="No CI workflow that runs tests, type checks, a build or an audit%s." % (" (workflows exist but only deploy)" if workflows else ""),
            fix_hint="Install assets/ci/prodready.yml and add install, typecheck, test, build and an audit step.",
        ))

    # --- launch polish -------------------------------------------------------
    if web:
        robots = project.any_exists("public/robots.txt", "robots.txt", "static/robots.txt") or any(re.search(r"(^|/)robots\.(ts|js)$", p) for p in paths)
        if not robots:
            env.add(Finding(
                "LAUNCH-003", "There is no robots.txt or sitemap, so search engines get no guidance about what to index.",
                file="package.json" if pkg_sf else None, line=1 if pkg_sf else None, snippet="", confidence="likely", subject={"kind": "project", "name": "robots"},
                detail="No robots.txt or sitemap found.",
                fix_hint="Add robots.txt and a sitemap; block private areas and non-production environments.",
            ))
        else:
            for rel in ("public/robots.txt", "robots.txt", "static/robots.txt"):
                t = project.read(rel)
                if re.search(r"(?im)^\s*Disallow:\s*/\s*$", t):
                    env.add(Finding("LAUNCH-003", "robots.txt tells every search engine to ignore the whole site.", file=rel, line=_lines(t, "Disallow: /"), snippet="Disallow: /", confidence="likely", detail="Disallow: / found; fine for staging, wrong for production.", fix_hint="Remove it before launch."))
        support = False
        for sf in project.files:
            if sf.ext in (".tsx", ".jsx", ".html", ".vue", ".svelte", ".astro", ".ts") and re.search(r"mailto:|/contact|/support|/help|security\.txt", project.text(sf)):
                support = True
                break
        if not support and not any("security.txt" in p for p in paths):
            env.add(Finding(
                "LAUNCH-006", "Users have no way to ask for help or report a problem, and there is no address for reporting security issues.",
                file=None, line=None, snippet="", confidence="possible", subject={"kind": "project", "name": "support-contact"},
                detail="No mailto link, contact or support page, or security.txt found.",
                fix_hint="Add a support email in the footer and a /.well-known/security.txt.",
            ))
    readme = project.read("README.md")
    stripped = re.sub(r"[#>*_`\-\s]", "", readme)
    default_readme = bool(re.search(r"(?i)welcome to your lovable project|this is a \[next\.js\]|react \+ vite|this template provides a minimal setup|getting started with create react app|bootstrapped with", readme))
    if not readme or len(stripped) < 120 or default_readme or not re.search(r"(?i)run|install|setup|deploy|start", readme):
        env.add(Finding(
            "LAUNCH-009", "There is no README that explains how to run, configure and deploy the app, so nobody else, including a future AI assistant, can safely work on it.",
            file="README.md" if readme else None, line=1 if readme else None, snippet=project.get("README.md").line_text(1) if readme else "", confidence="confirmed" if (not readme or default_readme) else "likely", subject={"kind": "file", "name": "README.md"},
            detail="README is %s." % ("missing" if not readme else "the template default" if default_readme else "very short or lacks setup instructions"),
            fix_hint="Write what the app is, the stack, how to run it, the environment variables, how to deploy, and where data lives.",
        ))
    if (stack or {}).get("mobile"):
        app_json = project.read("app.json")
        issues = []
        line, rel = 1, "app.json"
        if app_json:
            if re.search(r"com\.(?:anonymous|example|yourcompany)\.", app_json):
                issues.append("placeholder bundle identifier")
            if re.search(r"usesCleartextTraffic\"?\s*:\s*true", app_json):
                issues.append("cleartext (unencrypted) traffic is allowed on Android")
                line = _lines(app_json, "usesCleartextTraffic")
            plugs = app_json + project.read("app.config.js") + project.read("app.config.ts")
            uses = {"camera": r"expo-camera|expo-image-picker", "location": r"expo-location"}
            for perm, rx in uses.items():
                if re.search(rx, " ".join(deps)) and not re.search(r"NS%sUsageDescription|%s[A-Za-z]*Permission|infoPlist" % (perm.capitalize(), perm), plugs, re.I):
                    issues.append("no iOS usage description for %s" % perm)
        else:
            rel = "package.json"
        if not any(re.search(r"delete.?account|deleteUser|account.?deletion", project.text(sf), re.I) for sf in project.code_files()):
            issues.append("no account deletion, which both stores require for apps with sign-up")
        if issues:
            sfm = project.get(rel)
            env.add(Finding(
                "LAUNCH-008", "App store requirements are not met yet: %s. Rejection delays launch by days or weeks." % "; ".join(issues),
                file=rel, line=line, snippet=sfm.line_text(line) if sfm else "", confidence="likely", subject={"kind": "project", "name": "store-requirements"},
                detail="Mobile store review: %s." % "; ".join(issues),
                fix_hint="Add permission descriptions, a real bundle identifier, HTTPS-only traffic and an in-app account deletion flow.",
            ))
    # PERF-005 and REL-006 (light heuristics).
    if fw == "nextjs":
        for sf in project.code_files():
            if re.search(r"(^|/)app/(page|about|pricing|blog)[^/]*\.[jt]sx?$", sf.rel) and re.search(r"export const dynamic\s*=\s*[\"']force-dynamic[\"']", project.text(sf)) and not patterns.AUTH_CALL_RE.search(project.text(sf)):
                line = _lines(project.text(sf), "force-dynamic")
                env.add(Finding("PERF-005", "A public page is rendered from scratch on every visit although it shows the same content to everyone.", file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", detail="force-dynamic on a page that does not read the session.", fix_hint="Let it be static or revalidate it on a schedule."))
                break
    for sf in project.code_files():
        if project.classify(sf) in ("test",):
            continue
        t = project.text(sf)
        m = re.search(r"new Date\(\s*[\"'`]\d{4}-\d{2}-\d{2}[\"'`]\s*\)|\.getDay\(\)|\.setHours\(\s*0", t)
        if m and re.search(r"(?i)billing|subscription|due|expire|deadline", t):
            line = t.count("\n", 0, m.start()) + 1
            env.add(Finding("REL-006", "Dates are handled in the server's local time zone, which causes off-by-one-day bugs for part of your users.", file=sf.rel, line=line, snippet=sf.line_text(line), confidence="possible", detail="Local-time date construction in billing or deadline logic.", fix_hint="Store UTC, convert at the edges and test around midnight."))
            break

    env.inventory["config"] = {"header_sources": sorted(header_src), "workflows": workflows, "tests": tests}
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_config", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
