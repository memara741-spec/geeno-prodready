#!/usr/bin/env python3
"""Analyse environment variables: where they are defined, where they are read,
and whether any secret is exposed to the browser or about to be committed.

Detects: env files not ignored by git (SEC-004), secrets in public-prefixed
variables (SEC-005), a missing or incomplete .env.example (SEC-008),
unvalidated environment access (DEP-003), and redirect or callback URLs that
point to localhost or preview domains (MAIL-003). It also flags server-only
variables read from browser code as a likely SEC-001.

It builds ``inventory.env`` (every variable, where it is defined and read) and
``inventory.env_example`` (a ready-to-write example file).

What it deliberately does not do: it never prints a value. Values are only
classified. It does not look at the host's environment settings, which are not
in the repository.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import catalog, findings, jsast, patterns, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_env")
ALSO_EMITS = ["SEC-001"]

ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
VALIDATION_DEPS = ("envalid", "@t3-oss/env-nextjs", "@t3-oss/env-core", "znv", "env-var", "dotenv-safe", "envsafe", "pydantic-settings", "environs", "django-environ")
VALIDATION_CODE_RE = re.compile(r"(?:safeParse|parse|parseAsync)\(\s*(?:process\.env|import\.meta\.env)|createEnv\(|cleanEnv\(|BaseSettings\b|envsafe\(")
PREVIEW_HOST = r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|[\w.-]*\.(?:lovable\.app|lovableproject\.com|vercel\.app|netlify\.app|replit\.dev|repl\.co|webcontainer\.io|webcontainer-api\.io|stackblitz\.io|bolt\.host|ngrok\.io|ngrok-free\.app|pages\.dev|onrender\.com))"
URL_KEY = r"(?:redirectTo|emailRedirectTo|redirect_to|success_url|successUrl|cancel_url|cancelUrl|return_url|returnUrl|callbackURL|callbackUrl|callback_url|redirect_uri|redirectUri|redirectUrl|webhook_url|webhookUrl|NEXTAUTH_URL|baseURL|baseUrl|siteUrl|site_url|appUrl|origin)"
HARDCODED_URL_RE = re.compile(r"\b(" + URL_KEY + r")[\"']?\s*[:=]\s*[\"'`](https?://" + PREVIEW_HOST + r"[^\"'`\s]*)")
FALLBACK_URL_RE = re.compile(r"(?:process\.env\.|import\.meta\.env\.)(\w*(?:URL|SITE|HOST|ORIGIN|DOMAIN)\w*)\s*(?:\|\||\?\?)\s*[\"'`](https?://" + PREVIEW_HOST + r"[^\"'`\s]*)")


def parse_env(text: str) -> List[Dict[str, Any]]:
    out = []
    for i, raw in enumerate(text.split("\n"), 1):
        if raw.strip().startswith("#"):
            continue
        m = ENV_LINE_RE.match(raw)
        if not m:
            continue
        value = m.group(2).strip()
        if value[:1] in "\"'" and value[-1:] == value[:1] and len(value) >= 2:
            value = value[1:-1]
        else:
            value = re.sub(r"\s+#.*$", "", value)
        out.append({"name": m.group(1), "value": value, "line": i})
    return out


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_env", stack)
    variables: Dict[str, Dict[str, Any]] = {}

    def var(name: str) -> Dict[str, Any]:
        if name not in variables:
            prefix = patterns.public_prefix(name)
            variables[name] = {
                "name": name, "defined_in": [], "read_in": [], "public_prefix": prefix,
                "read_from_client": False, "secret_by_name": patterns.is_secret_name(name), "secret_by_value": False,
            }
        return variables[name]

    env_files = [sf for sf in project.files if walker.is_env_file(sf.rel)]
    example_files = [sf for sf in env_files if walker.is_env_example(sf.rel)]
    example_names: set = set()

    for sf in sorted(env_files, key=lambda f: f.rel):
        text = project.text(sf)
        is_example = walker.is_env_example(sf.rel)
        committed = project.will_be_committed(sf.rel)
        for entry in parse_env(text):
            name, value = entry["name"], entry["value"]
            v = var(name)
            v["defined_in"].append(sf.rel)
            if is_example:
                example_names.add(name)
            secret_match = None
            if value and not patterns.is_placeholder(value):
                found = [m for m in patterns.find_secrets("%s=%s" % (name, value)) if not m.public and not (m.pattern.id == "jwt" and m.label == "jwt")]
                secret_match = found[0] if found else None
                if secret_match:
                    v["secret_by_value"] = True
            if v["public_prefix"] and (secret_match or v["secret_by_name"]):
                if not committed and not secret_match:
                    continue
                ai = bool(patterns.AI_NAME_RE.search(name)) or bool(secret_match and secret_match.pattern.ai)
                what = "an AI provider key" if ai else "a secret"
                env.add(Finding(
                    "SEC-005", "%s is set up to hold %s, but its name starts with %s, which tells the build tool to copy the value into the code sent to every visitor." % (name, what, v["public_prefix"]),
                    file=sf.rel, line=entry["line"], snippet="%s=%s" % (name, "[value present]" if value else ""),
                    confidence="confirmed" if secret_match else "likely",
                    detail="Variable %s in %s. %s Variables with this prefix are inlined into the browser bundle at build time." % (
                        name, sf.rel, "Its value matches a private key format." if secret_match else "Its name suggests a private credential; no value is set in this file."),
                    fix_hint="Rename it without the public prefix, move the code that uses it to the server, and rotate the key if a real value was ever deployed.",
                    owner_action="references/owner-actions/rotate-keys.md" if secret_match else None,
                ))
            if committed and not is_example and re.search(r"(?i)production|prod", sf.rel) and re.search(r"https?://(?:localhost|127\.0\.0\.1)", value):
                env.add(Finding(
                    "MAIL-003", "The production settings file points %s at localhost. Links that use it will not work for real users." % name,
                    file=sf.rel, line=entry["line"], snippet="%s=%s" % (name, value), confidence="likely",
                    detail="%s in %s is a localhost URL." % (name, sf.rel),
                    fix_hint="Set the production domain here and in the provider dashboards.",
                ))

    # Where variables are read.
    files_reading: set = set()
    for sf in project.code_files():
        text = project.text(sf)
        kind = project.classify(sf)
        src = jsast.lexed(text).nocomment if sf.ext != ".py" else text
        for m in patterns.ENV_READ_RE.finditer(src):
            name = next((g for g in m.groups() if g), "")
            if not name or name in patterns.ENV_BUILTINS or name.startswith(("VERCEL_", "npm_", "NETLIFY_", "CF_", "AWS_LAMBDA", "RAILWAY_", "RENDER_", "FLY_")):
                continue
            line = jsast.line_of(src, m.start())
            v = var(name)
            if len(v["read_in"]) < 20:
                v["read_in"].append({"file": sf.rel, "line": line})
            if kind != "config":
                files_reading.add(sf.rel)
            if kind == "client":
                v["read_from_client"] = True
                if not v["public_prefix"] and v["secret_by_name"]:
                    env.add(Finding(
                        "SEC-001", "Browser code tries to read %s, a server-only secret." % name,
                        file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely",
                        detail="%s has no public prefix, so the build tool substitutes undefined in the browser. That usually means this code is broken rather than leaking, but it shows a privileged call was written for the browser." % name,
                        fix_hint="Move this code to a server route, server action or edge function.",
                    ))

    # SEC-004: env files and git.
    reads_env = bool(files_reading) or bool(env_files)
    real_env_files = [sf for sf in env_files if not walker.is_env_example(sf.rel)]
    if reads_env and (project.package or project.python_deps or env_files):
        if not project.has_gitignore:
            env.add(Finding(
                "SEC-004", "There is no .gitignore, so the file that holds your keys will be published with the next commit.",
                confidence="confirmed" if real_env_files else "likely", subject={"kind": "file", "name": ".gitignore"},
                detail="No .gitignore at the app root%s." % (" and %d env file(s) present" % len(real_env_files) if real_env_files else ""),
                fix_hint="Add a .gitignore with .env and .env.* (keeping !.env.example).",
            ))
        elif not project.gitignore.ignored(".env"):
            line = 1
            env.add(Finding(
                "SEC-004", "Your .gitignore does not exclude .env files, so the file that holds your keys will be published with the next commit.",
                file=".gitignore", line=line, snippet=(project.read(".gitignore").strip().splitlines() or [""])[0], confidence="confirmed",
                detail=".gitignore has no pattern that matches .env%s." % ("; env files present: " + ", ".join(sf.rel for sf in real_env_files) if real_env_files else ""),
                fix_hint="Add .env and .env.* to .gitignore, keep !.env.example, and run `git rm --cached .env` if it is already tracked.",
            ))
    for sf in real_env_files:
        if project.is_tracked(sf.rel):
            env.add(Finding(
                "SEC-004", "%s is tracked by git, so its contents are in the repository history." % sf.rel,
                file=sf.rel, line=1, snippet="(env file tracked by git)", confidence="confirmed",
                detail="`git ls-files` lists %s." % sf.rel,
                fix_hint="Run `git rm --cached %s`, add it to .gitignore, and rotate any real keys it held." % sf.rel,
            ))

    # SEC-008: example file.
    read_names = sorted(n for n, v in variables.items() if v["read_in"])
    if read_names:
        if not example_files:
            env.add(Finding(
                "SEC-008", "There is no .env.example listing the settings this app needs, so setting it up elsewhere is guesswork.",
                confidence="confirmed", subject={"kind": "file", "name": ".env.example"},
                detail="The code reads %d environment variable(s): %s." % (len(read_names), ", ".join(read_names[:12]) + ("..." if len(read_names) > 12 else "")),
                fix_hint="Create .env.example with these names and empty values, marking which are server-only.",
            ))
        else:
            missing = [n for n in read_names if n not in example_names]
            if missing:
                ex = sorted(example_files, key=lambda f: f.rel)[0]
                env.add(Finding(
                    "SEC-008", "The example settings file is missing %d variable(s) that the code reads." % len(missing),
                    file=ex.rel, line=1, snippet="missing: " + ", ".join(missing[:10]), confidence="confirmed",
                    detail="Read in code but absent from %s: %s." % (ex.rel, ", ".join(missing)),
                    fix_hint="Add the missing names with empty values.",
                ))

    # DEP-003: validation at startup.
    has_validation = any(d in project.deps or d in project.python_deps for d in VALIDATION_DEPS)
    if not has_validation:
        for sf in project.code_files():
            if VALIDATION_CODE_RE.search(project.text(sf)):
                has_validation = True
                break
    reading = sorted(files_reading)
    if not has_validation and len(reading) >= 3:
        first = project.get(reading[0])
        first_line = 1
        if first:
            fm = patterns.ENV_READ_RE.search(project.text(first))
            first_line = first.line_of(fm.start()) if fm else 1
        env.add(Finding(
            "DEP-003", "The app reads its settings in %d different files without checking them at startup. A missing setting shows up later as a confusing failure." % len(reading),
            file=reading[0], line=first_line, snippet=first.line_text(first_line) if first else "", confidence="likely",
            detail="Environment variables are read directly in: %s. No validation module was found." % ", ".join(reading[:8]),
            fix_hint="Add one module that validates the environment with a schema and fails fast, and read settings only through it.",
        ))

    # MAIL-003: hard-coded localhost or preview URLs in redirect and callback settings.
    for sf in project.code_files():
        text = project.text(sf)
        if project.classify(sf) == "config":
            continue
        src = jsast.lexed(text).nocomment if sf.ext != ".py" else text
        seen = set()
        for m in HARDCODED_URL_RE.finditer(src):
            line = jsast.line_of(src, m.start())
            if line in seen:
                continue
            seen.add(line)
            env.add(Finding(
                "MAIL-003", "A redirect or callback link is hard-coded to a local or preview address. In production, sign-in, email or payment links will send users to a page that does not exist.",
                file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely",
                detail="`%s` is set to %s." % (m.group(1), m.group(2)),
                fix_hint="Build the URL from a validated environment variable for the site address, and update the provider dashboards with the production domain.",
            ))
        for m in FALLBACK_URL_RE.finditer(src):
            line = jsast.line_of(src, m.start())
            if line in seen:
                continue
            seen.add(line)
            env.add(Finding(
                "MAIL-003", "If %s is missing in production, links silently fall back to a local address." % m.group(1),
                file=sf.rel, line=line, snippet=sf.line_text(line), confidence="possible",
                detail="Fallback to %s when %s is unset." % (m.group(2), m.group(1)),
                fix_hint="Remove the fallback and validate the variable at startup.",
            ))

    env.inventory["env"] = [variables[n] for n in sorted(variables)]
    lines = ["# Environment variables read by the app. Fill in the values for your environment."]
    public = [n for n in read_names if variables[n]["public_prefix"]]
    server = [n for n in read_names if not variables[n]["public_prefix"]]
    if public:
        lines += ["", "# Public (built into the browser bundle; never put secrets here)"] + ["%s=" % n for n in public]
    if server:
        lines += ["", "# Server-only"] + ["%s=" % n for n in server]
    env.inventory["env_example"] = "\n".join(lines) + "\n"
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_env", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
