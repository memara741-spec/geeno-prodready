#!/usr/bin/env python3
"""Review dependencies: known vulnerabilities, support status, invented or misspelled packages, and hygiene.

Detects: dependencies with known vulnerabilities (DEPS-001), frameworks past
security support (DEPS-002), packages that are imported but not declared or
whose names look like misspellings of popular packages (DEPS-003), unused
packages (DEPS-004), tools in the wrong dependency section (DEPS-005), no
automated update configuration (DEPS-006) and licences that need a decision
(DEPS-007).

Offline, DEPS-001 uses the small advisory table below. It is a safety net,
not an audit: each row carries its source URL and the date it was checked
(2026-11-13). With ``--allow-network`` and a lockfile it also runs the package
manager's own audit and reports high and critical advisories.

What it deliberately does not do: it never installs or runs project code, and
it never contacts a registry unless ``--allow-network`` is passed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import catalog, findings, jsast, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_deps")
ALSO_EMITS: List[str] = []

# package -> list of (advisory id, severity, [(low inclusive, high exclusive)], fixed text, source URL). Last checked 2026-11-13.
ADVISORIES: Dict[str, List[Tuple[str, str, List[Tuple[str, str]], str, str]]] = {
    "next": [
        ("CVE-2025-29927 (middleware authorization bypass)", "critical",
         [("12.0.0", "12.3.5"), ("13.0.0", "13.5.9"), ("14.0.0", "14.2.25"), ("15.0.0", "15.2.3")],
         "12.3.5, 13.5.9, 14.2.25 or 15.2.3", "https://github.com/advisories/GHSA-f82v-jwr5-mffw"),
        ("CVE-2025-66478 (React Server Components remote code execution)", "critical",
         [("15.0.0", "15.0.5"), ("15.1.0", "15.1.9"), ("15.2.0", "15.2.6"), ("15.3.0", "15.3.6"), ("15.4.0", "15.4.8"), ("15.5.0", "15.5.7"), ("16.0.0", "16.0.7")],
         "15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7 or 16.0.7", "https://nextjs.org/blog/CVE-2025-66478"),
        ("CVE-2025-55184 / CVE-2025-67779 (denial of service) and CVE-2025-55183 (source exposure)", "high",
         [("13.3.0", "14.2.35"), ("15.0.0", "15.0.7"), ("15.1.0", "15.1.11"), ("15.2.0", "15.2.8"), ("15.3.0", "15.3.8"), ("15.4.0", "15.4.10"), ("15.5.0", "15.5.9"), ("16.0.0", "16.0.10")],
         "14.2.35, 15.0.7, 15.1.11, 15.2.8, 15.3.8, 15.4.10, 15.5.9 or 16.0.10", "https://nextjs.org/blog/security-update-2025-12-11"),
    ],
    "jsonwebtoken": [
        ("CVE-2022-23540 (unsigned tokens accepted in some configurations)", "medium", [("0.0.0", "9.0.0")], "9.0.0", "https://github.com/advisories/GHSA-qwph-4952-7xr6"),
    ],
    "mongoose": [
        ("CVE-2025-23061 (code injection through $where)", "critical", [("0.0.0", "6.13.6"), ("7.0.0", "7.8.4"), ("8.0.0", "8.9.5")], "6.13.6, 7.8.4 or 8.9.5", "https://github.com/advisories/GHSA-vg7j-7cwx-8wgw"),
    ],
}
# Security support windows. Last checked 2026-11-13 from https://endoflife.date.
NEXT_MIN_SUPPORTED_MAJOR = 15
DJANGO_SUPPORTED = {"5.2", "6.0", "6.1"}

POPULAR = """react react-dom react-router react-router-dom next express lodash axios moment dayjs webpack typescript eslint prettier jest mocha chai
vite vitest tailwindcss postcss autoprefixer mongoose sequelize prisma sharp multer cors dotenv helmet bcrypt bcryptjs jsonwebtoken passport
uuid chalk commander yargs inquirer rxjs redux zustand mobx graphql apollo-server stripe openai firebase supabase nodemailer socket.io
body-parser cookie-parser express-session compression morgan winston pino debug request node-fetch cross-env nodemon concurrently
styled-components framer-motion lucide-react zod yup joi formik classnames immer swr nanoid validator semver minimist glob rimraf
mkdirp fs-extra jquery bootstrap angular vue svelte nuxt remix gatsby puppeteer playwright cheerio marked highlight.js
""".split()
NEAR_OK = {"react-dnd", "preact", "reactn", "react-dom", "express-session", "lodash-es", "moment-timezone", "yargs-parser", "cross-fetch", "node-fetch", "bcrypt", "sequelize", "mongoose", "ts-jest", "vitest"}
NODE_BUILTINS = set("""assert async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns domain events fs http http2 https inspector module net os path perf_hooks process punycode querystring readline repl stream string_decoder sys timers tls trace_events tty url util v8 vm wasi worker_threads zlib fs/promises""".split())
IMPLICIT = {"react-dom", "typescript", "tailwindcss", "postcss", "autoprefixer", "sass", "less", "eslint", "prettier", "server-only", "client-only", "next", "react", "vite", "webpack", "@types/node", "babel-loader", "sharp", "nodemon", "core-js", "tslib", "dotenv", "prisma", "@prisma/client", "ts-node", "tsx", "bufferutil", "utf-8-validate", "pg-native"}
TOOL_PACKAGES = re.compile(r"^(jest|vitest|mocha|chai|nodemon|ts-node|ts-node-dev|tsx|eslint(-.*)?|prettier|typescript|webpack(-cli)?|@types/.*|cypress|@playwright/test|storybook|@storybook/.*|supertest|ts-jest|babel-.*|@babel/.*|husky|lint-staged|concurrently|cross-env|rimraf|prisma|vite|@vitejs/.*|tailwindcss|postcss|autoprefixer|sass|jest-.*|@testing-library/.*)$")
RUNTIME_ONLY_DEV = {"react", "react-dom", "express", "next", "mongoose", "stripe", "openai", "zod", "@supabase/supabase-js", "firebase", "@prisma/client", "jsonwebtoken", "cors", "bcryptjs", "bcrypt"}
RESTRICTIVE_LICENSE = re.compile(r"(?i)\b(AGPL|GPL|SSPL|CC-BY-NC|BUSL|Commons Clause|non-?commercial)\b")


def vtuple(v: str) -> Tuple[int, int, int]:
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", v or "")
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)) if m else (0, 0, 0)


def lockfile_versions(project: walker.Project) -> Dict[str, str]:
    """Exact installed versions from package-lock.json when present."""
    out: Dict[str, str] = {}
    raw = project.read("package-lock.json")
    if raw:
        try:
            data = json.loads(raw)
            for key, val in (data.get("packages") or {}).items():
                if key.startswith("node_modules/") and key.count("node_modules/") == 1 and isinstance(val, dict) and val.get("version"):
                    out[key[len("node_modules/"):]] = str(val["version"])
        except ValueError:
            pass
    return out


def edit_distance(a: str, b: str, limit: int = 2) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def pkg_line(project: walker.Project, name: str) -> int:
    sf = project.get("package.json")
    if not sf:
        return 1
    return next((i for i, l in enumerate(sf.lines, 1) if '"%s"' % name in l), 1)


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_deps", stack)
    allow_network = bool(getattr(getattr(project, "options", None), "allow_network", False))
    deps = project.deps
    pkg_sf = project.get("package.json")
    if not deps and not project.python_deps:
        env.inventory["dependencies"] = {"node": 0}
        return env
    locked = lockfile_versions(project)
    prod = project.package.get("dependencies") or {}
    dev = project.package.get("devDependencies") or {}

    # DEPS-001 offline table and DEPS-002 support windows.
    for name, rows in ADVISORIES.items():
        if name not in deps:
            continue
        version = locked.get(name) or deps[name]
        v = vtuple(version)
        for adv, sev, ranges, fixed, url in rows:
            if any(vtuple(lo) <= v < vtuple(hi) for lo, hi in ranges):
                line = pkg_line(project, name)
                env.add(Finding(
                    "DEPS-001", "The installed %s %s has a known security hole (%s). Attackers scan the internet for apps that run affected versions." % (name, ".".join(map(str, v)), adv.split(" (")[0]),
                    file="package.json", line=line, snippet=pkg_sf.line_text(line) if pkg_sf else "", severity=sev, confidence="confirmed" if name in locked else "likely",
                    subject={"kind": "advisory", "name": "%s:%s" % (name, adv.split(" ")[0])},
                    detail="%s, fixed in %s. Source: %s. Version taken from %s. Offline safety-net table checked 2026-11-13; run `npm audit` for the complete picture." % (adv, fixed, url, "the lockfile" if name in locked else "the range in package.json"),
                    fix_hint="Upgrade %s to the latest patched release of your major version, then run the app's tests and build." % name,
                ))
    nv = deps.get("next")
    if nv and vtuple(locked.get("next") or nv)[0] < NEXT_MIN_SUPPORTED_MAJOR:
        line = pkg_line(project, "next")
        env.add(Finding(
            "DEPS-002", "Next.js %d no longer receives security fixes, so any new vulnerability will stay open." % vtuple(locked.get("next") or nv)[0],
            file="package.json", line=line, snippet=pkg_sf.line_text(line) if pkg_sf else "", confidence="confirmed", subject={"kind": "framework", "name": "next"},
            detail="Next.js security support: 15 until 2027-01-31, 16 current; 14 ended 2025-10-26 (source: endoflife.date, checked 2026-11-13).",
            fix_hint="Plan the upgrade to a supported major version; apply the latest patch of your current one meanwhile.",
        ))
    dj = project.python_deps.get("django")
    if dj is not None:
        m = re.search(r"(\d+\.\d+)", dj)
        if m and m.group(1) not in DJANGO_SUPPORTED:
            env.add(Finding("DEPS-002", "Django %s no longer receives security fixes." % m.group(1), file="requirements.txt", line=1, snippet="django" + dj, confidence="likely", subject={"kind": "framework", "name": "django"}, detail="Supported Django releases on 2026-11-13: 5.2 LTS, 6.0, 6.1 (source: endoflife.date).", fix_hint="Upgrade to a supported release."))

    # Imports, for DEPS-003 and DEPS-004.
    imported: Dict[str, Tuple[str, int]] = {}
    script_text = " ".join(str(v) for v in (project.package.get("scripts") or {}).values())
    config_text = " ".join(project.read(r) for r in ("vite.config.ts", "vite.config.js", "next.config.js", "next.config.mjs", "tailwind.config.js", "tailwind.config.ts", "postcss.config.js", ".eslintrc.json", "jest.config.js", "vitest.config.ts", "babel.config.js", "svelte.config.js", "astro.config.mjs", "nuxt.config.ts"))
    for sf in project.code_files(walker.JS_EXTS, include_tests=True):
        for imp in jsast.find_imports(project.text(sf)):
            if ":" in imp.spec:
                continue
            pkg = jsast.package_of(imp.spec)
            if pkg and pkg not in imported:
                imported[pkg] = (sf.rel, imp.line)
    declared = set(deps)
    for pkg, (rel, line) in sorted(imported.items()):
        if pkg in declared or pkg in NODE_BUILTINS or pkg in ("server-only", "client-only") or pkg.startswith("@types/"):
            continue
        if re.search(r"^(react|next)/", pkg) or pkg in ("fs", "path"):
            continue
        sfm = project.get(rel)
        env.add(Finding(
            "DEPS-003", "The code imports `%s`, which is not in the dependency list. It either works only by accident on your machine, or the name was invented by an AI tool and an attacker may have registered it." % pkg,
            file=rel, line=line, snippet=sfm.line_text(line) if sfm else "", confidence="likely", subject={"kind": "package", "name": pkg},
            detail="`%s` is imported but not declared in package.json." % pkg,
            fix_hint="Add the real package you intended (check its name and publisher on the registry) or remove the import.",
        ))
    for name in sorted(declared):
        if name in NEAR_OK or name.startswith("@types/"):
            continue
        for pop in POPULAR:
            if len(pop) >= 6 and name != pop and abs(len(name) - len(pop)) <= 2 and edit_distance(name, pop) <= 2 and not name.startswith(pop + "-") and not pop.startswith(name + "-") and not name.endswith("-" + pop) and name not in POPULAR:
                line = pkg_line(project, name)
                env.add(Finding(
                    "DEPS-003", "`%s` looks like a misspelling of the popular package `%s`. Attackers publish look-alike packages that steal secrets when installed." % (name, pop),
                    file="package.json", line=line, snippet=pkg_sf.line_text(line) if pkg_sf else "", confidence="likely", subject={"kind": "package", "name": name},
                    detail="Edit distance from `%s` is %d." % (pop, edit_distance(name, pop)),
                    fix_hint="Replace it with the intended package after checking the registry page, and remove the look-alike.",
                ))
                break
    # DEPS-004 unused production dependencies.
    haystack = script_text + " " + config_text
    unused = [n for n in sorted(prod) if n not in imported and n not in IMPLICIT and not TOOL_PACKAGES.match(n) and n not in haystack and not n.startswith("@types/") and not n.startswith("@")
              or (n.startswith("@") and n not in imported and n not in IMPLICIT and n not in haystack and not any(i.startswith(n + "/") for i in imported))]
    unused = [n for n in unused if not any(n.split("/")[0] == i.split("/")[0] and n.startswith("@") for i in imported)]
    for n in unused[:6]:
        line = pkg_line(project, n)
        env.add(Finding(
            "DEPS-004", "`%s` is listed as a dependency but nothing in the code uses it. Each unused package is extra attack surface and upgrade work." % n,
            file="package.json", line=line, snippet=pkg_sf.line_text(line) if pkg_sf else "", confidence="likely", subject={"kind": "package", "name": n},
            detail="No import of %s found in source files, scripts or config." % n,
            fix_hint="Remove it after confirming the build still passes.",
        ))
    # DEPS-005 tools in dependencies, runtime packages in devDependencies.
    for n in sorted(prod):
        if TOOL_PACKAGES.match(n) and n not in ("prisma", "tailwindcss", "postcss", "autoprefixer", "typescript", "vite", "@vitejs/plugin-react"):
            line = pkg_line(project, n)
            env.add(Finding(
                "DEPS-005", "`%s` is a development tool but is installed in production, which enlarges the attack surface." % n,
                file="package.json", line=line, snippet=pkg_sf.line_text(line) if pkg_sf else "", confidence="likely", subject={"kind": "package", "name": n},
                detail="Test runners, linters and build tools belong in devDependencies.",
                fix_hint="Move it to devDependencies.",
            ))
    for n in sorted(dev):
        if n in RUNTIME_ONLY_DEV and n in imported and project.package.get("scripts", {}).get("start") and not project.classify(project.get(imported[n][0])) in ("client",):
            line = pkg_line(project, n)
            env.add(Finding(
                "DEPS-005", "`%s` is needed at run time but is listed as a development-only package, so a production install may leave it out and crash." % n,
                file="package.json", line=line, snippet=pkg_sf.line_text(line) if pkg_sf else "", confidence="possible", subject={"kind": "package", "name": n},
                detail="Imported by server code but declared in devDependencies.", fix_hint="Move it to dependencies.",
            ))
    # DEPS-006 automated updates.
    paths = project.all_paths()
    if (project.package or project.python_deps) and not any(re.search(r"(^|/)(dependabot\.ya?ml|renovate\.json5?|\.renovaterc(\.json)?)$", p) for p in paths):
        env.add(Finding(
            "DEPS-006", "Nothing tells you when a new security fix is released for the packages you use.",
            file=None, line=None, snippet="", confidence="confirmed", subject={"kind": "project", "name": "dependency-updates"},
            detail="No Dependabot or Renovate configuration.",
            fix_hint="Add .github/dependabot.yml with weekly grouped updates and enable security updates.",
        ))
    # DEPS-007 licences (only when node_modules metadata is present).
    for n in sorted(prod):
        meta = project.read_outside_index("node_modules/%s/package.json" % n)
        if not meta:
            continue
        try:
            lic = json.loads(meta).get("license")
        except ValueError:
            continue
        lic = lic if isinstance(lic, str) else (lic or {}).get("type", "") if isinstance(lic, dict) else ""
        if lic and RESTRICTIVE_LICENSE.search(lic):
            line = pkg_line(project, n)
            env.add(Finding(
                "DEPS-007", "`%s` is licensed %s, which can oblige you to publish your own source or forbids commercial use. This needs a decision before you sell the product." % (n, lic),
                file="package.json", line=line, snippet=pkg_sf.line_text(line) if pkg_sf else "", confidence="likely", severity="medium", subject={"kind": "package", "name": n},
                detail="Licence %s read from installed package metadata. This is not legal advice." % lic,
                fix_hint="Ask whoever advises you on licences, or choose an alternative package.",
            ))
    # Optional network audit.
    audited = False
    if allow_network:
        mgr = {"pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn", "package-lock.json": "npm"}
        for lock, tool in mgr.items():
            if project.exists(lock) and shutil.which(tool):
                try:
                    out = subprocess.run([tool, "audit", "--json"] if tool != "yarn" else [tool, "audit", "--json"], cwd=project.root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
                    data = json.loads(out.stdout.decode("utf-8", "replace") or "{}")
                    for name, vuln in (data.get("vulnerabilities") or {}).items():
                        if vuln.get("severity") in ("high", "critical") and vuln.get("isDirect"):
                            line = pkg_line(project, name)
                            env.add(Finding("DEPS-001", "`%s` has a %s severity known vulnerability according to the registry's audit." % (name, vuln["severity"]), file="package.json", line=line, snippet=pkg_sf.line_text(line) if pkg_sf else "", severity=vuln["severity"], confidence="confirmed", subject={"kind": "advisory", "name": "audit:" + name}, detail="Reported by `%s audit`; fix available: %s." % (tool, vuln.get("fixAvailable")), fix_hint="Run `%s audit fix` or upgrade the package, then test." % tool))
                    audited = True
                except (OSError, subprocess.SubprocessError, ValueError):
                    env.warn("scan_deps: %s audit could not run" % tool)
                break
    if not audited:
        env.warn("scan_deps: full vulnerability audit skipped (offline). Only the bundled advisory table was used; run `npm audit` or pass --allow-network.")
    env.inventory["dependencies"] = {"node": len(deps), "production": len(prod), "locked": bool(locked), "audit": "registry" if audited else "offline-table"}
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    def configure(p: Any) -> None:
        p.add_argument("--allow-network", action="store_true", help="also run the package manager's audit (contacts the registry)")

    return findings.run_scanner_cli("scan_deps", __doc__ or "", scan, argv, configure)


if __name__ == "__main__":
    raise SystemExit(main())
