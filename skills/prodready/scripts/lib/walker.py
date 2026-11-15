"""File discovery, lazy text loading and file classification for the scanners.

``Project`` walks the app once and is shared by every scanner in a run, so
each file is read at most once. It never follows a symlink out of the app
root, never executes anything from the app, and only reads.

Limits, stated plainly: ``.gitignore`` support is simplified (root file only,
plain, directory and wildcard patterns, negation); classification of a file as
client or server code follows framework conventions and one level of imports,
so a scanner must treat it as a strong hint, not proof.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

ALWAYS_SKIP_DIRS = {
    ".git", "node_modules", ".next", ".nuxt", ".svelte-kit", ".output", ".vercel", ".netlify", ".turbo", ".cache",
    "coverage", "venv", ".venv", "__pycache__", "vendor", "Pods", ".expo", ".prodready", ".idea", ".vscode",
    ".pytest_cache", ".mypy_cache", ".parcel-cache", ".angular", ".gradle", "DerivedData", ".dart_tool",
}
BUILD_DIRS = {"dist", "build", "out"}
CODE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro", ".py", ".dart"}
JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro"}
ASSET_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp", ".tiff", ".svg", ".woff", ".woff2", ".ttf", ".otf",
    ".eot", ".mp4", ".webm", ".mov", ".mp3", ".wav", ".ogg", ".pdf", ".zip", ".gz", ".tar", ".wasm", ".psd", ".ai",
}
KEY_FILE_EXTS = {".p12", ".pfx", ".keystore", ".jks", ".pem", ".key"}
DOC_EXTS = {".md", ".mdx", ".txt", ".rst", ".adoc"}
CONFIG_EXTS = {".json", ".jsonc", ".toml", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".xml", ".plist", ".properties", ".lock", ".nix", ".prisma", ".graphql", ".gql"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "poetry.lock", "Pipfile.lock", "composer.lock", "Cargo.lock", "Gemfile.lock", "uv.lock", "npm-shrinkwrap.json"}
SERVER_DIR_NAMES = {"server", "api", "functions", "worker", "workers", "backend", "lambda", "lambdas", "edge-functions"}
ENV_FILE_RE = re.compile(r"(^|/)\.env(\.[A-Za-z0-9_.-]+)?$")
ENV_EXAMPLE_RE = re.compile(r"(^|/)\.env\.(example|sample|template|defaults|dist)$|(^|/)\.env\.[\w.-]*example[\w.-]*$|(^|/)env\.example$")
TEST_PATH_RE = re.compile(r"(^|/)(__tests__|__mocks__|tests?|e2e|cypress|playwright|spec)(/|$)|\.(test|spec|e2e|stories)\.[a-z]+$|(^|/)test_[\w-]+\.py$|_test\.(py|go|dart)$")


def is_env_file(rel: str) -> bool:
    return bool(ENV_FILE_RE.search(rel))


def is_env_example(rel: str) -> bool:
    return bool(ENV_EXAMPLE_RE.search(rel))


class SourceFile:
    """One file in the app. Text is loaded on first use and cached."""

    __slots__ = ("rel", "abs", "size", "ext", "name", "_text", "_lines", "binary", "skipped", "_kind", "ignored")

    def __init__(self, rel: str, abs_path: str, size: int) -> None:
        self.rel = rel
        self.abs = abs_path
        self.size = size
        self.name = rel.rsplit("/", 1)[-1]
        self.ext = os.path.splitext(self.name)[1].lower()
        self._text: Optional[str] = None
        self._lines: Optional[List[str]] = None
        self.binary = False
        self.skipped = False
        self.ignored = False
        self._kind: Optional[str] = None

    def load(self, max_size: int) -> str:
        if self._text is not None:
            return self._text
        if self.ext in ASSET_EXTS and self.ext != ".svg" or self.size > max_size:
            self.skipped = self.size > max_size
            self.binary = self.ext in ASSET_EXTS
            self._text = ""
            return self._text
        try:
            with open(self.abs, "rb") as fh:
                data = fh.read()
        except OSError:
            self.skipped = True
            self._text = ""
            return self._text
        if b"\x00" in data[:8192]:
            self.binary = True
            self._text = ""
            return self._text
        self._text = data.decode("utf-8", errors="replace").replace("\r\n", "\n")
        return self._text

    @property
    def text(self) -> str:
        return self._text if self._text is not None else self.load(1500000)

    @property
    def lines(self) -> List[str]:
        if self._lines is None:
            self._lines = self.text.split("\n")
        return self._lines

    def line_of(self, offset: int) -> int:
        return self.text.count("\n", 0, max(0, offset)) + 1

    def line_text(self, line: int) -> str:
        lines = self.lines
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""

    @property
    def minified(self) -> bool:
        t = self.text
        if len(t) < 3000:
            return False
        n = t.count("\n") + 1
        return len(t) / float(n) > 400 or self.name.endswith(".min.js")

    @property
    def is_lockfile(self) -> bool:
        return self.name in LOCKFILES


class _GitIgnore:
    def __init__(self, text: str) -> None:
        self.rules: List[Tuple[bool, str, bool, bool]] = []  # (negated, pattern, anchored, dir_only)
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            neg = line.startswith("!")
            if neg:
                line = line[1:]
            anchored = line.startswith("/") or ("/" in line.rstrip("/"))
            dir_only = line.endswith("/")
            pat = line.strip("/")
            if pat:
                self.rules.append((neg, pat, anchored, dir_only))

    @staticmethod
    def _match_one(rel: str, pat: str, anchored: bool) -> bool:
        parts = rel.split("/")
        if pat.startswith("**/"):
            pat = pat[3:]
            anchored = False
        if anchored:
            if fnmatch.fnmatchcase(rel, pat) or fnmatch.fnmatchcase(rel, pat + "/*"):
                return True
            for i in range(1, len(parts)):
                if fnmatch.fnmatchcase("/".join(parts[:i]), pat):
                    return True
            return False
        return any(fnmatch.fnmatchcase(seg, pat) for seg in parts)

    def ignored(self, rel: str) -> bool:
        result = False
        for neg, pat, anchored, _dir_only in self.rules:
            if self._match_one(rel, pat, anchored):
                result = not neg
        return result


class Project:
    """The app being scanned: its files, its manifest, and shared caches."""

    def __init__(self, root: str, include: Sequence[str] = (), exclude: Sequence[str] = (), max_size: int = 1500000) -> None:
        self.root = os.path.abspath(root)
        self.include = list(include or [])
        self.exclude = list(exclude or [])
        self.max_size = max_size
        self.warnings: List[str] = []
        self.stack: Optional[Dict[str, Any]] = None
        self.cache: Dict[str, Any] = {}
        self.options: Any = None
        self.files: List[SourceFile] = []
        self.build_files: List[SourceFile] = []
        self.assets: List[SourceFile] = []
        self._by_rel: Dict[str, SourceFile] = {}
        self._tracked: Optional[Set[str]] = None
        self._git_checked = False
        self._package: Optional[Dict[str, Any]] = None
        self.config: Dict[str, Any] = {}
        cfg_path = os.path.join(self.root, ".prodready.json")
        if os.path.isfile(cfg_path):
            try:
                loaded = json.loads(self._read_raw(cfg_path))
                if isinstance(loaded, dict):
                    self.config = loaded
                else:
                    self.warnings.append(".prodready.json must contain a JSON object; it was ignored")
            except ValueError:
                self.warnings.append(".prodready.json is not valid JSON; it was ignored")
        for pattern in self.config.get("exclude") or []:
            if isinstance(pattern, str):
                self.exclude.append(pattern)
        gi_path = os.path.join(self.root, ".gitignore")
        self.has_gitignore = os.path.isfile(gi_path)
        self.gitignore = _GitIgnore(self._read_raw(gi_path) if self.has_gitignore else "")
        self._walk()

    # -- discovery ----------------------------------------------------------

    @staticmethod
    def _read_raw(path: str) -> str:
        try:
            with open(path, "rb") as fh:
                return fh.read().decode("utf-8", errors="replace").replace("\r\n", "\n")
        except OSError:
            return ""

    def _selected(self, rel: str) -> bool:
        if self.include and not any(fnmatch.fnmatchcase(rel, g) for g in self.include):
            return False
        if any(fnmatch.fnmatchcase(rel, g) or fnmatch.fnmatchcase(rel, g.rstrip("/*") + "/*") for g in self.exclude):
            return False
        return True

    def _inside_root(self, path: str) -> bool:
        real = os.path.realpath(path)
        root = os.path.realpath(self.root)
        return real == root or real.startswith(root + os.sep)

    def _walk(self) -> None:
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            rel_dir = os.path.relpath(dirpath, self.root).replace(os.sep, "/")
            rel_dir = "" if rel_dir == "." else rel_dir
            in_build = bool(rel_dir) and rel_dir.split("/")[0] in BUILD_DIRS
            kept = []
            for d in sorted(dirnames):
                full = os.path.join(dirpath, d)
                if d in ALWAYS_SKIP_DIRS or (os.path.islink(full) and not self._inside_root(full)):
                    continue
                kept.append(d)
            dirnames[:] = kept
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if os.path.islink(full) and not self._inside_root(full):
                    continue
                rel = (rel_dir + "/" + name) if rel_dir else name
                if not self._selected(rel):
                    continue
                try:
                    size = os.path.getsize(full)
                except OSError:
                    continue
                sf = SourceFile(rel, full, size)
                if in_build:
                    self.build_files.append(sf)
                    continue
                sf.ignored = self.gitignore.ignored(rel)
                if sf.ignored and not is_env_file(rel):
                    continue
                self._by_rel[rel] = sf
                if sf.ext in ASSET_EXTS and sf.ext != ".svg" or sf.ext in KEY_FILE_EXTS and sf.ext not in (".pem", ".key"):
                    self.assets.append(sf)
                else:
                    self.files.append(sf)
        # Next.js ships .next/static to browsers; it is the only part of .next we look at.
        static = os.path.join(self.root, ".next", "static")
        if os.path.isdir(static):
            for dirpath, dirnames, filenames in os.walk(static, followlinks=False):
                dirnames.sort()
                for name in sorted(filenames):
                    full = os.path.join(dirpath, name)
                    rel = os.path.relpath(full, self.root).replace(os.sep, "/")
                    try:
                        self.build_files.append(SourceFile(rel, full, os.path.getsize(full)))
                    except OSError:
                        continue

    # -- access -------------------------------------------------------------

    def get(self, rel: str) -> Optional[SourceFile]:
        return self._by_rel.get(rel)

    def exists(self, rel: str) -> bool:
        return rel in self._by_rel

    def any_exists(self, *rels: str) -> Optional[str]:
        for r in rels:
            if r in self._by_rel:
                return r
        return None

    def text(self, sf: SourceFile) -> str:
        t = sf.load(self.max_size)
        return t

    def read(self, rel: str) -> str:
        sf = self._by_rel.get(rel)
        return self.text(sf) if sf else ""

    def read_outside_index(self, rel: str) -> str:
        """Read a file by path even if the walker skipped its directory (for example node_modules metadata)."""
        full = os.path.join(self.root, rel.replace("/", os.sep))
        if not os.path.isfile(full) or not self._inside_root(full):
            return ""
        return self._read_raw(full)

    def all_paths(self) -> List[str]:
        return sorted(self._by_rel)

    def glob(self, pattern: str) -> List[SourceFile]:
        return [self._by_rel[r] for r in sorted(self._by_rel) if fnmatch.fnmatchcase(r, pattern)]

    def code_files(self, exts: Optional[Set[str]] = None, include_tests: bool = False) -> Iterator[SourceFile]:
        """Source code files, skipping minified bundles and (by default) tests."""
        want = exts or CODE_EXTS
        for sf in self.files:
            if sf.ext not in want or (sf.ignored and not is_env_file(sf.rel)):
                continue
            text = self.text(sf)
            if not text or sf.minified:
                continue
            if not include_tests and self.classify(sf) == "test":
                continue
            yield sf

    def iter_files(self) -> Iterator[Tuple[str, SourceFile]]:
        for sf in self.files:
            yield sf.rel, sf

    def stats(self) -> Tuple[int, int]:
        scanned = sum(1 for f in self.files if f._text is not None and not f.skipped)
        skipped = sum(1 for f in self.files if f.skipped)
        return scanned, skipped

    # -- git ----------------------------------------------------------------

    def _load_git(self) -> None:
        if self._git_checked:
            return
        self._git_checked = True
        if not os.path.exists(os.path.join(self.root, ".git")):
            return
        try:
            out = subprocess.run(
                ["git", "-C", self.root, "ls-files", "-z"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            return
        if out.returncode != 0:
            return
        self._tracked = {p for p in out.stdout.decode("utf-8", errors="replace").split("\x00") if p}

    @property
    def is_git_repo(self) -> bool:
        return os.path.exists(os.path.join(self.root, ".git"))

    def is_tracked(self, rel: str) -> Optional[bool]:
        """True or False when the app root is a git repository; None when git cannot tell us."""
        self._load_git()
        if self._tracked is None:
            return None
        return rel in self._tracked

    def will_be_committed(self, rel: str) -> bool:
        """Tracked by git, or (when git cannot tell us) not covered by .gitignore."""
        tracked = self.is_tracked(rel)
        if tracked is not None:
            return tracked
        return not self.gitignore.ignored(rel)

    # -- manifest -----------------------------------------------------------

    @property
    def package(self) -> Dict[str, Any]:
        if self._package is None:
            self._package = {}
            raw = self.read("package.json")
            if raw:
                try:
                    data = json.loads(raw)
                    if isinstance(data, dict):
                        self._package = data
                except ValueError:
                    self.warnings.append("package.json is not valid JSON; dependency-based detection is limited")
        return self._package

    @property
    def deps(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            section = self.package.get(key)
            if isinstance(section, dict):
                for k, v in section.items():
                    out.setdefault(str(k), str(v))
        return out

    @property
    def python_deps(self) -> Dict[str, str]:
        if "python_deps" not in self.cache:
            out: Dict[str, str] = {}
            for rel in ("requirements.txt", "requirements/base.txt", "requirements/prod.txt", "requirements/production.txt"):
                for line in self.read(rel).splitlines():
                    m = re.match(r"\s*([A-Za-z0-9_.\-\[\]]+)\s*(?:([=<>~!]=?)\s*([\w.*]+))?", line)
                    if m and not line.strip().startswith(("#", "-")):
                        out[m.group(1).split("[")[0].lower()] = (m.group(2) or "") + (m.group(3) or "")
            pyproject = self.read("pyproject.toml")
            for m in re.finditer(r"[\"']([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:([=<>~!^]=?)\s*([\w.*]+))?[^\"']*[\"']\s*,?", pyproject):
                name = m.group(1).lower()
                if name in ("django", "flask", "fastapi", "uvicorn", "gunicorn", "sqlalchemy", "pydantic", "requests", "openai", "anthropic", "stripe", "celery", "supabase", "firebase-admin", "pyjwt"):
                    out.setdefault(name, (m.group(2) or "") + (m.group(3) or ""))
            for m in re.finditer(r"(?m)^([A-Za-z0-9_.\-]+)\s*=\s*[\"{]", self.read("Pipfile")):
                out.setdefault(m.group(1).lower(), "")
            self.cache["python_deps"] = out
        return self.cache["python_deps"]

    @property
    def framework(self) -> str:
        """Short framework name used for classification. detect_stack reports the detailed version."""
        if self.stack and isinstance(self.stack.get("framework"), dict) and self.stack["framework"].get("name"):
            return str(self.stack["framework"]["name"])
        if "framework" not in self.cache:
            self.cache["framework"] = self._guess_framework()
        return self.cache["framework"]

    def _guess_framework(self) -> str:
        d = self.deps
        if "next" in d:
            return "nextjs"
        if "nuxt" in d or "nuxt3" in d:
            return "nuxt"
        if "@sveltejs/kit" in d:
            return "sveltekit"
        if any(k.startswith("@remix-run/") for k in d) or "@react-router/dev" in d:
            return "remix"
        if "astro" in d:
            return "astro"
        if "expo" in d:
            return "expo"
        if "react-native" in d:
            return "react-native"
        if "@capacitor/core" in d and "vite" not in d and "react-scripts" not in d:
            return "capacitor"
        if "react-scripts" in d:
            return "cra"
        if "vite" in d:
            if "react" in d:
                return "vite-react"
            if "vue" in d:
                return "vite-vue"
            if "svelte" in d:
                return "vite-svelte"
            return "vite"
        if "@angular/core" in d:
            return "angular"
        for name in ("express", "fastify", "hono", "koa", "@nestjs/core"):
            if name in d:
                return name.replace("@nestjs/core", "nestjs")
        p = self.python_deps
        for name in ("django", "fastapi", "flask"):
            if name in p:
                return name
        if self.exists("manage.py"):
            return "django"
        if self.exists("pubspec.yaml"):
            return "flutter"
        if self.exists("composer.json"):
            raw = self.read("composer.json")
            if "laravel/framework" in raw or self.exists("artisan"):
                return "laravel"
        return "unknown"

    # -- classification -----------------------------------------------------

    def _client_imported(self) -> Set[str]:
        """Files imported (one level) by files that carry a top-level "use client" directive."""
        if "client_imported" in self.cache:
            return self.cache["client_imported"]
        out: Set[str] = set()
        imp = re.compile(r"(?:from\s+|import\s+|require\(\s*)[\"']([^\"']+)[\"']")
        for sf in self.files:
            if sf.ext not in JS_EXTS:
                continue
            text = self.text(sf)
            if not re.match(r"\s*(?:/\*[\s\S]*?\*/\s*|//[^\n]*\n\s*)*[\"']use client[\"']", text):
                continue
            base = sf.rel.rsplit("/", 1)[0] if "/" in sf.rel else ""
            for m in imp.finditer(text):
                spec = m.group(1)
                target = self.resolve_import(spec, base)
                if target:
                    out.add(target)
        self.cache["client_imported"] = out
        return out

    def resolve_import(self, spec: str, base_dir: str) -> Optional[str]:
        """Resolve a relative or alias import to a file in the project, if it exists."""
        if spec.startswith("."):
            cand = os.path.normpath(os.path.join(base_dir, spec)).replace(os.sep, "/")
        elif spec.startswith("@/") or spec.startswith("~/"):
            rest = spec[2:]
            cand = None
            for prefix in ("src/", "", "app/"):
                if self._resolve_file(prefix + rest):
                    cand = prefix + rest
                    break
            if cand is None:
                return None
        else:
            return None
        return self._resolve_file(cand)

    def _resolve_file(self, cand: str) -> Optional[str]:
        if cand in self._by_rel:
            return cand
        for ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".vue", ".svelte"):
            if cand + ext in self._by_rel:
                return cand + ext
        for ext in (".ts", ".tsx", ".js", ".jsx"):
            if cand + "/index" + ext in self._by_rel:
                return cand + "/index" + ext
        return None

    def classify(self, sf: SourceFile) -> str:
        """One of client, server, shared, config, migration, rules, test, doc, asset."""
        if sf._kind is None:
            sf._kind = self._classify(sf)
        return sf._kind

    def _classify(self, sf: SourceFile) -> str:
        rel, name, ext = sf.rel, sf.name, sf.ext
        low = rel.lower()
        if ext in ASSET_EXTS or ext in KEY_FILE_EXTS:
            return "asset"
        if ext == ".sql" or "/migrations/" in "/" + low:
            return "migration"
        if ext == ".rules" or name == "database.rules.json":
            return "rules"
        if TEST_PATH_RE.search(low) and ext in CODE_EXTS | {".sql"}:
            return "test"
        if ext in DOC_EXTS or name in ("LICENSE", "NOTICE", "AUTHORS"):
            return "doc"
        if is_env_file(rel) or ext in CONFIG_EXTS or name in ("Dockerfile", "Procfile", "Makefile", ".replit", ".gitignore", ".dockerignore", "_headers", "_redirects", ".nvmrc", ".node-version", ".python-version", ".npmrc") or name.startswith("Dockerfile"):
            return "config"
        if ext == ".html":
            return "client"
        if ext not in CODE_EXTS:
            return "config"
        if re.search(r"(^|/)[\w.-]+\.config\.[cm]?[jt]s$", rel) or name in ("next-env.d.ts", "vite-env.d.ts"):
            return "config"
        if ext == ".py":
            return "server"
        text = self.text(sf)
        fw = self.framework
        parts = rel.split("/")
        head = re.match(r"\s*(?:/\*[\s\S]*?\*/\s*|//[^\n]*\n\s*)*[\"'](use client|use server)[\"']", text)
        directive = head.group(1) if head else None
        if directive == "use client":
            return "client"
        if directive == "use server" or re.search(r"import\s+[\"']server-only[\"']", text):
            return "server"
        if rel.startswith("supabase/functions/") or rel.startswith("netlify/functions/") or rel.startswith("netlify/edge-functions/"):
            return "server"
        if fw == "nextjs":
            if re.search(r"(^|/)route\.[cm]?[jt]sx?$", rel) or re.match(r"(src/)?(middleware|proxy|instrumentation)\.[cm]?[jt]s$", rel):
                return "server"
            if re.match(r"(src/)?pages/api/", rel) or re.match(r"(src/)?app/api/", rel):
                return "server"
            if rel in self._client_imported():
                return "shared"
            if re.match(r"(src/)?pages/", rel):
                return "shared"
            if re.match(r"(src/)?app/", rel):
                return "server"
            has_app = any(p.startswith("app/") or p.startswith("src/app/") for p in self._by_rel)
            if not has_app:
                return "shared"
            if re.match(r"(src/)?(hooks|contexts|context|stores?)/", rel) or re.search(r"\buse(State|Effect|Ref|Context)\(|\bwindow\.|\bdocument\.|localStorage", text):
                return "client"
            return "server"
        if fw in ("remix",):
            if ".server." in name or "/.server/" in "/" + rel:
                return "server"
            if ".client." in name:
                return "client"
            return "shared"
        if fw == "sveltekit":
            if re.search(r"\+(server|page\.server|layout\.server)\.[jt]s$", name) or name.startswith("hooks.server.") or "/lib/server/" in "/" + rel or ".server." in name:
                return "server"
            return "client" if ext == ".svelte" else "shared"
        if fw == "nuxt":
            if parts[0] == "server" or (len(parts) > 1 and parts[0] in ("src", "app") and parts[1] == "server"):
                return "server"
            return "shared"
        if fw == "astro":
            if re.match(r"src/pages/.*\.[jt]s$", rel) or rel.startswith("src/actions/") or name == "middleware.ts":
                return "server"
            return "shared"
        if fw in ("expo", "react-native", "capacitor", "flutter"):
            if "+api." in name or parts[0] in ("server", "backend", "api", "functions"):
                return "server"
            return "client"
        if fw in ("vite-react", "vite-vue", "vite-svelte", "vite", "cra", "angular"):
            if parts[0] in SERVER_DIR_NAMES or (parts[0] == "src" and len(parts) > 1 and parts[1] in ("server", "backend")):
                return "server"
            return "client"
        if fw in ("express", "fastify", "hono", "koa", "nestjs"):
            if parts[0] in ("client", "frontend", "web", "public") or ext in (".jsx", ".tsx", ".vue", ".svelte"):
                return "client"
            return "server"
        if parts[0] in SERVER_DIR_NAMES:
            return "server"
        if ext in (".jsx", ".tsx", ".vue", ".svelte") or re.search(r"\bwindow\.|\bdocument\.|from\s+[\"']react[\"']", text):
            return "client"
        return "shared"


def iter_files(root: str, include: Sequence[str] = (), exclude: Sequence[str] = (), max_size: int = 1500000) -> Iterator[Tuple[str, SourceFile]]:
    """Yield (relative path, file) pairs. Text is loaded lazily through ``file.text``."""
    project = Project(root, include=include, exclude=exclude, max_size=max_size)
    for rel, sf in project.iter_files():
        sf.load(max_size)
        yield rel, sf


def snippet_at(sf: SourceFile, line: int) -> str:
    return sf.line_text(line)
