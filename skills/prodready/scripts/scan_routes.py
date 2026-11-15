#!/usr/bin/env python3
"""Inventory every server entry point and check how each one handles identity and input.

Step 1 builds ``inventory.routes``: route handlers, server actions, edge and
cloud functions, Express-style routes and Python views, with what each one
reads, what privileged clients it touches, and whether it checks who is
calling. Step 2 turns combinations into findings: privileged access with no
authentication (AUTH-002), middleware gaps (AUTH-003), client-supplied
identity (AUTH-004), unsafe cookies, redirects and token verification
(AUTH-007, AUTH-010, AUTH-012, AUTH-018), injection and mass assignment
(DB-012, DB-013, DB-014, DB-018), and the pattern parts of the API, upload,
performance and reliability checks listed in ``IMPLEMENTS``.

What it deliberately does not do: it does not prove that authorisation logic
is correct. A handler marked "present" calls something that looks like an
authentication check; whether the right user is allowed is for the reviewer
(API-005). The analysis is lexical, so findings are ``likely`` at most unless
the pattern is unambiguous.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detect_stack  # noqa: E402
from lib import catalog, findings, jsast, patterns, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_routes")
ALSO_EMITS = ["AUTH-005", "AUTH-013", "AUTH-015", "API-005"]

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
BUILTIN_CAPS = {"Object", "Array", "Promise", "JSON", "Math", "Number", "String", "Date", "Map", "Set", "Response", "NextResponse", "Buffer", "URL", "Error", "Boolean", "Symbol", "Reflect", "Intl", "RegExp", "Headers", "Request", "FormData", "Blob", "File"}
AUTH_ROUTE_RE = re.compile(r"(?i)(log-?in|sign-?in|sign-?up|register|log-?out|sign-?out|callback|forgot|reset|verify|otp|magic|nextauth|(^|/)auth(/|$)|token|refresh|session|password|confirm)")
CRED_ROUTE_RE = re.compile(r"(?i)(log-?in|sign-?in|sign-?up|register|forgot|reset|verify|otp|magic|password)")
HEALTH_RE = re.compile(r"(?i)(^|/)(health|healthz|ready|readyz|live|livez|ping|status)(/|$)")
DEBUG_SEGMENTS = {"debug": "likely", "seed": "likely", "admin-temp": "likely", "migrate": "likely", "phpinfo": "likely", "env": "likely", "test": "possible", "dev": "possible", "setup": "possible", "reset": "possible", "tmp": "possible"}
WRITE_OP_RE = re.compile(r"\.(?:insert|update|upsert|delete|create|createMany|updateMany|deleteMany|deleteOne|updateOne|save|remove|destroy|findByIdAndUpdate|findByIdAndDelete|findOneAndUpdate|findOneAndDelete|set|add)\(|\$executeRaw|\bDELETE\s+FROM\b|\bUPDATE\s+\w+\s+SET\b|\bINSERT\s+INTO\b")
RESPONSE_CALL_RE = re.compile(r"\b(?:res\.(?:status\([^)]*\)\.)?(?:json|send|end)|NextResponse\.json|Response\.json|new\s+Response|c\.json|reply\.send|jsonify|JsonResponse|return\s+json)\s*\(")
ERROR_LEAK_RE = re.compile(r"\b(?:err|error|e|ex|exc)\.(?:stack|message)\b|\berror\s*:\s*(?:err|error|e)\b(?!\.)|String\(\s*(?:err|error|e)\s*\)|\b(?:err|error|e)\.toString\(\)|str\(\s*(?:e|err|exc|error)\s*\)|traceback\.format_exc")
INPUT_EXPR_RE = re.compile(r"(?:req|request|ctx\.request)\.(?:body|query|params)\??\.\w+|(?:req|request)\.(?:body|query|params)\[[^\]]+\]|searchParams\.get\([^)]*\)|request\.(?:args|form|json|values|GET|POST)(?:\.get\([^)]*\)|\[[^\]]+\])")
WHOLE_BODY_RE = re.compile(r"(?:const|let|var)\s+(\w+)\s*(?::\s*[\w<>\[\]{}, |.]+)?=\s*(?:\(\s*)?(?:await\s+(?:req|request|c\.req|event\.request|ctx\.request)\.(?:json|formData)\(\)|(?:req|request)\.body\b(?![.\[])|await\s+readBody\(\w+\)|JSON\.parse\(\s*(?:event\.body|req\.body|body|rawBody|await\s+\w+\.text\(\))[^)]*\))")
DESTRUCT_RE = re.compile(r"(?:const|let|var)\s*\{([^}]*)\}\s*(?::\s*[^=]+?)?=\s*(?:\(\s*)?(?:await\s+)?((?:req|request|c\.req|event\.request|ctx\.request)\.(?:json|formData)\(\)|(?:req|request|ctx\.request|event)\.(?:body|query|params)\b|readBody\(\w+\)|getQuery\(\w+\)|JSON\.parse\([^)]*\)|(?:ctx\.|context\.|props\.)?params\b|[A-Za-z_]\w*\b(?![.(\[]))")
ASSIGN_RE = re.compile(r"(?:const|let|var)\s+(\w+)\s*(?::\s*[\w<>\[\] |]+)?=\s*([^;\n]+)")
PY_ASSIGN_RE = re.compile(r"(?m)^\s*(\w+)\s*=\s*(request\.(?:args|form|json|values|GET|POST|data|query_params)\b[^\n]*|request\.get_json\(\)[^\n]*)")
SQL_SINK_NAMES = ["$queryRawUnsafe", "$executeRawUnsafe", "sql.raw", "knex.raw", "sequelize.query", "pool.query", "client.query", "db.query", "connection.query", "conn.query", "db.execute", "connection.execute", "db.run", "db.all", "db.get", "db.prepare", "pg.query"]
FS_SINK_NAMES = ["fs.readFile", "fs.readFileSync", "fs.createReadStream", "fs.writeFile", "fs.writeFileSync", "fs.unlink", "fs.unlinkSync", "fs.promises.readFile", "fs.promises.writeFile", "readFile", "readFileSync", "createReadStream", "res.sendFile", "res.download", "sendFile", "send_file", "send_from_directory", "open", "path.join", "path.resolve"]
EXEC_SINK_NAMES = ["exec", "execSync", "spawn", "spawnSync", "execFile", "child_process.exec", "child_process.execSync", "eval", "vm.runInNewContext", "vm.runInContext", "vm.runInThisContext", "os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "pickle.loads", "yaml.load"]
FETCH_SINK_NAMES = ["fetch", "axios", "axios.get", "axios.post", "axios.request", "got", "got.get", "ky", "ky.get", "request", "needle", "superagent.get", "page.goto", "requests.get", "requests.post", "httpx.get", "httpx.post", "urllib.request.urlopen", "urlopen", "undici.request", "$fetch", "ofetch"]
REDIRECT_PARAM_RE = re.compile(r"(?i)^(next|redirect|redirectTo|redirect_to|redirect_uri|redirectUrl|returnTo|return_to|returnUrl|return_url|callbackUrl|callback_url|continue|dest|destination|url|goto|target|from)$")
REDIRECT_SINK_RE = re.compile(r"\b(?:redirect|res\.redirect|reply\.redirect|c\.redirect|NextResponse\.redirect|Response\.redirect|router\.(?:push|replace)|navigate|HttpResponseRedirect|RedirectResponse|sendRedirect)\s*\(|\b(?:window\.)?location(?:\.href)?\s*=\s*")
SAFE_REDIRECT_RE = re.compile(r"startsWith\(\s*[\"']/[\"']\s*\)|\.origin\s*[!=]==?|allowedRedirects|ALLOWED_REDIRECT|isSafeRedirect|safeRedirect|url_has_allowed_host_and_scheme|is_safe_url|new URL\([^)]*\)\.origin|\.startswith\(\s*[\"']/[\"']\s*\)")
LOOP_RE = re.compile(r"\bfor\s*(?:await\s*)?\(|\bwhile\s*\(|\.(?:forEach|map)\(\s*async\b")
DB_CALL_RE = re.compile(r"\bawait\s+(?:prisma|db|tx|supabase\w*|pool|client|conn|knex|sequelize)\b[\w.$]*\(|\bawait\s+[A-Z]\w*\.(?:find|findOne|findById|findMany|findUnique|findFirst|count|countDocuments|create|update\w*|delete\w*)\(|\bawait\s+\w+\.(?:findUnique|findFirst|findMany|findById|findOne)\(|\.from\(\s*[\"'][\w.]+[\"']\s*\)\s*\.select\(|\bgetDoc\(|\bcursor\.execute\(|\.objects\.(?:get|filter)\(")
COOKIE_NAME_RE = re.compile(r"(?i)sess|token|auth|jwt|sid|login|user|refresh|access")
FAST_HASH_RE = re.compile(r"createHash\(\s*[\"'](md5|sha1|sha-1|sha256|sha-256|sha512)[\"']\s*\)|hashlib\.(md5|sha1|sha256|sha512)\(|\bmd5\(|CryptoJS\.(MD5|SHA1|SHA256)\(")


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


class Entry:
    """One server entry point with the slice of source that implements it."""

    def __init__(self, rid: str, sf: walker.SourceFile, kind: str, methods: List[str], path: str, start: int, end: int, text: str, lx: Optional[jsast.Lexed]) -> None:
        self.id = rid
        self.sf = sf
        self.kind = kind
        self.methods = methods
        self.path = path
        self.start = start
        self.end = end
        self.line = _line(text, start)
        self.code = (lx.code if lx else text)[start:end]
        self.src = (lx.nocomment if lx else text)[start:end]
        self.file_src = lx.nocomment if lx else text
        self.file_code = lx.code if lx else text
        self.extra_auth = ""
        self.middleware_auth = False
        self.info: Dict[str, Any] = {}

    def line_at(self, rel_offset: int) -> int:
        return _line(self.file_src, self.start + rel_offset)


def _names_from_destructure(raw: str) -> List[str]:
    out = []
    for part in raw.split(","):
        part = part.strip()
        if not part or part.startswith("..."):
            if part.startswith("..."):
                out.append(part[3:].strip())
            continue
        part = part.split("=")[0].strip()
        if ":" in part:
            part = part.split(":")[-1].strip()
        if re.match(r"^[A-Za-z_$][\w$]*$", part):
            out.append(part)
    return out


def taint(src: str, is_py: bool = False, params: str = "") -> Tuple[Set[str], Set[str], Dict[str, str]]:
    """Names in a scope that hold request input: (tainted names, whole-body names, name -> source field)."""
    tainted: Set[str] = set()
    whole: Set[str] = set()
    origin: Dict[str, str] = {}
    if is_py:
        for m in PY_ASSIGN_RE.finditer(src):
            tainted.add(m.group(1))
            if re.search(r"request\.(?:json|form|data)\s*$|get_json\(\)\s*$", m.group(2).strip()):
                whole.add(m.group(1))
        for p in params.split(","):
            name = p.split(":")[0].split("=")[0].strip().lstrip("*")
            if name and name not in ("self", "request", "req", "db", "session", "current_user", "user", "background_tasks", "response", "cls") and "Depends" not in p:
                tainted.add(name)
                if re.search(r":\s*[A-Z]\w+", p) and "=" not in p:
                    whole.add(name)
        return tainted, whole, origin
    for m in WHOLE_BODY_RE.finditer(src):
        whole.add(m.group(1))
        tainted.add(m.group(1))
    for m in DESTRUCT_RE.finditer(src):
        source = m.group(2)
        if re.match(r"^[A-Za-z_]\w*$", source) and source not in whole and source not in ("params", "body", "query"):
            continue
        for name in _names_from_destructure(m.group(1)):
            tainted.add(name)
            origin[name] = name
    for m in ASSIGN_RE.finditer(src):
        rhs = m.group(2)
        if INPUT_EXPR_RE.search(rhs) or re.search(r"\bparams\??\.\w+|formData\.get\(|\.headers\.get\(\s*[\"']x-", rhs) or any(re.search(r"(?<![\w$.])%s\??\.\w+" % re.escape(w), rhs) for w in whole):
            if not re.search(r"\b(?:parseInt|Number|Boolean|z\.|schema\.|\.parse\(|\.safeParse\()", rhs):
                tainted.add(m.group(1))
                fm = re.search(r"\.(\w+)\s*\)?\s*$|\[\s*[\"'](\w+)[\"']\s*\]|get\(\s*[\"'](\w+)[\"']", rhs)
                if fm:
                    origin[m.group(1)] = next(g for g in fm.groups() if g)
    return tainted, whole, origin


def is_tainted(expr: str, tainted: Set[str]) -> Optional[str]:
    m = INPUT_EXPR_RE.search(expr)
    if m:
        return m.group(0)
    for name in sorted(tainted, key=len, reverse=True):
        if re.search(r"(?<![\w$.\"'])%s(?![\w$\"']|\s*:)" % re.escape(name), expr):
            return name
    return None


def privileged_imports(project: walker.Project, sf: walker.SourceFile) -> Dict[str, str]:
    """Local names imported from project modules that construct privileged clients."""
    cache = project.cache.setdefault("priv_imports", {})
    if sf.rel in cache:
        return cache[sf.rel]
    out: Dict[str, str] = {}
    base = sf.rel.rsplit("/", 1)[0] if "/" in sf.rel else ""
    for imp in jsast.find_imports(project.text(sf)):
        target = project.resolve_import(imp.spec, base)
        if not target:
            continue
        ttext = project.read(target)
        label = None
        if re.search(r"createClient[^;]{0,400}?(?:SERVICE_ROLE|SECRET_KEY|SERVICE_KEY|service_role|sb_secret_)", ttext, re.S):
            label = "supabase-service-role"
        elif "new PrismaClient" in ttext:
            label = "prisma"
        elif re.search(r"new\s+Stripe\(", ttext):
            label = "stripe"
        elif re.search(r"new\s+(?:OpenAI|Anthropic|GoogleGenerativeAI|GoogleGenAI|Groq|Mistral)\(|createOpenAI\(|createAnthropic\(", ttext):
            label = "llm"
        elif "mongoose.model(" in ttext or "mongoose.Schema" in ttext:
            label = "mongoose"
        elif re.search(r"drizzle\(", ttext):
            label = "drizzle"
        elif re.search(r"new\s+(?:Pool|Client)\(|postgres\(", ttext):
            label = "sql"
        if label:
            for name in list(imp.names) + [n for n in (imp.default, imp.namespace) if n]:
                out[name] = label
    cache[sf.rel] = out
    return out


def auth_helpers(project: walker.Project, sf: walker.SourceFile) -> Set[str]:
    """Names callable in this file whose definition (here or in an imported project module) checks authentication."""
    cache = project.cache.setdefault("auth_helpers", {})
    if sf.rel in cache:
        return cache[sf.rel]
    out: Set[str] = set()
    if sf.ext == ".py":
        cache[sf.rel] = out
        return out

    def helpers_in(rel: str) -> Set[str]:
        key = "auth_defs:" + rel
        if key not in project.cache:
            text = project.read(rel)
            names: Set[str] = set()
            if text:
                code = jsast.lexed(text).code
                for f in jsast.find_functions(text):
                    if f.name not in METHODS and patterns.AUTH_CALL_RE.search(code[f.body_start:f.end]):
                        names.add(f.name)
            project.cache[key] = names
        return project.cache[key]

    out |= helpers_in(sf.rel)
    base = sf.rel.rsplit("/", 1)[0] if "/" in sf.rel else ""
    for imp in jsast.find_imports(project.text(sf)):
        target = project.resolve_import(imp.spec, base)
        if not target:
            continue
        defined = helpers_in(target)
        for name in imp.names:
            if name in defined:
                out.add(name)
        if imp.default and ("default" in defined or imp.default in defined):
            out.add(imp.default)
    cache[sf.rel] = out
    return out


def analyse(project: walker.Project, e: Entry, stack: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    deps = project.deps
    is_py = e.sf.ext == ".py"
    code, src = e.code, e.src
    auth_m = patterns.AUTH_CALL_RE.search(code if not is_py else src) or (patterns.AUTH_CALL_RE.search(e.extra_auth) if e.extra_auth else None)
    if not auth_m:
        for helper in sorted(auth_helpers(project, e.sf)):
            auth_m = re.search(r"(?<![\w$.])%s\s*\(" % re.escape(helper), code)
            if auth_m and not re.match(r"(?:async\s+)?function|const", code[max(0, auth_m.start() - 20):auth_m.start()].strip()[-8:] or "x"):
                break
            auth_m = None
    auth_status = "present" if auth_m else ("middleware-only" if e.middleware_auth else "none")
    evidence = auth_m.group(0).strip() if auth_m else ("covered only by middleware" if e.middleware_auth else "")
    if e.extra_auth and not patterns.AUTH_CALL_RE.search(code if not is_py else src) and auth_m:
        evidence = "route middleware: " + auth_m.group(0).strip()
    reads: List[str] = []
    for label, rx in (
        ("body", r"\.json\(\)|\.formData\(\)|\b(?:req|request)\.body\b|readBody\(|request\.(?:json|form|data|POST)\b|get_json\("),
        ("query", r"searchParams|\b(?:req|request)\.query\b|getQuery\(|request\.(?:args|GET|query_params)\b"),
        ("params", r"\bparams\b|\b(?:req|request)\.params\b|getRouterParam\("),
        ("headers", r"\.headers\b"),
        ("cookies", r"\bcookies\b"),
    ):
        if re.search(rx, src):
            reads.append(label)
    priv: List[str] = []
    imported = privileged_imports(project, e.sf) if not is_py else {}
    for name, label in sorted(imported.items()):
        if label != "llm" and re.search(r"(?<![\w$.])%s\b\s*(?:\.|\(|\[)" % re.escape(name), code) and label not in priv:
            priv.append(label)
    file_has_service = bool(re.search(r"createClient[^;]{0,400}?(?:SERVICE_ROLE|SECRET_KEY|SERVICE_KEY|service_role)", e.file_src, re.S))
    if "supabase-service-role" not in priv and (re.search(r"supabaseAdmin|adminClient|createAdminClient\(|createServiceClient\(|createServiceRoleClient\(|serviceClient", code) or (file_has_service and re.search(r"\.from\(|\.rpc\(|\.auth\.admin\b|\.storage\b", code))):
        priv.append("supabase-service-role")
    if ("@prisma/client" in deps or "prisma" in deps) and "prisma" not in priv and patterns.PRIVILEGED_CLIENT_RES["prisma"].search(code):
        priv.append("prisma")
    if "drizzle-orm" in deps and "drizzle" not in priv and patterns.PRIVILEGED_CLIENT_RES["drizzle"].search(code):
        priv.append("drizzle")
    if ("mongoose" in deps or "mongodb" in deps) and "mongoose" not in priv:
        for m in patterns.PRIVILEGED_CLIENT_RES["mongoose"].finditer(code):
            if m.group(0).split(".")[0] not in BUILTIN_CAPS:
                priv.append("mongoose")
                break
    if (is_py or any(d in deps for d in ("pg", "mysql2", "postgres", "knex", "sequelize", "better-sqlite3", "sqlite3", "@neondatabase/serverless", "@vercel/postgres"))) and "sql" not in priv and patterns.PRIVILEGED_CLIENT_RES["sql"].search(code):
        priv.append("sql")
    if is_py and patterns.PRIVILEGED_CLIENT_RES["sqlalchemy"].search(src):
        priv.append("orm")
    if ("firebase-admin" in deps or "firebase-admin" in e.file_src) and patterns.PRIVILEGED_CLIENT_RES["firebase-admin"].search(code):
        priv.append("firebase-admin")
    if "stripe" not in priv and patterns.PRIVILEGED_CLIENT_RES["stripe"].search(code):
        priv.append("stripe")
    llm_names = [n for n, label in imported.items() if label == "llm"]
    calls_llm = bool(patterns.LLM_CALL_RE.search(src)) or any(re.search(r"(?<![\w$.])%s\b\s*\." % re.escape(n), code) for n in llm_names)
    sends = bool(patterns.MESSAGE_SEND_RE.search(src)) or bool(re.search(r"api\.resend\.com|api\.sendgrid\.com|api\.mailgun\.net|api\.postmarkapp\.com|api\.twilio\.com|api\.brevo\.com", src))
    is_webhook = "webhook" in e.path.lower() or "webhook" in e.sf.rel.lower() or bool(re.search(r"(?i)stripe-signature|svix-|x-hub-signature|x-signature|x-twilio-signature|paddle-signature", src))
    verifies = bool(patterns.WEBHOOK_VERIFY_RE.search(src)) if is_webhook else None
    ident = patterns.SESSION_IDENTITY_RE.search(code)
    info = {
        "id": e.id, "file": e.sf.rel, "line": e.line, "kind": e.kind, "methods": e.methods,
        "auth": {"status": auth_status, "evidence": evidence},
        "reads_input": reads,
        "validates_input": bool(patterns.VALIDATION_RE.search(src)),
        "privileged_access": priv,
        "ownership_scoped": "unknown" if auth_status == "none" else ("yes" if ident else "no"),
        "rate_limited": bool(patterns.RATE_LIMIT_RE.search(src)) or bool(e.extra_auth and patterns.RATE_LIMIT_RE.search(e.extra_auth)),
        "calls_llm": calls_llm,
        "sends_messages": sends,
        "is_webhook": is_webhook,
        "verifies_signature": verifies,
    }
    e.info = info
    return info


# --- Entry point enumeration ------------------------------------------------

def _route_path(rel: str) -> str:
    p = re.sub(r"^(src/)?(app|pages)", "", rel)
    p = re.sub(r"/(route|index)\.[cm]?[jt]sx?$|\.[cm]?[jt]sx?$", "", p)
    p = re.sub(r"/\([^/)]*\)", "", p)
    return p or "/"


def next_entries(project: walker.Project, sf: walker.SourceFile, text: str, lx: jsast.Lexed) -> List[Entry]:
    out: List[Entry] = []
    rel = sf.rel
    funcs = jsast.find_functions(text)
    by_name = {f.name: f for f in funcs}
    if re.search(r"(^|/)app/.*route\.[cm]?[jt]sx?$", rel):
        path = _route_path(rel)
        exported = [x for x in jsast.find_exports(text) if x.name in METHODS]
        seen = set()
        for ex in exported:
            if ex.name in seen:
                continue
            seen.add(ex.name)
            f = by_name.get(ex.name)
            start, end = (f.start, f.end) if f else (0, len(text))
            out.append(Entry("%s %s" % (ex.name, path), sf, "route-handler", [ex.name], path, start, end, text, lx))
        return out
    if re.match(r"(src/)?pages/api/", rel):
        path = _route_path(rel)
        out.append(Entry("ANY %s" % path, sf, "api-route", ["ANY"], path, 0, len(text), text, lx))
        return out
    if jsast.has_directive(text, "use server"):
        for ex in jsast.find_exports(text):
            f = by_name.get(ex.name)
            if f and ex.kind in ("function", "const", "default"):
                out.append(Entry("action %s" % ex.name, sf, "server-action", ["POST"], "action:" + ex.name, f.start, f.end, text, lx))
        return out
    for f in jsast.functions_with_directive(text, "use server"):
        out.append(Entry("action %s" % f.name, sf, "server-action", ["POST"], "action:" + f.name, f.start, f.end, text, lx))
    return out


EXPRESS_ROUTE_RE = re.compile(r"(?<![\w$.])(app|router|api|server|routes?|\w*[rR]outer|\w*[aA]pp|fastify|hono)\.(get|post|put|patch|delete|all)\(\s*([\"'`])([^\"'`\n]*)\3")
EXPRESS_USE_RE = re.compile(r"(?<![\w$.])(app|router|api|server|\w*[rR]outer|\w*[aA]pp)\.use\(")
NON_AUTH_MW_RE = re.compile(r"(?i)cors|json|static|cookie|urlencoded|helmet|morgan|rate|limit|compress|logger|bodyParser|session\(|csrf|express\.|multer|upload")
AUTH_MW_NAME_RE = re.compile(r"(?i)^(?:\w*auth\w*|\w*protect\w*|\w*guard\w*|\w*jwt\w*|verify\w*|require\w*|ensure\w*|isLoggedIn|loggedIn|checkToken|passport\.authenticate.*)$")


def express_entries(project: walker.Project, sf: walker.SourceFile, text: str, lx: jsast.Lexed, mounts: Dict[str, Dict[str, Any]]) -> List[Entry]:
    out: List[Entry] = []
    code, src = lx.code, lx.nocomment
    mount = mounts.get(sf.rel, {})
    prefix = mount.get("prefix", "")
    file_auth_pos = None
    for m in EXPRESS_USE_RE.finditer(code):
        close = jsast.match_close(code, m.end() - 1)
        if close == -1:
            continue
        args = jsast.split_args(src[m.end():close])
        if len(args) == 1 and AUTH_MW_NAME_RE.match(args[0].strip()) and not NON_AUTH_MW_RE.search(args[0]):
            file_auth_pos = m.start() if file_auth_pos is None else min(file_auth_pos, m.start())
    for m in EXPRESS_ROUTE_RE.finditer(src):
        if code[m.start()] == " ":
            continue
        open_idx = src.find("(", m.start())
        close = jsast.match_close(code, open_idx)
        if close == -1:
            continue
        method = m.group(2).upper().replace("ALL", "ANY")
        path = (prefix.rstrip("/") + "/" + m.group(4).lstrip("/")).rstrip("/") or "/"
        e = Entry("%s %s" % (method, path), sf, "express-route", [method], path, m.start(), close + 1, text, lx)
        args = jsast.split_args(src[open_idx + 1:close])
        mw = [a for a in args[1:-1]] if len(args) > 2 else []
        e.extra_auth = " ".join(mw)
        if mount.get("protected") or (file_auth_pos is not None and file_auth_pos < m.start()):
            e.extra_auth += " requireAuth( /* router-level auth middleware */"
        e.info["mount"] = mount
        out.append(e)
    return out


def express_mounts(project: walker.Project) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    """Map router files to their mount prefix and whether an auth middleware runs before them."""
    mounts: Dict[str, Dict[str, Any]] = {}
    gaps: List[Dict[str, Any]] = []
    for sf in project.code_files(walker.JS_EXTS):
        text = project.text(sf)
        if ".use(" not in text:
            continue
        lx = jsast.lexed(text)
        code, src = lx.code, lx.nocomment
        base = sf.rel.rsplit("/", 1)[0] if "/" in sf.rel else ""
        local: Dict[str, str] = {}
        for imp in jsast.find_imports(text):
            target = project.resolve_import(imp.spec, base)
            if target:
                for n in list(imp.names) + [x for x in (imp.default, imp.namespace) if x]:
                    local[n] = target
        auth_seen = False
        auth_line = None
        unprotected: List[Tuple[str, int, str]] = []
        for m in EXPRESS_USE_RE.finditer(code):
            close = jsast.match_close(code, m.end() - 1)
            if close == -1:
                continue
            args = [a.strip() for a in jsast.split_args(src[m.end():close])]
            if not args:
                continue
            line = _line(src, m.start())
            first = jsast.string_value(args[0])
            if first is None:
                if len(args) == 1 and AUTH_MW_NAME_RE.match(args[0]) and not NON_AUTH_MW_RE.search(args[0]):
                    auth_seen = True
                    auth_line = line
                continue
            target = None
            inline_auth = False
            for a in args[1:]:
                rm = re.match(r"require\(\s*[\"']([^\"']+)[\"']\s*\)", a)
                if rm:
                    target = project.resolve_import(rm.group(1), base)
                elif a in local:
                    target = local[a]
                elif AUTH_MW_NAME_RE.match(a) and not NON_AUTH_MW_RE.search(a):
                    inline_auth = True
            if target:
                protected = auth_seen or inline_auth
                mounts[target] = {"prefix": first, "protected": protected, "mounted_in": sf.rel, "line": line}
                if not protected and not AUTH_ROUTE_RE.search(first) and not re.search(r"(?i)webhook|health|public|static|docs", first):
                    unprotected.append((target, line, first))
        if auth_line is not None and unprotected:
            for target, line, prefix in unprotected:
                gaps.append({"file": sf.rel, "line": line, "prefix": prefix, "target": target, "auth_line": auth_line})
    return mounts, gaps


PY_ROUTE_RE = re.compile(r"(?m)^([ \t]*)@(\w+)\.(route|get|post|put|patch|delete|api_route|websocket)\(\s*[\"']([^\"']*)[\"']([^\n]*)\)\s*\n((?:[ \t]*@[^\n]+\n)*)[ \t]*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)")


def python_entries(project: walker.Project, sf: walker.SourceFile, text: str) -> List[Entry]:
    out: List[Entry] = []
    lines = text.split("\n")
    for m in PY_ROUTE_RE.finditer(text):
        indent = len(m.group(1).expandtabs(4))
        def_line = text.count("\n", 0, m.end())
        end_line = len(lines)
        for i in range(def_line + 1, len(lines)):
            ln = lines[i]
            if ln.strip() and len(ln) - len(ln.lstrip()) <= indent and not ln.lstrip().startswith(("#", ")")):
                end_line = i
                break
        end = sum(len(l) + 1 for l in lines[:end_line])
        verb = m.group(3)
        methods = [verb.upper()] if verb in ("get", "post", "put", "patch", "delete") else [x.upper() for x in re.findall(r"[\"'](GET|POST|PUT|PATCH|DELETE)[\"']", m.group(5))] or ["GET"]
        e = Entry("%s %s" % ("/".join(methods), m.group(4)), sf, "python-route", methods, m.group(4), m.start(), min(end, len(text)), text, None)
        e.info["params"] = m.group(8)
        out.append(e)
    if sf.name == "views.py" and not out:
        for m in re.finditer(r"(?m)^((?:@[^\n]+\n)*)(?:async\s+)?def\s+(\w+)\s*\(\s*request\b([^)]*)\)", text):
            def_line = text.count("\n", 0, m.end())
            end_line = len(lines)
            for i in range(def_line + 1, len(lines)):
                if lines[i].strip() and not lines[i].startswith((" ", "\t", "#")):
                    end_line = i
                    break
            end = sum(len(l) + 1 for l in lines[:end_line])
            e = Entry("VIEW %s" % m.group(2), sf, "django-view", ["ANY"], m.group(2), m.start(), min(end, len(text)), text, None)
            e.info["params"] = m.group(3)
            out.append(e)
    return out


def middleware_info(project: walker.Project) -> Optional[Dict[str, Any]]:
    for rel in ("middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js", "proxy.ts", "proxy.js", "src/proxy.ts", "src/proxy.js"):
        sf = project.get(rel)
        if not sf:
            continue
        text = project.text(sf)
        lx = jsast.lexed(text)
        mm = re.search(r"\bmatcher\s*:\s*(\[[^\]]*\]|[\"'`][^\"'`]*[\"'`])", lx.nocomment)
        matchers = re.findall(r"[\"'`]([^\"'`]+)[\"'`]", mm.group(1)) if mm else []
        has_auth = bool(patterns.AUTH_CALL_RE.search(lx.code)) or bool(re.search(r"clerkMiddleware|withAuth|authMiddleware|updateSession|auth0\.middleware|NextAuth", lx.code))
        covers_api = True if not matchers else any(
            ("/api" in mt and "(?!" not in mt) or (re.search(r"\(\?!", mt) and not re.search(r"\(\?![^)]*\bapi\b", mt)) or mt in ("/:path*", "/(.*)")
            for mt in matchers
        )
        return {"file": rel, "matcher": matchers, "has_auth": has_auth, "covers_api": covers_api, "line": _line(lx.nocomment, mm.start()) if mm else 1}
    return None


def build_inventory(project: walker.Project, stack: Optional[Dict[str, Any]]) -> List[Entry]:
    """Enumerate server entry points. Cached on the project so other scanners can reuse it."""
    if "route_entries" in project.cache:
        return project.cache["route_entries"]
    fw = project.framework
    deps = project.deps
    entries: List[Entry] = []
    has_expressish = any(d in deps for d in ("express", "fastify", "hono", "koa", "@hono/node-server", "elysia", "itty-router", "polka", "restify"))
    mounts, gaps = express_mounts(project) if has_expressish else ({}, [])
    project.cache["express_gaps"] = gaps
    mw = middleware_info(project) if fw == "nextjs" else None
    project.cache["middleware"] = mw
    firebase_fn = detect_stack.has(stack, "backend", "firebase-functions")
    for sf in project.code_files():
        text = project.text(sf)
        rel = sf.rel
        found: List[Entry] = []
        try:
            if sf.ext == ".py":
                found = python_entries(project, sf, text)
            else:
                lx = jsast.lexed(text)
                if fw == "nextjs":
                    found = next_entries(project, sf, text, lx)
                if not found and re.match(r"supabase/functions/[^/_][^/]*/index\.[jt]sx?$", rel):
                    name = rel.split("/")[2]
                    found = [Entry("FUNCTION %s" % name, sf, "edge-function", ["ANY"], "/functions/v1/" + name, 0, len(text), text, lx)]
                if not found and (re.match(r"netlify/(?:edge-)?functions/[^/]+\.[cm]?[jt]s$", rel) or (fw != "nextjs" and re.match(r"api/.+\.[cm]?[jt]s$", rel) and not has_expressish) or (not firebase_fn and re.match(r"functions/.+\.[cm]?[jt]s$", rel) and "onRequest" in text)):
                    found = [Entry("FUNCTION /%s" % re.sub(r"\.[cm]?[jt]s$", "", rel), sf, "serverless-function", ["ANY"], "/" + re.sub(r"\.[cm]?[jt]s$", "", rel), 0, len(text), text, lx)]
                if not found and fw == "sveltekit" and re.search(r"\+(server|page\.server|layout\.server)\.[jt]s$", sf.name):
                    path = "/" + re.sub(r"^src/routes/?|/?\+[^/]+$", "", rel)
                    exported = [x.name for x in jsast.find_exports(text) if x.name in METHODS or x.name in ("load", "actions")]
                    found = [Entry("%s %s" % (n, path), sf, "sveltekit", [n if n in METHODS else "POST" if n == "actions" else "GET"], path, 0, len(text), text, lx) for n in exported]
                if not found and fw == "remix" and re.match(r"app/routes/", rel):
                    funcs = {f.name: f for f in jsast.find_functions(text)}
                    for n in ("loader", "action"):
                        if n in funcs:
                            found.append(Entry("%s %s" % (n, _route_path(rel).replace("/routes", "")), sf, "remix-" + n, ["GET" if n == "loader" else "POST"], _route_path(rel), funcs[n].start, funcs[n].end, text, lx))
                if not found and fw == "nuxt" and re.match(r"(?:src/|app/)?server/(?:api|routes)/", rel):
                    path = "/" + re.sub(r"^(?:src/|app/)?server/(?:routes/)?|\.[jt]s$", "", rel)
                    found = [Entry("ANY %s" % path, sf, "nuxt-handler", ["ANY"], path, 0, len(text), text, lx)]
                if not found and fw == "astro" and re.match(r"src/pages/.+\.[jt]s$", rel):
                    exported = [x.name for x in jsast.find_exports(text) if x.name in METHODS]
                    found = [Entry("%s %s" % (n, _route_path(rel.replace("src/pages", "pages"))), sf, "astro-endpoint", [n], _route_path(rel.replace("src/pages", "pages")), 0, len(text), text, lx) for n in exported]
                if not found and has_expressish and project.classify(sf) != "client" and EXPRESS_ROUTE_RE.search(lx.nocomment):
                    found = express_entries(project, sf, text, lx, mounts)
                if "publicProcedure" in text or "protectedProcedure" in text:
                    for m in re.finditer(r"(\w+)\s*:\s*(publicProcedure|protectedProcedure|\w+Procedure)\b", lx.code):
                        stmt_end = lx.code.find("\n  }", m.end())
                        close = m.end()
                        depth = 0
                        for j in range(m.end(), len(lx.code)):
                            ch = lx.code[j]
                            if ch in "([{":
                                depth += 1
                            elif ch in ")]}":
                                if depth == 0:
                                    close = j
                                    break
                                depth -= 1
                            elif ch == "," and depth == 0:
                                close = j
                                break
                        e = Entry("trpc %s" % m.group(1), sf, "trpc-procedure", ["POST"], "trpc:" + m.group(1), m.start(), close, text, lx)
                        if m.group(2) != "publicProcedure":
                            e.extra_auth = "requireAuth( /* %s */" % m.group(2)
                        found.append(e)
        except Exception as exc:
            project.warnings.append("scan_routes: could not inventory %s (%s)" % (rel, type(exc).__name__))
            continue
        entries.extend(found)
    for e in entries:
        if mw and mw["has_auth"] and e.kind in ("route-handler", "api-route") and mw["covers_api"]:
            e.middleware_auth = True
        analyse(project, e, stack)
    entries.sort(key=lambda x: (x.sf.rel, x.start, x.id))
    project.cache["route_entries"] = entries
    return entries


def public_inventory(entries: List[Entry]) -> List[Dict[str, Any]]:
    return [dict(e.info) for e in entries if "id" in e.info]


# --- Findings from the inventory -------------------------------------------

def entry_findings(project: walker.Project, env: Envelope, e: Entry, stack: Optional[Dict[str, Any]]) -> None:
    info = e.info
    sf = e.sf
    is_py = sf.ext == ".py"
    src, code = e.src, e.code
    auth = info["auth"]["status"]
    priv = info["privileged_access"]
    data_priv = [p for p in priv if p != "llm"]
    path = e.path
    is_auth_route = bool(AUTH_ROUTE_RE.search(path)) or bool(re.search(r"NextAuth\(|toNextJsHandler|handlers\b.*auth", e.file_src))
    is_cron = bool(re.search(r"(?i)(^|/)(cron|crons|scheduled?)(/|$)", path))
    is_health = bool(HEALTH_RE.search(path))
    snippet = sf.line_text(e.line)
    tainted, whole, origin = taint(src, is_py, info.get("params", "") if is_py else "")
    if is_py:
        tainted, whole, origin = taint(src, True, e.info.get("params", ""))
    subject = {"kind": "route", "name": e.id}
    payment_webhook = info["is_webhook"] and bool(re.search(r"(?i)stripe|paddle|lemon|razorpay|paypal|polar|checkout\.session|payment_intent|invoice\.", e.file_src + path))

    # API-012: debug and scaffolding endpoints.
    segs = [s for s in re.split(r"[/:]", path.lower()) if s]
    debug_seg = next((s for s in segs if s in DEBUG_SEGMENTS), None)
    dumps_env = bool(re.search(r"(?:json|send|Response)\w*\(\s*(?:\{[^}]*)?\bprocess\.env\b(?!\.)|os\.environ\b(?!\.get|\[)", src))
    if dumps_env or (debug_seg and not (debug_seg in ("reset", "setup", "test", "dev") and (is_auth_route or auth != "none")) and not (debug_seg == "reset" and re.search(r"(?i)password|auth|account", path))):
        env.add(Finding(
            "API-012", "A leftover developer endpoint (`%s`) is part of the app. %s" % (e.id, "It returns the server's environment, which includes every secret key." if dumps_env else "Tools left for the developer are tools for an attacker."),
            file=sf.rel, line=e.line, snippet=snippet, confidence="confirmed" if dumps_env else DEBUG_SEGMENTS.get(debug_seg or "", "likely"), subject=subject,
            detail="Route %s %s." % (e.id, "serialises process.env into the response" if dumps_env else "has a debug-style path segment `%s`" % debug_seg),
            fix_hint="Delete the endpoint, or guard it with an environment check and admin authorisation.",
        ))

    # AUTH-002 / API-010 / AUTH-003: privileged access without authentication.
    exempt = is_health or info["is_webhook"] or (is_auth_route and e.kind != "server-action") or is_cron
    if data_priv and auth == "none" and not exempt:
        what = ", ".join(data_priv)
        if e.kind in ("server-action", "trpc-procedure", "remix-loader", "remix-action", "sveltekit"):
            env.add(Finding(
                "API-010", "The server action `%s` changes or returns data without checking who is calling it. Every server action is a public web address, wherever its button is shown." % e.id.split(" ", 1)[-1],
                file=sf.rel, line=e.line, snippet=snippet, confidence="likely", subject=subject,
                detail="%s uses %s and contains no session or authorisation check of its own." % (e.id, what),
                fix_hint="Verify the session inside the function and check that the caller may act on this record. Validate the arguments.",
            ))
        else:
            env.add(Finding(
                "AUTH-002", "Anyone on the internet can call `%s`. It reads or changes data with full access and never checks who is asking." % e.id,
                file=sf.rel, line=e.line, snippet=snippet, confidence="likely", subject=subject,
                detail="Handler uses %s and has no recognised authentication call%s." % (what, "; its router is mounted before the auth middleware" if e.info.get("mount") and not e.info["mount"].get("protected", True) else ""),
                fix_hint="Check the session at the top of the handler and return 401 when it is missing. Then check that the caller owns the record (API-005).",
            ))
    elif data_priv and auth == "middleware-only" and not exempt:
        env.add(Finding(
            "AUTH-003", "`%s` relies only on the middleware to keep strangers out. If the middleware's path pattern misses it, or a framework bug skips middleware, the route is open." % e.id,
            file=sf.rel, line=e.line, snippet=snippet, confidence="possible", subject=subject,
            detail="No authentication call inside the handler; a middleware with auth logic covers the path.",
            fix_hint="Verify the session inside the handler or in a shared data access layer. Keep middleware as an optimisation.",
        ))

    # AUTH-004 and AUTH-013: identity or role taken from the request.
    if (data_priv or info["calls_llm"]) and not (is_auth_route and not data_priv):
        ident_fields = [n for n in tainted if patterns.IDENTITY_FIELD_RE.match(origin.get(n, n))]
        m_inline = re.search(r"(?:req|request)\.(?:body|query|headers)\??\.(userId|user_id|uid|ownerId|owner_id)\b|headers(?:\.get\(|\[)\s*[\"']x-user-id[\"']|searchParams\.get\(\s*[\"'](?:userId|user_id|uid)[\"']\s*\)", src)
        compared = re.search(r"(?:userId|user_id|uid|ownerId|owner_id)\s*[!=]==?\s*(?:user|session|auth|req\.user|currentUser)\b|(?:user|session\.user|req\.user)\??\.id\s*[!=]==?\s*(?:userId|user_id|uid)", code)
        if (ident_fields or m_inline) and not compared and not (is_auth_route and auth == "none" and CRED_ROUTE_RE.search(path)):
            field = ident_fields[0] if ident_fields else m_inline.group(0)
            pos = re.search(r"(?<![\w$])%s(?![\w$])" % re.escape(ident_fields[0]), src) if ident_fields else m_inline
            line = e.line_at(pos.start()) if pos else e.line
            env.add(Finding(
                "AUTH-004", "`%s` believes whatever user ID the caller sends. Changing one field in the request lets a person act as any other user." % e.id,
                file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", subject=subject,
                detail="`%s` comes from the request and is used with %s. Identity must come from the verified session, not from the request body, query or headers." % (field, ", ".join(priv) or "the AI provider"),
                fix_hint="Derive the user ID from the verified session on the server and ignore identity fields sent by the client.",
            ))
        role_m = re.search(r"\b(role|isAdmin|is_admin|admin|plan|tier|credits)\s*:\s*(?:%s)\??\.(?:role|isAdmin|is_admin|admin|plan|tier|credits)\b" % "|".join(re.escape(w) for w in (sorted(whole) or ["body"]) + ["req.body", "request.body"]), src)
        if not role_m:
            role_names = [n for n in tainted if patterns.ROLE_FIELD_RE.match(origin.get(n, n)) and re.search(r"(?:data|set|values|update|insert|create)\w*\s*[:(][^;]{0,300}?(?<![\w$.])%s(?![\w$])" % re.escape(n), src, re.S)]
            role_m = re.search(r"(?<![\w$.])%s(?![\w$])" % re.escape(role_names[0]), src) if role_names else None
        if role_m and WRITE_OP_RE.search(code):
            line = e.line_at(role_m.start())
            env.add(Finding(
                "AUTH-013", "`%s` lets the caller choose their own role or plan: the value is taken from the request and saved." % e.id,
                file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", subject=subject,
                detail="A privileged field from the request body is written to the database.",
                fix_hint="Never accept role, plan or credit fields from the client. Set them only in server code paths that an administrator or a verified payment event triggers.",
            ))

    # API-005 (assist): authenticated, privileged, id from input, nothing session-derived in the query.
    if data_priv and auth == "present" and info["ownership_scoped"] == "no" and not info["is_webhook"] and not is_cron:
        id_names = [n for n in tainted if patterns.ID_FIELD_RE.match(origin.get(n, n))] or ([m.group(0) for m in [re.search(r"\bparams\??\.\w*[iI]d\b|(?:req|request)\.params\.\w+", src)] if m])
        if id_names:
            env.add(Finding(
                "API-005", "`%s` checks that someone is signed in, but not that the record they ask for is theirs. Changing the ID in the request may return or change another user's data." % e.id,
                file=sf.rel, line=e.line, snippet=snippet, confidence="possible", subject=subject,
                detail="Privileged client (%s), an ID from the request (`%s`), and no reference to the session user's ID in the handler." % (", ".join(data_priv), id_names[0]),
                fix_hint="Add the ownership condition to the query itself (for example where id = ? and user_id = the session user) and return 404 on mismatch.",
            ))

    # API-007: webhook without signature verification (payment webhooks are PAY-002).
    if info["is_webhook"] and not info["verifies_signature"] and not payment_webhook and "GET" not in e.methods[:1]:
        env.add(Finding(
            "API-007", "Anyone can send fake events to `%s`. The app accepts them as if they came from the real service." % e.id,
            file=sf.rel, line=e.line, snippet=snippet, confidence="likely", subject=subject,
            detail="Webhook handler with no signature verification against the raw request body.",
            fix_hint="Verify the provider's signature with its library and the raw body, check the timestamp tolerance, and reject on failure.",
        ))

    # API-014: scheduled endpoints anyone can trigger.
    if is_cron and not re.search(r"(?i)CRON_SECRET|authorization|x-vercel-signature|x-cron|timingSafeEqual|verifySignature|x-api-key|upstash-signature|qstash", e.file_src) and auth == "none":
        env.add(Finding(
            "API-014", "The scheduled job at `%s` can be started by anyone who visits its address, as often as they like." % e.id,
            file=sf.rel, line=e.line, snippet=snippet, confidence="likely", subject=subject,
            detail="Cron-style route with no shared secret or platform signature check.",
            fix_hint="Require the platform's cron secret in the Authorization header and compare it in constant time. Make the job idempotent.",
        ))

    # API-001: input used without validation.
    if ("body" in info["reads_input"] or "query" in info["reads_input"]) and not info["validates_input"] and (priv or info["calls_llm"] or info["sends_messages"]) and not info["is_webhook"]:
        env.add(Finding(
            "API-001", "`%s` uses what the caller sends without checking its type or size. Unexpected input can crash it or store bad data." % e.id,
            file=sf.rel, line=e.line, snippet=snippet, confidence="possible", subject=subject,
            detail="Handler reads %s with no schema validation (zod, valibot, yup, joi, pydantic) and no manual type checks." % " and ".join(r for r in info["reads_input"] if r in ("body", "query")),
            fix_hint="Parse the input with a schema at the top of the handler, return 400 on failure, and use only the parsed result.",
        ))

    # AUTH-010: credential endpoints without rate limiting (custom auth only).
    if CRED_ROUTE_RE.search(path) and not info["rate_limited"] and (data_priv or re.search(r"bcrypt|argon2|jwt\.sign|createHash|compare\(|signIn\(", src)) and "POST" in e.methods + ["POST" if e.methods == ["ANY"] else ""]:
        if not project.cache.get("global_rate_limit"):
            env.add(Finding(
                "AUTH-010", "Nothing limits how many times someone can try `%s`. An attacker can guess passwords or codes as fast as they like." % e.id,
                file=sf.rel, line=e.line, snippet=snippet, confidence="likely", subject=subject,
                detail="Credential endpoint with no rate limiter in the handler, its middleware, or the app.",
                fix_hint="Add per-IP and per-account limits backed by a shared store, with lockout and backoff.",
            ))

    # API-018: writes reachable by the wrong method.
    writes = bool(WRITE_OP_RE.search(code))
    if writes and not info["is_webhook"]:
        if (e.methods == ["GET"] and not is_cron and not (is_auth_route and "callback" in path.lower())) or (e.kind == "api-route" and not re.search(r"\.method\b", code)) or (e.methods == ["ANY"] and e.kind == "express-route"):
            env.add(Finding(
                "API-018", "`%s` changes data on a plain link visit. A crawler, a link preview or an image tag on another site can trigger it." % e.id,
                file=sf.rel, line=e.line, snippet=snippet, confidence="likely", subject=subject,
                detail="State-changing operation in a handler that %s." % ("answers GET" if e.methods == ["GET"] else "does not check the HTTP method"),
                fix_hint="Accept only the intended method (POST, PUT, PATCH or DELETE) and return 405 otherwise.",
            ))

    # API-008 and API-019: unbounded lists and over-wide responses.
    if not info["is_webhook"] and not is_cron:
        for call in jsast.find_calls(src, ["prisma.*", "db.*", "tx.*"]) if not is_py else []:
            if call.name.endswith(".findMany"):
                args = call.args
                model = call.name.split(".")[-2] if call.name.count(".") >= 2 else ""
                line = e.line_at(call.start)
                if not re.search(r"\btake\s*:", args):
                    env.add(Finding(
                        "API-008", "`%s` returns every matching row with no upper limit. As data grows this gets slow and expensive, and it hands scrapers a bulk export." % e.id,
                        file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely" if not args.strip() else "possible", subject=subject,
                        detail="%s() without `take`." % call.name,
                        fix_hint="Enforce a maximum page size on the server and paginate with a cursor.",
                    ))
            if re.search(r"\.(?:findMany|findUnique|findFirst|findUniqueOrThrow|findFirstOrThrow)$", call.name):
                model = call.name.split(".")[-2].lower() if call.name.count(".") >= 2 else ""
                if re.search(r"user|account|member|customer|profile", model) and not re.search(r"\b(?:select|omit)\s*:", call.args):
                    var_m = re.search(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?$", src[max(0, call.start - 60):call.start])
                    var = var_m.group(1) if var_m else None
                    returned = bool(var and re.search(r"(?:json|send)\(\s*(?:\{[^}]*)?\b%s\b" % re.escape(var), src))
                    if returned:
                        line = e.line_at(call.start)
                        env.add(Finding(
                            "API-019", "`%s` sends whole user records to the browser, including fields the page never shows, such as password hashes." % e.id,
                            file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", subject=subject,
                            detail="%s() result is returned without `select`, so every column is serialised into the response." % call.name,
                            fix_hint="Select only the fields the client needs, or map the result through a response schema.",
                        ))
        for m in re.finditer(r"\.from\(\s*[\"'`]([\w.]+)[\"'`]\s*\)\s*\.select\(\s*(?:[\"'`]\*[\"'`])?\s*\)", src):
            s_start, s_end = jsast.statement_at(code, m.start())
            stmt = code[s_start:s_end]
            if not re.search(r"\.(?:eq|limit|range|single|maybeSingle|match|in|lt|gt|lte|gte|contains|textSearch|order\([^)]*\)\s*\.limit)\(", stmt) and "service" in " ".join(priv):
                line = e.line_at(m.start())
                env.add(Finding(
                    "API-008", "`%s` returns the whole `%s` table with no limit." % (e.id, m.group(1)),
                    file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", subject=subject,
                    detail="select() on %s with no filter, limit or range, using a client that bypasses row level security." % m.group(1),
                    fix_hint="Filter by the session user, and enforce a maximum page size.",
                ))
        if "mongoose" in priv:
            for m in re.finditer(r"\b([A-Z]\w*)\.find\(\s*(?:\{\s*\})?\s*\)(?!\s*\.(?:limit|select))", code):
                if m.group(1) in BUILTIN_CAPS:
                    continue
                s_start, s_end = jsast.statement_at(code, m.start())
                if ".limit(" in code[s_start:s_end]:
                    continue
                line = e.line_at(m.start())
                env.add(Finding(
                    "API-008", "`%s` returns every `%s` document with no limit." % (e.id, m.group(1)),
                    file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", subject=subject,
                    detail="%s.find({}) with no limit or pagination." % m.group(1),
                    fix_hint="Add a filter for the session user and a maximum page size.",
                ))
                if re.search(r"(?i)user|account|member|customer", m.group(1)):
                    env.add(Finding(
                        "API-019", "`%s` sends whole user documents to the caller, including the stored password field." % e.id,
                        file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", subject=subject,
                        detail="%s.find() result returned without .select() to exclude sensitive fields." % m.group(1),
                        fix_hint="Use .select() to return only the needed fields, or exclude password and token fields in the schema.",
                    ))

    # API-006: server-side fetch of a caller-supplied URL.
    for call in jsast.find_calls(src, FETCH_SINK_NAMES) if not is_py else []:
        first = (jsast.split_args(call.args) or [""])[0]
        hit = is_tainted(first, tainted)
        if hit and not re.search(r"^[\"'`]https?://[\w.-]+/", first.strip()):
            if re.search(r"(?i)allowedHosts|ALLOWED_HOSTS|allowlist|isPrivate|private-ip|ssrf|dns\.lookup|\.hostname\s*[!=]==?|new URL\([^)]*\)\.(?:hostname|host)", src):
                continue
            line = e.line_at(call.start)
            env.add(Finding(
                "API-006", "`%s` makes the server fetch any address the caller supplies. That lets an outsider reach internal systems through your server, or use it as an anonymous proxy." % e.id,
                file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", subject=subject,
                detail="%s() is called with `%s`, which comes from the request, with no host allow-list or private-address check." % (call.name, hit),
                fix_hint="Allow-list hosts where possible. Otherwise resolve the host, block private, loopback and link-local ranges, refuse redirects to them, require https, and set a timeout and size limit.",
            ))
            break
    if is_py:
        m = re.search(r"\b(?:requests|httpx)\.(?:get|post|request)\(\s*(\w+)|urlopen\(\s*(\w+)", src)
        if m and (m.group(1) or m.group(2)) in tainted:
            line = e.line_at(m.start())
            env.add(Finding(
                "API-006", "`%s` makes the server fetch any address the caller supplies." % e.id,
                file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", subject=subject,
                detail="HTTP client called with a request-derived URL and no allow-list.",
                fix_hint="Allow-list hosts or block private address ranges, and set timeouts.",
            ))

    # API-015: file paths from input.
    for call in jsast.find_calls(src, FS_SINK_NAMES) if not is_py else []:
        hit = is_tainted(call.args, tainted)
        if not hit or call.name in ("path.join", "path.resolve") and not re.search(r"sendFile|readFile|createReadStream|download|unlink|writeFile", src):
            continue
        if re.search(r"path\.basename\(|\.startsWith\(\s*(?:base|root|UPLOAD|uploadDir|safe)|path\.relative\(|includes\(\s*[\"']\.\.[\"']\s*\)|sanitize", src):
            continue
        line = e.line_at(call.start)
        env.add(Finding(
            "API-015", "`%s` builds a file path from what the caller sends. With `../` in the name, anyone can read files such as the server's secret settings." % e.id,
            file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", subject=subject,
            detail="%s() receives `%s` from the request with no normalisation and base-directory check." % (call.name, hit),
            fix_hint="Resolve the path against a fixed base directory and verify that the result stays inside it, or map IDs to stored paths.",
        ))
        break
    if is_py:
        m = re.search(r"\b(?:open|send_file|send_from_directory)\(([^)]*)\)", src)
        if m and is_tainted(m.group(1), tainted) and not re.search(r"secure_filename|os\.path\.basename|commonpath", src):
            line = e.line_at(m.start())
            env.add(Finding(
                "API-015", "`%s` builds a file path from what the caller sends, so `../` sequences can reach files outside the intended folder." % e.id,
                file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", subject=subject,
                detail="File API called with a request-derived path.",
                fix_hint="Use secure_filename and verify the resolved path stays inside the base directory.",
            ))

    # API-016: shell, eval and unsafe deserialisation with input.
    uses_cp = bool(re.search(r"child_process|\bexeca\b|shelljs", e.file_src))
    for call in jsast.find_calls(src, EXEC_SINK_NAMES):
        short = call.name.split(".")[-1]
        if short in ("exec", "execSync", "spawn", "spawnSync", "execFile") and not uses_cp and not is_py:
            continue
        hit = is_tainted(call.args, tainted)
        if not hit:
            continue
        if short in ("spawn", "spawnSync", "execFile", "run", "call", "Popen", "check_output") and not re.search(r"shell\s*[:=]\s*[Tt]rue", call.args):
            continue
        if short == "load" and "SafeLoader" in call.args:
            continue
        line = e.line_at(call.start)
        env.add(Finding(
            "API-016", "`%s` passes what the caller sends into a command or code interpreter. An attacker can run their own commands on your server and take it over." % e.id,
            file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", subject=subject,
            detail="%s() is called with `%s` from the request." % (call.name, hit),
            fix_hint="Do not use a shell. Pass an argument array to execFile or spawn, allow-list values, and use safe parsers.",
        ))
        break

    # UP-001 and UP-003: uploads.
    if re.search(r"formData\.get\(\s*[\"'](?:file|image|upload|document|avatar|photo)|\.file\b|\.files\b|multipart|UploadFile", src):
        if not re.search(r"\.size\b|maxFileSize|limits\s*:|content_length|MAX_SIZE|MAX_FILE", e.file_src) and not re.search(r"multer\(", e.file_src):
            m = re.search(r"formData\.get\(|\.files?\b|UploadFile", src)
            line = e.line_at(m.start()) if m else e.line
            env.add(Finding(
                "UP-001", "`%s` accepts uploaded files of any size and type." % e.id,
                file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", subject=subject,
                detail="Upload handler with no size limit and no content-type allow-list checked on the server.",
                fix_hint="Enforce a maximum size and an allow-list of types on the server or in the storage policy.",
            ))


def file_findings(project: walker.Project, env: Envelope, sf: walker.SourceFile, stack: Optional[Dict[str, Any]], entries: List[Entry]) -> None:
    text = project.text(sf)
    rel = sf.rel
    kind = project.classify(sf)
    is_py = sf.ext == ".py"
    lx = jsast.lexed(text) if not is_py else None
    code = lx.code if lx else text
    src = lx.nocomment if lx else re.sub(r"(?m)#[^\n]*$", lambda m: " " * len(m.group(0)), text)
    file_entries = [e for e in entries if e.sf is sf]

    def scope(offset: int) -> str:
        best = None
        for e in file_entries:
            if e.start <= offset < e.end and (best is None or e.end - e.start < best.end - best.start):
                best = e
        return best.src if best else src

    def L(offset: int) -> int:
        return _line(src, offset)

    # DB-014: database drivers in client code.
    if kind == "client" and not is_py:
        for imp in jsast.find_imports(text):
            pkg = jsast.package_of(imp.spec) or ""
            if pkg in ("@prisma/client", "pg", "mysql2", "mongodb", "mongoose", "postgres", "better-sqlite3", "knex", "sequelize", "typeorm", "mssql", "ioredis", "redis") or imp.spec.startswith("drizzle-orm/") and not imp.spec.endswith(("/pg-core", "/sqlite-core", "/mysql-core")):
                env.add(Finding(
                    "DB-014", "Code that runs in the browser connects straight to the database. For that to work, the database password has to be shipped to every visitor.",
                    file=rel, line=imp.line, snippet=sf.line_text(imp.line), confidence="likely",
                    detail="Client-bundled file imports the server-only database package `%s`." % imp.spec,
                    fix_hint="Move data access behind a server route or server action, and rotate the database password if it was ever in a public variable.",
                    owner_action="references/owner-actions/rotate-keys.md",
                ))
                break
        m = re.search(r"(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)\w*(?:DATABASE_URL|DB_URL|MONGO\w*URI?|POSTGRES\w*URL)", src)
        if m:
            env.add(Finding(
                "DB-014", "The database connection string is stored in a variable that is copied into the browser code.",
                file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
                detail="`%s` is read in client code." % m.group(0),
                fix_hint="Use a server-only variable and server-side data access. Rotate the database password.",
                owner_action="references/owner-actions/rotate-keys.md",
            ))
    if kind in ("test", "doc", "config"):
        return

    # API-004: internal error details returned to the client.
    if kind != "client" or rel.startswith("supabase/functions/"):
        for m in RESPONSE_CALL_RE.finditer(code):
            close = jsast.match_close(code, m.end() - 1) if not is_py else code.find("\n", m.end())
            if close == -1:
                continue
            if ERROR_LEAK_RE.search(code[m.end():close]):
                env.add(Finding(
                    "API-004", "When something fails, the server sends the internal error text to the caller. That can reveal table names, file paths and sometimes secrets.",
                    file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
                    detail="Response body includes the error's message or stack.",
                    fix_hint="Return a generic message with a request ID, and send the full error to server logs and the error tracker.",
                ))
                break

    # DB-012: SQL built from request data.
    if not is_py:
        for call in jsast.find_calls(text, SQL_SINK_NAMES):
            first = (jsast.split_args(call.args) or [""])[0].strip()
            tainted, _, _ = taint(scope(call.start))
            dynamic = ("${" in first and first.startswith("`")) or re.search(r"[\"'`]\s*\+\s*\w|\w\s*\+\s*[\"'`]", first)
            if not dynamic:
                continue
            unsafe_api = "Unsafe" in call.name or call.name.endswith(".raw")
            hit = is_tainted(first, tainted)
            if not (hit or unsafe_api):
                continue
            env.add(Finding(
                "DB-012", "This query is assembled by pasting request text into SQL. A crafted input can read or destroy the whole database.",
                file=rel, line=call.line, snippet=sf.line_text(call.line), confidence="likely" if hit else "possible",
                detail="%s() receives a string built with interpolation or concatenation%s." % (call.name, " that includes `%s` from the request" % hit if hit else ""),
                fix_hint="Use parameterised queries or tagged templates (for Prisma: $queryRaw with a template literal), and allow-list identifiers.",
            ))
        for m in re.finditer(r"\.(?:or|filter)\(\s*`[^`]*\$\{", src):
            tainted, _, _ = taint(scope(m.start()))
            seg = src[m.start():src.find("`", m.end()) + 1]
            hit = is_tainted(seg, tainted)
            if hit:
                env.add(Finding(
                    "DB-012", "A database filter string is built from request text, so the caller can rewrite the filter and see rows it was meant to hide.",
                    file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
                    detail="PostgREST filter string interpolates `%s`." % hit,
                    fix_hint="Use the typed filter methods (.eq, .ilike) or strictly validate the value.",
                ))
    else:
        for m in re.finditer(r"\.execute\(\s*(f[\"']|[\"'][^\"'\n]*[\"']\s*(?:%|\.format\(|\+))", src):
            env.add(Finding(
                "DB-012", "This query is assembled by pasting values into SQL text. A crafted input can read or destroy the whole database.",
                file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
                detail="cursor.execute() with an f-string, % formatting or concatenation.",
                fix_hint="Pass parameters separately: cursor.execute(sql, params).",
            ))

    # DB-013: mass assignment.
    if kind != "client" or rel.startswith("supabase/functions/"):
        seen: Set[int] = set()
        pats = [
            r"\bdata\s*:\s*(?:\{\s*\.\.\.\s*)?(%s)\b\s*[,})]",
            r"\.(?:insert|update|upsert)\(\s*(?:\[\s*)?(?:\{\s*\.\.\.\s*)?(%s)\b\s*[,})\]]",
            r"\.(?:findByIdAndUpdate|findOneAndUpdate|updateOne|updateMany)\(\s*[^,]+,\s*(?:\{\s*(?:\$set\s*:\s*)?(?:\.\.\.\s*)?)?(%s)\b",
            r"\.(?:create|insertMany)\(\s*(?:\{\s*\.\.\.\s*)?(%s)\b\s*[,})]",
            r"Object\.assign\(\s*\w+\s*,\s*(%s)\b",
            r"\.set\(\s*(%s)\b\s*[,)]",
            r"\bnew\s+[A-Z]\w*\(\s*(%s)\s*\)",
        ]
        for m0 in re.finditer(r"\.(?:insert|update|upsert|create|findByIdAndUpdate|findOneAndUpdate|updateOne|updateMany|set|insertMany)\(|\bdata\s*:|Object\.assign\(|\bnew\s+[A-Z]\w*\(", code):
            sc = scope(m0.start())
            _, whole, _ = taint(sc, is_py)
            names = sorted(whole) + ["req.body", "request.body"]
            alt = "|".join(re.escape(n) for n in names)
            window = src[m0.start(): m0.start() + 200]
            for p in pats:
                m = re.match(p % alt, window, re.S) if p.startswith(r"\b") or p.startswith("Object") else re.match(p % alt, window, re.S)
                if m:
                    ln = L(m0.start())
                    if ln in seen:
                        break
                    if re.match(r"\bnew\s+(?:URL|Response|Request|Headers|Error|Date|Map|Set|Blob|FormData|URLSearchParams)\(", window):
                        break
                    seen.add(ln)
                    env.add(Finding(
                        "DB-013", "The whole request body is written to the database. The caller can set fields they were never meant to control, such as a role, an owner or a price.",
                        file=rel, line=ln, snippet=sf.line_text(ln), confidence="likely",
                        detail="`%s` (the raw request body) is passed to a write call without picking allowed fields." % m.group(1),
                        fix_hint="Validate the body with a schema, pass only the allowed fields, and set ownership from the session.",
                    ))
                    break
        if is_py:
            m = re.search(r"\b[A-Z]\w*\(\s*\*\*\s*(?:request\.(?:json|form|data)|data|payload|body)\b", src)
            if m:
                env.add(Finding(
                    "DB-013", "The whole request body is passed into a model, so the caller can set any field.",
                    file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
                    detail="Model constructed with **request data.",
                    fix_hint="Validate with a schema and pass explicit fields.",
                ))

    # DB-018: database clients created per request.
    if not is_py and detect_stack.is_serverless(stack):
        funcs = jsast.find_functions(text)
        for m in re.finditer(r"\bnew\s+(PrismaClient|Pool|Client|MongoClient)\s*\(", code):
            f = jsast.enclosing_function(funcs, m.start())
            if f is None and not file_entries:
                continue
            if f is None and "globalThis" in text or re.search(r"global(?:This|ForPrisma)?\b[^;\n]*prisma", text):
                continue
            if m.group(1) == "Client" and "pg" not in project.deps:
                continue
            env.add(Finding(
                "DB-018", "A new database connection is opened on every request. Under real traffic the database runs out of connections and the app goes down.",
                file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
                detail="`new %s()` is constructed inside a request handler on a serverless runtime." % m.group(1),
                fix_hint="Create one client per runtime in a shared module (cached on globalThis in development) and use the provider's pooled connection string.",
            ))
            break

    # AUTH-005 (JWT part): decoding without verifying.
    if kind != "client":
        m = re.search(r"\bjwt\.decode\(|\bjwtDecode\(|\bjwt_decode\(|\bdecodeJwt\(|JSON\.parse\(\s*(?:atob|Buffer\.from)\([^)]*split\(\s*[\"']\.[\"']\s*\)\[1\]", code if not is_py else src)
        if m and not is_py and not re.search(r"\bjwt\.verify\(|\bjwtVerify\(|verifyIdToken\(", scope(m.start())):
            env.add(Finding(
                "AUTH-005", "The server reads who the user is from a login token without checking that the token is genuine. Anyone can write their own token and be accepted as any user.",
                file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
                detail="Token is decoded (%s) with no signature verification in the same function." % m.group(0).rstrip("("),
                fix_hint="Verify the signature, issuer, audience and expiry (jwt.verify with an algorithms allow-list, or jose jwtVerify).",
            ))
        if is_py:
            m = re.search(r"jwt\.decode\([^)]*(?:verify_signature[\"']?\s*:\s*False|verify\s*=\s*False)", src)
            if m:
                env.add(Finding(
                    "AUTH-018", "Token checking is switched off: the server accepts login tokens without verifying their signature.",
                    file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="confirmed",
                    detail="jwt.decode called with signature verification disabled.",
                    fix_hint="Verify the signature with an explicit algorithms list and validate exp, iss and aud.",
                ))

    # AUTH-018: unsafe verification options.
    if not is_py:
        for call in jsast.find_calls(text, ["jwt.verify", "jsonwebtoken.verify", "verify"]):
            if call.name == "verify" and "jsonwebtoken" not in text:
                continue
            args = call.args
            issue = None
            conf = "likely"
            if re.search(r"ignoreExpiration\s*:\s*true", args):
                issue = "ignoreExpiration: true, so expired tokens are accepted forever"
            elif re.search(r"algorithms?\s*:\s*\[?[^\]]*[\"']none[\"']", args):
                issue, conf = "the `none` algorithm is allowed, so unsigned tokens are accepted", "confirmed"
            elif "algorithms" not in args and re.search(r"(?i)public|cert|pem|jwks|getKey", (jsast.split_args(args) + ["", ""])[1]):
                issue, conf = "no algorithms allow-list while verifying with a public key (algorithm confusion)", "possible"
            if issue:
                env.add(Finding(
                    "AUTH-018", "Login tokens are checked too loosely, so forged or expired tokens are accepted.",
                    file=rel, line=call.line, snippet=sf.line_text(call.line), confidence=conf,
                    detail="jwt.verify: %s." % issue,
                    fix_hint="Pin the algorithms, and validate exp, iss and aud.",
                ))

    # AUTH-007: cookies without protective attributes.
    if not is_py:
        for call in jsast.find_calls(text, ["res.cookie", "reply.setCookie", "response.cookies.set", "cookieStore.set", "cookies().set", "setCookie", "c.cookie"]):
            parts = jsast.split_args(call.args)
            name = jsast.string_value(parts[0]) if parts else None
            if name is None or not COOKIE_NAME_RE.search(name):
                continue
            opts = " ".join(parts[2:])
            missing = [a for a in ("httpOnly", "secure", "sameSite") if not re.search(r"\b%s\b" % a, opts)]
            none = bool(re.search(r"sameSite\s*:\s*[\"']none[\"']", opts, re.I))
            if missing or none:
                env.add(Finding(
                    "AUTH-007", "The login cookie `%s` is set without its protective flags, which makes it easier to steal or misuse." % name,
                    file=rel, line=call.line, snippet=sf.line_text(call.line), confidence="likely",
                    detail="Cookie `%s`: %s." % (name, ("missing " + ", ".join(missing)) if missing else "sameSite is none"),
                    fix_hint="Set httpOnly: true, secure: true and sameSite: 'lax' (or 'strict').",
                ))
        m = re.search(r"\bsession\(\s*\{", code)
        if m and "express-session" in text:
            close = jsast.match_close(code, code.find("{", m.start()))
            opts = src[m.start(): close if close != -1 else m.start() + 400]
            if not re.search(r"cookie\s*:\s*\{[^}]*secure", opts, re.S):
                env.add(Finding(
                    "AUTH-007", "Session cookies use the library's default settings, which do not require HTTPS.",
                    file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
                    detail="express-session configured without cookie.secure (and sameSite).",
                    fix_hint="Set cookie: { httpOnly: true, secure: true, sameSite: 'lax' } and trust proxy behind a load balancer.",
                ))
    if is_py:
        m = re.search(r"(?m)^\s*@csrf_exempt", src)
        if m:
            env.add(Finding(
                "AUTH-015", "Protection against forged cross-site requests is switched off for this view.",
                file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="possible",
                detail="@csrf_exempt on a view. This is correct for signed webhooks and wrong for cookie-authenticated actions.",
                fix_hint="Remove the decorator unless the view verifies a webhook signature.",
            ))

    # AUTH-012: open redirects.
    for m in REDIRECT_SINK_RE.finditer(code):
        sc = scope(m.start())
        tainted, _, origin = taint(sc, is_py)
        end = code.find(";", m.end())
        end = code.find("\n", m.end()) if end == -1 or end - m.end() > 300 else end
        arg = src[m.end(): end if end != -1 else m.end() + 200]
        hit = None
        im = re.search(r"searchParams\.get\(\s*[\"'](\w+)[\"']\s*\)|(?:req|request)\.query\.(\w+)|request\.(?:args|GET)\.get\(\s*[\"'](\w+)[\"']", arg)
        if im and REDIRECT_PARAM_RE.match(next(g for g in im.groups() if g)):
            hit = im.group(0)
        else:
            for name in tainted:
                if REDIRECT_PARAM_RE.match(origin.get(name, name)) and re.search(r"(?<![\w$.])%s(?![\w$])" % re.escape(name), arg):
                    hit = name
                    break
        if not hit or SAFE_REDIRECT_RE.search(sc):
            continue
        env.add(Finding(
            "AUTH-012", "After sign-in the app sends people wherever the link says, including to another website. Attackers use this to make a phishing link look like yours.",
            file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
            detail="Redirect target `%s` comes from the request and is not checked to be a same-site path." % hit,
            fix_hint="Allow only relative paths that start with a single `/` (reject `//` and backslashes) or an explicit allow-list.",
        ))
        break

    # API-009: very large body limits.
    for m in re.finditer(r"(?:limit|sizeLimit|bodySizeLimit|bodyLimit|maxBodyLength)\s*:\s*[\"'`]?(\d+)\s*(mb|gb|kb)?", src, re.I):
        n = int(m.group(1))
        unit = (m.group(2) or "").lower()
        mb = n if unit == "mb" else n * 1024 if unit == "gb" else n / 1024.0 if unit == "kb" else n / 1048576.0
        ctx = src[max(0, m.start() - 120): m.start()]
        if mb >= 10 and re.search(r"json\(|urlencoded\(|bodyParser|serverActions|api\s*:|raw\(|text\(|fastify\(", ctx):
            env.add(Finding(
                "API-009", "The server accepts request bodies up to %s%s. A few large requests can exhaust memory and take the app down." % (m.group(1), unit or " bytes"),
                file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
                detail="Body parser limit set far above what a JSON API needs.",
                fix_hint="Use a small default (about 100 KB to 1 MB) and raise it only on upload routes that stream.",
            ))
            break

    # API-011: GraphQL without limits.
    if not is_py and re.search(r"new\s+ApolloServer\(|createYoga\(|graphqlHTTP\(|mercurius", code):
        m = re.search(r"new\s+ApolloServer\(|createYoga\(|graphqlHTTP\(|mercurius", code)
        open_p = code.find("(", m.start())
        close = jsast.match_close(code, open_p)
        opts = src[open_p: close if close != -1 else open_p + 600]
        issues = []
        if re.search(r"introspection\s*:\s*true", opts):
            issues.append("introspection enabled")
        if re.search(r"(?:playground|graphiql)\s*:\s*true", opts):
            issues.append("playground enabled")
        if not re.search(r"depthLimit|validationRules|costLimit|complexity|maxDepth|armor", text):
            issues.append("no depth or complexity limit")
        if issues and (len(issues) > 1 or "introspection enabled" in issues):
            env.add(Finding(
                "API-011", "The GraphQL API publishes its full schema and accepts arbitrarily deep queries, which makes it easy to map and to overload.",
                file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
                detail="GraphQL server: %s." % ", ".join(issues),
                fix_hint="Disable introspection and the playground in production for a private API, add depth and cost limits, and authorise in resolvers.",
            ))

    # UP-001 / UP-003 / UP-004: upload configuration and storage paths.
    if not is_py:
        for call in jsast.find_calls(text, ["multer"]):
            if not re.search(r"\blimits\s*:", call.args) or not re.search(r"fileFilter\s*:", call.args):
                missing = [n for n, rx in (("size limit", r"\blimits\s*:"), ("file type filter", r"fileFilter\s*:")) if not re.search(rx, call.args)]
                env.add(Finding(
                    "UP-001", "File uploads are accepted with no %s. Anyone can fill the disk or upload executable content." % " and no ".join(missing),
                    file=rel, line=call.line, snippet=sf.line_text(call.line), confidence="likely",
                    detail="multer() configured without %s." % " or ".join(missing),
                    fix_hint="Set limits.fileSize and a fileFilter that allow-lists types, and verify the content, not just the declared type.",
                ))
                break
        m = re.search(r"\b(?:file|req\.file|f)\.originalname\b|\boriginalFilename\b", code)
        m2 = re.search(r"\.upload\(\s*(?:`[^`]*\$\{\s*(?:file|f|image|doc)\w*\.name\s*\}|(?:file|f|image)\w*\.name\b)|\bKey\s*:\s*(?:`[^`]*\$\{\s*)?(?:file|f)\w*\.(?:name|originalname)", src)
        if m and re.search(r"filename\s*:|path\.join\(|\.upload\(|Key\s*:|writeFile|createWriteStream|\.mv\(", src):
            env.add(Finding(
                "UP-003", "Uploaded files are saved under the name the uploader chose. Someone can overwrite other people's files or use `../` to write outside the upload folder.",
                file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
                detail="The original file name is used to build the storage path.",
                fix_hint="Generate a random key on the server under a per-user prefix and keep the original name as metadata only.",
            ))
        elif m2 and kind != "client":
            env.add(Finding(
                "UP-003", "Uploaded files are stored under the name the uploader chose, so one upload can replace another.",
                file=rel, line=L(m2.start()), snippet=sf.line_text(L(m2.start())), confidence="likely",
                detail="Object key built from the client-supplied file name.",
                fix_hint="Generate a random key on the server under a per-user prefix.",
            ))
        for m in re.finditer(r"\.from\(\s*[\"'`]([\w-]+)[\"'`]\s*\)\s*\.getPublicUrl\(", src):
            bucket = m.group(1)
            private_like = bool(re.search(r"(?i)\bid|doc|passport|kyc|invoice|private|medical|contract|receipt|statement|resume|cv", bucket))
            if private_like:
                env.add(Finding(
                    "UP-004", "Private documents in `%s` are shared through permanent public links. Anyone who gets a link has the file forever." % bucket,
                    file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
                    detail="getPublicUrl() on bucket \"%s\", whose name suggests private files." % bucket,
                    fix_hint="Make the bucket private and issue short-lived signed URLs after checking that the caller may see the file.",
                ))
        m = re.search(r"createSignedUrl\(\s*[^,]+,\s*(\d[\d_]*(?:\s*\*\s*\d+)*)", src)
        if m:
            try:
                seconds = eval(m.group(1).replace("_", ""), {"__builtins__": {}})  # digits and * only, by the regex above
            except Exception:
                seconds = 0
            if seconds > 7 * 24 * 3600:
                env.add(Finding(
                    "UP-004", "Signed links to private files stay valid for a very long time, which makes them as good as public.",
                    file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
                    detail="createSignedUrl with an expiry of %d seconds." % seconds,
                    fix_hint="Use minutes, not weeks, and issue a new link on each view.",
                ))

    # PERF-001: queries inside loops.
    if kind != "client" or is_py:
        for m in LOOP_RE.finditer(code):
            brace = code.find("{", m.end())
            if brace == -1 or brace - m.end() > 200:
                continue
            close = jsast.match_close(code, brace)
            body = code[brace: close if close != -1 else brace + 1500]
            dm = DB_CALL_RE.search(body)
            if dm:
                ln = L(brace + dm.start())
                env.add(Finding(
                    "PERF-001", "The code asks the database one question per item in a list. With real data, a page that took milliseconds takes seconds.",
                    file=rel, line=ln, snippet=sf.line_text(ln), confidence="likely",
                    detail="A database call runs inside a loop (N+1 queries).",
                    fix_hint="Fetch related rows in one query with `in`, a join or an include.",
                ))
                break

    # REL-002: outbound calls without a timeout (server code only).
    if kind == "server" and not is_py:
        for call in jsast.find_calls(text, ["fetch"]):
            parts = jsast.split_args(call.args)
            first = parts[0] if parts else ""
            if first.strip().startswith(("'/", '"/', "`/")):
                continue
            if re.search(r"signal|timeout|AbortSignal", call.args) or re.search(r"AbortController|AbortSignal\.timeout", scope(call.start)):
                continue
            env.add(Finding(
                "REL-002", "A call to another service has no time limit. If that service hangs, every request that depends on it hangs too.",
                file=rel, line=call.line, snippet=sf.line_text(call.line), confidence="possible",
                detail="fetch() without an abort signal or timeout.",
                fix_hint="Pass signal: AbortSignal.timeout(ms) and handle the timeout.",
            ))
            break

    # PRIV-005: fast hashes for passwords.
    for m in FAST_HASH_RE.finditer(src):
        near = src[max(0, m.start() - 200): m.end() + 200]
        if re.search(r"(?i)passw(?:or)?d|\bpwd\b", near):
            algo = next(g for g in m.groups() if g) if any(m.groups()) else "md5"
            env.add(Finding(
                "PRIV-005", "Passwords are stored with a fast hash (%s). If the database leaks, most passwords can be recovered within hours." % algo,
                file=rel, line=L(m.start()), snippet=sf.line_text(L(m.start())), confidence="likely",
                detail="%s used to hash a password. Fast hashes are designed for speed, which is the opposite of what password storage needs." % algo,
                fix_hint="Use argon2id, scrypt or bcrypt, and rehash existing passwords at next sign-in.",
            ))
            break


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_routes", stack)
    deps = project.deps
    rate_dep = any(d in deps or d in project.python_deps for d in ("express-rate-limit", "@upstash/ratelimit", "rate-limiter-flexible", "@fastify/rate-limit", "express-slow-down", "hono-rate-limiter", "flask-limiter", "slowapi", "django-ratelimit", "@nestjs/throttler", "limiter", "bottleneck"))
    rate_code = False
    for sf in project.code_files():
        if project.classify(sf) in ("server", "shared") and re.search(r"(?i)\b(?:check|enforce|apply|with)?RateLimit\w*\(|\bratelimit\.limit\(|\blimiter\b|hit_rate_limit|throttle\(", project.text(sf)):
            rate_code = True
            break
    project.cache["global_rate_limit"] = rate_dep and any(re.search(r"\.use\(\s*\w*(?:[lL]imit|[tT]hrottle)\w*", project.text(sf)) for sf in project.code_files(walker.JS_EXTS))
    entries = build_inventory(project, stack)

    for e in entries:
        try:
            entry_findings(project, env, e, stack)
        except Exception as exc:
            env.warn("scan_routes: entry analysis failed for %s (%s)" % (e.id, type(exc).__name__))
    for sf in project.code_files():
        try:
            file_findings(project, env, sf, stack, entries)
        except Exception as exc:
            env.warn("scan_routes: skipped %s (%s)" % (sf.rel, type(exc).__name__))

    # AUTH-003: middleware and mount-order gaps.
    mw = project.cache.get("middleware")
    if mw and mw["has_auth"] and not mw["covers_api"]:
        exposed = [e for e in entries if e.kind in ("route-handler", "api-route") and e.path.startswith("/api") and e.info["privileged_access"]]
        unauth = [e for e in exposed if e.info["auth"]["status"] == "none"]
        sf = project.get(mw["file"])
        env.add(Finding(
            "AUTH-003", "The login check in the middleware skips every `/api` address, and the middleware is the only gate for %d of them%s." % (len(unauth), "" if unauth else "; each API route must therefore check the session itself"),
            file=mw["file"], line=mw["line"], snippet=sf.line_text(mw["line"]) if sf else "", confidence="likely" if unauth else "possible",
            detail="Middleware matcher %s excludes /api. API routes with privileged access and no in-handler check: %s." % (mw["matcher"], ", ".join(e.id for e in unauth[:6]) or "none found"),
            fix_hint="Verify the session inside each handler or in a shared data access layer. Treat middleware as an optimisation, and keep the framework patched.",
        ))
    for gap in project.cache.get("express_gaps", []):
        sf = project.get(gap["file"])
        env.add(Finding(
            "AUTH-003", "The routes under `%s` are registered before the login check, so the check never runs for them." % gap["prefix"],
            file=gap["file"], line=gap["line"], snippet=sf.line_text(gap["line"]) if sf else "", confidence="likely",
            detail="Router %s is mounted on line %d; the auth middleware is applied on line %d, after it. Express runs middleware in registration order." % (gap["target"], gap["line"], gap["auth_line"]),
            fix_hint="Register the auth middleware before these routers, or apply it to each router that needs it. Keep only truly public routes above it.",
        ))

    # API-002: no rate limiting anywhere while abusable endpoints exist.
    costly = [e for e in entries if e.info["calls_llm"] or e.info["sends_messages"] or CRED_ROUTE_RE.search(e.path) and (e.info["privileged_access"] or "POST" in e.methods) or re.search(r"(?i)export|search|upload|import|checkout", e.path)]
    limited = [e for e in costly if e.info["rate_limited"]]
    if costly and not rate_dep and not rate_code and not limited:
        first = costly[0]
        env.add(Finding(
            "API-002", "Nothing limits how often the app's costly endpoints can be called. One script can run up your bills, exhaust quotas or take the app down.",
            file=first.sf.rel, line=first.line, snippet=first.sf.line_text(first.line), confidence="likely", subject={"kind": "project", "name": "rate-limiting"},
            detail="No rate limiting library or code was found. Endpoints that should be limited: %s." % ", ".join(e.id for e in costly[:8]),
            fix_hint="Add per-user and per-IP limits backed by a shared store or the host's firewall rules, stricter on the costly endpoints.",
        ))
    env.inventory["routes"] = public_inventory(entries)
    env.inventory["middleware"] = mw
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_routes", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
