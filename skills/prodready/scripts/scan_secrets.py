#!/usr/bin/env python3
"""Find credentials in the working tree and in built output, classified by exposure.

Detects: admin keys reachable from client code (SEC-001), secrets committed in
env and config files (SEC-002), hard-coded credentials in source (SEC-006),
secrets inside build output (SEC-007), secrets and personal data written to
logs (SEC-009, PRIV-004), weak or fallback signing secrets (SEC-010), AI
provider keys used from the browser (SEC-013), secrets in mobile app config
(SEC-014), private key files (SEC-015), seeded or bypass credentials
(AUTH-017), and public keys, which it reports as information so they are never
mistaken for leaks (SEC-016).

What it deliberately does not do: it never prints a secret (every finding is
redacted on construction), it does not contact any provider to test a key, and
it does not report an ignored local env file as committed. Git history is the
job of scan_git_history.py.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import catalog, findings, jsast, patterns, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402
from lib.redact import redact  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_secrets")
ALSO_EMITS: List[str] = []

MOBILE_CONFIG_RE = re.compile(r"(^|/)(app\.json|app\.config\.[jt]s|eas\.json|Info\.plist|strings\.xml|google-services\.json|GoogleService-Info\.plist|capacitor\.config\.(?:ts|json))$|\.dart$")
KEY_FILE_NAME_RE = re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.(p12|pfx|keystore|jks)$")
SECRET_FIELD_RE = re.compile(r"(?i)[\"']?([A-Za-z0-9_]*(?:service_?(?:role_?)?key|secret_?key|private_?key|api_?secret|client_?secret|admin_?key)[A-Za-z0-9_]*)[\"']?\s*[:=]\s*[\"']([^\"'\s]{16,})[\"']")
WEAK_WORDS = {"secret", "changeme", "change-me", "your-secret-key", "supersecret", "super-secret", "dev", "dev-secret", "development", "password", "test", "mysecret", "my-secret", "jwtsecret", "jwt-secret", "keyboard cat", "shhh", "s3cr3t", "default", "123456", "secretkey", "secret-key", "topsecret"}
SIGNING_NAME = r"(?:\w*(?:JWT|SESSION|COOKIE|NEXTAUTH|AUTH|TOKEN|SIGNING)\w*SECRET\w*|SECRET_KEY|APP_SECRET|SECRET)"
FALLBACK_RE = re.compile(r"process\.env\.(" + SIGNING_NAME + r")\s*(?:\|\||\?\?)\s*([\"'`])([^\"'`\n]+)\2")
PY_FALLBACK_RE = re.compile(r"(?:os\.environ\.get|os\.getenv)\(\s*[\"'](" + SIGNING_NAME + r")[\"']\s*,\s*([\"'])([^\"'\n]+)\2")
SECRET_OPTION_RE = re.compile(r"(?<![\w.])secret\s*:\s*([\"'`])([^\"'`\n]+)\1")
PY_SECRET_RE = re.compile(r"(?m)^\s*(?:SECRET_KEY|JWT_SECRET(?:_KEY)?|app\.secret_key|app\.config\[[\"']SECRET_KEY[\"']\])\s*=\s*([\"'])([^\"'\n]+)\1")
ENV_SIGNING_RE = re.compile(r"(?m)^\s*(?:export\s+)?(" + SIGNING_NAME + r")\s*=\s*[\"']?([^\"'\n#]*)[\"']?\s*$")
LOG_CALL_RE = re.compile(r"\b(?:console\.(?:log|info|debug|warn|error|dir)|logger\.\w+|log\.(?:info|debug|warn|error)|logging\.\w+|print)\s*\(")
SENSITIVE_ARG_RE = re.compile(r"(?i)(?<![\w$])(password|passwd|secret|token|access_?token|refresh_?token|authorization|cookies?|api_?key|credentials)(?![\w$])|process\.env(?!\.NODE_ENV)(?:\s*[,)]|\b(?!\.))|\b(?:req|request)\.headers(?!\s*[.\[])")
PII_ARG_RE = re.compile(r"(?i)(?<![\w$])(?:[\w$]+\??\.)?(e?mail|phone(?:Number)?|address|full_?name|ssn|date_?of_?birth|dob)(?![\w$(])")
ANALYTICS_CALL_RE = re.compile(r"\b(?:Sentry\.setUser|posthog\.identify|analytics\.identify|mixpanel\.(?:identify|people\.set)|amplitude\.\w+|gtag|fbq|track(?:Event)?|LogRocket\.identify)\s*\(")
SEED_CRED_RE = re.compile(r"e?mail\s*:\s*[\"'][^\"'\n]+@[^\"'\n]+[\"'][^}]{0,200}?password\w*\s*:\s*(?:await\s+)?(?:[\w.]+\(\s*)?[\"'][^\"'\n]{3,}[\"']", re.S)
BYPASS_RES = [
    re.compile(r"(?i)\b(?:code|otp|pin|token)\b\s*={2,3}\s*[\"'](?:123456|000000|111111|654321|0000|1234)[\"']"),
    re.compile(r"(?i)\be?mail\b\s*={2,3}\s*[\"'][\w.+-]*(?:test|demo|admin)[\w.+-]*@[\w.-]+[\"']"),
    re.compile(r"(?i)\bpassword\b\s*={2,3}\s*[\"'][^\"'\n]{1,40}[\"']"),
]
CLIENT_AI_RE = re.compile(r"dangerouslyAllowBrowser\s*:\s*true|\bnew\s+(?:OpenAI|Anthropic|GoogleGenerativeAI|GoogleGenAI|Groq|Mistral|Replicate|ElevenLabsClient)\s*\(")


def _var_name(line: str, start_col: int) -> str:
    head = line[:start_col]
    m = re.search(r"([A-Za-z_][A-Za-z0-9_.\-]*)[\"']?\s*[:=]\s*[\"'`]?$", head)
    return m.group(1) if m else ""


def _provider_label(m: patterns.SecretMatch, name: str) -> str:
    if m.label == "supabase-service-role":
        return "Supabase service-role key"
    if m.label == "google-ai":
        return "Google AI key"
    if m.pattern.id == "stripe-secret" and re.search(r"(?i)clerk", name):
        return "Clerk secret key"
    return m.pattern.description.split(" (")[0]


def _is_ai(m: patterns.SecretMatch, name: str) -> bool:
    return m.pattern.ai or m.label == "google-ai" or bool(patterns.AI_NAME_RE.search(name))


def _weak(value: str) -> bool:
    return value.strip().lower() in WEAK_WORDS or len(value) < 32


def scan_file_secrets(project: walker.Project, sf: walker.SourceFile, env: Envelope, public_seen: Dict[str, Finding], env_inventory: List[Dict[str, Any]]) -> None:
    text = project.text(sf)
    rel = sf.rel
    kind = project.classify(sf)
    is_env = walker.is_env_file(rel)
    committed = project.will_be_committed(rel)
    tracked = project.is_tracked(rel)
    is_mobile_cfg = bool(MOBILE_CONFIG_RE.search(rel)) and (project.framework in ("expo", "react-native", "capacitor", "flutter") or rel.endswith((".plist", ".dart", "strings.xml")))

    if '"service_account"' in text and '"private_key"' in text and sf.ext == ".json":
        line = text[: text.find('"private_key"')].count("\n") + 1
        if committed:
            env.add(Finding(
                "SEC-015", "A Google service account key file is in the repository. Anyone who gets the repository can act as your backend with full admin rights.",
                file=rel, line=line, snippet=sf.line_text(line), confidence="confirmed" if tracked else "likely",
                detail="File contains \"type\": \"service_account\" and a private_key. Admin SDK credentials bypass all security rules.",
                fix_hint="Delete the file from the repository, load the credential from the host's secret storage, then revoke this key in the Google Cloud console and create a new one.",
                owner_action="references/owner-actions/rotate-keys.md",
            ))
        return

    matches = patterns.find_secrets(text)
    secret_count = 0
    for m in matches:
        line_text = sf.lines[m.line - 1] if m.line - 1 < len(sf.lines) else ""
        col = m.start - (text.rfind("\n", 0, m.start) + 1)
        name = m.name or _var_name(line_text, col)
        snippet = line_text.strip()
        label = _provider_label(m, name)
        red = redact(m.value)

        if m.pattern.id == "private-key":
            if committed:
                env.add(Finding(
                    "SEC-015", "A private key is stored in the repository. Whoever has the repository can impersonate the service this key belongs to.",
                    file=rel, line=m.line, snippet=snippet, confidence="confirmed" if tracked else "likely",
                    detail="PEM private key block found in %s." % rel,
                    fix_hint="Remove the key from the repository, load it from secret storage, and revoke and reissue it.",
                    owner_action="references/owner-actions/rotate-keys.md",
                ))
            continue

        if m.public:
            if kind in ("test", "doc"):
                continue
            provider = m.pattern.provider if m.label != "supabase-anon" else "supabase"
            if provider not in public_seen:
                extra = " Confirm it is restricted by referrer or app in the provider console (SEC-012)." if m.pattern.id == "google-api-key" else ""
                public_seen[provider] = env.add(Finding(
                    "SEC-016", "This %s key is designed to be public. It is not a leak; what protects your data is the access rules behind it." % provider.capitalize(),
                    file=rel, line=m.line, snippet=snippet, confidence="confirmed", subject={"kind": "public-key", "name": provider},
                    detail="%s found (%s). Public by design; see the database checks for the rules that matter.%s" % (label, red, extra),
                    fix_hint="Nothing to fix here. Review the access rules instead.",
                ))
            continue

        secret_count += 1
        generic = m.pattern.generic or m.pattern.id == "jwt" and m.label == "jwt"
        if kind == "test":
            continue
        pub_prefix = patterns.public_prefix(name) if name else None
        ai = _is_ai(m, name)

        if is_env:
            if not committed:
                continue
            note = " The variable name starts with %s, so the value is also built into the browser bundle (SEC-005)." % pub_prefix if pub_prefix else ""
            env.add(Finding(
                "SEC-002", "A real-looking %s is saved in %s, a file that is part of the repository. Anyone who can see the repository has this key." % (label, rel),
                file=rel, line=m.line, snippet=snippet, confidence="confirmed" if tracked else "likely",
                detail="%s = %s in an env file that %s.%s" % (name or "value", red, "is tracked by git" if tracked else "is not covered by .gitignore", note),
                fix_hint="Remove the value from the file, add the file to .gitignore, keep an .env.example with empty values, and rotate the key.",
                owner_action="references/owner-actions/rotate-keys.md",
            ))
            continue
        if is_mobile_cfg:
            env.add(Finding(
                "SEC-014", "A secret key is written into the mobile app's configuration. Anyone who downloads the app can unpack it and read this key.",
                file=rel, line=m.line, snippet=snippet, confidence="likely" if generic else "confirmed",
                detail="%s (%s) in %s, which is packaged into the app binary." % (label, red, rel),
                fix_hint="Move the privileged calls to a backend. Keep only public keys in the app. Rotate this key.",
                owner_action="references/owner-actions/rotate-keys.md",
            ))
            continue
        if kind == "client":
            check = "SEC-013" if ai else "SEC-001"
            if generic and not ai:
                env.add(Finding(
                    "SEC-006", "A credential-like value is written directly in code that runs in the browser.",
                    file=rel, line=m.line, snippet=snippet, confidence="possible",
                    detail="%s = %s in client code. If this is a private key it is public now; if it is a publishable key, no action is needed." % (name or "value", red),
                    fix_hint="Confirm what this value is. Private keys must move to the server and be rotated.",
                ))
                continue
            msg = (
                "Your AI provider key is inside the code sent to every visitor. Anyone can copy it and run up charges on your account."
                if ai else
                "An admin-level key is inside the code sent to every visitor. Anyone can copy it and read or change all of your data."
            )
            env.add(Finding(
                check, msg, file=rel, line=m.line, snippet=snippet, confidence="confirmed",
                detail="%s (%s) is a literal in a file that is bundled for the browser." % (label, red),
                fix_hint="Move the call behind a server route, read the key from a server-only variable, and rotate the key.",
                owner_action="references/owner-actions/rotate-keys.md",
            ))
            continue
        if kind in ("config", "doc") and not committed:
            continue
        if kind == "doc":
            env.add(Finding(
                "SEC-002", "A real-looking %s appears in a documentation file in the repository." % label,
                file=rel, line=m.line, snippet=snippet, confidence="likely",
                detail="%s in %s. If it is a working key, it is exposed to everyone with repository access." % (red, rel),
                fix_hint="Replace it with a placeholder and rotate the key if it was ever valid.",
                owner_action="references/owner-actions/rotate-keys.md",
            ))
            continue
        if kind == "config":
            env.add(Finding(
                "SEC-002", "A real-looking %s is saved in a configuration file in the repository." % label,
                file=rel, line=m.line, snippet=snippet, confidence="likely" if generic else "confirmed" if tracked else "likely",
                detail="%s = %s in %s." % (name or "value", red, rel),
                fix_hint="Load the value from the environment and rotate the key.",
                owner_action="references/owner-actions/rotate-keys.md",
            ))
            continue
        env.add(Finding(
            "SEC-006", "A %s is written directly in the source code. It travels wherever the code goes: the repository, AI tools, every deployment." % label,
            file=rel, line=m.line, snippet=snippet, confidence="likely" if generic else "confirmed",
            severity="critical" if (not generic and m.pattern.severity == "critical") else None,
            detail="%s = %s as a literal in %s code." % (name or "value", red, kind),
            fix_hint="Replace the literal with an environment lookup that is validated at startup, then rotate the key.",
            owner_action="references/owner-actions/rotate-keys.md",
        ))

    if is_mobile_cfg and not any(f.file == rel and f.check_id == "SEC-014" for f in env.findings):
        for fm in SECRET_FIELD_RE.finditer(text):
            if patterns.is_placeholder(fm.group(2)) or re.search(r"(?i)publishable|anon|public", fm.group(1)):
                continue
            line = text.count("\n", 0, fm.start()) + 1
            env.add(Finding(
                "SEC-014", "A value named like a secret key is written into the mobile app's configuration, which ships inside the app.",
                file=rel, line=line, snippet=sf.line_text(line), confidence="likely",
                detail="Field %s holds a %d-character value in %s." % (fm.group(1), len(fm.group(2)), rel),
                fix_hint="Move privileged calls to a backend and keep only public keys in the app.",
                owner_action="references/owner-actions/rotate-keys.md",
            ))
            break

    if is_env:
        env_inventory.append({
            "file": rel, "example": walker.is_env_example(rel), "ignored": project.gitignore.ignored(rel),
            "tracked": tracked, "committed": committed, "secret_like_values": secret_count,
        })


def scan_code_patterns(project: walker.Project, sf: walker.SourceFile, env: Envelope) -> None:
    text = project.text(sf)
    rel = sf.rel
    kind = project.classify(sf)
    is_py = sf.ext == ".py"
    lx = jsast.lexed(text) if not is_py else None
    code = lx.code if lx else text
    src = lx.nocomment if lx else re.sub(r"(?m)#.*$", "", text)

    # SEC-001 / SEC-013: secret-named public variables read in client code, and AI SDKs in the browser.
    if kind == "client":
        for m in sorted(CLIENT_AI_RE.finditer(code), key=lambda x: (0 if "dangerouslyAllowBrowser" in x.group(0) else 1, x.start())):
            line = jsast.line_of(code, m.start())
            confirmed = "dangerouslyAllowBrowser" in m.group(0)
            if any(f.check_id == "SEC-013" and f.file == rel for f in env.findings):
                continue
            env.add(Finding(
                "SEC-013", "The AI provider is called straight from the browser, so the key that pays for it is in every visitor's hands.",
                file=rel, line=line, snippet=sf.line_text(line), confidence="confirmed" if confirmed else "likely",
                detail="AI SDK constructed in client-bundled code%s." % (" with dangerouslyAllowBrowser: true" if confirmed else ""),
                fix_hint="Create a server endpoint that holds the key, checks who is calling and enforces limits. Rotate the key and set a provider spending limit.",
                owner_action="references/owner-actions/rotate-keys.md",
            ))
        for m in patterns.ENV_READ_RE.finditer(src):
            name = next((g for g in m.groups() if g), "")
            if not patterns.public_prefix(name) or not patterns.is_secret_name(name):
                continue
            line = jsast.line_of(src, m.start())
            ai = bool(patterns.AI_NAME_RE.search(name))
            if ai and any(f.check_id == "SEC-013" and f.file == rel for f in env.findings):
                continue
            env.add(Finding(
                "SEC-013" if ai else "SEC-001",
                ("The app reads an AI provider key in browser code. The key is shipped to every visitor and can be used to spend your money."
                 if ai else "Browser code reads a variable named like an admin key. Whatever value is set there is shipped to every visitor."),
                file=rel, line=line, snippet=sf.line_text(line), confidence="likely",
                detail="%s is read in client-bundled code; variables with a public prefix are inlined into the bundle." % name,
                fix_hint="Move this call to a server route and use a server-only variable. Rotate the key if a real value was ever set.",
                owner_action="references/owner-actions/rotate-keys.md",
            ))
        if not any(f.check_id == "SEC-013" and f.file == rel for f in env.findings):
            hm = patterns.LLM_HOST_RE.search(src)
            if hm and re.search(r"(?i)authorization|x-api-key|api[-_]?key", src):
                line = jsast.line_of(src, hm.start())
                env.add(Finding(
                    "SEC-013", "Browser code calls an AI provider directly with an API key.",
                    file=rel, line=line, snippet=sf.line_text(line), confidence="likely",
                    detail="Request to %s with an authorization header from client-bundled code." % hm.group(0),
                    fix_hint="Proxy the call through your own authenticated server endpoint.",
                    owner_action="references/owner-actions/rotate-keys.md",
                ))

    if kind in ("test", "doc"):
        return

    # SEC-010: weak, literal or fallback signing secrets.
    seen_lines = set()

    def weak(m: re.Match, value: str, how: str, confidence: str) -> None:
        line = jsast.line_of(src, m.start())
        if line in seen_lines or patterns._ENV_LOOKUP.search(value):
            return
        seen_lines.add(line)
        env.add(Finding(
            "SEC-010", "The secret that signs login sessions is a known or guessable value. Anyone who knows it can sign in as any user, including an administrator.",
            file=rel, line=line, snippet=sf.line_text(line), confidence=confidence,
            detail="%s (%d characters)." % (how, len(value)),
            fix_hint="Require the variable at startup with no fallback, generate a long random value, and store it in the host's secret settings.",
            owner_action="references/owner-actions/rotate-keys.md",
        ))

    if not is_py:
        for call in jsast.find_calls(text, ["jwt.sign", "jwt.verify", "jsonwebtoken.sign", "jsonwebtoken.verify"]):
            parts = jsast.split_args(call.args)
            literal = jsast.string_value(parts[1]) if len(parts) > 1 else None
            if literal is not None:
                class _M:  # minimal match-like object for weak()
                    def __init__(self, pos): self._pos = pos
                    def start(self): return self._pos
                weak(_M(call.start), literal, "%s is called with a string literal as the secret" % call.name, "confirmed")
    for m in FALLBACK_RE.finditer(src):
        weak(m, m.group(3), "%s falls back to a literal when the variable is missing" % m.group(1), "confirmed")
    if is_py:
        for m in PY_FALLBACK_RE.finditer(src):
            weak(m, m.group(3), "%s falls back to a literal default" % m.group(1), "confirmed")
        for m in PY_SECRET_RE.finditer(src):
            weak(m, m.group(2), "signing secret assigned a literal in code", "confirmed" if _weak(m.group(2)) else "likely")
    elif re.search(r"(?i)session|next-?auth|jwt|cookie|passport|better-auth|iron", src):
        for m in SECRET_OPTION_RE.finditer(src):
            weak(m, m.group(2), "session or auth configuration uses a literal secret", "confirmed" if _weak(m.group(2)) else "likely")

    # SEC-009 and PRIV-004: credentials and personal data in log and analytics calls.
    sec9_done = priv4_done = False
    for m in LOG_CALL_RE.finditer(code):
        open_idx = m.end() - 1
        close = jsast.match_close(code, open_idx) if not is_py else code.find(")", open_idx)
        if close == -1:
            continue
        args = code[open_idx + 1:close]
        line = jsast.line_of(code, m.start())
        sm = SENSITIVE_ARG_RE.search(args)
        if sm and not sec9_done:
            sec9_done = True
            env.add(Finding(
                "SEC-009", "This log line writes a password, token or other credential into the logs, where many people and services can read it.",
                file=rel, line=line, snippet=sf.line_text(line), confidence="likely",
                detail="Log call includes `%s`." % sm.group(0).strip(" ,)"),
                fix_hint="Remove it or log an identifier instead of the credential.",
            ))
        elif not sm and not priv4_done and kind != "client":
            pm = PII_ARG_RE.search(args)
            if pm:
                priv4_done = True
                env.add(Finding(
                    "PRIV-004", "This log line records personal data such as an email address. Logs are kept for a long time and copied to other services.",
                    file=rel, line=line, snippet=sf.line_text(line), confidence="likely",
                    detail="Log call includes `%s`." % pm.group(0),
                    fix_hint="Log the user ID instead of the personal data.",
                ))
    if not priv4_done:
        for m in ANALYTICS_CALL_RE.finditer(code):
            open_idx = m.end() - 1
            close = jsast.match_close(code, open_idx)
            if close == -1:
                continue
            pm = PII_ARG_RE.search(code[open_idx + 1:close])
            if pm:
                line = jsast.line_of(code, m.start())
                env.add(Finding(
                    "PRIV-004", "Personal data is sent to an analytics or error tracking service.",
                    file=rel, line=line, snippet=sf.line_text(line), confidence="possible",
                    detail="`%s` passed to %s. Check that this is disclosed and necessary." % (pm.group(0), m.group(0).rstrip("( ")),
                    fix_hint="Send an internal ID, or disclose this in the privacy policy and scrub what is not needed.",
                ))
                break

    # AUTH-017: seeded, demo or bypass credentials.
    for m in SEED_CRED_RE.finditer(src):
        line = jsast.line_of(src, m.start())
        env.add(Finding(
            "AUTH-017", "The code creates an account with a known email and password. Anyone who reads the code, or guesses, can sign in with it.",
            file=rel, line=line, snippet=sf.line_text(line), confidence="likely",
            detail="An email literal and a password literal appear together in a user creation call.",
            fix_hint="Remove the account from production, restrict seeds to development, and never commit real passwords.",
        ))
        break
    for rx in BYPASS_RES:
        m = rx.search(src)
        if m:
            line = jsast.line_of(src, m.start())
            if any(f.check_id == "AUTH-017" and f.file == rel and f.line == line for f in env.findings):
                continue
            env.add(Finding(
                "AUTH-017", "The sign-in code contains a built-in shortcut: a fixed code, email or password that lets someone in without the real check.",
                file=rel, line=line, snippet=sf.line_text(line), confidence="likely",
                detail="Comparison against a hard-coded credential: `%s`." % m.group(0),
                fix_hint="Delete the shortcut. Use a test account in a development environment instead.",
            ))


def scan_env_signing(project: walker.Project, sf: walker.SourceFile, env: Envelope) -> None:
    if walker.is_env_example(sf.rel) or not project.will_be_committed(sf.rel):
        return
    text = project.text(sf)
    for m in ENV_SIGNING_RE.finditer(text):
        value = m.group(2).strip()
        if not value or value.startswith("$") or not _weak(value):
            continue
        line = text.count("\n", 0, m.start()) + 1
        env.add(Finding(
            "SEC-010", "The secret that signs login sessions is short or guessable and is saved in the repository.",
            file=sf.rel, line=line, snippet="%s=[%d characters]" % (m.group(1), len(value)), confidence="confirmed",
            detail="%s is %d characters long in a committed env file." % (m.group(1), len(value)),
            fix_hint="Generate a long random value, store it only in the host's secret settings, and remove this file from the repository.",
            owner_action="references/owner-actions/rotate-keys.md",
        ))


def scan_build_output(project: walker.Project, env: Envelope) -> None:
    for sf in project.build_files:
        if sf.ext not in (".js", ".mjs", ".map", ".html", ".css", ".json") or sf.size > 8000000:
            continue
        text = sf.load(8000000)
        if not text:
            continue
        for m in patterns.find_secrets(text):
            if m.public or m.pattern.generic or (m.pattern.id == "jwt" and m.label == "jwt"):
                continue
            ctx = text[max(0, m.start - 60): m.end + 20].replace("\n", " ")
            env.add(Finding(
                "SEC-007", "A secret key is inside the built files that are sent to every visitor. This proves the key is already public wherever this build was deployed.",
                file=sf.rel, line=m.line, snippet=ctx, confidence="confirmed",
                detail="%s (%s) found in build output %s." % (_provider_label(m, ""), redact(m.value), sf.rel),
                fix_hint="Remove the key from client code, rebuild, redeploy, and rotate the key.",
                owner_action="references/owner-actions/rotate-keys.md",
            ))


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_secrets", stack)
    public_seen: Dict[str, Finding] = {}
    env_inventory: List[Dict[str, Any]] = []
    for sf in project.files:
        if sf.is_lockfile:
            continue
        text = project.text(sf)
        if not text:
            continue
        try:
            if not sf.minified or walker.is_env_file(sf.rel):
                scan_file_secrets(project, sf, env, public_seen, env_inventory)
            if walker.is_env_file(sf.rel):
                scan_env_signing(project, sf, env)
            elif sf.ext in walker.CODE_EXTS and not sf.minified:
                scan_code_patterns(project, sf, env)
        except Exception as exc:  # one bad file must not stop the scan
            env.warn("scan_secrets: skipped %s (%s)" % (sf.rel, type(exc).__name__))
    for sf in list(project.assets) + list(project.files):
        if KEY_FILE_NAME_RE.search(sf.rel) and project.will_be_committed(sf.rel):
            env.add(Finding(
                "SEC-015", "A key file is stored in the repository. Whoever has the repository can use this identity.",
                file=sf.rel, confidence="confirmed" if project.is_tracked(sf.rel) else "likely", subject={"kind": "key-file", "name": sf.rel},
                detail="File name or extension marks %s as a private key or keystore." % sf.rel,
                fix_hint="Remove it from the repository, add it to .gitignore, and revoke and reissue the key.",
                owner_action="references/owner-actions/rotate-keys.md",
            ))
    try:
        scan_build_output(project, env)
    except Exception as exc:
        env.warn("scan_secrets: build output pass failed (%s)" % type(exc).__name__)
    env.inventory["env_files"] = sorted(env_inventory, key=lambda e: e["file"])
    local = [e["file"] for e in env_inventory if not e["committed"] and e["secret_like_values"]]
    if local:
        env.inventory["local_env_note"] = "Local env file(s) %s contain live-looking keys and are ignored by git. That is normal; keep them out of the repository." % ", ".join(local)
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_secrets", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
