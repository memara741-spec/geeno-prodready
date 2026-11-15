#!/usr/bin/env python3
"""Review Firebase security rules and Cloud Functions from the repository.

It parses ``firestore.rules`` and ``storage.rules`` with a small recursive
descent parser, reads ``database.rules.json``, and classifies every ``allow``
condition. It reports rules that are open or still in time-boxed test mode
(DB-010), rules that check sign-in but not ownership or the shape of the data
(DB-011, DB-009 for Storage), rules that are not in the repository (DB-015),
and HTTP or callable functions that never check who is calling (API-013).

``inventory.firebase_access`` is the access matrix per collection path: what
an anonymous visitor and a signed-in user can read and write.

What it deliberately does not do: it does not evaluate rules the way the
emulator does. Conditions it cannot classify are labelled ``custom`` and left
for review. It never contacts the Firebase project.
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detect_stack  # noqa: E402
from lib import catalog, findings, jsast, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_firebase")
ALSO_EMITS = ["DB-009", "DB-015", "API-013", "AUTH-013"]

READ_OPS = {"read", "get", "list"}
WRITE_OPS = {"write", "create", "update", "delete"}
USER_COLLECTION_RE = re.compile(r"(?i)^/?(users?|profiles?|accounts?|members?|customers?)/")
PRIVILEGED_FIELD_RE = re.compile(r"(?i)role|admin|credits|plan|balance|owner")


class Allow:
    def __init__(self, path: str, ops: List[str], condition: str, line: int, text: str) -> None:
        self.path = path
        self.ops = ops
        self.condition = condition
        self.line = line
        self.text = text
        self.klass = "custom"


class Rules:
    def __init__(self) -> None:
        self.service = ""
        self.allows: List[Allow] = []
        self.functions: Dict[str, str] = {}
        self.errors: List[str] = []


def strip_comments(text: str) -> str:
    """Blank out // and /* */ comments, keeping length and newlines."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _close(text: str, open_idx: int) -> int:
    depth = 0
    for j in range(open_idx, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return j
    return -1


def parse_rules(text: str) -> Rules:
    """Parse the rules language: service, nested match blocks, allow statements and functions."""
    rules = Rules()
    src = strip_comments(text)
    sm = re.search(r"\bservice\s+([\w.]+)\s*\{", src)
    if not sm:
        rules.errors.append("no service block found")
        return rules
    rules.service = sm.group(1)

    def walk(start: int, end: int, prefix: str) -> None:
        i = start
        while i < end:
            m = re.compile(r"\b(match|allow|function)\b").search(src, i, end)
            if not m:
                return
            kw = m.group(1)
            if kw == "match":
                brace = src.find("{", m.end(), end)
                # path variables use braces too: find the block brace, which follows whitespace after the path
                pm = re.compile(r"\s*((?:/(?:\{[^}]*\}|[^\s{/]+))+)\s*\{").match(src, m.end(), end)
                if not pm:
                    i = m.end()
                    continue
                brace = pm.end() - 1
                close = _close(src, brace)
                if close == -1:
                    rules.errors.append("unbalanced braces after match at offset %d" % m.start())
                    return
                walk(brace + 1, close, prefix + pm.group(1))
                i = close + 1
            elif kw == "function":
                fm = re.compile(r"\s+(\w+)\s*\([^)]*\)\s*\{").match(src, m.end(), end)
                if not fm:
                    i = m.end()
                    continue
                brace = fm.end() - 1
                close = _close(src, brace)
                if close == -1:
                    return
                body = src[brace + 1:close]
                rm = re.search(r"\breturn\b([\s\S]*?);", body)
                rules.functions[fm.group(1)] = re.sub(r"\s+", " ", rm.group(1)).strip() if rm else ""
                i = close + 1
            else:
                semi = src.find(";", m.end(), end)
                semi = end if semi == -1 else semi
                stmt = src[m.end():semi]
                parts = stmt.split(":", 1)
                ops = [o.strip() for o in parts[0].split(",") if o.strip()]
                cond = "true"
                if len(parts) > 1:
                    cond = re.sub(r"^\s*if\b", "", parts[1].strip()).strip()
                    cond = re.sub(r"\s+", " ", cond)
                line = src.count("\n", 0, m.start()) + 1
                shown = re.sub(r"^/databases/\{[^}]+\}/documents|^/b/\{[^}]+\}/o", "", prefix) or "/"
                rules.allows.append(Allow(shown, ops, cond, line, re.sub(r"\s+", " ", "allow" + stmt).strip()))
                i = semi + 1

    brace = sm.end() - 1
    close = _close(src, brace)
    walk(brace + 1, close if close != -1 else len(src), "")
    for a in rules.allows:
        a.klass = classify_condition(a.condition, rules.functions, a.path)
    return rules


def _expand(cond: str, functions: Dict[str, str], depth: int = 0) -> str:
    """Inline helper functions (two levels) so the classifier sees the real condition."""
    if depth > 2:
        return cond
    def repl(m: re.Match) -> str:
        body = functions.get(m.group(1))
        if body is None:
            return m.group(0)
        return "(" + _expand(body, functions, depth + 1) + ")"
    return re.sub(r"(?<![\w.])(\w+)\s*\([^()]*\)", repl, cond)


def classify_condition(cond: str, functions: Dict[str, str], path: str = "") -> str:
    """open, time-boxed-open, none, auth-only, owner-scoped, validated, or custom."""
    c = _expand(cond.strip(), functions)
    flat = re.sub(r"[\s()]", "", c)
    if flat == "true":
        return "open"
    if flat == "false":
        return "none"
    if re.search(r"request\.time\s*<\s*timestamp\.date\(", c) and "request.auth" not in c:
        return "time-boxed-open"
    owner = bool(re.search(r"request\.auth\.uid\s*==\s*(?!null)[\w.\[\]'\"]+|[\w.\[\]'\"]+\s*==\s*request\.auth\.uid|request\.auth\.uid\s+in\s+|request\.auth\.token\.\w+", c))
    validated = bool(re.search(r"request\.resource\.data|request\.resource\.(size|contentType)", c))
    if owner:
        return "validated" if validated and "hasOnly" in c else "owner-scoped"
    if re.fullmatch(r"request\.auth!=null(&&request\.auth\.uid!=null)?", flat):
        return "auth-only"
    if "request.auth" in c and not owner:
        return "auth-only" if not validated else "custom"
    if validated:
        return "custom"
    return "custom"


def matrix_for(rules: Rules) -> Dict[str, Dict[str, Dict[str, str]]]:
    order = ["none", "own data", "needs review", "all data"]

    def level(klass: str, role: str) -> str:
        if klass in ("open", "time-boxed-open"):
            return "all data"
        if klass == "none":
            return "none"
        if klass == "auth-only":
            return "all data" if role == "signed-in" else "none"
        if klass in ("owner-scoped", "validated"):
            return "own data" if role == "signed-in" else "none"
        return "needs review"

    out: Dict[str, Dict[str, Dict[str, str]]] = {}
    for a in rules.allows:
        entry = out.setdefault(a.path, {"anonymous": {"read": "none", "write": "none"}, "signed-in": {"read": "none", "write": "none"}})
        for role in ("anonymous", "signed-in"):
            lvl = level(a.klass, role)
            for group, ops in (("read", READ_OPS), ("write", WRITE_OPS)):
                if set(a.ops) & ops and order.index(lvl) > order.index(entry[role][group]):
                    entry[role][group] = lvl
    return out


def report_rules(env: Envelope, rel: str, rules: Rules, kind: str) -> None:
    label = "database" if kind == "firestore" else "file storage"
    for a in rules.allows:
        reads = bool(set(a.ops) & READ_OPS)
        writes = bool(set(a.ops) & WRITE_OPS)
        what = " and ".join(w for w, on in (("read", reads), ("change", writes)) if on) or "access"
        subject = {"kind": "rule", "name": "%s:%s" % (kind, a.path)}
        if a.klass in ("open", "time-boxed-open"):
            timed = a.klass == "time-boxed-open"
            env.add(Finding(
                "DB-010", "Anyone on the internet can %s everything under `%s` in your %s, without signing in.%s" % (what, a.path, label, " This is the temporary test-mode rule; when its date passes the app stops working instead." if timed else ""),
                file=rel, line=a.line, snippet=a.text, confidence="confirmed", subject=subject,
                detail="%s rule at %s: `%s` (%s)." % (kind.capitalize(), a.path, a.condition, a.klass),
                fix_hint="Deny by default and write per-collection rules scoped by request.auth.uid. Keep the rules in the repository and add emulator tests.",
            ))
        elif a.klass == "auth-only":
            if kind == "storage":
                env.add(Finding(
                    "DB-009", "Any signed-up user can %s every file under `%s`, including other users' files." % (what, a.path),
                    file=rel, line=a.line, snippet=a.text, confidence="likely", subject=subject,
                    detail="Storage rule only checks request.auth != null.",
                    fix_hint="Scope the path by user ID (match /users/{userId}/...) and compare it with request.auth.uid. Add size and content-type limits.",
                ))
            else:
                env.add(Finding(
                    "DB-011", "Any signed-up user can %s every document under `%s`, not just their own." % (what, a.path),
                    file=rel, line=a.line, snippet=a.text, confidence="likely", subject=subject,
                    detail="Rule only checks that the caller is signed in: `%s`." % a.condition,
                    fix_hint="Compare request.auth.uid with the path's user ID or the document's owner field, and validate writable fields with hasOnly().",
                ))
                if writes and USER_COLLECTION_RE.search(a.path):
                    env.add(Finding(
                        "AUTH-013", "Users can rewrite any profile document under `%s`, including fields such as role or credits." % a.path,
                        file=rel, line=a.line, snippet=a.text, confidence="possible", subject={"kind": "rule", "name": "role:%s" % a.path},
                        detail="Write access to a user collection with no ownership check and no field validation.",
                        fix_hint="Store roles in custom claims or in documents only the server writes.",
                    ))
        elif a.klass == "owner-scoped" and kind == "firestore" and set(a.ops) & {"write", "update", "create"} and USER_COLLECTION_RE.search(a.path):
            env.add(Finding(
                "DB-011", "Users can only edit their own profile under `%s`, but nothing limits which fields they change, so server-controlled fields such as role or credits are editable." % a.path,
                file=rel, line=a.line, snippet=a.text, confidence="possible", severity="high", subject=subject,
                detail="Owner-scoped write with no request.resource.data validation.",
                fix_hint="Restrict writable fields with request.resource.data.diff(resource.data).affectedKeys().hasOnly([...]).",
            ))


def scan_rtdb(env: Envelope, rel: str, text: str) -> None:
    try:
        data = json.loads(re.sub(r"(?m)^\s*//.*$", "", text))
    except ValueError:
        env.warn("scan_firebase: %s is not valid JSON" % rel)
        return
    lines = text.split("\n")

    def line_of(needle: str) -> int:
        return next((i for i, l in enumerate(lines, 1) if needle in l), 1)

    def walk(node: Any, path: str) -> None:
        if not isinstance(node, dict):
            return
        for key in (".read", ".write"):
            if key not in node:
                continue
            val = node[key]
            expr = str(val).strip().lower()
            what = "read" if key == ".read" else "change"
            ln = line_of('"%s"' % key)
            if val is True or expr == "true":
                env.add(Finding(
                    "DB-010", "Anyone on the internet can %s everything under `%s` in your Realtime Database." % (what, path or "/"),
                    file=rel, line=ln, snippet='"%s": %s' % (key, json.dumps(val)), confidence="confirmed", subject={"kind": "rule", "name": "rtdb:%s:%s" % (path or "/", key)},
                    detail="Realtime Database rule %s is true at %s." % (key, path or "/"),
                    fix_hint="Deny by default and scope rules by auth.uid.",
                ))
            elif expr in ("auth != null", "auth!=null", "auth.uid != null"):
                env.add(Finding(
                    "DB-011", "Any signed-up user can %s everything under `%s` in your Realtime Database." % (what, path or "/"),
                    file=rel, line=ln, snippet='"%s": %s' % (key, json.dumps(val)), confidence="likely", subject={"kind": "rule", "name": "rtdb:%s:%s" % (path or "/", key)},
                    detail="Rule only checks that the caller is signed in.",
                    fix_hint="Scope by auth.uid, for example \"$uid === auth.uid\".",
                ))
        for k, v in node.items():
            if not k.startswith("."):
                walk(v, path + "/" + k)

    walk(data.get("rules", data), "")


FN_DEF_RE = re.compile(r"(?:exports\.(\w+)\s*=|export\s+const\s+(\w+)\s*=)\s*(?:functions\.)?(?:\w+\.)*?(https\.onRequest|https\.onCall|onRequest|onCall)\s*\(")


def scan_functions(project: walker.Project, env: Envelope) -> None:
    for sf in project.code_files():
        text = project.text(sf)
        if "onRequest" not in text and "onCall" not in text:
            continue
        if "firebase-functions" not in text and not sf.rel.startswith("functions/"):
            continue
        code = jsast.lexed(text).code
        for m in FN_DEF_RE.finditer(code):
            name = m.group(1) or m.group(2)
            open_idx = m.end() - 1
            close = jsast.match_close(code, open_idx)
            if close == -1:
                continue
            body = code[open_idx:close]
            raw = jsast.lexed(text).nocomment[open_idx:close]
            line = jsast.line_of(code, m.start())
            kind = "onCall" if "onCall" in m.group(3) else "onRequest"
            if kind == "onRequest":
                if re.search(r"verifyIdToken\(|verifySessionCookie\(|verifyAppCheckToken|constructEvent\(|timingSafeEqual\(|authorization", raw, re.I) and re.search(r"verify|constructEvent|timingSafeEqual", raw):
                    continue
                env.add(Finding(
                    "API-013", "The cloud function `%s` is a public web address that runs with full admin rights and never checks who is calling it." % name,
                    file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", subject={"kind": "function", "name": name},
                    detail="onRequest handler with no ID token verification (verifyIdToken) and no signature check.",
                    fix_hint="Verify the bearer ID token with admin.auth().verifyIdToken(), or switch to a callable function and check the auth context.",
                ))
            else:
                if re.search(r"\b(?:context|request|req)\.auth\b|\bauth\s*[,})]|\.auth\?\.", body):
                    continue
                env.add(Finding(
                    "API-013", "The callable function `%s` never looks at who is calling it, so anyone can run it for any data." % name,
                    file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely", subject={"kind": "function", "name": name},
                    detail="onCall handler that never reads the auth context.",
                    fix_hint="Reject the call when the auth context is missing, and authorise against the caller's uid.",
                ))
        im = re.search(r"invoker\s*:\s*[\"']public[\"']", code and jsast.lexed(text).nocomment)
        if im and not any(f.file == sf.rel and f.check_id == "API-013" for f in env.findings):
            line = jsast.line_of(text, im.start())
            env.add(Finding(
                "API-013", "A cloud function is explicitly opened to the public.",
                file=sf.rel, line=line, snippet=sf.line_text(line), confidence="possible",
                detail="invoker: 'public' set on a function. Confirm that it verifies callers itself.",
                fix_hint="Remove the public invoker for internal functions.",
            ))


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_firebase", stack)
    uses_firebase = detect_stack.has(stack, "backend", "firebase")
    if not uses_firebase:
        env.inventory["firebase"] = {"detected": False}
        return env
    access: Dict[str, Any] = {}
    found_rules: List[str] = []
    fb_json: Dict[str, Any] = {}
    try:
        fb_json = json.loads(project.read("firebase.json") or "{}")
    except ValueError:
        env.warn("scan_firebase: firebase.json is not valid JSON")
    declared: List[Tuple[str, str]] = []
    for key, default in (("firestore", "firestore.rules"), ("storage", "storage.rules"), ("database", "database.rules.json")):
        section = fb_json.get(key) if isinstance(fb_json, dict) else None
        sections = section if isinstance(section, list) else [section] if isinstance(section, dict) else []
        for s in sections:
            if isinstance(s, dict) and s.get("rules"):
                declared.append((key, str(s["rules"])))
    for sf in project.files:
        try:
            if sf.name.endswith(".rules"):
                text = project.text(sf)
                rules = parse_rules(text)
                kind = "storage" if "storage" in rules.service or "storage" in sf.name else "firestore"
                found_rules.append(sf.rel)
                for err in rules.errors:
                    env.warn("scan_firebase: %s: %s" % (sf.rel, err))
                report_rules(env, sf.rel, rules, kind)
                access[sf.rel] = matrix_for(rules)
            elif sf.name == "database.rules.json":
                found_rules.append(sf.rel)
                scan_rtdb(env, sf.rel, project.text(sf))
        except Exception as exc:
            env.warn("scan_firebase: skipped %s (%s)" % (sf.rel, type(exc).__name__))
    for key, path in declared:
        if not project.exists(path):
            env.add(Finding(
                "DB-015", "firebase.json points to a rules file that is not in the repository, so the rules cannot be reviewed or redeployed from here.",
                file="firebase.json", line=1, snippet='"%s": { "rules": "%s" }' % (key, path), confidence="confirmed", subject={"kind": "file", "name": path},
                detail="Declared %s rules file %s does not exist." % (key, path),
                fix_hint="Download the current rules from the Firebase console into this file and commit it.",
            ))
    client_sdk = detect_stack.has(stack, "database", "firebase") or detect_stack.has(stack, "storage", "firebase")
    if client_sdk and not found_rules and not declared:
        env.add(Finding(
            "DB-015", "The rules that decide who can read your Firebase data are not in this repository. They exist only in the Firebase console, and this audit could not see them.",
            confidence="confirmed", subject={"kind": "project", "name": "firebase-rules"},
            detail="The Firebase SDK is used but there is no firestore.rules, storage.rules or database.rules.json.",
            fix_hint="Run `firebase init firestore` (and storage) to pull the rules into the repository, commit them, and re-run the scan.",
        ))
    try:
        scan_functions(project, env)
    except Exception as exc:
        env.warn("scan_firebase: functions pass failed (%s)" % type(exc).__name__)
    env.inventory["firebase"] = {"detected": True, "rules_files": sorted(found_rules)}
    env.inventory["firebase_access"] = access
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_firebase", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
