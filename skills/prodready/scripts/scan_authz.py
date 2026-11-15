#!/usr/bin/env python3
"""Deep authorization audit for Laravel: is each operation on each record really checked?

Having an ``auth`` middleware only proves someone signed in. This scanner builds a
matrix of controller actions that work on a record (create, read, update, delete),
finds the policies that should guard them, and checks both halves: that the code
asks the policy (AUTHZ-001, AUTHZ-003) and that the policy answers sensibly
(AUTHZ-002, AUTHZ-004). The matrix is in ``inventory.authorization``.

What it deliberately does not do: it does not run policies, resolve custom gate
names, or follow authorization done in other classes or traits. A finding means
"read this", and an unresolved enforcement is treated as covering the ability.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional, Set

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import catalog, findings, phpscan, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_authz")
ALSO_EMITS: List[str] = []
RECORD_ABILITIES = {"view", "update", "delete", "restore", "forcedelete"}
MUTATE = re.compile(r"->(?:update|delete|forceDelete|save|fill|restore|attach|detach|sync)\s*\(|::destroy\s*\(")
ENFORCE = re.compile(r"(?:authorize\w*|Gate::(?:authorize|allows|denies|check|inspect)|->(?:can|cannot|cant))\s*\(\s*['\"](\w+)['\"]\s*(?:,\s*([^;]*?))?\)")
GUARD = re.compile(r"authorize\w*\s*\(|Gate::|->can\s*\(|->cannot\s*\(|abort_(?:if|unless)\s*\(|->user\(\)->\w+\(\)->")
CLASS_LEVEL = re.compile(r"authorizeResource\s*\(\s*(\w+)::class|middleware\(\s*\[?\s*['\"]can:|new\s+Middleware\(\s*['\"]can:")


def studly(var: str) -> str:
    var = var.lstrip("$").split("->")[-1]
    return var[:1].upper() + var[1:] if var else ""


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_authz", stack)
    if not phpscan.is_laravel(project):
        env.files_scanned, env.files_skipped = project.stats()
        return env
    pfs = [p for p in phpscan.php_files(project) if not walker.TEST_PATH_RE.search(p.rel)]
    models = phpscan.model_class_names(project)
    policies = {p.class_name[:-6]: p for p in pfs if p.rel.startswith("app/Policies/") and p.class_name.endswith("Policy")}
    policy_files = set(id(p) for p in policies.values())
    enforced: Dict[str, Set[str]] = {}
    unresolved: Set[str] = set()
    whole: Set[str] = set()
    for pf in pfs:
        if id(pf) in policy_files:
            continue
        for m in CLASS_LEVEL.finditer(pf.code):
            if m.group(1):
                whole.add(m.group(1))
        for m in ENFORCE.finditer(pf.code):
            ability, rest = m.group(1).lower(), m.group(2) or ""
            cm = re.search(r"(\w+)::class", rest)
            name = cm.group(1) if cm else (studly(rest.split(",")[0].strip()) if rest.strip().startswith("$") else "")
            if name in models or name in policies:
                enforced.setdefault(name, set()).add(ability)
            else:
                unresolved.add(ability)
        if pf.rel.startswith("routes/"):
            for m in re.finditer(r"can:(\w+)(?:,(\w+))?", pf.code):
                if m.group(2):
                    enforced.setdefault(studly(m.group(2)), set()).add(m.group(1).lower())
                else:
                    unresolved.add(m.group(1).lower())

    def add(check: str, pf: phpscan.PhpFile, offset: int, msg: str, fix: str, conf: str = "likely", subject: Optional[Dict[str, str]] = None) -> None:
        ln = pf.line(offset)
        env.add(Finding(check, msg, file=pf.rel, line=ln, snippet=pf.line_text(ln), confidence=conf, fix_hint=fix, subject=subject))

    # Policy side
    for name, pf in sorted(policies.items()):
        abilities = {m["name"].lower(): m for m in pf.methods() if m["vis"] == "public" and not m["name"].startswith("__")}
        real = {a for a in abilities if a not in ("before", "after", "viewany", "create")}
        used = enforced.get(name, set()) | {a for a in unresolved if a in real}
        if real and name not in whole and not used:
            first = abilities[sorted(real)[0]]
            add("AUTHZ-001", pf, first["start"], "`%sPolicy` defines %s but no controller, route or Livewire action asks it. The rules exist only on paper; the code is as open as if the policy were missing." % (name, ", ".join(sorted(real))),
                "Call `$this->authorize('update', $%s)` in each action or add `authorizeResource(%s::class, ...)` to the controller." % (name[:1].lower() + name[1:], name), subject={"kind": "policy", "name": name})
        for ab, m in abilities.items():
            params = re.findall(r"\$\w+", m["params"])
            body = re.sub(r"\s+", " ", m["body"][1:-1]).strip()
            if ab in RECORD_ABILITIES or ab == "before":
                if re.fullmatch(r"return true;?", body):
                    add("AUTHZ-004", pf, m["start"], "`%sPolicy::%s()` always returns true, so every user is allowed to do this to every record." % (name, m["name"]), "Return a real condition (owner, tenant, role) or delete the method so the default (deny) applies.", "confirmed", {"kind": "policy-rule", "name": "%s::%s" % (name, m["name"])})
                    continue
            if ab in RECORD_ABILITIES and len(params) >= 2 and not re.fullmatch(r"return false;?", body):
                if params[1] not in body and not re.search(r"hasRole|hasPermissionTo|hasAnyRole|->can\(|is_admin|isAdmin|Gate::|->role\b|->is\(", body):
                    add("AUTHZ-002", pf, m["start"], "`%sPolicy::%s()` never looks at the record (`%s`) or the user's role, so it gives the same answer for everyone." % (name, m["name"], params[1]), "Compare the user with the record: `return $user->id === %s->user_id;` or the tenant column." % params[1], "likely", {"kind": "policy-rule", "name": "%s::%s" % (name, m["name"])})

    # Controller side: per-action matrix
    matrix: List[Dict[str, Any]] = []
    for pf in pfs:
        if "/Http/Controllers/" not in pf.rel or not pf.class_name:
            continue
        class_level = bool(CLASS_LEVEL.search(pf.code))
        meths = [m for m in pf.methods() if m["vis"] == "public" and not m["name"].startswith("__")]
        any_auth = any(GUARD.search(m["body"]) for m in meths)
        for m in meths:
            types = [t for t in re.findall(r"\b([A-Z]\w+)\s+\$\w+", m["params"]) if t in models]
            by_id = bool(re.search(r"\$id\b|\$\w*Id\b", m["params"]))
            if not (types or by_id):
                continue
            kind = "write" if MUTATE.search(m["body"]) else "read" if re.search(r"\breturn\b", m["body"]) else "other"
            checked = bool(GUARD.search(m["body"])) or class_level
            matrix.append({"controller": pf.class_name, "action": m["name"], "record": (types or ["id"])[0], "operation": kind, "checked": checked, "file": pf.rel, "line": m["line"]})
            if any_auth and not checked and kind != "other":
                add("AUTHZ-003", pf, m["start"], "`%s::%s()` works on a record (%s) without a permission check, while other actions in this controller do check. The unchecked action is the one attackers use." % (pf.class_name, m["name"], kind),
                    "Add `$this->authorize()` here, or `authorizeResource()` in the constructor so no action can be forgotten.", "likely", {"kind": "action", "name": "%s::%s" % (pf.class_name, m["name"])})
    env.inventory["authorization"] = {"policies": sorted(policies), "actions": matrix}
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_authz", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
