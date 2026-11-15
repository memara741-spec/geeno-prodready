#!/usr/bin/env python3
"""Review a Supabase project from its migrations, config and client code.

It replays every SQL migration in order and reports the final state: tables
with row level security off (DB-001), policies that allow everyone (DB-002),
signed-in-only policies with no ownership condition (DB-003), write policies
whose WITH CHECK is missing or weaker than USING (DB-004), policies that trust
user-editable metadata (DB-005, AUTH-013), security definer functions
(DB-007), views that bypass RLS (DB-008), public buckets (DB-009), schema kept
only in the dashboard (DB-015), unindexed policy columns (DB-017), broad
grants (DB-021) and profile tables that expose private fields (DB-024). From
config and code it reports unverified session reads on the server (AUTH-005),
functions deployed without JWT verification (API-013) and reliance on the
built-in email sender (MAIL-002).

The most useful output is ``inventory.access_matrix``: for every table, what
an anonymous visitor and a signed-in user can read and write.

What it deliberately does not do: it never connects to the database. It sees
only what is in the repository, so a table or policy created in the dashboard
and never pulled into a migration is invisible to it, and it says so.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detect_stack  # noqa: E402
from lib import catalog, findings, jsast, patterns, sqlparse_lite, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_supabase")
ALSO_EMITS = ["AUTH-008", "DB-006", "DB-020"]

LEVELS = ["none", "own rows", "needs review", "all rows"]
COMMANDS = ["select", "insert", "update", "delete"]
PRIVILEGED_COLUMN_RE = re.compile(r"(?i)^(role|roles|is_admin|admin|is_staff|plan|tier|credits|balance|permissions|is_verified|verified|subscription_status|is_pro|is_premium)$")
PROFILE_TABLE_RE = re.compile(r"(?i)profile|user|account|member|customer|people|contact|patient|employee")
SENSITIVE_BUCKET_RE = re.compile(r"(?i)\bid|doc|passport|kyc|licen[cs]e|invoice|private|medical|contract|receipt|statement|upload|resume|cv")
OWN_EQ_RE = re.compile(r"auth\.uid\(\)\s*\)?\s*(?:::\s*\w+\s*)?=\s*\(?\s*([\w.\"]+)|([\w.\"]+)\s*(?:::\s*\w+\s*)?=\s*\(?\s*(?:select\s+)?auth\.uid\(\)")
AUTH_ONLY_RES = [
    re.compile(r"^\(?\s*(?:select\s+)?auth\.role\(\)\s*\)?\s*=\s*'authenticated'$"),
    re.compile(r"^\(?\s*(?:select\s+)?auth\.uid\(\)\s*\)?\s*is\s+not\s+null$"),
    re.compile(r"^\(?\s*(?:select\s+)?auth\.jwt\(\)\s*\)?\s*is\s+not\s+null$"),
]


def _verbs(cmds: List[str]) -> str:
    names = {"select": "read", "insert": "add", "update": "change", "delete": "delete"}
    words = [names[c] for c in cmds if c in names]
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " and " + words[-1]


def classify_expr(expr: Optional[str]) -> str:
    """open, auth-only, owner-scoped, tenant-scoped, metadata, or custom."""
    e = sqlparse_lite.normalise_expr(expr)
    if not e:
        return "open"
    if e in ("true", "1=1", "1 = 1", "(true)") or re.fullmatch(r"'(\w*)'\s*=\s*'\1'", e):
        return "open"
    if e == "false":
        return "none"
    if "user_metadata" in e or "raw_user_meta_data" in e:
        return "metadata"
    if any(rx.match(e) for rx in AUTH_ONLY_RES):
        return "auth-only"
    has_uid = "auth.uid()" in e
    if has_uid and re.search(r"exists\s*\(|\bin\s*\(\s*select\b", e):
        return "tenant-scoped"
    if has_uid and OWN_EQ_RE.search(e):
        return "owner-scoped"
    if re.search(r"\b(?:\w+\.)?(?:is|has|can|check|user_is|user_has)_\w+\s*\(", e):
        return "tenant-scoped"
    return "custom"


def effective_class(policy: sqlparse_lite.Policy, command: str) -> str:
    if command == "insert":
        expr = policy.check if policy.check is not None else policy.using
    else:
        expr = policy.using if policy.using is not None else (policy.check if policy.command == "insert" else None)
    return classify_expr(expr)


def level_for(cls: str, role: str) -> str:
    if cls == "open":
        return "all rows"
    if cls == "none":
        return "none"
    if cls == "auth-only":
        return "all rows" if role == "authenticated" else "none"
    if cls in ("owner-scoped", "tenant-scoped"):
        return "own rows" if role == "authenticated" else "none"
    return "needs review"


def access_matrix(table: sqlparse_lite.Table, policies: List[sqlparse_lite.Policy]) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    for role in ("anon", "authenticated"):
        row: Dict[str, str] = {}
        for cmd in COMMANDS:
            if not table.rls:
                row[cmd] = "all rows"
                continue
            best = "none"
            for p in policies:
                if not p.permissive or not p.applies_to(role) or not p.covers(cmd):
                    continue
                lvl = level_for(effective_class(p, cmd), role)
                if LEVELS.index(lvl) > LEVELS.index(best):
                    best = lvl
            row[cmd] = best
        out[role] = row
    return out


def parse_toml_sections(text: str) -> Dict[str, Dict[str, Tuple[str, int]]]:
    """Tiny TOML reader: {section: {key: (raw value, line)}}. Enough for supabase/config.toml."""
    out: Dict[str, Dict[str, Tuple[str, int]]] = {"": {}}
    section = ""
    for i, raw in enumerate(text.split("\n"), 1):
        line = raw.split("#", 1)[0].strip() if not re.search(r"[\"'].*#.*[\"']", raw) else raw.strip()
        if not line:
            continue
        m = re.match(r"\[\[?([^\]]+)\]\]?$", line)
        if m:
            section = m.group(1).strip().strip('"')
            out.setdefault(section, {})
            continue
        m = re.match(r"([A-Za-z0-9_.\-\"]+)\s*=\s*(.+)$", line)
        if m:
            out[section][m.group(1).strip('"')] = (m.group(2).strip(), i)
    return out


def collect_sql(project: walker.Project) -> List[Tuple[str, str]]:
    out = []
    for sf in project.files:
        if sf.ext != ".sql":
            continue
        low = sf.rel.lower()
        if re.search(r"(^|/)(tests?|prisma|drizzle|node_modules)/", low) or low.endswith(".test.sql"):
            continue
        text = project.text(sf)
        if text:
            out.append((sf.rel, text))
    return out


def _sensitive(table: sqlparse_lite.Table) -> List[str]:
    return [c for c in table.columns if patterns.SENSITIVE_COLUMN_RE.match(c)]


def _owner_cols(table: sqlparse_lite.Table) -> List[str]:
    return [c for c, col in table.columns.items() if patterns.OWNER_COLUMN_RE.match(c) or (col.references or "").startswith("auth.users")]


def scan_schema(project: walker.Project, env: Envelope, schema: sqlparse_lite.Schema, exposed: List[str]) -> None:
    public_tables = {str(t).lower() for t in (project.config.get("public_tables") or [])}
    tables_inv: List[Dict[str, Any]] = []
    matrix_inv: Dict[str, Any] = {}

    for qname in sorted(schema.tables):
        table = schema.tables[qname]
        if table.schema not in exposed:
            continue
        pols = schema.policies_for(qname)
        matrix = access_matrix(table, pols)
        matrix_inv[qname] = matrix
        sens = _sensitive(table)
        owners = _owner_cols(table)
        tables_inv.append({
            "table": qname, "rls": table.rls, "forced": table.rls_forced, "file": table.file, "line": table.line,
            "sensitive_columns": sens, "owner_columns": owners,
            "policies": [{"name": p.name, "command": p.command, "roles": p.roles or ["public"], "permissive": p.permissive,
                          "using": classify_expr(p.using) if p.using is not None else None,
                          "with_check": classify_expr(p.check) if p.check is not None else None,
                          "file": p.file, "line": p.line} for p in pols],
        })
        subject = {"kind": "table", "name": qname}
        sens_note = " It holds columns that look sensitive: %s." % ", ".join(sens[:6]) if sens else ""

        if not table.rls:
            env.add(Finding(
                "DB-001", "Anyone on the internet can read and change every row in `%s`, because the table has no access rules switched on." % table.name,
                file=table.file, line=table.line, snippet=table.text[:200], confidence="confirmed", subject=subject,
                detail="Table %s is in an exposed schema and row level security is never enabled in the migrations.%s The publishable key that ships in the app is enough to query it." % (qname, sens_note),
                fix_hint="Write a new migration that enables row level security and adds per-operation policies scoped to the row owner.",
            ))

        for p in pols:
            psubject = {"kind": "policy", "name": "%s:%s" % (qname, p.name)}
            using_cls = classify_expr(p.using) if p.using is not None else None
            check_cls = classify_expr(p.check) if p.check is not None else None
            reaches_anon = p.applies_to("anon")
            cmds = COMMANDS if p.command == "all" else [p.command]
            writes = [c for c in cmds if c != "select"]

            if "metadata" in (using_cls, check_cls):
                env.add(Finding(
                    "DB-005", "The rule on `%s` decides access from profile data that users can edit themselves, so any user can grant themselves that access." % table.name,
                    file=p.file, line=p.line, end_line=p.end_line, snippet=p.text, confidence="confirmed", subject=psubject,
                    detail="Policy \"%s\" reads user_metadata, which a signed-in user can change with one API call." % p.name,
                    fix_hint="Use app_metadata (server-controlled) or a roles table that users cannot write.",
                ))
                continue

            if table.rls and p.permissive:
                eff = {c: effective_class(p, c) for c in cmds}
                open_cmds = [c for c in cmds if eff[c] == "open"]
                if open_cmds and reaches_anon:
                    open_writes = [c for c in open_cmds if c != "select"]
                    if open_writes:
                        env.add(Finding(
                            "DB-002", "Anyone on the internet can %s rows in `%s` without signing in. The access rule is switched on but lets everyone through." % (_verbs(open_cmds), table.name),
                            file=p.file, line=p.line, end_line=p.end_line, snippet=p.text, confidence="confirmed", subject=subject,
                            detail="Policy \"%s\" applies to %s for %s with an unconditional expression.%s" % (p.name, ", ".join(p.roles) or "all roles", p.command, sens_note),
                            fix_hint="Replace it with per-operation policies scoped to authenticated users and to the row owner.",
                        ))
                    elif qname.lower() in public_tables:
                        pass
                    elif sens:
                        env.add(Finding(
                            "DB-002", "Anyone on the internet can read every row in `%s`, including %s." % (table.name, ", ".join(sens[:4])),
                            file=p.file, line=p.line, end_line=p.end_line, snippet=p.text, confidence="likely", subject=subject,
                            detail="Policy \"%s\" allows SELECT for all roles with USING (true) on a table with sensitive-looking columns." % p.name,
                            fix_hint="Scope reads to the row owner, or move the public columns to a separate table or view.",
                        ))
                    else:
                        env.add(Finding(
                            "DB-002", "Everyone can read `%s`. If this is public reference data that is fine; confirm that it is intended." % table.name,
                            file=p.file, line=p.line, end_line=p.end_line, snippet=p.text, confidence="possible", severity="info", subject=subject,
                            detail="Policy \"%s\" allows SELECT for all roles. No sensitive-looking columns were found. List the table under public_tables in .prodready.json to record the decision." % p.name,
                            fix_hint="None needed if the data is meant to be public.",
                        ))
                authonly_cmds = [c for c in cmds if eff[c] == "auth-only" or (eff[c] == "open" and not reaches_anon)]
                non_insert = [c for c in authonly_cmds if c != "insert"]
                if non_insert:
                    scoped = bool(owners or sens)
                    env.add(Finding(
                        "DB-003", "Any signed-up user can %s every row in `%s`, not just their own. Signing up is open to anyone, so this protects nothing." % (" and ".join("change" if c == "update" else "read" if c == "select" else c for c in non_insert), table.name),
                        file=p.file, line=p.line, end_line=p.end_line, snippet=p.text, confidence="likely" if scoped else "possible", subject=subject,
                        detail="Policy \"%s\" only checks that the caller is signed in.%s%s" % (p.name, sens_note, "" if scoped else " The table has no ownership column, so this may be shared data by design."),
                        fix_hint="Add an ownership or membership condition, for example (select auth.uid()) = %s." % (owners[0] if owners else "user_id"),
                    ))
                if "insert" in cmds and owners:
                    ins_cls = eff["insert"]
                    if p.command == "insert" and p.check is None or ins_cls in ("open", "auth-only") and not (ins_cls == "open" and reaches_anon):
                        env.add(Finding(
                            "DB-004", "A signed-in user can add rows to `%s` that claim to belong to someone else." % table.name,
                            file=p.file, line=p.line, end_line=p.end_line, snippet=p.text, confidence="confirmed" if p.check is None or ins_cls == "open" else "likely", subject=subject,
                            detail="Insert policy \"%s\" has %s, so nothing ties the new row's %s to the caller." % (p.name, "no WITH CHECK" if p.check is None else "a WITH CHECK that does not compare the owner column with auth.uid()", owners[0]),
                            fix_hint="Add WITH CHECK ((select auth.uid()) = %s)." % owners[0],
                        ))
                if p.command in ("update", "all") and using_cls in ("owner-scoped", "tenant-scoped") and check_cls in ("open", "auth-only"):
                    env.add(Finding(
                        "DB-004", "A user can hand their rows in `%s` to another user or team, because the rule checks ownership before the change but not after." % table.name,
                        file=p.file, line=p.line, end_line=p.end_line, snippet=p.text, confidence="confirmed", subject=subject,
                        detail="Policy \"%s\" has an ownership USING condition but an unconditional WITH CHECK. (Without any WITH CHECK, PostgreSQL would reuse USING; an explicit weak one overrides that.)" % p.name,
                        fix_hint="Make WITH CHECK mirror the USING condition.",
                    ))

        # AUTH-013: a privileged column on a row the user may update.
        priv_cols = [c for c in table.columns if PRIVILEGED_COLUMN_RE.match(c)]
        if table.rls and priv_cols and matrix["authenticated"]["update"] in ("own rows", "all rows"):
            column_grants = any(g.object_kind == "table" and g.target == qname and re.search(r"update\s*\(", g.privileges) for g in schema.grants)
            if not column_grants:
                upd = next((p for p in pols if p.covers("update")), None)
                env.add(Finding(
                    "AUTH-013", "Users can edit their own row in `%s`, and that row also stores %s. A user can promote or credit themselves with one request." % (table.name, ", ".join(priv_cols)),
                    file=(upd.file if upd else table.file), line=(upd.line if upd else table.line), snippet=(upd.text if upd else table.text[:200]),
                    confidence="likely", subject={"kind": "table", "name": qname},
                    detail="The update policy on %s does not restrict which columns change, and the table has privileged column(s): %s." % (qname, ", ".join(priv_cols)),
                    fix_hint="Move these columns to a table users cannot write, or revoke UPDATE on them and grant UPDATE only on the safe columns.",
                ))

        # DB-006 hint: nothing to scope by.
        if table.rls and not owners and qname.lower() not in public_tables and any(matrix["authenticated"][c] == "all rows" for c in ("insert", "update", "delete")):
            env.add(Finding(
                "DB-006", "`%s` has no column that says who owns each row, so no rule can keep users apart." % table.name,
                file=table.file, line=table.line, snippet=table.text[:200], confidence="possible", subject=subject,
                detail="No user_id, owner_id or tenant column found, and signed-in users can write all rows.",
                fix_hint="Add an ownership column with a default of auth.uid(), backfill it, then add owner-scoped policies.",
            ))

        # DB-017: policy columns without an index, and auth.uid() not wrapped in a sub-select.
        if table.rls and pols:
            indexed = schema.indexed_columns(qname)
            policy_cols = set()
            unwrapped = False
            for p in pols:
                for expr in (p.using, p.check):
                    e = sqlparse_lite.normalise_expr(expr)
                    if not e:
                        continue
                    for m in OWN_EQ_RE.finditer(e):
                        col = (m.group(1) or m.group(2) or "").split(".")[-1].strip('"')
                        if col in table.columns:
                            policy_cols.add(col)
                    stripped = re.sub(r"\(\s*select\s+auth\.uid\(\)\s*\)", "", e)
                    if "auth.uid()" in stripped:
                        unwrapped = True
            missing = sorted(c for c in policy_cols if c not in indexed)
            if missing or unwrapped:
                first = pols[0]
                parts = []
                if missing:
                    parts.append("no index on %s" % ", ".join(missing))
                if unwrapped:
                    parts.append("auth.uid() is called per row instead of once via (select auth.uid())")
                env.add(Finding(
                    "DB-017", "The access rules on `%s` will make every query slower as the table grows." % table.name,
                    file=first.file, line=first.line, snippet=first.text, confidence="likely", subject=subject,
                    detail="Policies on %s: %s." % (qname, "; ".join(parts)),
                    fix_hint="Add an index on the policy column(s) and wrap auth.uid() in a sub-select.",
                ))

        # DB-024: a profile-like table readable by everyone with private columns.
        if PROFILE_TABLE_RE.search(table.name) and sens:
            readers = [r for r in ("anon", "authenticated") if matrix[r]["select"] == "all rows"]
            if readers:
                who = "Anyone on the internet" if "anon" in readers else "Any signed-up user"
                env.add(Finding(
                    "DB-024", "%s can download every user's %s from `%s`." % (who, ", ".join(sens[:4]), table.name),
                    file=table.file, line=table.line, snippet=table.text[:200], confidence="likely", subject=subject,
                    detail="%s is readable in full by %s and contains: %s." % (qname, " and ".join(readers), ", ".join(sens)),
                    fix_hint="Split public and private columns into separate tables, or expose a restricted view, and select explicit columns.",
                ))

    # DB-020 hint: realtime on a table with weak read rules.
    for qname, file, line in schema.realtime_tables:
        m = matrix_inv.get(qname)
        if m and (m["authenticated"]["select"] == "all rows" or m["anon"]["select"] == "all rows"):
            env.add(Finding(
                "DB-020", "Live updates from `%s` are broadcast to everyone who can read the table, and the table's read rule lets everyone in." % qname.split(".")[-1],
                file=file, line=line, snippet="alter publication supabase_realtime add table %s" % qname, confidence="possible",
                subject={"kind": "table", "name": qname},
                detail="%s is in the supabase_realtime publication and its SELECT access is not scoped to the row owner." % qname,
                fix_hint="Fix the SELECT policy first; realtime follows it.",
            ))

    # DB-007: security definer functions in an exposed schema.
    for qname in sorted(schema.functions):
        fn = schema.functions[qname]
        if not fn.security_definer or qname.split(".")[0] not in exposed:
            continue
        revoked = any(g.revoke and (g.object_kind == "function" and g.target == qname or g.object_kind == "all-functions") and ({"public", "anon"} & set(g.roles)) for g in schema.grants)
        checks_caller = "auth.uid()" in fn.body.lower() or "auth.jwt()" in fn.body.lower()
        issues = []
        if fn.search_path is None:
            issues.append("no fixed search_path")
        if not revoked:
            issues.append("EXECUTE is not revoked from anon/public")
        if not checks_caller and re.search(r"(?i)\buuid\b", fn.args):
            issues.append("it takes a user ID argument and never checks auth.uid()")
        if fn.search_path is None or (not revoked and not checks_caller):
            env.add(Finding(
                "DB-007", "The database function `%s` runs with full rights and can be called by anyone through the API, skipping the access rules." % qname.split(".")[-1],
                file=fn.file, line=fn.line, snippet=fn.text, confidence="likely", subject={"kind": "function", "name": qname},
                detail="%s is SECURITY DEFINER in an exposed schema: %s." % (qname, "; ".join(issues)),
                fix_hint="Move it to a private schema or revoke EXECUTE from anon and public, set search_path = '', and check auth.uid() inside the function.",
            ))

    # DB-008: views.
    for qname in sorted(schema.views):
        view = schema.views[qname]
        if qname.split(".")[0] not in exposed:
            continue
        if view.materialized or not view.security_invoker:
            env.add(Finding(
                "DB-008", "The view `%s` shows rows to every caller regardless of the access rules on the tables behind it." % qname.split(".")[-1],
                file=view.file, line=view.line, snippet=view.text, confidence="likely", subject={"kind": "view", "name": qname},
                detail="%s is %s in an exposed schema. Views run with their owner's rights unless created with security_invoker = true." % (qname, "a materialized view" if view.materialized else "created without security_invoker"),
                fix_hint="Recreate it WITH (security_invoker = true), or move it out of the exposed schema.",
            ))

    # DB-009: public buckets.
    for name in sorted(schema.buckets):
        b = schema.buckets[name]
        if not b.public:
            continue
        sensitive = bool(SENSITIVE_BUCKET_RE.search(name))
        env.add(Finding(
            "DB-009", "Every file in the `%s` storage bucket can be downloaded by anyone who has or guesses its link." % name,
            file=b.file, line=b.line, snippet=b.text, confidence="likely", severity="critical" if sensitive else None, subject={"kind": "bucket", "name": name},
            detail="Bucket \"%s\" is created with public = true.%s" % (name, " Its name suggests private documents." if sensitive else " That is fine for public assets such as avatars; confirm what is stored there."),
            fix_hint="Make the bucket private, add policies on storage.objects scoped to the user's folder, and serve files with short-lived signed URLs.",
        ))

    # DB-021: grants to anon or public that matter because the rules behind them are weak.
    weak_tables = sorted(q for q, m in matrix_inv.items() if any(v == "all rows" for k, v in m["anon"].items() if k != "select") or not schema.tables[q].rls)
    for g in schema.grants:
        if g.revoke or not ({"anon", "public"} & set(g.roles)):
            continue
        broad = bool(re.search(r"\ball\b|insert|update|delete|truncate", g.privileges))
        if not broad or g.object_kind not in ("all-tables", "table", "default"):
            continue
        affected = weak_tables if g.object_kind != "table" else [t for t in weak_tables if t == g.target]
        if not affected:
            continue
        env.add(Finding(
            "DB-021", "Visitors who are not signed in are granted write access, and %d table(s) have no rule to stop them." % len(affected),
            file=g.file, line=g.line, snippet=g.text, confidence="likely", subject={"kind": "grant", "name": g.target},
            detail="Grant to %s combined with missing or permissive row level security on: %s." % (", ".join(g.roles), ", ".join(affected[:8])),
            fix_hint="Fix the row level security on those tables, and grant anon only what public pages need.",
        ))

    env.inventory["tables"] = tables_inv
    env.inventory["access_matrix"] = matrix_inv
    env.inventory["buckets"] = [{"name": b.name, "public": b.public} for b in schema.buckets.values()]


def scan_config(project: walker.Project, env: Envelope, stack: Optional[Dict[str, Any]]) -> None:
    sf = project.get("supabase/config.toml")
    if sf is None:
        return
    text = project.text(sf)
    cfg = parse_toml_sections(text)
    email = cfg.get("auth.email", {})
    if email.get("enable_confirmations", ("", 0))[0].lower() == "false":
        line = email["enable_confirmations"][1]
        env.add(Finding(
            "AUTH-008", "Email addresses are not confirmed in this configuration, so someone can sign up with an address they do not own.",
            file=sf.rel, line=line, snippet=sf.line_text(line), confidence="possible",
            detail="[auth.email] enable_confirmations = false in supabase/config.toml. This file configures local development; the hosted project may differ, so confirm in the dashboard under Authentication.",
            fix_hint="Enable email confirmation in the hosted project and in config.toml.",
        ))
    for section, values in sorted(cfg.items()):
        m = re.match(r"functions\.(.+)$", section)
        if not m or values.get("verify_jwt", ("", 0))[0].lower() != "false":
            continue
        fn = m.group(1).strip('"')
        body = "".join(project.read("supabase/functions/%s/%s" % (fn, n)) for n in ("index.ts", "index.js", "index.tsx"))
        if re.search(r"(?i)webhook|signature", fn + body[:4000]) and patterns.WEBHOOK_VERIFY_RE.search(body):
            continue
        if re.search(r"auth\.getUser\(|auth\.getClaims\(|jwtVerify\(|verifyToken\(|verifyIdToken\(", body):
            continue
        line = values["verify_jwt"][1]
        env.add(Finding(
            "API-013", "The server function `%s` accepts calls from anyone, with no check that the caller is signed in." % fn,
            file=sf.rel, line=line, snippet="[functions.%s] verify_jwt = false" % fn, confidence="likely", subject={"kind": "function", "name": fn},
            detail="verify_jwt = false for function %s, and its code does not verify the caller or a webhook signature itself." % fn,
            fix_hint="Remove verify_jwt = false, or verify the bearer token in the function. For webhooks, verify the provider's signature.",
        ))
    scripts = " ".join(str(v) for v in (project.package.get("scripts") or {}).values())
    if "--no-verify-jwt" in scripts:
        pkg = project.get("package.json")
        line = next((i for i, l in enumerate(pkg.lines, 1) if "--no-verify-jwt" in l), 1) if pkg else 1
        env.add(Finding(
            "API-013", "A deploy script publishes server functions with sign-in checking switched off.",
            file="package.json", line=line, snippet=pkg.line_text(line) if pkg else "", confidence="likely",
            detail="`supabase functions deploy --no-verify-jwt` in package.json scripts.",
            fix_hint="Remove the flag for functions that are not webhooks.",
        ))
    if detect_stack.has(stack, "auth", "supabase-auth"):
        smtp = cfg.get("auth.email.smtp", {})
        smtp_on = bool(smtp) and smtp.get("enabled", ("true", 0))[0].lower() != "false"
        if not smtp_on:
            line = email.get("enable_signup", email.get("enable_confirmations", ("", 1)))[1] or 1
            env.add(Finding(
                "MAIL-002", "Sign-up and password reset emails go through the provider's built-in test mail service, which is tightly rate limited. Once real users arrive, some of them will never receive their email.",
                file=sf.rel, line=line, snippet="[auth.email] (no [auth.email.smtp] section)", confidence="possible", subject={"kind": "config", "name": "auth.email.smtp"},
                detail="No custom SMTP is configured in supabase/config.toml. Confirm in the dashboard under Authentication, SMTP settings.",
                fix_hint="Configure a transactional email provider as custom SMTP and authenticate the sending domain.",
                owner_action="references/owner-actions/dns-and-email.md",
            ))


def scan_code(project: walker.Project, env: Envelope) -> None:
    for sf in project.code_files():
        text = project.text(sf)
        if "supabase" not in text and "user_metadata" not in text:
            continue
        kind = project.classify(sf)
        lx = jsast.lexed(text)
        code = lx.code
        if kind == "server" and not sf.rel.startswith("supabase/functions/"):
            m = re.search(r"\.auth\.getSession\(", code)
            if m and not re.search(r"\.auth\.(?:getUser|getClaims)\(", code):
                line = jsast.line_of(code, m.start())
                env.add(Finding(
                    "AUTH-005", "The server decides who the visitor is from a cookie it does not verify. A visitor who edits the cookie can pose as another user.",
                    file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely",
                    detail="Server code uses supabase.auth.getSession() and never calls getUser() or getClaims() in this file. getSession() reads the session from the cookie without revalidating it.",
                    fix_hint="Use supabase.auth.getUser() (or getClaims()) for every server-side decision.",
                ))
        m = re.search(r"user_metadata\??\s*(?:\.\s*|\[\s*[\"'])(role|roles|plan|tier|is_admin|isAdmin|admin|credits|permissions)\b", code if "[" not in text else lx.nocomment)
        if m:
            line = jsast.line_of(code, m.start())
            env.add(Finding(
                "AUTH-013", "The app decides a user's %s from profile data that the user can edit. Any user can change it with one request from the browser console." % m.group(1),
                file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely",
                detail="Reads user_metadata.%s for an access decision. user_metadata is writable by the signed-in user through auth.updateUser()." % m.group(1),
                fix_hint="Store this in app_metadata (set only by the server) or in a table users cannot write.",
            ))


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_supabase", stack)
    uses_supabase = detect_stack.has(stack, "backend", "supabase")
    if not uses_supabase:
        env.inventory["supabase"] = {"detected": False}
        return env
    sql_files = collect_sql(project)
    exposed = ["public"]
    cfg_text = project.read("supabase/config.toml")
    sm = re.search(r"(?m)^\s*schemas\s*=\s*\[([^\]]*)\]", cfg_text)
    if sm:
        listed = [s.strip().strip("\"'") for s in sm.group(1).split(",") if s.strip()]
        exposed = [s for s in listed if s not in ("graphql_public", "storage")] or ["public"]
    env.inventory["supabase"] = {"detected": True, "sql_files": [p for p, _ in sorted(sql_files)], "exposed_schemas": exposed}
    if sql_files:
        schema = sqlparse_lite.apply(sql_files)
        try:
            scan_schema(project, env, schema, exposed)
        except Exception as exc:
            env.warn("scan_supabase: schema analysis failed (%s)" % type(exc).__name__)
    else:
        names: List[str] = []
        for sf in project.files:
            if sf.name in ("types.ts", "database.types.ts", "supabase.ts") and "Tables" in project.text(sf):
                tm = re.search(r"Tables:\s*\{([\s\S]*?)\n\s{4,6}\}\s*;?\s*\n", project.text(sf))
                names = re.findall(r"(?m)^\s{6,8}([A-Za-z_]\w*):\s*\{", tm.group(1)) if tm else []
                break
        env.inventory["tables"] = [{"table": "public.%s" % n, "rls": None, "policies": "unknown"} for n in names]
        env.add(Finding(
            "DB-015", "The rules that decide who can read your data exist only in the Supabase dashboard. They cannot be reviewed, tested or restored from this repository, and this audit could not see them.",
            confidence="confirmed", subject={"kind": "project", "name": "supabase-schema"},
            detail="The app uses the Supabase SDK but the repository has no SQL migrations or schema file.%s" % (" Tables referenced in generated types: %s." % ", ".join(names[:12]) if names else ""),
            fix_hint="Run `supabase link` and `supabase db pull` to bring the schema and policies into supabase/migrations, commit them, and re-run the scan.",
        ))
    for step in (lambda: scan_config(project, env, stack), lambda: scan_code(project, env)):
        try:
            step()
        except Exception as exc:
            env.warn("scan_supabase: a pass failed (%s)" % type(exc).__name__)
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_supabase", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
