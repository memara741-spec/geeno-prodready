#!/usr/bin/env python3
"""Launch readiness inventory: legal pages, account deletion, third parties and open owner questions.

Detects: no privacy policy or terms where accounts exist (PRIV-001), no way
for users to delete their account (PRIV-003), message-sending endpoints that
anyone can trigger (MAIL-004), and the list of third parties that receive user
data (PRIV-006, as ``inventory.third_parties``). It also builds
``inventory.owner_questions``: the things only the owner can answer (backups,
monitoring, budgets, domain), each mapped to its check ID, so the reviewer can
ask them in one batch.

What it deliberately does not do: it does not judge the content of a privacy
policy and gives no legal advice.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detect_stack  # noqa: E402
import scan_routes  # noqa: E402
from lib import catalog, findings, jsast, patterns, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_launch")
ALSO_EMITS: List[str] = []

THIRD_PARTY = {
    "supabase": ("database and auth", "accounts, all app data"), "firebase": ("database and auth", "accounts, all app data"),
    "stripe": ("payments", "name, email, payment details"), "paddle": ("payments", "name, email, payment details"),
    "lemonsqueezy": ("payments", "name, email, payment details"), "openai": ("AI provider", "prompts and uploaded content"),
    "anthropic": ("AI provider", "prompts and uploaded content"), "google-ai": ("AI provider", "prompts and uploaded content"),
    "clerk": ("authentication", "email, name, sign-in history"), "authjs": ("authentication", "email, name"),
    "auth0": ("authentication", "email, name, sign-in history"), "resend": ("email", "email addresses and message content"),
    "sendgrid": ("email", "email addresses and message content"), "nodemailer": ("email", "email addresses and message content"),
    "sentry": ("error tracking", "error context, possibly user IDs"), "posthog": ("analytics", "usage events"),
    "google-analytics": ("analytics", "page views, device and location data"), "facebook-pixel": ("advertising", "page views, device data"),
    "hotjar": ("session recording", "page activity, possibly inputs"), "logrocket": ("session recording", "page activity, possibly inputs"),
    "vercel": ("hosting", "all traffic"), "netlify": ("hosting", "all traffic"), "cloudflare": ("hosting", "all traffic"),
    "firebase-hosting": ("hosting", "all traffic"), "s3": ("file storage", "uploaded files"), "cloudinary": ("file storage", "uploaded images"),
}
ACCOUNT_RE = re.compile(r"signUp\(|signInWith|createUserWithEmailAndPassword|\bregister\b|sign-?up|auth\.users|SignUp\b|<SignIn\b|NextAuth\(|\.auth\.|Credentials", re.I)
DELETE_RE = re.compile(r"delete[_-]?account|account[_-]?deletion|auth\.admin\.deleteUser|\bdeleteUser\(|deleteAccount|remove[_-]?account|delete[_-]?my[_-]?account|user\.delete\(\)", re.I)
LEGAL_PATH_RE = re.compile(r"(?i)(^|/)(privacy|terms|tos|legal|policy)([/.\-_]|$)")
LEGAL_LINK_RE = re.compile(r"(?i)[\"'/](privacy|terms|terms-of-service|legal)[\"'/#]")


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_launch", stack)
    paths = project.all_paths()
    has_accounts = bool(detect_stack.names(stack, "auth")) or any(ACCOUNT_RE.search(project.text(sf)) for sf in project.code_files() if project.classify(sf) != "test")
    web_or_mobile = detect_stack.is_web(stack) or bool((stack or {}).get("mobile"))

    # PRIV-001
    if has_accounts and web_or_mobile:
        legal_page = any(LEGAL_PATH_RE.search(p) and p.endswith((".tsx", ".jsx", ".html", ".md", ".vue", ".svelte", ".astro", ".mdx", ".ts", ".js")) for p in paths)
        legal_link = any(LEGAL_LINK_RE.search(project.text(sf)) for sf in project.files if sf.ext in (".tsx", ".jsx", ".html", ".vue", ".svelte", ".astro") and not walker.TEST_PATH_RE.search(sf.rel))
        if not (legal_page or legal_link):
            auth_names = ", ".join(sorted(detect_stack.names(stack, "auth"))) or "sign-up code"
            env.add(Finding(
                "PRIV-001", "Your app collects people's accounts but has no privacy policy or terms. App stores, payment providers and sign-in screens require them, and most countries do too.",
                confidence="likely", subject={"kind": "project", "name": "legal-pages"},
                detail="Accounts are present (%s) but no privacy or terms page, route or link was found. This is a factual finding, not legal advice." % auth_names,
                fix_hint="Add privacy and terms pages linked from sign-up and the footer. Use the data inventory from this report to draft the policy with a lawyer or a policy generator.",
            ))

    # PRIV-003
    if has_accounts and web_or_mobile:
        deletion = any(DELETE_RE.search(project.text(sf)) or DELETE_RE.search(sf.rel) for sf in project.files if sf.ext in walker.CODE_EXTS and project.classify(sf) != "test")
        if not deletion:
            env.add(Finding(
                "PRIV-003", "Users cannot delete their account or their data. That is a legal right in many places and a requirement of both app stores for apps with sign-up.",
                confidence="likely", subject={"kind": "project", "name": "account-deletion"},
                detail="No account deletion endpoint, function or screen was found.",
                fix_hint="Add a confirmed deletion flow that removes the user's rows, files and third-party records (database cascades help), plus an export of their data.",
            ))

    # MAIL-004 from the route inventory
    for e in scan_routes.build_inventory(project, stack):
        info = e.info
        if info.get("sends_messages") and info["auth"]["status"] == "none" and not info.get("rate_limited") and not info.get("is_webhook"):
            env.add(Finding(
                "MAIL-004", "Anyone can make `%s` send email or text messages to any address, as often as they like. Your sending domain will be blacklisted and SMS fraud costs real money." % e.id,
                file=e.sf.rel, line=e.line, snippet=e.sf.line_text(e.line), confidence="likely", subject={"kind": "route", "name": e.id},
                detail="Message-sending handler with no authentication, rate limit or CAPTCHA, and a recipient taken from the request.",
                fix_hint="Require sign-in where possible, rate limit per IP, account and recipient, add a CAPTCHA to public forms, and send fixed templates only.",
            ))

    # PRIV-006 inventory
    third: Dict[str, Dict[str, Any]] = {}
    for key in ("backend", "database", "auth", "payments", "llm", "email", "storage", "analytics", "error_tracking", "hosting"):
        for item in (stack or {}).get(key) or []:
            n = item.get("name", "")
            base = n.split("-")[0] if n.split("-")[0] in THIRD_PARTY else n
            if base in THIRD_PARTY and base not in third:
                cat, data = THIRD_PARTY[base]
                third[base] = {"name": base, "category": cat, "data": data, "evidence": key}
    env.inventory["third_parties"] = sorted(third.values(), key=lambda t: t["name"])
    if third:
        env.add(Finding(
            "PRIV-006", "%d outside services receive your users' data. You need this list for your privacy policy and for customers who ask." % len(third),
            confidence="confirmed", severity="info", subject={"kind": "project", "name": "third-party-inventory"},
            detail="Detected: %s. The report appendix lists what each likely receives; confirm and complete it." % ", ".join(sorted(third)),
            fix_hint="Copy the generated inventory into your privacy policy and keep it updated.",
        ))

    # Owner questions
    q: List[Dict[str, str]] = []
    if detect_stack.names(stack, "database"):
        q += [{"check": "DB-016", "question": "Are automated database backups switched on, and have you ever restored one to a scratch project?"},
              {"check": "REL-007", "question": "When did you last test restoring from a backup?"}]
    q += [{"check": "OBS-003", "question": "Is an uptime monitor checking the site and alerting someone who will see it?"},
          {"check": "DEP-005", "question": "Do you know how to roll back a bad release on your host?"},
          {"check": "LAUNCH-007", "question": "Which is the production domain, and do www and the bare domain redirect to one of them?"}]
    if third:
        q.append({"check": "DEP-014", "question": "Have you set budgets and usage alerts at each pay-per-use provider (%s)?" % ", ".join(sorted(t for t in third if third[t]["category"] in ("AI provider", "email", "payments", "hosting", "database and auth")))})
    if detect_stack.names(stack, "email") or detect_stack.has(stack, "auth", "supabase-auth", "firebase-auth"):
        q.append({"check": "MAIL-001", "question": "Is the sending domain authenticated with SPF, DKIM and DMARC?"})
    if (stack or {}).get("builder", {}).get("name") and (stack or {}).get("builder", {}).get("name") != "ide-agent":
        q.append({"check": "DEP-011", "question": "Is the code in a GitHub repository you own, and is the backend project under your own account?"})
    if detect_stack.names(stack, "payments"):
        q.append({"check": "PAY-008", "question": "Are the live payment keys and webhook secret set only in production, and have you made one real test purchase?"})
    q.append({"check": "DEP-002", "question": "Are development and production using separate databases or backend projects?"})
    q.append({"check": "DEP-013", "question": "Is the default branch protected, so changes need a review or passing checks?"})
    env.inventory["owner_questions"] = q
    env.inventory["is_live_hint"] = "ask the owner whether the app already has real users"
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_launch", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
