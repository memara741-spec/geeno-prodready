#!/usr/bin/env python3
"""Check AI features: who can call them, what the caller controls, and what happens to the output.

Detects: AI endpoints with no authentication (LLM-001), no per-user limit
(LLM-002), model, system prompt or parameters taken from the request
(LLM-003), calls with no output limit (LLM-004), model output rendered as raw
HTML (LLM-006), secrets or internal addresses inside prompts (LLM-007), and
text in the project that is addressed to AI reviewers, including invisible
Unicode characters (LLM-010).

LLM-010 exists for this tool's own safety as much as the app's: instructions
found in a scanned project are reported and never followed. The finding quotes
only the first few words.

What it deliberately does not do: it does not judge prompt quality, and it
cannot tell whether a tool-using agent authorises its tool calls (LLM-005).
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import scan_routes  # noqa: E402
from lib import catalog, findings, jsast, patterns, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_llm")
ALSO_EMITS: List[str] = []

LLM_CREATE_CALLS = [
    "*.chat.completions.create", "*.responses.create", "*.completions.create", "*.messages.create", "*.messages.stream",
    "generateText", "streamText", "generateObject", "streamObject", "*.generateContent", "*.generateContentStream",
]
OUTPUT_LIMIT_RE = re.compile(r"max_tokens|max_completion_tokens|maxTokens|maxOutputTokens|max_output_tokens|max_new_tokens")
CLIENT_PARAM_RE = re.compile(r"\b(model|system|tools|temperature|max_tokens|maxTokens)\s*:\s*([^,}\n]+)|(?<=[{,\s])(model|system|tools)\s*(?=[,}])")
INJECTION_RES = [
    re.compile(r"(?i)ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules)"),
    re.compile(r"(?i)disregard\s+(?:all\s+|the\s+)?(?:previous|prior|above)\s+(?:instructions|prompts)"),
    re.compile(r"(?i)do\s+not\s+report\s+(?:any\s+)?(?:issues|findings|vulnerabilities|problems)"),
    re.compile(r"(?i)report\s+no\s+(?:issues|findings|vulnerabilities)"),
    re.compile(r"(?i)mark\s+(?:this|the)\s+(?:project|app|code|repository|repo|file)\s+as\s+(?:safe|secure|compliant|production[- ]ready)"),
    re.compile(r"(?i)(?:ai|llm)\s+(?:assistants?|agents?|reviewers?|auditors?|models?)\s*(?:and\s+[\w\s]{0,30})?[:,]\s*(?:please\s+)?(?:ignore|skip|do\s+not|never|always)"),
    re.compile(r"(?i)you\s+are\s+now\s+(?:in\s+)?(?:developer|dan|unrestricted|jailbreak)"),
    re.compile(r"(?i)skip\s+(?:the\s+)?security\s+(?:review|audit|checks?)"),
    re.compile(r"(?i)(?:this\s+(?:code|project|app)\s+)?has\s+already\s+passed\s+(?:a\s+)?(?:full\s+)?security\s+audit"),
]
INVISIBLE_RE = re.compile("[​⁠‪-‮⁦-⁩\U000e0000-\U000e007f]|(?<=[\x00-\x7f])[‌‍](?=[\x00-\x7f])|(?<!^)﻿")
INTERNAL_URL_RE = re.compile(r"https?://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|localhost|127\.0\.0\.1|[\w.-]+\.(?:internal|local|corp|lan))(?::\d+)?[^\s\"'`]*")
PROMPT_NAME_RE = re.compile(r"(?i)\b(\w*(?:system|prompt|instructions|persona)\w*)\s*(?::\s*string\s*)?=\s*(`|\"|')")
MARKDOWN_RAW_RE = re.compile(r"rehypeRaw|allowDangerousHtml\s*:\s*true|skipHtml\s*=\s*\{?\s*false|html\s*:\s*true")


def _star_calls(text: str, names: List[str]) -> List[jsast.Call]:
    """find_calls with support for a leading ``*.`` meaning any receiver."""
    lx = jsast.lexed(text)
    code, src = lx.code, lx.nocomment
    out: List[jsast.Call] = []
    for name in names:
        if name.startswith("*."):
            pat = r"[\w$\])]\s*\??\." + re.escape(name[2:]).replace(r"\.", r"\s*\??\.\s*") + r"\s*\("
        else:
            pat = r"(?<![\w$.])" + re.escape(name) + r"\s*\("
        for m in re.finditer(pat, code):
            open_idx = m.end() - 1
            close = jsast.match_close(code, open_idx)
            if close != -1:
                out.append(jsast.Call(name.lstrip("*."), jsast.line_of(code, m.start()), m.start(), close + 1, src[open_idx + 1:close]))
    out.sort(key=lambda c: c.start)
    return out


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_llm", stack)
    entries = scan_routes.build_inventory(project, stack)
    call_sites: List[Dict[str, Any]] = []

    # LLM-001 / LLM-002 from the route inventory.
    for e in entries:
        info = e.info
        if not info.get("calls_llm"):
            continue
        subject = {"kind": "route", "name": e.id}
        if info["auth"]["status"] == "none":
            env.add(Finding(
                "LLM-001", "Anyone on the internet can use your AI feature at `%s` without an account. Every request is paid for by you." % e.id,
                file=e.sf.rel, line=e.line, snippet=e.sf.line_text(e.line), confidence="likely", subject=subject,
                detail="Handler calls an AI provider and contains no authentication check.",
                fix_hint="Require a signed-in session. If the endpoint must be public, add strict rate limits, a CAPTCHA and a hard budget.",
            ))
        if not info.get("rate_limited") and not re.search(r"(?i)\bquota\b|usage_?limit|checkUsage|remaining|creditsLeft|enforceLimit|dailyLimit|monthlyLimit", e.src):
            env.add(Finding(
                "LLM-002", "Nothing caps how much AI usage one caller can run up at `%s`. A single user, or a bug in a loop, produces an unbounded bill." % e.id,
                file=e.sf.rel, line=e.line, snippet=e.sf.line_text(e.line), confidence="likely", subject=subject,
                detail="AI handler with no rate limiter and no per-user quota check before the provider call.",
                fix_hint="Track usage per user on the server, refuse requests over the quota, rate limit the endpoint, and set a monthly budget with alerts at the provider.",
                owner_action="references/checks/llm.md#llm-002",
            ))

    for sf in project.code_files():
        text = project.text(sf)
        rel = sf.rel
        kind = project.classify(sf)
        if sf.ext == ".py":
            continue
        lx = jsast.lexed(text)
        src, code = lx.nocomment, lx.code
        file_entries = [e for e in entries if e.sf is sf]

        def scope(offset: int) -> str:
            best = None
            for e in file_entries:
                if e.start <= offset < e.end and (best is None or e.end - e.start < best.end - best.start):
                    best = e
            return best.src if best else src

        # LLM-003 and LLM-004 at provider call sites (server side).
        if kind != "client" and patterns.LLM_CALL_RE.search(src):
            for call in _star_calls(text, LLM_CREATE_CALLS):
                call_sites.append({"file": rel, "line": call.line, "call": call.name})
                tainted, whole, origin = scan_routes.taint(scope(call.start))
                controlled = []
                for m in CLIENT_PARAM_RE.finditer(call.args):
                    key = m.group(1) or m.group(3)
                    value = (m.group(2) or key).strip()
                    if scan_routes.is_tainted(value, tainted):
                        controlled.append(key)
                sys_m = re.search(r"role\s*:\s*[\"']system[\"']\s*,\s*content\s*:\s*([^}\n]+)", call.args)
                if sys_m and scan_routes.is_tainted(sys_m.group(1), tainted) and "system" not in controlled:
                    controlled.append("system")
                if controlled:
                    env.add(Finding(
                        "LLM-003", "The browser chooses the %s for the AI call. A user can pick the most expensive model, remove your instructions, or use your endpoint as a free general-purpose AI." % " and ".join(sorted(set(controlled))),
                        file=rel, line=call.line, snippet=sf.line_text(call.line), confidence="likely",
                        detail="%s() takes %s from the request body." % (call.name, ", ".join(sorted(set(controlled)))),
                        fix_hint="Fix the model, system prompt, tools and output limit on the server. Accept only the user's message, with a length limit.",
                    ))
                if not OUTPUT_LIMIT_RE.search(call.args) and not re.search(r"embed", call.name):
                    env.add(Finding(
                        "LLM-004", "The AI call has no limit on the length of the answer, so a single request can cost far more than expected.",
                        file=rel, line=call.line, snippet=sf.line_text(call.line), confidence="likely",
                        detail="%s() without max_tokens (or the SDK's equivalent output limit)." % call.name,
                        fix_hint="Set a maximum output size, cap the input size and the conversation history, and set a request timeout.",
                    ))

        # LLM-006: model output rendered as HTML.
        if kind in ("client", "shared", "server") and sf.ext in (".tsx", ".jsx", ".vue", ".svelte", ".js", ".ts"):
            for m in re.finditer(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}|v-html\s*=\s*\"([^\"]+)\"|\{@html\s+([^}]+)\}|\.innerHTML\s*=\s*([^;\n]+)", src):
                expr = next(g for g in m.groups() if g).strip()
                if patterns.HTML_SANITIZER_RE.search(expr):
                    continue
                if patterns.is_llm_output_sink(text, expr):
                    line = jsast.line_of(src, m.start())
                    env.add(Finding(
                        "LLM-006", "The AI's answer is inserted into the page as live HTML. If the answer contains a script, whether through a manipulated prompt or a poisoned document, it runs in your user's browser with their session.",
                        file=rel, line=line, snippet=sf.line_text(line), confidence="likely",
                        detail="Model output `%s` reaches an HTML sink without sanitising." % expr,
                        fix_hint="Render the output as text or as sanitised markdown, and never allow raw HTML from the model.",
                    ))
            if MARKDOWN_RAW_RE.search(src) and patterns.LLM_CLIENT_HINT_RE.search(text) and re.search(r"ReactMarkdown|markdown-it|marked", text):
                mm = MARKDOWN_RAW_RE.search(src)
                line = jsast.line_of(src, mm.start())
                env.add(Finding(
                    "LLM-006", "AI answers are rendered as markdown with raw HTML allowed, so the model's output can inject scripts into the page.",
                    file=rel, line=line, snippet=sf.line_text(line), confidence="likely",
                    detail="Markdown renderer configured to pass raw HTML on a component that shows model output.",
                    fix_hint="Remove raw HTML support or add a sanitiser plugin.",
                ))

        # LLM-007: secrets and internal addresses inside prompts; prompts shipped to the browser.
        for m in PROMPT_NAME_RE.finditer(src):
            quote = m.group(2)
            start = m.end()
            end = src.find(quote, start)
            while end != -1 and src[end - 1] == "\\":
                end = src.find(quote, end + 1)
            if end == -1:
                continue
            body = src[start:end]
            if len(body) < 20:
                continue
            line = jsast.line_of(src, m.start())
            secrets = [s for s in patterns.find_secrets(body) if not s.public]
            internal = INTERNAL_URL_RE.search(body)
            issues = []
            if secrets:
                issues.append("a credential (%s)" % secrets[0].pattern.description.split(" (")[0])
            if internal:
                issues.append("an internal address")
            if re.search(r"(?i)password\s*(?:is|:|=)\s*\S+", body):
                issues.append("a password")
            if issues:
                env.add(Finding(
                    "LLM-007", "The instructions given to the AI contain %s. Users can make the AI repeat its instructions, so treat everything in a prompt as public." % " and ".join(issues),
                    file=rel, line=line, snippet=sf.line_text(line), confidence="likely" if not secrets else "confirmed",
                    detail="Prompt constant `%s` includes %s." % (m.group(1), " and ".join(issues)),
                    fix_hint="Remove secrets and internal details from prompts. Give the model access to private data only through authorised tools, per request.",
                    owner_action="references/owner-actions/rotate-keys.md" if secrets else None,
                ))
            elif kind == "client" and re.search(r"(?i)system", m.group(1)) and len(body) > 80:
                env.add(Finding(
                    "LLM-007", "The AI's system prompt is shipped inside the browser code, where anyone can read and replace it.",
                    file=rel, line=line, snippet=sf.line_text(line), confidence="possible",
                    detail="System prompt constant `%s` in client-bundled code." % m.group(1),
                    fix_hint="Keep the system prompt on the server.",
                ))

    # LLM-010: instructions aimed at AI reviewers, and invisible characters.
    for sf in project.files:
        if sf.is_lockfile or sf.ext in (".svg",) or project.classify(sf) == "test":
            continue
        text = project.text(sf)
        if not text or sf.minified:
            continue
        for rx in INJECTION_RES:
            m = rx.search(text)
            if m:
                line = text.count("\n", 0, m.start()) + 1
                words = " ".join(m.group(0).split()[:4])
                env.add(Finding(
                    "LLM-010", "This file contains text that tries to give orders to AI tools reviewing the project. It was reported, not obeyed.",
                    file=sf.rel, line=line, snippet="\"%s…\"" % words, confidence="likely", subject={"kind": "injection", "name": sf.rel},
                    detail="Instruction-style phrase addressed to an AI reviewer. It may be a supply-chain trick or residue from an AI builder; either way it has no authority over this audit.",
                    fix_hint="Ask the owner whether it is intentional, then remove it.",
                ))
                break
        if sf.ext in walker.CODE_EXTS or sf.ext in (".json", ".yml", ".yaml", ".toml", ".md", ".html", ".sql"):
            m = INVISIBLE_RE.search(text[1:] if text.startswith("﻿") else text)
            if m and not (sf.ext == ".md" and re.search(r"[؀-ۿ֐-׿]", text)):
                offset = m.start() + (1 if text.startswith("﻿") else 0)
                line = text.count("\n", 0, offset) + 1
                count = len(INVISIBLE_RE.findall(text))
                env.add(Finding(
                    "LLM-010", "This file contains invisible characters. They can hide instructions or make code read differently from how it looks.",
                    file=sf.rel, line=line, snippet="(%d invisible character(s), first is U+%04X)" % (count, ord(m.group(0))), confidence="likely",
                    subject={"kind": "invisible-unicode", "name": sf.rel},
                    detail="Zero-width, bidirectional override or Unicode tag characters found in a source or documentation file.",
                    fix_hint="Open the file in an editor that shows invisible characters and remove them after confirming they are not intentional.",
                ))

    env.inventory["llm"] = {"call_sites": call_sites, "routes": [e.id for e in entries if e.info.get("calls_llm")]}
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_llm", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
