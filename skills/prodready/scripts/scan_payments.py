#!/usr/bin/env python3
"""Check how money moves: prices, webhooks, billing identifiers and card data.

Detects: checkout or payment creation that takes the amount or price from the
request (PAY-001), payment webhooks that do not verify the provider's
signature (PAY-002), billing calls that accept a customer or subscription ID
from the request (PAY-007), test keys in production settings or live keys in
development settings (PAY-008), card numbers handled by the app's own code
(PAY-009) and money stored or computed as floating point (PAY-011). It also
leaves hints for two review-only checks: plans granted on the success page
(PAY-003) and webhook handlers that never record the event ID (PAY-004).

What it deliberately does not do: it does not decide whether entitlements are
enforced everywhere (PAY-005) or whether subscription lifecycle events are
handled (PAY-006). Those need a reviewer who follows the flow.
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

IMPLEMENTS = catalog.by_scanner("scan_payments")
ALSO_EMITS = ["PAY-003", "PAY-004"]

PAYMENT_HINT_RE = re.compile(r"(?i)stripe|paddle|lemon\s*squeezy|lemonsqueezy|razorpay|paypal|polar|checkout\.session|payment_intent|invoice\.paid")
CREATE_CALLS = ["stripe.*", "stripe().*", "paddle.*", "razorpay.*", "lemonSqueezy.*", "paypal.*"]
AMOUNT_KEY_RE = re.compile(r"\b(unit_amount|amount|unit_amount_decimal|price|total|plan|priceId|price_id|variantId|variant_id)\s*:\s*([^,}\n]+)|(?<=[{,\s])(amount|priceId|price_id)\s*(?=[,}])")
ALLOWLIST_RE = re.compile(r"(?i)PRICES?\s*\[|PLANS?\s*\[|priceFor\w*\(|allowedPrices|ALLOWED_PRICES|\.includes\(\s*priceId|prices\.retrieve\(|lookup_keys|priceMap|PRICE_IDS|\.from\(\s*[\"'](?:prices|plans|products)[\"']\)")
MONEY_NAME_RE = re.compile(r"(?i)^(price|amount|total|subtotal|balance|cost|fee|budget|salary|credit_amount|unit_price|\w*_price|\w*_amount|\w*_total|\w*_cost|\w*_fee)$")
FLOAT_TYPE_RE = re.compile(r"(?i)^(real|float\d?|double precision|double|float8|float4)$")
CARD_FIELD_RE = re.compile(r"(?i)\b(?:name|id)\s*=\s*[\"'{]\s*[\"']?(card[_-]?number|cardnumber|cc[_-]?number|ccnum|cvv|cvc|card[_-]?cvc|security[_-]?code)[\"']")
CARD_BODY_RE = re.compile(r"(?i)\b(?:body|req\.body|data|payload|json)\.(cardNumber|card_number|cvv|cvc|ccNumber)\b|\{\s*[^}]*\b(cardNumber|card_number|cvv|cvc)\b[^}]*\}\s*=\s*(?:await\s+)?(?:req|request)")


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_payments", stack)
    has_payments = bool(detect_stack.names(stack, "payments"))
    entries = scan_routes.build_inventory(project, stack)
    call_sites: List[Dict[str, Any]] = []

    for sf in project.code_files():
        text = project.text(sf)
        rel = sf.rel
        kind = project.classify(sf)
        is_py = sf.ext == ".py"
        if is_py:
            continue
        lx = jsast.lexed(text)
        src = lx.nocomment
        file_entries = [e for e in entries if e.sf is sf]

        def scope(offset: int) -> str:
            best = None
            for e in file_entries:
                if e.start <= offset < e.end and (best is None or e.end - e.start < best.end - best.start):
                    best = e
            return best.src if best else src

        if kind != "client" and PAYMENT_HINT_RE.search(text):
            for call in jsast.find_calls(text, CREATE_CALLS):
                tail = call.name.split(".")[-1]
                if tail not in ("create", "update", "cancel", "del", "retrieve"):
                    continue
                sc = scope(call.start)
                tainted, whole, origin = scan_routes.taint(sc)
                site = "checkout" if "checkout" in call.name else "payment-intent" if "paymentIntent" in call.name or "payment_intent" in call.name else "portal" if "billingPortal" in call.name else "subscription" if "subscription" in call.name else "other"
                call_sites.append({"file": rel, "line": call.line, "call": call.name, "kind": site})
                if tail == "create" and site in ("checkout", "payment-intent", "subscription", "other") and re.search(r"sessions|paymentIntents|subscriptions|orders|invoiceItems|prices|paymentLinks|transactions", call.name):
                    reported = False
                    for m in AMOUNT_KEY_RE.finditer(call.args):
                        key = m.group(1) or m.group(3)
                        value = (m.group(2) or key).strip()
                        hit = scan_routes.is_tainted(value, tainted)
                        if not hit:
                            continue
                        is_price_ref = key in ("price", "plan", "priceId", "price_id", "variantId", "variant_id")
                        if is_price_ref and ALLOWLIST_RE.search(sc):
                            continue
                        line = call.line + call.args[: m.start()].count("\n")
                        env.add(Finding(
                            "PAY-001", "The buyer's browser decides %s. Anyone can change the request and pay whatever they like, or pick a plan they should not get." % ("which price is charged" if is_price_ref else "how much is charged"),
                            file=rel, line=line, snippet=sf.line_text(line), confidence="likely",
                            detail="%s() uses `%s: %s`, and `%s` comes from the request body." % (call.name, key, value, hit),
                            fix_hint="Send only a product or plan name from the client. Map it to a price on the server from an allow-list or the database, and recompute totals there.",
                        ))
                        reported = True
                    if reported:
                        continue
                if site == "portal" or (site == "subscription" and tail in ("update", "cancel", "del")):
                    probe = call.args if site == "portal" else (jsast.split_args(call.args) or [""])[0]
                    hit = None
                    cm = re.search(r"\bcustomer\s*:\s*([^,}\n]+)", probe)
                    if cm:
                        hit = scan_routes.is_tainted(cm.group(1), tainted)
                    elif site == "subscription":
                        hit = scan_routes.is_tainted(probe, tainted)
                    if hit:
                        env.add(Finding(
                            "PAY-007", "The billing action uses a customer or subscription ID sent by the browser. A user can put in someone else's ID and open or change their billing.",
                            file=rel, line=call.line, snippet=sf.line_text(call.line), confidence="likely",
                            detail="%s() receives `%s` from the request instead of looking it up for the signed-in user." % (call.name, hit),
                            fix_hint="Store the customer and subscription IDs with the user's record and read them from there on the server.",
                        ))

        # PAY-009: card data in the app's own forms and handlers.
        m = CARD_FIELD_RE.search(src) or (CARD_BODY_RE.search(src) if kind != "client" else None)
        if m and not re.search(r"CardElement|PaymentElement|CardNumberElement|hosted-?fields|braintree-hosted", text):
            line = jsast.line_of(src, m.start())
            env.add(Finding(
                "PAY-009", "The app collects card numbers in its own form and sends them to its own server. That puts you in the strictest card-security rules and makes a breach catastrophic.",
                file=rel, line=line, snippet=sf.line_text(line), confidence="likely",
                detail="Card field `%s` handled by the app instead of the payment provider's hosted fields." % next(g for g in m.groups() if g),
                fix_hint="Use the provider's hosted checkout or embedded elements so card data never touches your code.",
            ))

        # PAY-011 (code part): parseFloat on money.
        if kind != "client":
            m = re.search(r"parseFloat\(\s*[\w.\[\]\"']*(?:amount|price|total|balance)\w*", src, re.I)
            if m:
                line = jsast.line_of(src, m.start())
                env.add(Finding(
                    "PAY-011", "Money is handled as a floating point number, which rounds in surprising ways. Totals, tax and refunds can be off by a cent.",
                    file=rel, line=line, snippet=sf.line_text(line), confidence="possible",
                    detail="parseFloat on a money value.",
                    fix_hint="Use integer minor units (cents) or a decimal type end to end.",
                ))

    # PAY-002, PAY-004 hint, PAY-003 hint from the route inventory.
    webhook_handlers = []
    for e in entries:
        info = e.info
        is_payment = bool(PAYMENT_HINT_RE.search(e.file_src + " " + e.path))
        if info.get("is_webhook") and is_payment and e.methods[:1] != ["GET"]:
            webhook_handlers.append(e)
            if not info.get("verifies_signature"):
                env.add(Finding(
                    "PAY-002", "Anyone can send a fake \"payment succeeded\" message to `%s` and get the paid plan for free. The app never checks that the message really came from the payment provider." % e.id,
                    file=e.sf.rel, line=e.line, snippet=e.sf.line_text(e.line), confidence="likely", subject={"kind": "route", "name": e.id},
                    detail="Payment webhook handler with no signature verification (for Stripe: stripe.webhooks.constructEvent with the raw body and the endpoint secret).",
                    fix_hint="Read the raw body, verify the signature with the provider's library and the signing secret, and return 400 when it fails.",
                ))
            elif not re.search(r"event\.id|event_id|eventId|\bevt\.id|idempot", e.src):
                env.add(Finding(
                    "PAY-004", "The payment webhook does not remember which events it has handled. The provider re-sends events, so users can be credited twice or left in the wrong state.",
                    file=e.sf.rel, line=e.line, snippet=e.sf.line_text(e.line), confidence="possible", subject={"kind": "route", "name": e.id},
                    detail="Verified webhook handler with no reference to the event ID being stored or checked.",
                    fix_hint="Store processed event IDs with a unique constraint and derive state from the provider's current object.",
                ))
    if has_payments:
        for sf in project.code_files():
            rel = sf.rel
            if not re.search(r"(?i)(^|/)(success|thank-?you|thanks|complete|confirmation|return)(/|\.|$)", rel) or project.classify(sf) == "test":
                continue
            text = project.text(sf)
            code = jsast.lexed(text).code
            m = re.search(r"\.update\w*\(|\.upsert\(|\.insert\(|updateUserById\(|\bgrant\w*\(|\bupgrade\w*\(|setPlan\(|\bfulfil\w*\(", code)
            if m and not re.search(r"sessions\.retrieve\(|payment_status|paymentIntents\.retrieve\(", code):
                line = jsast.line_of(code, m.start())
                env.add(Finding(
                    "PAY-003", "The \"thank you\" page itself upgrades the account. Anyone who opens that page's address gets the paid plan without paying%s." % ("" if webhook_handlers else ", and there is no payment webhook to do it properly"),
                    file=rel, line=line, snippet=sf.line_text(line), confidence="likely" if not any(h.info.get("verifies_signature") for h in webhook_handlers) else "possible",
                    detail="A success page or route writes entitlement data without confirming the payment status on the server.",
                    fix_hint="Grant access in the verified webhook handler. The success page should only display status.",
                ))

    # PAY-008: key modes against environment files.
    for sf in project.files:
        if not walker.is_env_file(sf.rel) or walker.is_env_example(sf.rel):
            continue
        name = sf.name.lower()
        is_prod = "prod" in name
        is_dev = "dev" in name or name in (".env.local", ".env.test")
        text = project.text(sf)
        for i, line in enumerate(text.split("\n"), 1):
            if line.strip().startswith("#"):
                continue
            test_key = re.search(r"\b(?:sk|pk|rk)_test_[0-9A-Za-z]{8,}", line)
            live_key = re.search(r"\b(?:sk|rk)_live_[0-9A-Za-z]{8,}", line)
            var = line.split("=", 1)[0].strip()
            if is_prod and test_key and project.will_be_committed(sf.rel):
                env.add(Finding(
                    "PAY-008", "The production settings use a payment key in test mode. Customers will go through checkout and no money will arrive.",
                    file=sf.rel, line=i, snippet=line.strip(), confidence="likely",
                    detail="%s in %s holds a test-mode key." % (var, sf.rel),
                    fix_hint="Set the live keys in the host's production environment, and keep test keys for development and preview.",
                ))
            elif is_dev and live_key:
                env.add(Finding(
                    "PAY-008", "The development settings use a live payment key. Testing on your machine will create real charges.",
                    file=sf.rel, line=i, snippet=line.strip(), confidence="likely",
                    detail="%s in %s holds a live-mode key." % (var, sf.rel),
                    fix_hint="Use test-mode keys in development, and a restricted live key in production only.",
                ))

    # PAY-011 (schema part): float types for money columns.
    for sf in project.files:
        text = project.text(sf)
        if sf.ext == ".sql":
            for m in re.finditer(r"(?im)^\s*\"?(\w+)\"?\s+(real|float\d?|double precision|float8|float4)\b", text):
                if MONEY_NAME_RE.match(m.group(1)):
                    line = text.count("\n", 0, m.start()) + 1
                    env.add(Finding(
                        "PAY-011", "The `%s` amount is stored as a floating point number, which cannot represent most decimal amounts exactly." % m.group(1),
                        file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely",
                        detail="Column %s has type %s." % (m.group(1), m.group(2)),
                        fix_hint="Store integer minor units (cents) or use numeric(12,2).",
                    ))
        elif sf.ext == ".prisma":
            for m in re.finditer(r"(?m)^\s*(\w+)\s+Float\??", text):
                if MONEY_NAME_RE.match(m.group(1)):
                    line = text.count("\n", 0, m.start()) + 1
                    env.add(Finding(
                        "PAY-011", "The `%s` amount is stored as a floating point number, which cannot represent most decimal amounts exactly." % m.group(1),
                        file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely",
                        detail="Prisma field %s is a Float." % m.group(1),
                        fix_hint="Use Int for minor units or Decimal.",
                    ))

    env.inventory["payments"] = {
        "providers": sorted(detect_stack.names(stack, "payments")),
        "call_sites": call_sites,
        "webhook_handlers": [{"route": e.id, "file": e.sf.rel, "verifies_signature": bool(e.info.get("verifies_signature"))} for e in webhook_handlers],
    }
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_payments", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
