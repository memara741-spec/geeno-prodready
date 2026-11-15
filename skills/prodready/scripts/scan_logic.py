#!/usr/bin/env python3
"""Business logic audit: bookings, payments, wallets, balances and repeated requests.

Looks at the code that moves money or counts scarce things and asks the questions
a careful reviewer would. Detects: balance or stock changed by read-then-write
without a lock (BIZ-001), availability checked and then used without a lock
(BIZ-002), money-moving endpoints that do nothing about repeated requests
(BIZ-003), amounts not limited to a positive range (BIZ-004), money stored as
floating point (BIZ-005), prices, totals or status fields set by the client
(BIZ-006) and queued money jobs that can run twice (BIZ-007).

What it deliberately does not do: it does not understand your pricing rules, and
a clean result does not mean the logic is right. Findings are candidates to read.
Laravel and PHP are covered fully; BIZ-001 also reads JavaScript and TypeScript
servers.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import catalog, findings, phpscan, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_logic")
ALSO_EMITS: List[str] = []

MONEY_FIELD = r"balance|credits?|stock|quantity|points|available\w*|seats|wallet\w*|amount_available|remaining\w*|inventory"
LOCK_RE = re.compile(r"DB::transaction|lockForUpdate|sharedLock|Cache::lock|beginTransaction|->decrement\s*\(|->increment\s*\(|DB::raw\(\s*['\"]\s*\w+\s*[-+]|\$transaction|FOR UPDATE|\.increment|\.decrement|increment\s*:|decrement\s*:|findOneAndUpdate|\$inc\b|\.transaction\(|\.forUpdate\(")
MONEY_ROUTE_RE = re.compile(r"(?i)transfer|withdraw|payout|refund|charge|\bpay\b|/pay|checkout|deposit|top-?up|send-?money|redeem|purchase|/orders?\b|buy|subscribe|tip|donat")
IDEMP_RE = re.compile(r"(?i)idempoten|Idempotency-Key|firstOrCreate|updateOrCreate|lockForUpdate|processed_at|already|wasRecentlyCreated|Cache::lock|Cache::add|ShouldBeUnique|unique|reference|uuid|Rule::unique|exists\(\)|->doesntExist\(\)")
MONEY_WORDS = re.compile(r"(?i)balance|wallet|transfer|payment|charge|order|invoice|withdraw|credit|refund|payout|checkout|booking|subscription")
AVAIL_CHECK = re.compile(r"->(?:exists|doesntExist|count|first)\s*\(\s*\)|->(?:%s)\s*(?:>=?|<=?|===?|!==?)|\b(?:isAvailable|available|hasCapacity|hasStock|inStock)\b" % MONEY_FIELD)
BOOKING_WORDS = re.compile(r"\b(?:Booking|Reservation|Appointment|Slot|Seat|Ticket|Room|Table|Order|Enrol\w+|Registration|Product|Item)\b|stock|available|capacity|quantity")


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_logic", stack)
    laravel = phpscan.is_laravel(project) or any(p.endswith(".php") for p in project.all_paths())
    pfs = [p for p in phpscan.php_files(project) if not walker.TEST_PATH_RE.search(p.rel) and not p.rel.startswith(("database/factories/", "database/seeders/"))] if laravel else []

    def add(check: str, pf: phpscan.PhpFile, offset: int, msg: str, conf: str = "likely", fix: str = "", detail: str = "", sev: Optional[str] = None, subject: Optional[Dict[str, str]] = None) -> None:
        line = pf.line(offset)
        env.add(Finding(check, msg, file=pf.rel, line=line, snippet=pf.line_text(line), confidence=conf, fix_hint=fix, detail=detail, severity=sev, subject=subject))

    for pf in pfs:
        in_app = pf.rel.startswith(("app/", "routes/"))
        if not in_app:
            continue
        for meth in pf.methods():
            body = meth["body"]
            base = meth["body_start"]
            sub = {"kind": "method", "name": "%s::%s" % (pf.class_name or pf.rel, meth["name"])}
            locked = bool(LOCK_RE.search(body))
            # BIZ-001
            for m in re.finditer(r"->(%s)\s*(?:-=|\+=)|->(%s)\s*=\s*\$?\w+(?:->\w+)*->(?:%s)\s*[-+]\s*" % (MONEY_FIELD, MONEY_FIELD, MONEY_FIELD), body):
                if not locked and re.search(r"->save\s*\(|->update\s*\(", body):
                    field = m.group(1) or m.group(2)
                    add("BIZ-001", pf, base + m.start(), "`%s::%s()` reads `%s`, changes it in PHP and saves it back with no lock or transaction. Two requests at the same moment both read the old value, so money or stock is created or spent twice." % (pf.class_name, meth["name"], field),
                        "likely", fix="Wrap it in `DB::transaction` and load the row with `lockForUpdate()`, or use the atomic `decrement()`/`increment()` with a `where balance >= ?` condition.", subject=sub)
                    break
            # BIZ-002
            if not locked and not re.search(r"firstOrCreate|upsert|updateOrCreate|insertOrIgnore", body):
                chk = AVAIL_CHECK.search(body)
                act = re.search(r"::create\s*\(|->save\s*\(|->(?:update|decrement|increment)\s*\(|::insert\s*\(", body)
                if chk and act and chk.start() < act.start() and BOOKING_WORDS.search(body) and re.search(r"abort|return\s+(?:response|back|redirect)|throw|if\s*\(", body[:act.start()]):
                    add("BIZ-002", pf, base + chk.start(), "`%s::%s()` checks that something is free or in stock and then books or sells it in a separate step. Two buyers who ask at the same moment both pass the check, so the last seat is sold twice." % (pf.class_name, meth["name"]),
                        "likely", fix="Do the check and the write in one `DB::transaction` with `lockForUpdate()`, add a unique index on the slot (for example room and date), or use an atomic conditional update.", subject=sub)
            # BIZ-006
            if "/Http/" in pf.rel or "/Livewire/" in pf.rel:
                for m in re.finditer(r"['\"](price|total|subtotal|discount|balance|amount_paid|paid_at|is_paid|commission|tax|credits|unit_price|fee)['\"]\s*=>\s*\$request->|\$request->(?:only|safe\(\)->only)\s*\(\s*\[[^\]]*['\"](?:price|total|subtotal|discount|balance|amount_paid|paid_at|is_paid|commission|unit_price)['\"]", body):
                    add("BIZ-006", pf, base + m.start(), "`%s::%s()` accepts a price, total, discount or paid flag from the request. The caller can set it to zero and pay nothing." % (pf.class_name, meth["name"]), "likely",
                        fix="Work out money fields on the server from the product or plan IDs and your own prices; never copy them from input.", subject=sub)
                    break
                else:
                    m = re.search(r"['\"]status['\"]\s*=>\s*\$request->", body)
                    if m and re.search(r"(?i)order|payment|invoice|subscription|booking", body):
                        add("BIZ-006", pf, base + m.start(), "`%s::%s()` lets the request choose an order, payment or booking status. A caller can mark their own order as paid." % (pf.class_name, meth["name"]), "likely",
                            fix="Set status transitions in code, from verified events such as a payment webhook.", subject=sub)
        # BIZ-004 validation rules
        if re.search(r"/(Http|Livewire)/", pf.rel):
            for m in re.finditer(r"['\"](amount|price|quantity|qty|total|credits?|points|value|cost|fee|sum)['\"]\s*=>\s*(\[[^\]]*\]|['\"][^'\"]*['\"])", pf.code):
                rule = m.group(2)
                if re.search(r"numeric|integer|decimal|\bint\b|float|required", rule) and not re.search(r"min:|gt:|gte:|between:|digits|in:|Rule::in|size:|prohibited", rule) and not re.search(r"->min\(|->between\(|->gt\(", rule):
                    ctx = pf.code[max(0, m.start() - 1500):m.end() + 1500]
                    if MONEY_WORDS.search(ctx):
                        add("BIZ-004", pf, m.start(), "The `%s` rule has no minimum. A negative amount makes a transfer or payment run backwards and credits the sender." % m.group(1), "likely",
                            fix="Add `min:0.01` (or `gt:0`) and a `max:` that matches your limits, and use `integer` cents for money.", subject={"kind": "rule", "name": pf.rel + ":" + m.group(1)})
        # BIZ-005 floats in PHP code and casts
        for m in re.finditer(r"['\"](\w*(?:price|amount|total|balance|cost|fee|tax|subtotal|discount|salary)\w*)['\"]\s*=>\s*['\"](?:float|double|real)['\"]", pf.code):
            add("BIZ-005", pf, m.start(), "`%s` is cast to a floating-point number. Floats cannot hold amounts such as 0.10 exactly, so totals drift by fractions of a cent." % m.group(1), "likely", fix="Store integer cents, or use `decimal:2` casts with `brick/money`.")
        # BIZ-007 jobs
        if re.search(r"\bimplements\s+[^{]*\bShouldQueue\b", pf.bare) and in_app:
            ops = re.search(r"(?i)balance|credit|payout|refund|charge|transfer|wallet|deposit|->decrement\(|->increment\(", pf.code)
            if ops and not re.search(r"ShouldBeUnique|WithoutOverlapping|ShouldBeUniqueUntilProcessing|lockForUpdate|(?i:idempoten)|processed|firstOrCreate|Cache::lock|Cache::add|->where\(\s*['\"]status['\"]", pf.code):
                m = re.search(r"\bclass\s+\w+", pf.bare)
                add("BIZ-007", pf, m.start() if m else 0, "The queued job `%s` moves money or balances and has nothing that stops it running twice. Queues deliver a job again after a crash or timeout, so a payout can be paid twice." % pf.class_name, "possible",
                    fix="Implement `ShouldBeUnique`, or record a processed marker inside a transaction and return early when it exists.", subject={"kind": "job", "name": pf.class_name})

    # BIZ-003 from routes
    if laravel:
        for r in phpscan.route_inventory(project):
            if r["method"].lower() not in phpscan.WRITE_VERBS or not MONEY_ROUTE_RE.search(r["uri"]) or re.search(r"(?i)webhook", r["uri"]):
                continue
            cf = phpscan.controller_file(project, r["controller"])
            meth = next((m for m in cf.methods() if m["name"] == r["action"]), None) if cf else None
            body = meth["body"] if meth else r["snippet"]
            if IDEMP_RE.search(body) or any("idempot" in x.lower() for x in r["middleware"]):
                continue
            if cf and meth:
                env.add(Finding("BIZ-003", "`%s %s` moves money or places an order and does nothing about the same request arriving twice. A double click or a retry after a timeout charges or pays twice." % (r["method"], r["uri"]), file=cf.rel, line=meth["line"],
                                snippet=cf.line_text(meth["line"]), confidence="likely", subject={"kind": "route", "name": "%s %s" % (r["method"], r["uri"])},
                                fix_hint="Require an `Idempotency-Key` header, store it with the result in a unique column inside the transaction, and return the stored result on a repeat."))

    # BIZ-005 migrations
    for pf in pfs:
        if "/migrations/" not in "/" + pf.rel:
            continue
        for m in re.finditer(r"\$table->(float|double|real)\(\s*['\"](\w*(?:price|amount|total|balance|cost|fee|tax|subtotal|discount|credit|salary|rate)\w*)['\"]", pf.code):
            env.add(Finding("BIZ-005", "The column `%s` stores money as `%s`. Floating-point numbers cannot hold amounts like 0.10 exactly, so sums drift and balances stop matching." % (m.group(2), m.group(1)), file=pf.rel, line=pf.line(m.start()),
                            snippet=pf.line_text(pf.line(m.start())), confidence="confirmed", subject={"kind": "column", "name": m.group(2)}, fix_hint="Use `decimal('%s', 12, 2)` or store integer cents (`unsignedBigInteger`)." % m.group(2)))

    # BIZ-001 for JavaScript servers
    for sf in project.code_files({".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx"}):
        if project.classify(sf) not in ("server", "shared"):
            continue
        text = project.text(sf)
        for m in re.finditer(r"\b(\w+)\.(%s)\s*(?:-=|\+=)|data\s*:\s*\{\s*(%s)\s*:\s*\w+\.(?:%s)\s*[-+]" % (MONEY_FIELD, MONEY_FIELD, MONEY_FIELD), text):
            window = text[max(0, m.start() - 800):m.end() + 800]
            if LOCK_RE.search(window) or not re.search(r"\.save\s*\(|\.update\s*\(|\bupdate\s*\(", window):
                continue
            line = sf.line_of(m.start())
            env.add(Finding("BIZ-001", "This code reads a balance or stock level, changes it in memory and writes it back with no lock or atomic update. Two requests at once both read the old value.", file=sf.rel, line=line, snippet=sf.line_text(line), confidence="likely",
                            fix_hint="Use an atomic update (`{ decrement: n }`, `$inc`) with a condition, or a transaction with a row lock."))
            break
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_logic", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
