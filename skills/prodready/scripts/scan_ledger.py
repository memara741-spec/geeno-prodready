#!/usr/bin/env python3
"""Financial integrity engine: does every balance change leave a trace, and can money appear or vanish?

Reads the code that changes balances and the migrations that define money tables.
Detects: balance changes with no ledger or transaction row (FIN-001), transfers
that debit without crediting (FIN-002), balance columns that can go negative
(FIN-003) and payment tables with no unique key against duplicates (FIN-004).
Together with BIZ-001 to BIZ-003 (locks, repeats) this covers double spending,
duplicates and unbalanced books.

What it deliberately does not do: it does not replay your data or prove the books
balance. A ledger written by an observer, trigger or another service is invisible
to it; those findings are ``likely`` and say what to confirm.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import catalog, findings, phpscan, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_ledger")
ALSO_EMITS: List[str] = []
BAL = r"balance|credits?|points|funds|wallet\w*"
DEBIT = re.compile(r"->decrement\(\s*['\"](?:%s)['\"]|->(?:%s)\s*-=|->(?:%s)\s*=\s*[^;]*->(?:%s)\s*-\s" % (BAL, BAL, BAL, BAL))
CREDIT = re.compile(r"->increment\(\s*['\"](?:%s)['\"]|->(?:%s)\s*\+=|->(?:%s)\s*=\s*[^;]*->(?:%s)\s*\+\s" % (BAL, BAL, BAL, BAL))
LEDGER = re.compile(r"(?i)(?:ledger|transactions?|entries|journal|movements?|statement)\w*\s*(?:::|->)\s*(?:create|insert|forceCreate|save)|DB::table\(\s*['\"]\w*(?:ledger|transactions?|entries|journal|movements?)\w*['\"]\s*\)\s*->\s*insert|\bLedgerEntry\b|->(?:transactions|ledger|entries)\(\)->create|Transaction::create")
MONEY_TABLE = re.compile(r"^(?:\w*payments?|\w*transactions?|\w*transfers?|\w*payouts?|\w*refunds?|\w*charges|\w*withdrawals?)$")
TRANSFERISH = re.compile(r"(?i)transfer|send|move|convert|exchange|swap|internal")


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_ledger", stack)
    if not any(p.endswith(".php") for p in project.all_paths()):
        env.files_scanned, env.files_skipped = project.stats()
        return env
    pfs = [p for p in phpscan.php_files(project) if p.rel.startswith("app/") and not walker.TEST_PATH_RE.search(p.rel)]
    for pf in pfs:
        by_name = {m["name"]: m for m in pf.methods()}
        for m in pf.methods():
            body = m["body"]
            deb, cred = DEBIT.search(body), CREDIT.search(body)
            if not (deb or cred):
                continue
            hop = body + "".join(by_name[c]["body"] for c in set(re.findall(r"\$this->(\w+)\s*\(", body)) if c in by_name)
            sub = {"kind": "method", "name": "%s::%s" % (pf.class_name, m["name"])}
            line = pf.line(m["body_start"] + (deb or cred).start())
            if not LEDGER.search(hop):
                env.add(Finding("FIN-001", "`%s::%s()` changes a balance and writes no ledger or transaction row. Later nobody can say why the balance is what it is, or undo a mistake." % (pf.class_name, m["name"]), file=pf.rel, line=line, snippet=pf.line_text(line), confidence="likely",
                                subject=sub, detail="No insert into a ledger, transactions or entries table was found in this method or the methods it calls.", fix_hint="Insert a ledger row (account, signed amount, reason, reference) inside the same DB::transaction as the balance change."))
            if deb and not cred and TRANSFERISH.search(m["name"]):
                env.add(Finding("FIN-002", "`%s::%s()` is a transfer that takes money from one account and never adds it anywhere. The amount disappears from the books." % (pf.class_name, m["name"]), file=pf.rel, line=line, snippet=pf.line_text(line), confidence="likely", subject=sub,
                                fix_hint="Credit the receiving account (or a clearing account) in the same transaction and record both sides in the ledger."))
    mig = [p for p in phpscan.php_files(project) if "/migrations/" in "/" + p.rel]
    all_mig = "\n".join(p.code for p in mig)
    for pf in mig:
        for m in re.finditer(r"\$table->(decimal|integer|bigInteger|float|double|smallInteger|mediumInteger)\(\s*['\"](balance|credits?|points|funds|available_balance|wallet_balance)['\"][^;]*;", pf.code):
            col = m.group(2)
            if "unsigned" in m.group(0) or re.search(r"CHECK\s*\(\s*\W?\w*\W?\.?\W?%s\W?\s*>=\s*0" % col, all_mig, re.I) or "->check(" in all_mig:
                continue
            env.add(Finding("FIN-003", "The `%s` column accepts negative numbers. If two requests race or a bug subtracts too much, the database will store a negative balance instead of refusing it." % col, file=pf.rel, line=pf.line(m.start()), snippet=pf.line_text(pf.line(m.start())), confidence="confirmed",
                            subject={"kind": "column", "name": col}, fix_hint="Add `DB::statement('ALTER TABLE t ADD CONSTRAINT t_%s_nonneg CHECK (%s >= 0)')` in a migration, in addition to the code check." % (col, col)))
        for t in re.finditer(r"Schema::create\(\s*['\"](\w+)['\"]", pf.code):
            name = t.group(1)
            if not MONEY_TABLE.match(name):
                continue
            open_idx = pf.bare.find("{", t.end())
            body = pf.code[open_idx:phpscan.match_brace(pf.bare, open_idx)] if open_idx > 0 else ""
            if not re.search(r"\bunique\(", body):
                env.add(Finding("FIN-004", "The `%s` table has no unique key. A retry or a double submit can store the same payment or transfer twice, and nothing in the database will notice." % name, file=pf.rel, line=pf.line(t.start()), snippet=pf.line_text(pf.line(t.start())), confidence="likely",
                                subject={"kind": "table", "name": name}, fix_hint="Add a unique index on the provider reference or an idempotency key column."))
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_ledger", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
