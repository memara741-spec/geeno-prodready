#!/usr/bin/env python3
"""Performance audit for Laravel apps: N+1 queries, heavy queries, queue and cache problems.

Detects: relationships loaded one row at a time inside loops and Blade views
(PERF-007, also PERF-001 for any query inside a loop), whole tables loaded on a
request path (PERF-008), queries that cannot use an index or pull everything into
memory (PERF-009), mail and notifications sent inside the request (PERF-010),
queue, cache or session drivers that do not work in production (PERF-011) and
foreign key columns without an index (PERF-012).

What it deliberately does not do: it does not run the app or measure anything.
These are patterns that are slow at scale; confirm with Laravel Telescope or
Debugbar's query count on a real page before spending time on a fix.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional, Set

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import catalog, findings, phpscan, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_performance")
ALSO_EMITS = ["PERF-001"]

REL_FUNC = re.compile(r"function\s+(\w+)\s*\([^)]*\)[^{]*\{[^}]*\$this->(?:hasMany|hasOne|belongsTo|belongsToMany|morphTo|morphMany|morphToMany|hasManyThrough|hasOneThrough|morphOne)\s*\(", re.S)


def _relations(models: Dict[str, phpscan.PhpFile]) -> Set[str]:
    rels: Set[str] = set()
    for pf in models.values():
        rels |= set(REL_FUNC.findall(pf.code))
    return rels


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_performance", stack)
    if not any(p.endswith(".php") for p in project.all_paths()):
        env.files_scanned, env.files_skipped = project.stats()
        return env
    models = phpscan.model_class_names(project)
    rels = _relations(models)
    pfs = [p for p in phpscan.php_files(project) if not walker.TEST_PATH_RE.search(p.rel) and not p.rel.startswith(("database/factories/", "database/seeders/"))]
    all_code = "\n".join(p.code for p in pfs)
    eager = set()
    for m in re.finditer(r"(?:->|::)(?:with|load|loadMissing|withCount|withExists|without)\s*\(\s*(\[[^\]]*\]|['\"][^'\"]+['\"])|\$with\s*=\s*\[([^\]]*)\]", all_code):
        for name in re.findall(r"['\"](\w+)", (m.group(1) or "") + (m.group(2) or "")):
            eager.add(name)
    prevent = bool(re.search(r"preventLazyLoading\s*\(", all_code))
    env.inventory["performance"] = {"relations": sorted(rels), "eager_loaded": sorted(eager & rels), "prevent_lazy_loading": prevent}
    model_names = set(models)
    request_pfs = [p for p in pfs if re.search(r"app/(Http|Livewire)/", p.rel)]

    def add(check: str, pf: phpscan.PhpFile, offset: int, msg: str, conf: str = "likely", fix: str = "", sev: Optional[str] = None, subject: Optional[Dict[str, str]] = None) -> None:
        line = pf.line(offset)
        env.add(Finding(check, msg, file=pf.rel, line=line, snippet=pf.line_text(line), confidence=conf, fix_hint=fix, severity=sev, subject=subject))

    # PERF-007 / PERF-001 in PHP loops
    for pf in pfs:
        for m in re.finditer(r"\bforeach\s*\(\s*(.*?)\s+as\s+(?:\$\w+\s*=>\s*)?\$(\w+)\s*\)\s*\{", pf.bare):
            open_idx = m.end() - 1
            end = phpscan.match_brace(pf.bare, open_idx)
            body = pf.code[open_idx:end]
            var = m.group(2)
            hit = None
            for r in re.finditer(r"\$%s->(\w+)->\w+" % re.escape(var), body):
                if r.group(1) in rels and r.group(1) not in eager:
                    hit = (r.start(), r.group(1))
                    break
            if hit:
                add("PERF-007", pf, open_idx + hit[0], "Inside this loop each row's `%s` is fetched with its own query. A page with 100 rows runs 101 queries, and it gets slower with every new row." % hit[1], "likely", subject={"kind": "relation", "name": "%s in %s" % (hit[1], pf.rel)},
                    fix="Load the relationship up front: `Model::with('%s')->get()`. Add `Model::preventLazyLoading(! app()->isProduction())` so new cases fail in development." % hit[1])
            q = re.search(r"\b(?:%s)::(?:find|findOrFail|where|first|firstOrFail|count|all|pluck|exists)\s*\(|\bDB::(?:table|select)\s*\(|\$%s->(?:\w+)\(\)->(?:where|first|count|get|exists)\s*\(" % ("|".join(sorted(model_names)) or "(?!)", re.escape(var)), body)
            if q:
                add("PERF-001", pf, open_idx + q.start(), "A database query runs on every pass of this loop. With many rows it means many round trips.", "likely", fix="Fetch everything once before the loop (`whereIn`, `with`, or a join) and look results up in memory.")

    # PERF-007 in Blade
    for sf in project.files:
        if not sf.rel.endswith(".blade.php"):
            continue
        text = project.text(sf)
        for m in re.finditer(r"@foreach\s*\(\s*([^)]*?)\s+as\s+(?:\$\w+\s*=>\s*)?\$(\w+)\s*\)(.*?)@endforeach", text, re.S):
            var, body = m.group(2), m.group(3)
            for r in re.finditer(r"\$%s->(\w+)->\w+" % re.escape(var), body):
                if r.group(1) in rels and r.group(1) not in eager:
                    line = text.count("\n", 0, m.start(3) + r.start()) + 1
                    env.add(Finding("PERF-007", "This view reads `$%s->%s` for every row and nothing loads it in advance, so the page runs one extra query per row." % (var, r.group(1)), file=sf.rel, line=line, snippet=text.splitlines()[line - 1].strip(),
                                    confidence="likely", subject={"kind": "relation", "name": "%s in %s" % (r.group(1), sf.rel)}, fix_hint="Add `with('%s')` to the query that feeds this view, or `$this->%s` loading in the Livewire component." % (r.group(1), r.group(1))))
                    break

    # PERF-008 and PERF-009
    for pf in request_pfs:
        for m in re.finditer(r"\b(%s)::all\s*\(\s*\)" % ("|".join(sorted(model_names)) or "(?!)"), pf.code):
            ctx = pf.code[max(0, m.start() - 120):m.start()]
            if re.search(r"Cache::|remember\s*\(", ctx):
                continue
            add("PERF-008", pf, m.start(), "`%s::all()` loads every row of the table into memory on a web request. It is fine with 50 rows and brings the server down with 500,000." % m.group(1), "likely", fix="Use `paginate()` (or `cursor()`/`chunk()` for exports) and select only the columns you need.")
        for m in re.finditer(r"->get\s*\(\s*\)\s*->(count|sum|avg|max|min)\s*\(|->all\s*\(\s*\)\s*->(filter|where|count)\s*\(|::all\s*\(\s*\)\s*->(where|filter|count|sum)\s*\(", pf.code):
            fn = next(g for g in m.groups() if g)
            add("PERF-009", pf, m.start(), "This loads all matching rows into PHP just to call `%s()` on them. The database can do it in one query without sending the rows." % fn, "likely", fix="Call `%s()` on the query builder (`->%s('column')`) before `get()`." % (fn, fn))
        for m in re.finditer(r"->inRandomOrder\s*\(|orderByRaw\s*\(\s*['\"]\s*(?:RAND|RANDOM)\s*\(", pf.code):
            add("PERF-009", pf, m.start(), "Random ordering makes the database sort the whole table on every request.", "likely", fix="Pick random IDs in PHP from a cached list, or order by an indexed column.")
        for m in re.finditer(r"['\"]like['\"]\s*,\s*(?:['\"]%['\"]\s*\.|\"%\$|\"%\{)|(?i:like)\s+['\"]%\$?\{?[\w$]|whereRaw\s*\(\s*['\"](?i:lower|upper|date|year|month|day)\s*\(", pf.code):
            add("PERF-009", pf, m.start(), "A search that starts with a wildcard (`%...`) or wraps the column in a function cannot use an index, so it reads the whole table.", "likely", fix="Search by prefix (`term%`), use a full-text index (Scout, `whereFullText`), or store a normalised column.")

    # PERF-010 mail and notifications inside the request
    class_src = {p.class_name: p for p in pfs if p.class_name}
    for pf in request_pfs:
        for m in re.finditer(r"Mail::(?:to|cc|bcc|mailer)\s*\([^;]*?->send\s*\(\s*new\s+(\w+)|Mail::send\s*\(", pf.code):
            klass = m.group(1)
            src = class_src.get(klass) if klass else None
            if src and re.search(r"\bShouldQueue\b", src.bare):
                continue
            add("PERF-010", pf, m.start(), "An email is sent while the visitor waits. If the mail server is slow, the page hangs; if it is down, the request fails.", "likely", fix="Use `->queue()` (or make the Mailable implement `ShouldQueue`) and run a queue worker.")
        for m in re.finditer(r"->notify\s*\(\s*new\s+(\w+)|Notification::send\s*\([^;]*?new\s+(\w+)", pf.code):
            klass = m.group(1) or m.group(2)
            src = class_src.get(klass)
            if src is not None and not re.search(r"\bShouldQueue\b", src.bare):
                add("PERF-010", pf, m.start(), "The notification `%s` is sent during the request because it does not implement `ShouldQueue`." % klass, "likely", fix="Add `implements ShouldQueue` and `use Queueable;` to the notification.")

    # PERF-011 environment drivers
    for sf in project.files:
        if not re.search(r"(^|/)\.env(\.(production|prod|staging|live))?$", sf.rel) or walker.is_env_example(sf.rel) or not project.will_be_committed(sf.rel):
            continue
        text = project.text(sf)
        appenv = (re.search(r"^APP_ENV\s*=\s*(\S+)", text, re.M) or [None, ""])[1].strip("'\"").lower()
        if appenv not in ("production", "prod", "live", "staging") and not re.search(r"prod|live", sf.name):
            continue
        for key, bad, why in (("QUEUE_CONNECTION", ("sync", "null"), "Queued jobs run inside the request, so the queue does nothing and slow jobs slow every page."),
                              ("CACHE_STORE", ("array", "null"), "The cache is emptied on every request, so it caches nothing."), ("CACHE_DRIVER", ("array", "null"), "The cache is emptied on every request, so it caches nothing."),
                              ("SESSION_DRIVER", ("array",), "Sessions are lost on every request, so nobody stays signed in.")):
            m = re.search(r"^%s\s*=\s*['\"]?(\w+)" % key, text, re.M)
            if m and m.group(1).lower() in bad:
                line = text.count("\n", 0, m.start()) + 1
                env.add(Finding("PERF-011", "`%s=%s` in a production environment file. %s" % (key, m.group(1), why), file=sf.rel, line=line, snippet="%s=%s" % (key, m.group(1)), confidence="confirmed", subject={"kind": "env", "name": key},
                                fix_hint="Use `redis` or `database` for the queue and `redis`, `database` or `file` for the cache, and run `php artisan queue:work` under a process manager."))

    # PERF-012 migrations
    indexed: Set[str] = set()
    for pf in pfs:
        if "/migrations/" in "/" + pf.rel:
            for c in re.finditer(r"\$table->(?:index|foreign|unique|primary)\s*\(\s*(\[[^\]]*\]|['\"][^'\"]+['\"])", pf.code):
                indexed |= set(re.findall(r"['\"](\w+)['\"]", c.group(1)))
    for pf in pfs:
        if "/migrations/" not in "/" + pf.rel:
            continue
        for c in re.finditer(r"\$table->(?:unsignedBigInteger|bigInteger|unsignedInteger|integer|unsignedSmallInteger|uuid|ulid)\(\s*['\"](\w+_id)['\"][^;]*;", pf.code):
            col = c.group(1)
            if re.search(r"->(?:index|unique|primary|constrained|references)\s*\(", c.group(0)) or col in indexed:
                continue
            add("PERF-012", pf, c.start(), "`%s` is a link to another table but has no index. Every lookup, join or delete on it reads the whole table." % col, "confirmed", subject={"kind": "column", "name": col},
                fix="Use `foreignId('%s')->constrained()` or add `->index()`." % col)
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_performance", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
