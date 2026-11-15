#!/usr/bin/env python3
"""Measure a running Laravel app: queries per page, repeated queries (real N+1), time and memory.

Static scanners guess that a page is slow; this measures it. Install the small
middleware from ``assets/laravel/ProdreadyProfile.php`` in a local or staging copy
of the app, then run this script against it. The middleware adds headers with the
number of queries, the most repeated query shape (without values), time and peak
memory, and only answers a request that carries the secret in ``PRODREADY_PROFILE_KEY``.

Detects: too many queries per page (PERF-013), the same query repeated many times
(PERF-014) and slow or memory-hungry responses (PERF-015).

Safety: GET requests only, at most 60 per run, paced, with the app's own routes
(``--app-root``) or paths you list. A token for pages that need sign-in is read
from the environment variable ``PRODREADY_TOKEN``, never from the command line.
Hosts other than localhost need both ``--allow-network`` and ``--i-own-this``.

What it deliberately does not do: it does not read response bodies, send data,
or profile without the middleware beyond wall-clock time.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import probe_live  # noqa: E402
from lib import catalog, findings, phpscan, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("profile_runtime")
ALSO_EMITS: List[str] = []
LOCAL = ("localhost", "127.0.0.1", "[::1]", "::1")


def _num(h: Any, name: str) -> Optional[float]:
    try:
        return float(h.get(name))
    except (TypeError, ValueError):
        return None


def profile(base_url: str, paths: List[str], budget: probe_live.Budget, repeat: int, limits: Dict[str, float], token: str, key: str) -> Envelope:
    env = Envelope("profile_runtime")
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if key:
        headers["X-Prodready-Profile"] = key
    rows: List[Dict[str, Any]] = []
    saw_headers = False
    for path in paths:
        url = base_url.rstrip("/") + path
        best: Optional[Dict[str, Any]] = None
        for _ in range(repeat):
            t0 = time.time()
            resp = budget.request(url, "GET", headers)
            wall = (time.time() - t0) * 1000
            if resp is None:
                break
            h = resp.headers
            row = {"path": path, "status": getattr(resp, "status", None) or getattr(resp, "code", 0), "wall_ms": round(wall), "queries": _num(h, "X-Prodready-Queries"), "repeat": _num(h, "X-Prodready-Max-Repeat"),
                   "sample": (h.get("X-Prodready-Repeat-Sample") or "")[:160], "memory_mb": (_num(h, "X-Prodready-Memory-Kb") or 0) / 1024 or None, "app_ms": _num(h, "X-Prodready-Time-Ms")}
            saw_headers = saw_headers or row["queries"] is not None
            if best is None or (row["queries"] or 0) > (best["queries"] or 0) or row["wall_ms"] > best["wall_ms"]:
                best = row
        if best:
            rows.append(best)
    env.inventory["profile"] = rows
    if rows and not saw_headers:
        env.warn("No profiler headers came back, so only wall-clock time was measured. Install assets/laravel/ProdreadyProfile.php, set PRODREADY_PROFILE=true and send PRODREADY_PROFILE_KEY.")
    for r in rows:
        if r["status"] and r["status"] >= 400:
            env.warn("%s answered %s and was not profiled" % (r["path"], r["status"]))
            continue
        sub = {"kind": "page", "name": r["path"]}
        if r["queries"] is not None and r["queries"] > limits["queries"]:
            env.add(Finding("PERF-013", "`%s` runs %d database queries to build one page (limit %d). Each is a round trip to the database." % (r["path"], r["queries"], limits["queries"]), subject=sub, confidence="confirmed",
                            detail="Measured with the profiler middleware.", fix_hint="Eager load relations with `with()`, replace loops of queries with `whereIn` or joins, and cache what does not change."))
        if r["repeat"] is not None and r["repeat"] >= limits["repeat"]:
            env.add(Finding("PERF-014", "`%s` runs the same query %d times while building one page. That is an N+1: the work grows with the number of rows. Repeated query: %s" % (r["path"], r["repeat"], r["sample"] or "(shape not reported)"), subject=sub, confidence="confirmed",
                            detail="Measured with the profiler middleware.", fix_hint="Load the relation once with `with('relation')` (or `loadMissing`) before the loop or in the view's query."))
        slow = r["wall_ms"] > limits["ms"] or (r["app_ms"] is not None and r["app_ms"] > limits["ms"])
        heavy = r["memory_mb"] is not None and r["memory_mb"] > limits["memory"]
        if slow or heavy:
            env.add(Finding("PERF-015", "`%s` took %d ms%s. Pages over about %d ms feel slow and heavy ones exhaust PHP workers under load." % (r["path"], r["app_ms"] or r["wall_ms"], " and %d MB of memory" % r["memory_mb"] if r["memory_mb"] else "", limits["ms"]),
                            subject=sub, confidence="confirmed" if saw_headers else "likely", detail="Slowest of %d request(s)." % repeat, fix_hint="Paginate, select fewer columns, cache, and move heavy work to a queue."))
    return env


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="profile_runtime.py", description=(__doc__ or "").split("\n\n")[0])
    p.add_argument("--base-url", required=True)
    p.add_argument("--paths", help="comma-separated paths such as /,/invoices")
    p.add_argument("--app-root", help="read GET routes without parameters from this Laravel app")
    p.add_argument("--allow-network", action="store_true")
    p.add_argument("--i-own-this", action="store_true")
    p.add_argument("--repeat", type=int, default=3)
    p.add_argument("--delay", type=float, default=None)
    p.add_argument("--max-queries", type=int, default=50)
    p.add_argument("--max-repeat", type=int, default=8)
    p.add_argument("--max-ms", type=int, default=1500)
    p.add_argument("--max-memory-mb", type=int, default=128)
    p.add_argument("--out")
    p.add_argument("--version", action="version", version="prodready %s" % findings.__version__)
    args = p.parse_args(argv)
    host = urllib.parse.urlparse(args.base_url).hostname or ""
    local = host in LOCAL or host.endswith(".localhost") or host.endswith(".test")
    if not args.i_own_this or (not local and not args.allow_network):
        sys.stderr.write("prodready: profile_runtime.py sends requests to your app. Pass --i-own-this, and --allow-network too unless the host is localhost.\n")
        return findings.EXIT_USAGE
    paths = [x.strip() for x in (args.paths or "").split(",") if x.strip()]
    if args.app_root:
        proj = walker.Project(os.path.abspath(args.app_root))
        for r in phpscan.route_inventory(proj):
            if r["method"] == "GET" and "{" not in r["uri"] and r["uri"] not in paths:
                paths.append(r["uri"])
    if not paths:
        sys.stderr.write("prodready: give --paths or --app-root\n")
        return findings.EXIT_USAGE
    budget = probe_live.Budget(limit=60, delay=args.delay if args.delay is not None else (0.1 if local else 1.0))
    env = profile(args.base_url, paths[:20], budget, max(1, args.repeat), {"queries": args.max_queries, "repeat": args.max_repeat, "ms": args.max_ms, "memory": args.max_memory_mb},
                  os.environ.get("PRODREADY_TOKEN", ""), os.environ.get("PRODREADY_PROFILE_KEY", ""))
    findings.emit(env.to_dict(), args.out)
    return findings.EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
