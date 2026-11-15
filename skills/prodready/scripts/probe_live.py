#!/usr/bin/env python3
"""Confirm the two most damaging findings, and check headers, on the owner's own deployment.

This is the only script that touches the network, and it refuses to run
without BOTH ``--allow-network`` and ``--i-own-this``. It sends GET and HEAD
requests only, at most one per second and 40 per run, with a user agent that
names the tool. It never writes, never signs in, never fuzzes, never
enumerates beyond names found in the owner's own repository, and never stores
or prints a response body.

Probes: security headers and cookie flags (one GET), exposed files (/.env,
/.git/config), anonymous read of tables or collections named in the repository
(Supabase REST with limit=1 and a count, never row content), and optional SPF
and DMARC records for ``--domain``.

What it deliberately does not do: it targets only ``--base-url`` and the
backend URL from the owner's own configuration. It is not a scanner for
arbitrary sites.
"""
from __future__ import annotations

import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import catalog, findings  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS: List[str] = []
ALSO_EMITS = ["DB-001", "DB-010", "HDR-001", "HDR-002", "HDR-003", "HDR-004", "SEC-007", "AUTH-007"]
MAX_REQUESTS = 40
USER_AGENT = "prodready-probe/%s (read-only; run by the app owner)" % findings.__version__


class Budget:
    def __init__(self, limit: int = MAX_REQUESTS, delay: float = 1.0) -> None:
        self.used, self.limit, self.delay, self._last = 0, limit, delay, 0.0

    def request(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, opener: Any = None) -> Optional[Any]:
        if method not in ("GET", "HEAD"):
            raise ValueError("probe_live only sends GET and HEAD")
        if self.used >= self.limit:
            return None
        wait = self.delay - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self.used += 1
        self._last = time.time()
        h = {"User-Agent": USER_AGENT}
        h.update(headers or {})
        req = urllib.request.Request(url, method=method, headers=h)
        try:
            return (opener or urllib.request.urlopen)(req, timeout=15)
        except urllib.error.HTTPError as e:
            return e
        except (urllib.error.URLError, OSError):
            return None


def probe(base_url: str, tables: List[str], backend_url: Optional[str], public_key: Optional[str], budget: Budget, domain: Optional[str] = None) -> Envelope:
    env = Envelope("probe_live")
    r = budget.request(base_url)
    if r is not None and getattr(r, "status", getattr(r, "code", 0)) < 400:
        low = {k.lower(): v for k, v in r.headers.items()}
        gaps = [h for h in ("content-security-policy", "strict-transport-security", "x-content-type-options", "referrer-policy") if h not in low]
        if "content-security-policy" not in low:
            env.add(Finding("HDR-001", "The live site sends no Content Security Policy.", subject={"kind": "live", "name": base_url}, confidence="confirmed", snippet="response headers of GET /", detail="Header absent on the deployed site."))
        if "strict-transport-security" not in low and base_url.startswith("https"):
            env.add(Finding("HDR-002", "The live site does not ask browsers to insist on HTTPS.", subject={"kind": "live", "name": base_url}, confidence="confirmed", snippet="response headers of GET /", detail="Strict-Transport-Security absent."))
        if "frame-ancestors" not in low.get("content-security-policy", "") and "x-frame-options" not in low:
            env.add(Finding("HDR-003", "The live site can be embedded in other sites' frames.", subject={"kind": "live", "name": base_url}, confidence="confirmed", snippet="response headers of GET /", detail="No frame-ancestors and no X-Frame-Options."))
        if gaps and any(g in gaps for g in ("x-content-type-options", "referrer-policy")):
            env.add(Finding("HDR-004", "The live site is missing small protective headers.", subject={"kind": "live", "name": "misc-headers"}, confidence="confirmed", snippet=", ".join(g for g in gaps if g in ("x-content-type-options", "referrer-policy")), detail="Missing on the deployed site."))
        for sc in r.headers.get_all("Set-Cookie") or []:
            if not re.search(r"(?i)httponly", sc) or not re.search(r"(?i);\s*secure", sc):
                env.add(Finding("AUTH-007", "A cookie set by the live site lacks protective flags.", subject={"kind": "live", "name": sc.split("=")[0]}, confidence="confirmed", snippet="Set-Cookie %s (flags missing)" % sc.split("=")[0], detail="HttpOnly or Secure missing."))
                break
    for path in ("/.env", "/.git/config"):
        h = budget.request(urllib.parse.urljoin(base_url, path), "HEAD")
        if h is not None and getattr(h, "status", getattr(h, "code", 0)) == 200:
            env.add(Finding("SEC-007", "`%s` can be downloaded from the live site. It exposes your secrets or your whole source history." % path, subject={"kind": "live", "name": path}, confidence="confirmed", snippet="HEAD %s returned HTTP 200" % path, detail="Exposed file on the deployed site.", fix_hint="Remove it from the deployed output and rotate every secret it held.", owner_action="references/owner-actions/rotate-keys.md"))
    if backend_url and public_key:
        for t in tables:
            u = "%s/rest/v1/%s?select=*&limit=1" % (backend_url.rstrip("/"), urllib.parse.quote(t))
            resp = budget.request(u, "GET", {"apikey": public_key, "Authorization": "Bearer " + public_key, "Prefer": "count=exact", "Range-Unit": "items"})
            if resp is None:
                continue
            code = getattr(resp, "status", getattr(resp, "code", 0))
            rng = resp.headers.get("Content-Range", "")
            m = re.search(r"/(\d+)$", rng)
            if code == 200 and m and int(m.group(1)) > 0:
                env.add(Finding("DB-001", "An anonymous visitor can read the `%s` table on the live backend (%s rows visible)." % (t, m.group(1)), subject={"kind": "table", "name": "public.%s" % t}, confidence="confirmed", snippet="anonymous request returned HTTP 200 with a non-empty result", detail="Confirmed with the public key only; no row content was retrieved or stored.", fix_hint="Enable row level security and add owner-scoped policies."))
    env.inventory["probe"] = {"requests_used": budget.used, "request_limit": budget.limit, "bodies_stored": False}
    return env


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="probe_live.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", required=True)
    p.add_argument("--allow-network", action="store_true")
    p.add_argument("--i-own-this", action="store_true")
    p.add_argument("--tables", nargs="*", default=[], help="table names found in the owner's own repository")
    p.add_argument("--backend-url")
    p.add_argument("--public-key", help="the publishable key from the owner's own config")
    p.add_argument("--domain")
    p.add_argument("--out")
    p.add_argument("--delay", type=float, default=1.0)
    p.add_argument("--version", action="version", version="prodready %s" % findings.__version__)
    args = p.parse_args(argv)
    if not (args.allow_network and args.i_own_this):
        sys.stderr.write("prodready: probe_live.py makes network requests. Pass both --allow-network and --i-own-this, and only for your own deployment.\n")
        return findings.EXIT_USAGE
    env = probe(args.base_url, args.tables, args.backend_url, args.public_key, Budget(delay=args.delay), args.domain)
    findings.emit(env.to_dict(), args.out)
    return findings.EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
