#!/usr/bin/env python3
"""Check the live site, read-only: certificate, HTTPS redirect, exposed files and a health report.

Run it against your own deployed site. Detects: a certificate that is invalid or
close to expiry (PROD-001), plain HTTP that is not redirected or old TLS versions
that are accepted (PROD-002), sensitive files and debug tools reachable from the
internet such as `/.env`, `/storage/logs/laravel.log`, `/telescope` (PROD-003), and
a stale scheduler, queue or backup in the health report served by
``assets/laravel/prodready-health.php`` (PROD-004).

Safety: refuses to run without both ``--allow-network`` and ``--i-own-this``.
GET and HEAD only, paced, at most 40 requests, bodies are inspected in memory for a
signature and never stored or printed. The health token comes from the environment
variable ``PRODREADY_HEALTH_TOKEN``. No sign-in, no writes, no guessing beyond the
fixed path list below.

What it deliberately does not do: it cannot see inside the server. Services it
cannot reach through the health report (a database dump, disk space) stay owner
questions.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import probe_live  # noqa: E402
from lib import catalog, findings  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("verify_production")
ALSO_EMITS: List[str] = []

SENSITIVE: List[Tuple[str, "re.Pattern[str]", str]] = [
    ("/.env", re.compile(r"^[A-Z][A-Z0-9_]{2,}=", re.M), "an environment file with your secrets"),
    ("/.git/config", re.compile(r"\[core\]"), "your git configuration"),
    ("/storage/logs/laravel.log", re.compile(r"(?:local|production|staging)\.(?:ERROR|CRITICAL|INFO)|Stack trace"), "the application log"),
    ("/telescope", re.compile(r"Telescope", re.I), "the Laravel Telescope dashboard"),
    ("/horizon", re.compile(r"Horizon", re.I), "the Laravel Horizon dashboard"),
    ("/_ignition/health-check", re.compile(r"can_execute_commands"), "the Ignition debug endpoint"),
    ("/phpinfo.php", re.compile(r"PHP Version", re.I), "phpinfo()"),
    ("/vendor/composer/installed.json", re.compile(r'"packages"'), "your installed packages"),
]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: Any, **k: Any) -> None:  # type: ignore[override]
        return None


def check_certificate(host: str, port: int, env: Envelope) -> None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
            cert = s.getpeercert()
            tls = s.version()
    except ssl.SSLCertVerificationError as exc:
        env.add(Finding("PROD-001", "The certificate for `%s` is not accepted by a normal browser: %s." % (host, exc.verify_message), subject={"kind": "host", "name": host}, confidence="confirmed",
                        fix_hint="Install a certificate for this exact name from a trusted authority (Let's Encrypt is free) and include the intermediate chain.", owner_action="Renew or replace the certificate."))
        return
    except (OSError, ssl.SSLError) as exc:
        env.warn("could not open a TLS connection to %s:%d (%s)" % (host, port, type(exc).__name__))
        return
    not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
    days = (not_after - datetime.datetime.now(datetime.timezone.utc)).days
    env.inventory["tls"] = {"host": host, "protocol": tls, "days_left": days}
    if days < 30:
        env.add(Finding("PROD-001", "The certificate for `%s` expires in %d days. When it does, browsers show a full-page warning and nobody can sign in or pay." % (host, days), subject={"kind": "host", "name": host},
                        severity="critical" if days < 7 else "high", confidence="confirmed", fix_hint="Renew it and switch on automatic renewal (certbot timer, or your host's managed certificates).", owner_action="Renew the certificate."))
    for name, ver in (("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)), ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None))):
        if ver is None:
            continue
        try:
            old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            old.check_hostname = False
            old.verify_mode = ssl.CERT_NONE
            old.minimum_version = ver
            old.maximum_version = ver
            with socket.create_connection((host, port), timeout=8) as raw, old.wrap_socket(raw, server_hostname=host):
                env.add(Finding("PROD-002", "The server still accepts %s, a retired protocol that payment providers and security scans reject." % name, subject={"kind": "tls", "name": name}, confidence="confirmed",
                                fix_hint="Allow only TLS 1.2 and 1.3 (`ssl_protocols TLSv1.2 TLSv1.3;` in nginx)."))
        except (OSError, ssl.SSLError, ValueError):
            pass


def check_redirect(host: str, budget: probe_live.Budget, env: Envelope) -> None:
    opener = urllib.request.build_opener(NoRedirect)
    resp = budget.request("http://%s/" % host, "GET", opener=opener.open)
    if resp is None:
        env.warn("plain HTTP on port 80 did not answer; if it is closed on purpose that is fine")
        return
    code = getattr(resp, "status", None) or getattr(resp, "code", 0)
    loc = resp.headers.get("Location", "")
    if not (code in (301, 302, 307, 308) and loc.startswith("https://")):
        env.add(Finding("PROD-002", "`http://%s/` answers %s and does not redirect to HTTPS. Anyone who types the address without https sends their password and session cookie in plain text." % (host, code), subject={"kind": "redirect", "name": host},
                        confidence="confirmed", fix_hint="Redirect all port 80 traffic: `return 301 https://$host$request_uri;` (nginx) and enable HSTS."))


def check_sensitive(base: str, budget: probe_live.Budget, env: Envelope) -> None:
    for path, sig, what in SENSITIVE:
        resp = budget.request(base + path, "GET")
        if resp is None:
            continue
        code = getattr(resp, "status", None) or getattr(resp, "code", 0)
        if code != 200:
            continue
        try:
            body = resp.read(4096).decode("utf-8", "replace")
        except Exception:
            body = ""
        if sig.search(body):
            env.add(Finding("PROD-003", "`%s` is reachable from the internet and returns %s." % (path, what), subject={"kind": "path", "name": path}, confidence="confirmed",
                            detail="Checked with one GET request; the content was inspected in memory and not stored.", fix_hint="Block it in the web server, point the web root at `public`, remove debug tools from production, and rotate anything that was exposed.",
                            owner_action="Rotate every secret that file or log contained."))


def check_health(url: str, token: str, budget: probe_live.Budget, env: Envelope) -> None:
    resp = budget.request(url, "GET", {"Authorization": "Bearer " + token, "Accept": "application/json"})
    code = getattr(resp, "status", None) or getattr(resp, "code", 0) if resp is not None else 0
    if resp is None or code != 200:
        env.add(Finding("PROD-004", "The health report at the given address did not answer with 200 (got %s), so scheduler, queue and backup cannot be verified." % (code or "no answer"), subject={"kind": "health", "name": "report"}, confidence="likely", severity="medium",
                        fix_hint="Install assets/laravel/prodready-health.php and check the token."))
        return
    try:
        data = json.loads(resp.read(65536).decode("utf-8"))
    except ValueError:
        env.warn("health report is not valid JSON")
        return
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    env.inventory["health"] = {k: data.get(k) for k in ("scheduler_last_run", "queue_size", "queue_oldest_job_age_s", "last_backup_at", "database_ok")}
    problems = []
    if data.get("scheduler_last_run") is None or now - float(data["scheduler_last_run"]) > 600:
        problems.append(("scheduler", "The scheduler has not run in the last 10 minutes, so scheduled tasks are not running."))
    if (data.get("queue_oldest_job_age_s") or 0) > 900:
        problems.append(("queue", "The oldest queued job has waited more than 15 minutes, so the queue worker is stopped or overloaded."))
    if data.get("last_backup_at") is None or now - float(data["last_backup_at"]) > 36 * 3600:
        problems.append(("backup", "No database backup in the last 36 hours."))
    if data.get("database_ok") is False:
        problems.append(("database", "The app could not reach its database."))
    for kind, msg in problems:
        env.add(Finding("PROD-004", msg, subject={"kind": "health", "name": kind}, confidence="confirmed", severity="high" if kind in ("backup", "database") else "medium",
                        fix_hint="Restart the process, find why it stopped, and alert on this report.", owner_action="Check the %s on the server." % kind))


def verify(url: str, budget: probe_live.Budget, health_url: Optional[str], token: str) -> Envelope:
    env = Envelope("verify_production")
    parsed = urllib.parse.urlparse(url if "//" in url else "https://" + url)
    host, port = parsed.hostname or "", parsed.port or 443
    base = "%s://%s" % (parsed.scheme or "https", parsed.netloc)
    if parsed.scheme == "https" or not parsed.scheme:
        check_certificate(host, port, env)
        check_redirect(host, budget, env)
    check_sensitive(base, budget, env)
    if health_url:
        check_health(health_url, token, budget, env)
    else:
        env.inventory["health"] = {"note": "no --health-url given; scheduler, queue and backup were not verified"}
    return env


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="verify_production.py", description=(__doc__ or "").split("\n\n")[0])
    p.add_argument("--url", required=True, help="your site, for example https://app.example.com")
    p.add_argument("--health-url", help="the address served by prodready-health.php")
    p.add_argument("--allow-network", action="store_true")
    p.add_argument("--i-own-this", action="store_true")
    p.add_argument("--delay", type=float, default=1.0)
    p.add_argument("--out")
    p.add_argument("--version", action="version", version="prodready %s" % findings.__version__)
    args = p.parse_args(argv)
    if not (args.allow_network and args.i_own_this):
        sys.stderr.write("prodready: verify_production.py makes network requests. Pass both --allow-network and --i-own-this, and only for your own site.\n")
        return findings.EXIT_USAGE
    env = verify(args.url, probe_live.Budget(delay=args.delay), args.health_url, os.environ.get("PRODREADY_HEALTH_TOKEN", ""))
    findings.emit(env.to_dict(), args.out)
    return findings.EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
