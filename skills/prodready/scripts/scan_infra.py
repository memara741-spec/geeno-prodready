#!/usr/bin/env python3
"""Production infrastructure audit: web server, TLS, permissions, backups, schedules and containers.

Reads the files that describe how the app runs (nginx and Apache configs,
Dockerfiles, compose files, shell scripts, CI workflows, supervisor and cron
files, Laravel's schedule) and checks them. Detects: a web server that serves the
project root or dotfiles (INFRA-001), old TLS versions, no HTTPS redirect or
disabled certificate checks (INFRA-002), world-writable permissions (INFRA-003),
a scheduler or queue worker that nothing starts (INFRA-004), scheduled tasks that
can overlap or fail silently (INFRA-005), no database backup job (INFRA-006),
deploys without production optimisation (INFRA-007), database ports open to the
internet and default passwords (INFRA-008) and logs that are never rotated
(INFRA-009).

What it deliberately does not do: it cannot see your server. Settings made in a
hosting dashboard (Forge, Vercel, a managed database) are not in the repository,
so absence findings are marked possible and come with an owner question.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import catalog, findings, phpscan, walker  # noqa: E402
from lib.findings import Envelope, Finding  # noqa: E402

IMPLEMENTS = catalog.by_scanner("scan_infra")
ALSO_EMITS: List[str] = []

DB_PORTS = {"3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis", "27017": "MongoDB", "9200": "Elasticsearch", "11211": "Memcached", "1433": "SQL Server", "5984": "CouchDB"}
WEAK_PW = {"root", "password", "secret", "admin", "123456", "changeme", "postgres", "mysql", "pass", "test", "laravel", "toor", "12345678", "qwerty", "example"}


def _infra_files(project: walker.Project) -> List[walker.SourceFile]:
    out = []
    for sf in project.files:
        low = sf.rel.lower()
        name = sf.name.lower()
        if sf.ext in (".conf", ".sh", ".yml", ".yaml", ".cron", ".service", ".ini", ".vhost") or name.startswith(("dockerfile", "docker-compose", "compose.", "procfile", "makefile", "crontab", ".htaccess", "nginx", "supervisor")) or "/nginx/" in low or "/apache" in low or "/docker/" in low or "/deploy" in low:
            out.append(sf)
    return out


def scan(root: str, stack: Optional[Dict[str, Any]], project: walker.Project) -> Envelope:
    env = Envelope("scan_infra", stack)
    laravel = phpscan.is_laravel(project)
    files = _infra_files(project)
    texts = {sf.rel: project.text(sf) for sf in files}

    def line_of(text: str, idx: int) -> int:
        return text.count("\n", 0, idx) + 1

    def add(check: str, rel: str, text: str, idx: int, msg: str, conf: str = "likely", fix: str = "", sev: Optional[str] = None, owner: Optional[str] = None, subject: Optional[Dict[str, str]] = None) -> None:
        ln = line_of(text, idx)
        env.add(Finding(check, msg, file=rel, line=ln, snippet=text.splitlines()[ln - 1].strip() if text else "", confidence=conf, fix_hint=fix, severity=sev, owner_action=owner, subject=subject))

    has_443 = any(re.search(r"listen\s+(?:\[::\]:)?443|ssl_certificate\b", t) for r, t in texts.items() if "nginx" in r.lower() or r.endswith(".conf"))
    for rel, text in texts.items():
        low = rel.lower()
        is_nginx = bool(re.search(r"\bserver\s*\{|\blisten\s+\d+|\blocation\s+", text)) and (low.endswith(".conf") or "nginx" in low)
        is_apache = bool(re.search(r"<VirtualHost|DocumentRoot|Options\s+[+-]?(?:Indexes|FollowSymLinks)", text, re.I)) and (low.endswith((".conf", ".vhost")) or ".htaccess" in low or "apache" in low)
        is_docker = os.path.basename(low).startswith("dockerfile") or low.endswith(".dockerfile")
        # INFRA-001
        if is_nginx:
            for m in re.finditer(r"^\s*root\s+([^;]+);", text, re.M):
                path = m.group(1).strip().strip("'\"").rstrip("/")
                if laravel and not path.endswith("/public") and not re.search(r"/(?:dist|build|out|html/public)$", path):
                    add("INFRA-001", rel, text, m.start(), "The web server's `root` is `%s`, the project folder itself, not Laravel's `public` folder. Visitors can then request `/.env`, `/storage/logs/laravel.log` and your source files." % path, "confirmed",
                        "Point `root` at `.../public` and keep `location ~ /\\.(?!well-known) { deny all; }`.")
            if re.search(r"^\s*autoindex\s+on\s*;", text, re.M):
                m = re.search(r"^\s*autoindex\s+on\s*;", text, re.M)
                add("INFRA-001", rel, text, m.start(), "Directory listing is on (`autoindex on`), so visitors can browse folders and download files.", "confirmed", "Remove `autoindex on` or limit it to a download folder you meant to share.")
            if laravel and re.search(r"\bserver\s*\{", text) and "root" in text and not re.search(r"location\s+~\s*/\\\.", text) and not re.search(r"/public\s*;", text):
                pass
        if is_apache:
            m = re.search(r"Options\s+[^\n]*\+?Indexes", text, re.I)
            if m and not re.search(r"-Indexes", m.group(0)):
                add("INFRA-001", rel, text, m.start(), "Directory listing is on (`Options Indexes`), so visitors can browse folders and download files.", "confirmed", "Use `Options -Indexes`.")
            m = re.search(r"DocumentRoot\s+\"?([^\s\"]+)", text, re.I)
            if m and laravel and not m.group(1).rstrip("/").endswith("/public"):
                add("INFRA-001", rel, text, m.start(), "Apache's `DocumentRoot` is `%s`, not Laravel's `public` folder. Visitors can request `/.env` and other project files." % m.group(1), "confirmed", "Set `DocumentRoot` to the `public` folder.")
        if is_docker and laravel and re.search(r"APACHE_DOCUMENT_ROOT|DocumentRoot", text) is None and re.search(r"FROM\s+php:[\w.\-]*apache", text) and not re.search(r"public", text):
            m = re.search(r"FROM\s+php:[\w.\-]*apache", text)
            add("INFRA-001", rel, text, m.start() if m else 0, "The Apache PHP image serves `/var/www/html`, which is the whole project, unless you point `APACHE_DOCUMENT_ROOT` at `public`. Nothing in this Dockerfile does.", "likely", "Set `ENV APACHE_DOCUMENT_ROOT /var/www/html/public` and update the vhost with `sed`.")
        # INFRA-002
        for m in re.finditer(r"^\s*ssl_protocols\s+([^;]+);", text, re.M):
            old = [p for p in m.group(1).split() if p in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")]
            if old:
                add("INFRA-002", rel, text, m.start(), "The server still accepts %s, which are broken or retired and fail security scans and payment-provider checks." % ", ".join(old), "confirmed", "Use `ssl_protocols TLSv1.2 TLSv1.3;`.")
        if is_nginx and re.search(r"listen\s+80\b", text) and not has_443 and not re.search(r"return\s+30[18]\s+https|X-Forwarded-Proto|rewrite\s+\^.*https", text):
            m = re.search(r"listen\s+80\b", text)
            add("INFRA-002", rel, text, m.start() if m else 0, "The server listens on port 80 only: no HTTPS and no redirect to it. Passwords and session cookies cross the internet in plain text, unless a load balancer in front handles HTTPS.", "possible", "Terminate TLS here (Let's Encrypt with certbot) or confirm the load balancer does, then redirect port 80 to HTTPS.", sev="medium",
                owner="Confirm where HTTPS is terminated (load balancer, CDN or this server).")
        for m in re.finditer(r"\bcurl\b[^\n|;]*\s(?:-k\b|--insecure\b)|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|wget[^\n]*--no-check-certificate|GIT_SSL_NO_VERIFY", text):
            add("INFRA-002", rel, text, m.start(), "A script turns off certificate checking, so anyone on the network path can impersonate the server it talks to.", "confirmed", "Remove `-k` / `--insecure` and install the right CA certificate.")
        # INFRA-003
        for m in re.finditer(r"\bchmod\s+(?:-[a-zA-Z]+\s+)*(?:0?777|a\+rwx|ugo\+rwx|o\+w|a\+w)\b", text):
            add("INFRA-003", rel, text, m.start(), "A build or deploy step makes files world-writable (`%s`). Any process or user on the machine, including a compromised web request, can change your code." % m.group(0).strip(), "confirmed",
                "Use `chown -R www-data:www-data storage bootstrap/cache && chmod -R ug+rwX storage bootstrap/cache` and leave the rest read-only.")
    # code that disables certificate checks
    for sf in project.files:
        if sf.ext not in (".php", ".js", ".ts", ".mjs", ".py") or walker.TEST_PATH_RE.search(sf.rel):
            continue
        text = project.text(sf)
        for m in re.finditer(r"CURLOPT_SSL_VERIFY(?:PEER|HOST)['\"]?\s*(?:=>|,)\s*(?:false|0)\b|withoutVerifying\s*\(|['\"]verify['\"]\s*=>\s*false|rejectUnauthorized\s*:\s*false|verify\s*=\s*False|ssl\s*:\s*\{\s*rejectUnauthorized\s*:\s*false", text):
            add("INFRA-002", sf.rel, text, m.start(), "Certificate checking is turned off for an outgoing connection. An attacker on the network can read or change what this app sends and receives, including API keys.", "confirmed", "Remove the override and fix the certificate chain instead.")
            break

    # INFRA-008 compose
    for rel, text in texts.items():
        if not re.search(r"(^|/)(docker-)?compose[\w.\-]*\.ya?ml$", rel.lower()):
            continue
        for m in re.finditer(r"^\s*-\s*[\"']?(?:(\d+\.\d+\.\d+\.\d+|\[[:\w]+\]):)?(\d+):(%s)(?:/\w+)?[\"']?\s*$" % "|".join(DB_PORTS), text, re.M):
            ip = m.group(1)
            if ip and ip not in ("0.0.0.0",) and (ip.startswith("127.") or ip in ("[::1]",)):
                continue
            add("INFRA-008", rel, text, m.start(), "The %s port %s is published on every network interface. If this file runs on a server, anyone on the internet can reach your %s directly and try passwords." % (DB_PORTS[m.group(3)], m.group(2), DB_PORTS[m.group(3)]),
                "likely", "Remove the `ports:` mapping (other containers reach it by service name) or bind it to `127.0.0.1:%s:%s`." % (m.group(2), m.group(3)), owner="Check the server firewall and that this service is not exposed.")
        for m in re.finditer(r"^\s*(?:-\s*)?(MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|REDIS_PASSWORD|DB_PASSWORD|MARIADB_ROOT_PASSWORD)\s*[:=]\s*[\"']?([^\s\"'#]*)", text, re.M):
            val = m.group(2)
            if val.lower() in WEAK_PW and not val.startswith("$"):
                add("INFRA-008", rel, text, m.start(), "`%s` is set to a common default. Anyone who can reach the database can sign in with it." % m.group(1), "confirmed", "Read it from an environment variable or secret and use a long random value.",
                    owner="Change the real database password if this value was ever used on a server.", subject={"kind": "variable", "name": m.group(1)})
        for m in re.finditer(r"(?:MYSQL_ALLOW_EMPTY_PASSWORD|ALLOW_EMPTY_PASSWORD|POSTGRES_HOST_AUTH_METHOD)\s*[:=]\s*[\"']?(?:yes|true|1|trust)", text, re.I):
            add("INFRA-008", rel, text, m.start(), "The database is configured to accept connections without a password.", "confirmed", "Remove the setting and set a strong password.", owner="Check the server firewall and database users.")

    # Laravel-specific process, schedule, backup, deploy, log checks
    if laravel:
        pfs = [p for p in phpscan.php_files(project) if not walker.TEST_PATH_RE.search(p.rel)]
        infra_text = "\n".join(texts.values()) + "\n" + "\n".join(project.text(sf) for sf in project.files if sf.ext in (".yml", ".yaml", ".sh", ".conf", ".ini") or sf.name in ("Procfile", "crontab", "Makefile", "Envoy.blade.php", "deploy.php"))
        schedule_src = [p for p in pfs if p.rel in ("routes/console.php", "app/Console/Kernel.php") or re.search(r"Schedule::|\$schedule->", p.code)]
        uses_schedule = any(re.search(r"Schedule::\w+\(|\$schedule->\w+\(", p.code) for p in schedule_src)
        uses_queue = any(re.search(r"\bShouldQueue\b|\bdispatch\s*\(|::dispatch\s*\(|Queue::|->queue\s*\(", p.code) for p in pfs)
        queue_sync = any(re.search(r"^QUEUE_CONNECTION\s*=\s*sync", project.text(sf), re.M) for sf in project.files if sf.name.startswith(".env") and not walker.is_env_example(sf.rel))
        has_runner = bool(re.search(r"schedule:run|schedule:work|artisan\s+schedule|supercronic|php-fpm.*cron", infra_text))
        has_worker = bool(re.search(r"queue:work|queue:listen|horizon|artisan\s+queue", infra_text))
        env.inventory["processes"] = {"scheduler_defined": uses_schedule, "scheduler_runner_found": has_runner, "queue_used": uses_queue, "queue_worker_found": has_worker}
        anchor = next((p for p in schedule_src if re.search(r"Schedule::|\$schedule->", p.code)), None)
        if uses_schedule and not has_runner and anchor:
            m = re.search(r"Schedule::\w+\(|\$schedule->\w+\(", anchor.code)
            add("INFRA-004", anchor.rel, anchor.raw, m.start() if m else 0, "The app defines scheduled tasks, but nothing in the repository runs Laravel's scheduler (`php artisan schedule:run` every minute, or `schedule:work`). If the server has no cron entry, none of these tasks ever run.", "possible",
                "Add a cron line `* * * * * cd /path && php artisan schedule:run >> /dev/null 2>&1`, or a `schedule:work` process in your container or supervisor config.", sev="medium", owner="Confirm how the scheduler is started on the production server.")
        if uses_queue and not queue_sync and not has_worker:
            first = next((p for p in pfs if re.search(r"\bShouldQueue\b|::dispatch\s*\(|\bdispatch\s*\(", p.code)), None)
            if first:
                m = re.search(r"\bShouldQueue\b|::dispatch\s*\(|\bdispatch\s*\(", first.code)
                add("INFRA-004", first.rel, first.raw, m.start() if m else 0, "The app queues jobs, but nothing in the repository starts a queue worker. Queued emails and jobs pile up unprocessed unless the server runs `php artisan queue:work`.", "possible",
                    "Run `php artisan queue:work --tries=3` under Supervisor or a container service and restart it on every deploy (`queue:restart`).", sev="medium", owner="Confirm a queue worker runs on production and restarts after a crash.")
        # INFRA-005 schedule hygiene
        any_failure_hook = False
        for p in schedule_src:
            for m in re.finditer(r"(?:Schedule::|\$schedule->)(\w+)\s*\(([^;]*);", p.code):
                chain = m.group(0)
                if re.search(r"onFailure|emailOutputOnFailure|pingOnFailure|thenPing|sendOutputTo|appendOutputTo", chain):
                    any_failure_hook = True
                if re.search(r"everyMinute|everyTwoMinutes|everyFiveMinutes|everyTenMinutes|everyFifteenMinutes|everyThirtyMinutes|cron\(\s*['\"]\*", chain) and not re.search(r"withoutOverlapping", chain):
                    add("INFRA-005", p.rel, p.raw, m.start(), "This task runs often and has no `withoutOverlapping()`. If one run takes longer than the interval, a second copy starts on top of it, doubling work or corrupting data.", "likely", "Add `->withoutOverlapping()` and `->onOneServer()` if you run more than one server.")
        if uses_schedule and not any_failure_hook:
            anchor2 = schedule_src[0]
            m = re.search(r"Schedule::\w+\(|\$schedule->\w+\(", anchor2.code)
            add("INFRA-005", anchor2.rel, anchor2.raw, m.start() if m else 0, "None of your scheduled tasks reports a failure. If one stops working, nobody finds out until the data is wrong.", "possible",
                "Add `->onFailure(...)`, `->emailOutputOnFailure()` or a heartbeat (`->pingOnSuccess(url)`) to a monitor such as Healthchecks.io.", sev="low", subject={"kind": "project", "name": "schedule-failure-alerts"})
        # INFRA-006 backups
        comp = phpscan.composer(project)
        has_backup_pkg = any("backup" in k for k in list(comp["require"]) + list(comp["dev"]))
        scheduled_backup = bool(re.search(r"backup:run|backup:clean|mysqldump|pg_dump|snapshot", "\n".join(p.code for p in schedule_src)))
        infra_backup = bool(re.search(r"mysqldump|pg_dump|backup:run|rds[\w-]*snapshot|pgbackrest|restic|borg|wal-g|backup", infra_text, re.I))
        has_db = project.exists("database/migrations") or any("/migrations/" in "/" + p for p in project.all_paths()) or any(re.search(r"image:\s*[\"']?(?:mysql|mariadb|postgres|mongo)", t) for t in texts.values())
        if has_db and not (scheduled_backup or infra_backup):
            anchor3 = next((sf for sf in files if sf.name.lower().startswith(("docker-compose", "compose"))), None)
            rel = anchor3.rel if anchor3 else "composer.json"
            env.add(Finding("INFRA-006", "No database backup is defined anywhere in the repository%s. If the database is lost or damaged, there is nothing to restore." % ("; the backup package is installed but never scheduled" if has_backup_pkg else ""), file=rel, line=1, snippet="",
                            confidence="possible", subject={"kind": "project", "name": "database-backup"}, owner_action="Confirm automated backups are on at your host and that you restored one to a scratch database.",
                            fix_hint="Install `spatie/laravel-backup`, schedule `backup:run` daily and `backup:monitor`, send the files off the server, or enable the managed database's own backups and test a restore."))
        # INFRA-007 deploy optimisation
        for rel, text in texts.items():
            low = rel.lower()
            deploy_like = os.path.basename(low).startswith("dockerfile") or "deploy" in low or low.endswith(".sh") or "release" in low or "production" in low
            if not deploy_like and not (".github/workflows" in low and re.search(r"(?i)deploy|production|release", text)):
                continue
            for m in re.finditer(r"composer\s+install\b([^\n&;]*)", text):
                if "--no-dev" not in m.group(1):
                    add("INFRA-007", rel, text, m.start(), "`composer install` runs without `--no-dev`, so test and debug packages (and their known vulnerabilities) are installed on the production server.", "likely", "Use `composer install --no-dev --optimize-autoloader --no-interaction`.")
                    break
        deploy_files = [r for r in texts if os.path.basename(r.lower()).startswith("dockerfile") or "deploy" in r.lower() or r.lower().endswith(".sh")]
        if deploy_files and not re.search(r"config:cache|artisan\s+optimize|route:cache", "\n".join(texts[r] for r in deploy_files)):
            rel = deploy_files[0]
            add("INFRA-007", rel, texts[rel], 0, "The deploy steps never run `php artisan config:cache`, `route:cache` or `optimize`. Laravel then re-reads every config file and route on every request, which is slow, and `env()` calls behave differently once you do cache.", "possible",
                "Run `php artisan optimize` (or `config:cache route:cache view:cache event:cache`) and `php artisan migrate --force` on every deploy.", sev="low", subject={"kind": "project", "name": "laravel-optimize"})
        # INFRA-009 logs
        for sf in project.files:
            if sf.name.startswith(".env") and not walker.is_env_example(sf.rel) and project.will_be_committed(sf.rel):
                text = project.text(sf)
                m = re.search(r"^(LOG_CHANNEL|LOG_STACK)\s*=\s*single\b", text, re.M)
                if m and re.search(r"^APP_ENV\s*=\s*(production|prod|live)", text, re.M):
                    add("INFRA-009", sf.rel, text, m.start(), "Logs go to a single file that grows for ever. One noisy day or attack can fill the disk and take the whole server down.", "likely", "Use `daily` (`LOG_CHANNEL=daily`, `LOG_DAILY_DAYS=14`) or ship logs to a service, and set up logrotate for other files.", subject={"kind": "env", "name": m.group(1)})
    env.files_scanned, env.files_skipped = project.stats()
    return env


def main(argv: Optional[List[str]] = None) -> int:
    return findings.run_scanner_cli("scan_infra", __doc__ or "", scan, argv)


if __name__ == "__main__":
    raise SystemExit(main())
