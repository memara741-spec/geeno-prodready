"""Report rendering, probe consent, determinism, offline operation and packaging."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
import zipfile

import helpers
from lib import findings

RUN_ALL = os.path.join(helpers.SCRIPTS, "run_all.py")
LOVABLE = helpers.fixture_path("lovable-supabase-vite")


def run_all(*args):
    env = dict(os.environ, PRODREADY_FIXED_TIME="2026-01-01T00:00:00Z")
    return subprocess.run([sys.executable, RUN_ALL, LOVABLE, "--quiet"] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)


class Tools(unittest.TestCase):
    def test_deterministic_output(self):
        a, b = run_all(), run_all()
        self.assertEqual(a.returncode, 0)
        a_doc, b_doc = json.loads(a.stdout), json.loads(b.stdout)
        for d in (a_doc, b_doc):
            d["stats"]["duration_ms"] = 0
            for s in d["scanners"]:
                s.pop("duration_ms", None)
        self.assertEqual(json.dumps(a_doc, sort_keys=True), json.dumps(b_doc, sort_keys=True))

    def test_scanners_work_with_sockets_disabled(self):
        code = (
            "import socket,sys,runpy\n"
            "def deny(*a, **k): raise RuntimeError('network access attempted')\n"
            "socket.socket.connect = deny\nsocket.create_connection = deny\nsocket.getaddrinfo = deny\n"
            "sys.argv = ['run_all.py', %r, '--quiet', '--format', 'summary']\n"
            "runpy.run_path(%r, run_name='__main__')\n" % (LOVABLE, RUN_ALL)
        )
        r = subprocess.run([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(r.returncode, 0, r.stderr.decode()[-300:])

    def test_fail_on(self):
        self.assertEqual(run_all("--fail-on", "critical").returncode, 1)
        clean = subprocess.run([sys.executable, RUN_ALL, helpers.fixture_path("clean-nextjs-supabase"), "--quiet", "--fail-on", "critical", "--format", "summary"], stdout=subprocess.PIPE)
        self.assertEqual(clean.returncode, 0)

    def test_sarif(self):
        sarif = json.loads(run_all("--format", "sarif").stdout)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])

    def test_report_markdown_and_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, "f.json")
            with open(f, "wb") as fh:
                fh.write(run_all().stdout)
            render = os.path.join(helpers.SCRIPTS, "render_report.py")
            md = subprocess.run([sys.executable, render, LOVABLE, "--findings", f], stdout=subprocess.PIPE).stdout.decode()
            order = [md.index(h) for h in ("## Verdict", "## The three things to do first", "## Summary", "## Who can access what", "## Findings", "## Owner actions", "## Appendix")]
            self.assertEqual(order, sorted(order))
            self.assertIn("BLOCKED", md)
            html = subprocess.run([sys.executable, render, LOVABLE, "--findings", f, "--format", "html", "--lang", "ar"], stdout=subprocess.PIPE).stdout.decode()
            self.assertIn('dir="rtl"', html)
            self.assertNotIn("<script", html.lower().split("<body>")[0])
            import re
            self.assertFalse(re.search(r'(?:src|href)="https?://', html), "external request in report")

    def test_report_escapes_hostile_input(self):
        doc = findings.Envelope("t")
        doc.add(findings.Finding("DB-002", "<script>alert(1)</script>", file="a<img src=x onerror=alert(1)>.sql", line=1, snippet="<b onmouseover=alert(1)>", confidence="confirmed"))
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, "f.json")
            with open(f, "w", encoding="utf-8") as fh:
                json.dump(doc.to_dict(), fh)
            out = subprocess.run([sys.executable, os.path.join(helpers.SCRIPTS, "render_report.py"), tmp, "--findings", f, "--format", "html"], stdout=subprocess.PIPE).stdout.decode()
            self.assertNotIn("<script>alert", out)
            self.assertNotIn("<img src=x", out)
            self.assertNotIn("<b onmouseover", out)

    def test_probe_requires_both_flags(self):
        probe = os.path.join(helpers.SCRIPTS, "probe_live.py")
        for extra in ([], ["--allow-network"], ["--i-own-this"]):
            r = subprocess.run([sys.executable, probe, "--base-url", "http://127.0.0.1:9"] + extra, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(r.returncode, 2)

    def test_probe_request_cap_and_methods(self):
        import probe_live
        b = probe_live.Budget(limit=3, delay=0)
        with self.assertRaises(ValueError):
            b.request("http://127.0.0.1:9", "POST")
        for _ in range(5):
            b.request("http://127.0.0.1:9")
        self.assertEqual(b.used, 3)

    def test_every_script_has_help(self):
        for name in sorted(os.listdir(helpers.SCRIPTS)):
            if name.endswith(".py"):
                r = subprocess.run([sys.executable, os.path.join(helpers.SCRIPTS, name), "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(r.returncode, 0, name)

    def test_usage_and_missing_root_exit_codes(self):
        r = subprocess.run([sys.executable, RUN_ALL], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(r.returncode, 2)
        r = subprocess.run([sys.executable, RUN_ALL, os.path.join(LOVABLE, "nope")], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(r.returncode, 3)

    def test_package_zip(self):
        subprocess.run([sys.executable, os.path.join(helpers.REPO, "tools", "package.py")], check=True, stdout=subprocess.PIPE)
        z = zipfile.ZipFile(os.path.join(helpers.REPO, "dist", "prodready-skill.zip"))
        names = z.namelist()
        self.assertIn("prodready/SKILL.md", names)
        self.assertFalse([n for n in names if "__pycache__" in n or n.startswith("prodready/../")])
        self.assertTrue(any(n.endswith("scripts/run_all.py") for n in names))
        z.close()

    def test_verify_fixes_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "base.json")
            with open(base, "wb") as fh:
                fh.write(run_all().stdout)
            r = subprocess.run([sys.executable, os.path.join(helpers.SCRIPTS, "verify_fixes.py"), LOVABLE, "--baseline", base, "--out", os.path.join(tmp, "v.json"), "--quiet"], stdout=subprocess.PIPE)
            self.assertEqual(r.returncode, 0)
            v = json.load(open(os.path.join(tmp, "v.json")))
            self.assertEqual(v["counts"]["fixed"], 0)
            self.assertEqual(v["new"], [])


if __name__ == "__main__":
    unittest.main()
