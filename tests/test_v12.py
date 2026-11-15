"""Tests for 1.2.0: data flow, record-level authorization, financial integrity, runtime profiler, live verification."""
import http.server
import json
import threading
import time
import unittest

import helpers
from helpers import find, scan_files
from lib import phpflow

import probe_live
import profile_runtime
import verify_production
from lib.findings import Envelope

COMPOSER = '{"require": {"laravel/framework": "^12.0"}}'
BASE = {"composer.json": COMPOSER, "artisan": "<?php\n"}


def app(extra):
    d = dict(BASE)
    d.update(extra)
    return d


class Flow(unittest.TestCase):
    def test_taint_follows_assignments_loops_and_sanitisers(self):
        body = "{ $a = $request->q; $n = (int) $request->n; $c = \"x $a\"; $sql = 'select ' . $c; foreach ($request->ids as $id) { $z = $id; } }"
        t = phpflow.tainted_vars(body)
        self.assertTrue({"$a", "$c", "$sql", "$id", "$z"} <= t)
        self.assertNotIn("$n", t)

    def test_taint_crosses_methods_of_one_class(self):
        code = "<?php\nclass A {\n public function go($request) { $x = $request->cmd; $this->run($x); }\n private function run($c) { shell_exec($c); }\n}\n"
        doc = scan_files("scan_laravel", app({"app/Http/Controllers/A.php": code}))
        self.assertTrue(find(doc, "LARA-012"))

    def test_sql_built_in_a_variable_is_found(self):
        code = "<?php\nclass A { public function i($request) { $sql = \"select * from t where a = '\" . $request->a . \"'\"; return DB::select($sql); } }\n"
        self.assertTrue(find(scan_files("scan_laravel", app({"app/Http/Controllers/A.php": code})), "LARA-004"))
        safe = "<?php\nclass A { public function i($request) { $id = (int) $request->a; $sql = \"select * from t where a = $id\"; return DB::select($sql); } }\n"
        hits = find(scan_files("scan_laravel", app({"app/Http/Controllers/A.php": safe})), "LARA-004")
        self.assertTrue(all(h["confidence"] == "possible" for h in hits))


class Authz(unittest.TestCase):
    POLICY = "<?php\nnamespace App\\Policies;\nclass PostPolicy {\n    public function update(User $user, Post $post): bool { %s }\n}\n"
    MODEL = "<?php\nnamespace App\\Models;\nclass Post extends Model {}\n"

    def run_scan(self, policy_body, controller=None):
        files = app({"app/Policies/PostPolicy.php": self.POLICY % policy_body, "app/Models/Post.php": self.MODEL})
        if controller:
            files["app/Http/Controllers/PostController.php"] = controller
        return scan_files("scan_authz", files)

    def test_always_true_and_blind_rules(self):
        self.assertTrue(find(self.run_scan("return true;"), "AUTHZ-004"))
        self.assertTrue(find(self.run_scan("return $user->id > 0;"), "AUTHZ-002"))
        self.assertFalse(find(self.run_scan("return $user->id === $post->user_id;"), "AUTHZ-002"))

    def test_unused_policy_and_mixed_controller(self):
        self.assertTrue(find(self.run_scan("return $user->id === $post->user_id;"), "AUTHZ-001"))
        ctrl = "<?php\nclass PostController {\n public function show(Post $post) { $this->authorize('update', $post); return $post; }\n public function destroy(Post $post) { $post->delete(); }\n}\n"
        doc = self.run_scan("return $user->id === $post->user_id;", ctrl)
        self.assertFalse(find(doc, "AUTHZ-001"))
        self.assertEqual([f["subject"]["name"] for f in find(doc, "AUTHZ-003")], ["PostController::destroy"])


class Ledger(unittest.TestCase):
    def test_balance_without_ledger_and_one_sided_transfer(self):
        code = "<?php\nclass S {\n public function transferOut($w, $a) { $w->decrement('balance', $a); }\n public function pay($w, $a) { $w->decrement('balance', $a); DB::table('ledger_entries')->insert(['a' => $a]); }\n}\n"
        doc = scan_files("scan_ledger", app({"app/Services/S.php": code}))
        self.assertEqual([f["subject"]["name"] for f in find(doc, "FIN-001")], ["S::transferOut"])
        self.assertTrue(find(doc, "FIN-002"))

    def test_negative_balance_column_and_money_table(self):
        mig = "<?php\nSchema::create('payments', function (Blueprint $table) {\n    $table->id();\n    $table->decimal('balance', 12, 2);\n});\n"
        doc = scan_files("scan_ledger", app({"database/migrations/2025_01_01_000000_a.php": mig}))
        self.assertTrue(find(doc, "FIN-003") and find(doc, "FIN-004"))
        ok = mig.replace("->id();", "->id();\n    $table->string('ref')->unique();") + "DB::statement('ALTER TABLE payments ADD CONSTRAINT c CHECK (balance >= 0)');\n"
        doc = scan_files("scan_ledger", app({"database/migrations/2025_01_01_000000_a.php": ok}))
        self.assertFalse(find(doc, "FIN-003") or find(doc, "FIN-004"))


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/slow":
            self.send_response(200)
            self.send_header("X-Prodready-Queries", "120")
            self.send_header("X-Prodready-Max-Repeat", "40")
            self.send_header("X-Prodready-Repeat-Sample", "select * from users where id = ?")
            self.send_header("X-Prodready-Time-Ms", "2400")
            self.send_header("X-Prodready-Memory-Kb", "262144")
            self.end_headers()
        elif self.path == "/fast":
            self.send_response(200)
            self.send_header("X-Prodready-Queries", "4")
            self.send_header("X-Prodready-Max-Repeat", "1")
            self.send_header("X-Prodready-Time-Ms", "20")
            self.send_header("X-Prodready-Memory-Kb", "8192")
            self.end_headers()
        elif self.path == "/.env":
            body = b"APP_NAME=Acme\nDB_HOST=db\n"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/health":
            if self.headers.get("Authorization") != "Bearer tok":
                self.send_response(404)
                self.end_headers()
                return
            body = json.dumps({"database_ok": True, "scheduler_last_run": time.time() - 4000, "queue_oldest_job_age_s": 0, "last_backup_at": time.time() - 3600}).encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


class Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_profiler_flags_measured_n_plus_one(self):
        env = profile_runtime.profile(self.base, ["/slow", "/fast"], probe_live.Budget(delay=0), 1, {"queries": 50, "repeat": 8, "ms": 1500, "memory": 128}, "", "")
        doc = env.to_dict()
        ids = {(f["check_id"], f["subject"]["name"]) for f in doc["findings"]}
        self.assertEqual(ids, {("PERF-013", "/slow"), ("PERF-014", "/slow"), ("PERF-015", "/slow")})

    def test_profiler_refuses_without_ownership_flag(self):
        self.assertNotEqual(profile_runtime.main(["--base-url", self.base, "--paths", "/fast"]), 0)

    def test_verify_finds_exposed_env_and_stale_scheduler(self):
        env = Envelope("verify_production")
        verify_production.check_sensitive(self.base, probe_live.Budget(delay=0), env)
        self.assertEqual([f.check_id for f in env.findings], ["PROD-003"])
        self.assertNotIn("Acme", json.dumps(env.to_dict()))
        env = Envelope("verify_production")
        verify_production.check_health(self.base + "/health", "tok", probe_live.Budget(delay=0), env)
        self.assertEqual([(f.check_id, f.subject["name"]) for f in env.findings], [("PROD-004", "scheduler")])

    def test_verify_refuses_without_flags(self):
        self.assertNotEqual(verify_production.main(["--url", "https://example.invalid"]), 0)


if __name__ == "__main__":
    unittest.main()
