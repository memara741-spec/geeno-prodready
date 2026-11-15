"""Tests for 1.3.0: scanner failure blocks READY, cross-class data flow, generated policy and concurrency tests, restore drill."""
import importlib
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

import helpers
from helpers import find, scan_files

COMPOSER = '{"require": {"laravel/framework": "^12.0", "laravel/sanctum": "^4.0"}}'
BASE = {"composer.json": COMPOSER, "artisan": "<?php\n"}


def app(extra):
    d = dict(BASE)
    d.update(extra)
    return d


class CrossClass(unittest.TestCase):
    def test_taint_crosses_classes_and_traits(self):
        ctrl = "<?php\nnamespace App\\Http\\Controllers;\nclass C {\n public function __construct(private Runner $runner) {}\n public function go($request) { $this->runner->exec($request->cmd); }\n}\n"
        runner = "<?php\nnamespace App\\Services;\nclass Runner {\n use Shell;\n public function exec($c) { $this->sh($c); }\n}\n"
        trait = "<?php\nnamespace App\\Services;\ntrait Shell {\n protected function sh($x) { shell_exec($x); }\n}\n"
        doc = scan_files("scan_laravel", app({"app/Http/Controllers/C.php": ctrl, "app/Services/Runner.php": runner, "app/Services/Shell.php": trait}))
        self.assertEqual([f["file"] for f in find(doc, "LARA-012")], ["app/Services/Shell.php"])

    def test_untainted_cross_class_call_is_quiet(self):
        ctrl = "<?php\nclass C {\n public function __construct(private Runner $runner) {}\n public function go($request) { $this->runner->exec('ls'); }\n}\n"
        runner = "<?php\nclass Runner {\n public function exec($c) { shell_exec($c); }\n}\n"
        doc = scan_files("scan_laravel", app({"app/Http/Controllers/C.php": ctrl, "app/Services/Runner.php": runner}))
        self.assertFalse(find(doc, "LARA-012"))


class Incomplete(unittest.TestCase):
    def test_failed_scanner_blocks_ready(self):
        import render_report
        ok = render_report.verdict([], None, [{"scanner": "scan_routes", "status": "ran"}])
        bad = render_report.verdict([], None, [{"scanner": "scan_routes", "status": "failed"}])
        self.assertEqual((ok["verdict"], bad["verdict"], bad["incomplete"]), ("READY", "INCOMPLETE", ["scan_routes"]))

    def test_run_all_exits_4_when_a_scanner_crashes(self):
        import run_all
        orig = importlib.import_module

        def boom(name, *a, **k):
            if name == "scan_launch":
                raise RuntimeError("boom")
            return orig(name, *a, **k)
        with helpers.TempApp({"package.json": "{}", "index.js": "x"}) as root:
            importlib.import_module = boom
            try:
                self.assertEqual(run_all.main([root, "--quiet", "--out", root + "/o.json"]), 4)
                self.assertEqual(run_all.main([root, "--quiet", "--out", root + "/o.json", "--allow-scanner-failure"]), 0)
            finally:
                importlib.import_module = orig


class GeneratedTests(unittest.TestCase):
    def test_policy_and_concurrency_tests_are_generated_and_lint(self):
        files = app({
            "app/Policies/InvoicePolicy.php": "<?php\nnamespace App\\Policies;\nclass InvoicePolicy {\n public function view(User $user, Invoice $invoice): bool { return $user->id === $invoice->user_id; }\n public function update(User $user, Invoice $invoice): bool { return true; }\n}\n",
            "app/Models/Invoice.php": "<?php\nnamespace App\\Models;\nclass Invoice extends Model {}\n",
            "app/Models/Wallet.php": "<?php\nnamespace App\\Models;\nclass Wallet extends Model { protected $fillable = ['user_id', 'balance']; }\n",
            "routes/api.php": "<?php\nRoute::middleware('auth:sanctum')->group(function () {\n    Route::post('/wallet/withdraw', [WalletController::class, 'withdraw']);\n});\n",
            "app/Http/Controllers/WalletController.php": "<?php\nclass WalletController { public function withdraw($request) { return 1; } }\n",
        })
        run_all = os.path.join(helpers.SCRIPTS, "run_all.py")
        gen = os.path.join(helpers.SCRIPTS, "generate_regression_tests.py")
        with tempfile.TemporaryDirectory() as tmp:
            helpers.write_tree(tmp, files)
            subprocess.run([sys.executable, run_all, tmp, "--out", tmp + "/f.json", "--quiet"], check=True)
            r = subprocess.run([sys.executable, gen, tmp, "--findings", tmp + "/f.json"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            reg = os.path.join(tmp, ".prodready", "regression")
            policy = open(os.path.join(reg, "ProdreadyPolicyTest.php"), encoding="utf-8").read()
            self.assertIn("test_invoice_update", policy)
            self.assertIn("'update'", policy)
            conc = open(os.path.join(reg, "ProdreadyConcurrencyTest.php"), encoding="utf-8").read()
            self.assertIn("Concurrency::run", conc)
            self.assertIn("DatabaseTruncation", conc)
            self.assertIn("/wallet/withdraw", conc)
            import shutil
            if shutil.which("php"):
                for name in os.listdir(reg):
                    if name.endswith(".php"):
                        r = subprocess.run(["php", "-l", os.path.join(reg, name)], capture_output=True, text=True)
                        self.assertEqual(r.returncode, 0, name + ": " + r.stdout + r.stderr)


class RestoreDrill(unittest.TestCase):
    def run_drill(self, *args):
        script = os.path.join(helpers.SCRIPTS, "restore_drill.py")
        return subprocess.run([sys.executable, script] + list(args), capture_output=True, text=True)

    def test_good_backup_passes_and_missing_tables_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "b.zip")
            sql = "CREATE TABLE `users` (id int);\nCREATE TABLE `invoices` (id int);\n-- Dump completed on 2026-11-15\n"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("db-dumps/mysql-acme.sql", sql)
            good = self.run_drill("--backup", path, "--expect-tables", "users,invoices")
            self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
            bad = self.run_drill("--backup", path, "--expect-tables", "users,wallets")
            self.assertEqual(bad.returncode, 1)
            self.assertIn("wallets", bad.stdout)

    def test_restore_command_requires_explicit_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "b.sql")
            open(path, "w").write("CREATE TABLE a (id int);\n-- Dump completed\n")
            r = self.run_drill("--backup", path, "--restore-cmd", "echo restoring {file}")
            self.assertEqual(r.returncode, 2)
            r = self.run_drill("--backup", path, "--restore-cmd", "echo restoring {file}", "--run-restore", "--i-own-this")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("restore command exited 0", r.stdout)


if __name__ == "__main__":
    unittest.main()
