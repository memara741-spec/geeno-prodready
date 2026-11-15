"""Tests for the 1.1.0 scanners: Laravel, multi-tenancy, business logic, performance, infrastructure, and the regression-test generator."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

import helpers
from helpers import find, ids, scan_files
from lib import phpscan

COMPOSER = '{"require": {"laravel/framework": "^12.0", "livewire/livewire": "^3.6"}}'
BASE = {"composer.json": COMPOSER, "artisan": "<?php\n"}


def app(extra):
    d = dict(BASE)
    d.update(extra)
    return d


class PhpScanLib(unittest.TestCase):
    def test_mask_blanks_comments_but_keeps_strings_and_offsets(self):
        text = "<?php\n// DB::raw($x)\n$a = 'http://x'; /* shell_exec($y) */ $b = \"#not\";\n#[Attr]\n"
        code, bare = phpscan.mask(text)
        self.assertEqual(len(code), len(text))
        self.assertNotIn("shell_exec", code)
        self.assertNotIn("DB::raw", code)
        self.assertIn("http://x", code)
        self.assertNotIn("http://x", bare)
        self.assertIn("#[Attr]", code)

    def test_route_inventory_inherits_group_middleware(self):
        files = app({"routes/api.php": "<?php\nRoute::middleware(['auth:sanctum', 'throttle:60,1'])->group(function () {\n    Route::get('/a', [AController::class, 'index']);\n    Route::prefix('v1')->group(function () {\n        Route::post('/b', [AController::class, 'store']);\n    });\n});\nRoute::post('/open', [AController::class, 'open']);\nRoute::apiResource('items', ItemController::class)->only(['index', 'show']);\n"})
        with helpers.TempApp(files) as root:
            from lib import walker
            routes = phpscan.route_inventory(walker.Project(root))
        by = {(r["method"], r["uri"]): r for r in routes}
        self.assertTrue(by[("GET", "/api/a")]["auth"] and by[("GET", "/api/a")]["throttle"])
        self.assertTrue(by[("POST", "/api/v1/b")]["auth"])
        self.assertFalse(by[("POST", "/api/open")]["auth"])
        self.assertEqual({k for k in by if k[1].startswith("/api/items")}, {("GET", "/api/items"), ("GET", "/api/items/{id}")})


class LaravelScanner(unittest.TestCase):
    def run_scan(self, extra):
        return scan_files("scan_laravel", app(extra))

    def test_not_laravel_is_silent(self):
        doc = scan_files("scan_laravel", {"package.json": "{}", "index.js": "x"})
        self.assertEqual(doc["findings"], [])

    def test_raw_sql_interpolation_found_and_bindings_pass(self):
        bad = self.run_scan({"app/Http/Controllers/A.php": "<?php\nclass A { public function i($request) { return DB::select(\"select * from t where a = '$request->a'\"); } }\n"})
        self.assertTrue(find(bad, "LARA-004"))
        ok = self.run_scan({"app/Http/Controllers/A.php": "<?php\nclass A { public function i($request) { return DB::select('select * from t where a = ?', [$request->a]); } }\n"})
        self.assertFalse(find(ok, "LARA-004"))

    def test_commented_out_code_is_ignored(self):
        doc = self.run_scan({"app/Http/Controllers/A.php": "<?php\nclass A { public function i($request) {\n // shell_exec($request->x);\n } }\n"})
        self.assertFalse(find(doc, "LARA-012"))

    def test_mass_assignment_and_unguard(self):
        doc = self.run_scan({"app/Models/P.php": "<?php\nnamespace App\\Models;\nclass P extends Model { protected $guarded = []; }\n", "app/Providers/AppServiceProvider.php": "<?php\nModel::unguard();\n"})
        self.assertEqual(len(find(doc, "LARA-003")), 2)

    def test_blade_escaping(self):
        doc = self.run_scan({"resources/views/a.blade.php": "<div>{!! $post->body !!}</div>\n<div>{!! $links->links() !!}</div>\n<div>{{ $safe }}</div>\n"})
        hits = find(doc, "LARA-005")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["line"], 1)

    def test_livewire_locked_property_and_authorised_action(self):
        comp = "<?php\nnamespace App\\Livewire;\nuse Livewire\\Component;\nclass E extends Component {\n    %s\n    public $invoiceId;\n    public function remove() { %s Invoice::find($this->invoiceId)->delete(); }\n}\n"
        bad = self.run_scan({"app/Livewire/E.php": comp % ("", "")})
        self.assertTrue(find(bad, "LARA-007") and find(bad, "LARA-008"))
        good = self.run_scan({"app/Livewire/E.php": comp % ("#[Locked]", "$this->authorize('delete', Invoice::find($this->invoiceId));")})
        self.assertFalse(find(good, "LARA-007") or find(good, "LARA-008"))

    def test_unauthenticated_write_route_and_throttle(self):
        files = {"routes/api.php": "<?php\nRoute::post('/orders', [OrderController::class, 'store']);\nRoute::post('/login', [AuthController::class, 'login']);\n",
                 "app/Http/Controllers/OrderController.php": "<?php\nclass OrderController { public function store($request) { Order::create($request->all()); } }\n"}
        doc = self.run_scan(files)
        self.assertTrue(find(doc, "AUTH-002"))
        self.assertTrue(find(doc, "API-020"))

    def test_version_support(self):
        old = scan_files("scan_laravel", {"composer.json": '{"require": {"laravel/framework": "^10.0"}}', "artisan": "<?php\n"})
        self.assertTrue(find(old, "LARA-015"))
        new = self.run_scan({})
        self.assertFalse(find(new, "LARA-015"))

    def test_app_key_never_in_output(self):
        key = helpers.fake("base64:", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5")
        doc = self.run_scan({".env": "APP_ENV=production\nAPP_DEBUG=true\nAPP_KEY=%s\n" % key})
        self.assertTrue(find(doc, "LARA-002") and find(doc, "LARA-001"))
        self.assertNotIn("QUJDREVG", json.dumps(doc))


class TenancyScanner(unittest.TestCase):
    MIG = "<?php\nSchema::create('invoices', function (Blueprint $table) {\n    $table->id();\n    $table->foreignId('company_id')->constrained();\n});\n"

    def test_unscoped_model_is_found_and_scoped_model_is_not(self):
        files = app({"database/migrations/2025_01_01_000000_a.php": self.MIG, "app/Models/Invoice.php": "<?php\nnamespace App\\Models;\nclass Invoice extends Model {}\n"})
        self.assertTrue(find(scan_files("scan_tenancy", files), "TEN-001"))
        files["app/Models/Invoice.php"] = "<?php\nnamespace App\\Models;\nclass Invoice extends Model { use BelongsToTenant; }\n"
        self.assertFalse(find(scan_files("scan_tenancy", files), "TEN-001"))

    def test_lookup_without_tenant_and_tenant_from_request(self):
        files = app({"database/migrations/2025_01_01_000000_a.php": self.MIG, "app/Models/Invoice.php": "<?php\nnamespace App\\Models;\nclass Invoice extends Model {}\n",
                     "app/Http/Controllers/I.php": "<?php\nclass I { public function a($request) { return Invoice::findOrFail($request->id); }\n public function b($request) { $c = $request->input('company_id'); } }\n"})
        doc = scan_files("scan_tenancy", files)
        self.assertTrue(find(doc, "TEN-003") and find(doc, "TEN-004"))

    def test_prisma_lookup_without_tenant(self):
        files = {"package.json": '{"dependencies": {"next": "15.5.9", "@prisma/client": "6.0.0"}}', "prisma/schema.prisma": "model Task {\n  id String @id\n  orgId String\n}\n",
                 "app/api/t/route.ts": "import { prisma } from '@/lib/prisma'\nexport async function GET() { return prisma.task.findMany() }\nexport async function POST() { return prisma.task.findMany({ where: { orgId: 'x' } }) }\n"}
        hits = find(scan_files("scan_tenancy", files), "TEN-003")
        self.assertEqual([h["line"] for h in hits], [2])


class LogicScanner(unittest.TestCase):
    def test_read_modify_write_balance(self):
        bad = "<?php\nclass W { public function p($r) { $w = Wallet::first(); $w->balance -= $r->amount; $w->save(); } }\n"
        good = "<?php\nclass W { public function p($r) { DB::transaction(function () use ($r) { $w = Wallet::lockForUpdate()->first(); $w->balance -= $r->amount; $w->save(); }); } }\n"
        self.assertTrue(find(scan_files("scan_logic", app({"app/Http/Controllers/W.php": bad})), "BIZ-001"))
        self.assertFalse(find(scan_files("scan_logic", app({"app/Http/Controllers/W.php": good})), "BIZ-001"))

    def test_amount_rule_needs_a_minimum(self):
        base = "<?php\nclass W { public function p($r) { $r->validate(['amount' => '%s']); $wallet = transfer(1); } }\n"
        self.assertTrue(find(scan_files("scan_logic", app({"app/Http/Controllers/W.php": base % "required|numeric"})), "BIZ-004"))
        self.assertFalse(find(scan_files("scan_logic", app({"app/Http/Controllers/W.php": base % "required|numeric|min:0.01"})), "BIZ-004"))

    def test_float_money_column_and_client_price(self):
        files = app({"database/migrations/2025_01_01_000000_a.php": "<?php\n$table->float('price');\n$table->decimal('total', 12, 2);\n",
                     "app/Http/Controllers/O.php": "<?php\nclass O { public function s($request) { return Order::create(['price' => $request->price]); } }\n"})
        doc = scan_files("scan_logic", files)
        self.assertEqual(len(find(doc, "BIZ-005")), 1)
        self.assertTrue(find(doc, "BIZ-006"))


class PerformanceScanner(unittest.TestCase):
    def test_n_plus_one_in_blade_and_eager_loading_clears_it(self):
        files = app({"app/Models/Post.php": "<?php\nnamespace App\\Models;\nclass Post extends Model { public function author() { return $this->belongsTo(User::class); } }\n",
                     "resources/views/p.blade.php": "@foreach ($posts as $post)\n{{ $post->author->name }}\n@endforeach\n"})
        self.assertTrue(find(scan_files("scan_performance", files), "PERF-007"))
        files["app/Http/Controllers/P.php"] = "<?php\nclass P { public function i() { return Post::with('author')->get(); } }\n"
        self.assertFalse(find(scan_files("scan_performance", files), "PERF-007"))

    def test_queue_driver_and_missing_index(self):
        files = app({".env": "APP_ENV=production\nQUEUE_CONNECTION=sync\n", "database/migrations/2025_01_01_000000_a.php": "<?php\n$table->unsignedBigInteger('user_id');\n$table->foreignId('team_id')->constrained();\n"})
        doc = scan_files("scan_performance", files)
        self.assertTrue(find(doc, "PERF-011"))
        self.assertEqual([f["snippet"] for f in find(doc, "PERF-012")], ["$table->unsignedBigInteger('user_id');"])


class InfraScanner(unittest.TestCase):
    def test_compose_ports_passwords_and_nginx_root(self):
        files = app({"docker-compose.yml": "services:\n  db:\n    image: mysql:8\n    environment:\n      MYSQL_ROOT_PASSWORD: root\n    ports:\n      - \"3306:3306\"\n  safe:\n    image: redis:7\n    ports:\n      - \"127.0.0.1:6379:6379\"\n",
                     "nginx.conf": "server {\n  listen 443 ssl;\n  root /var/www/html;\n  ssl_protocols TLSv1.2 TLSv1.3;\n}\n"})
        doc = scan_files("scan_infra", files)
        self.assertEqual(len(find(doc, "INFRA-008")), 2)
        self.assertTrue(find(doc, "INFRA-001"))
        self.assertFalse(find(doc, "INFRA-002"))

    def test_scheduler_and_worker_need_a_process(self):
        files = app({"routes/console.php": "<?php\nSchedule::command('a')->everyMinute();\n", "app/Jobs/J.php": "<?php\nclass J implements ShouldQueue {}\n"})
        doc = scan_files("scan_infra", files)
        self.assertEqual(len(find(doc, "INFRA-004")), 2)
        files["Procfile"] = "web: php-fpm\nworker: php artisan queue:work\nscheduler: php artisan schedule:work\n"
        self.assertFalse(find(scan_files("scan_infra", files), "INFRA-004"))


class RegressionGenerator(unittest.TestCase):
    def test_generates_guard_and_laravel_tests(self):
        script = os.path.join(helpers.SCRIPTS, "generate_regression_tests.py")
        run_all = os.path.join(helpers.SCRIPTS, "run_all.py")
        with tempfile.TemporaryDirectory() as tmp:
            helpers.write_tree(tmp, app({"routes/api.php": "<?php\nRoute::post('/orders', [OrderController::class, 'store']);\nRoute::post('/login', [AuthController::class, 'login']);\n",
                                         "app/Http/Controllers/OrderController.php": "<?php\nclass OrderController { public function store($request) { Order::create($request->all()); } }\n"}))
            out = os.path.join(tmp, ".prodready", "findings.json")
            subprocess.run([sys.executable, run_all, tmp, "--out", out, "--quiet"], check=True, env=dict(os.environ, PRODREADY_FIXED_TIME="2026-01-01T00:00:00Z"))
            r = subprocess.run([sys.executable, script, tmp], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            reg = os.path.join(tmp, ".prodready", "regression")
            for name in ("prodready_guard.py", "ProdreadyRouteContractTest.php", "ProdreadyFindingsTest.php", "README.md"):
                self.assertTrue(os.path.isfile(os.path.join(reg, name)), name)
            php = open(os.path.join(reg, "ProdreadyFindingsTest.php"), encoding="utf-8").read()
            self.assertIn("test_unauthenticated_1_post_api_orders", php)
            self.assertIn("test_rate_limit_1_post_api_login", php)
            # before the fix the guard must fail
            guard = subprocess.run([sys.executable, os.path.join(reg, "prodready_guard.py")], capture_output=True, text=True)
            self.assertNotEqual(guard.returncode, 0)


if __name__ == "__main__":
    unittest.main()
