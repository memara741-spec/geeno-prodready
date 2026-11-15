"""Unit tests for the shared library: patterns, tokenizer, SQL splitter, findings."""
from __future__ import annotations

import unittest

import helpers  # noqa: F401  (sets sys.path)
from helpers import fake
from lib import catalog, findings, jsast, patterns, sqlparse_lite, walker


class PatternExamples(unittest.TestCase):
    def test_every_pattern_has_examples(self):
        for p in patterns.SECRET_PATTERNS:
            self.assertTrue(p.positive and p.negative, p.id)

    def test_positive_examples_match(self):
        for p in patterns.SECRET_PATTERNS:
            for ex in p.positive:
                self.assertTrue(p.regex.search(ex), "%s should match its positive example" % p.id)

    def test_negative_examples_do_not_survive(self):
        for p in patterns.SECRET_PATTERNS:
            for ex in p.negative:
                hits = [m for m in patterns.find_secrets(ex) if m.pattern.id == p.id]
                self.assertFalse(hits, "%s should not report its negative example %r" % (p.id, ex))

    def test_placeholders(self):
        for v in ("your-key-here", "xxxxxxxxxxxxxxxx", "changeme", "<paste key>", "sk_" + "live_" + "a" * 24, "AKIAIOSFODNN7EXAMPLE"):
            self.assertTrue(patterns.is_placeholder(v), v)
        self.assertFalse(patterns.is_placeholder(fake("sk_", "live_", "Fx9aQz7k" * 4)))

    def test_jwt_roles(self):
        import base64
        import json

        def jwt(payload):
            enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
            return enc({"alg": "HS256", "typ": "JWT"}) + "." + enc(payload) + "." + "c2lnbmF0dXJlZmFrZXNpZw"

        self.assertEqual(patterns.classify_jwt(jwt({"iss": "supabase", "role": "anon"})), "supabase-anon")
        self.assertEqual(patterns.classify_jwt(jwt({"iss": "supabase", "role": "service_role"})), "supabase-service-role")
        self.assertEqual(patterns.classify_jwt(jwt({"iss": "supabase-demo", "role": "anon"})), "supabase-demo")
        anon = patterns.find_secrets("KEY=" + jwt({"iss": "supabase", "role": "anon", "ref": "abcdefghij"}))
        self.assertTrue(anon and anon[0].public)
        svc = patterns.find_secrets("KEY=" + jwt({"iss": "supabase", "role": "service_role", "ref": "abcdefghij"}))
        self.assertTrue(svc and not svc[0].public and svc[0].label == "supabase-service-role")

    def test_false_positive_controls(self):
        noise = "\n".join([
            '"integrity": "sha512-9aQz7kFx9aQz7kFx9aQz7kFx9aQz7kFx9aQz7kFx9aQz7kFx9aQz7kFx9aQz7kFx9aQz7kFx9aQz7kFx9aQz7kFx9aQ=="',
            "id: 123e4567-e89b-12d3-a456-426614174000",
            "commit 9fceb02d0ae598e95dc970b74767f19372d61af8",
            'src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="',
            'const passwordLabel = "Enter your password to continue"',
            "apiKey: process.env.API_KEY",
            'password: "password"',
        ])
        self.assertEqual([m.pattern.id for m in patterns.find_secrets(noise)], [])

    def test_google_key_context(self):
        key = fake("AI", "za", "Sy", "A1b2C3d4E5f" * 3)
        self.assertTrue(patterns.find_secrets("apiKey: '%s'" % key)[0].public)
        self.assertFalse(patterns.find_secrets("GEMINI_API_KEY=%s" % key)[0].public)

    def test_env_names(self):
        self.assertEqual(patterns.public_prefix("NEXT_PUBLIC_SUPABASE_URL"), "NEXT_PUBLIC_")
        self.assertTrue(patterns.is_secret_name("VITE_OPENAI_API_KEY"))
        self.assertTrue(patterns.is_secret_name("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"))
        self.assertFalse(patterns.is_secret_name("NEXT_PUBLIC_SUPABASE_ANON_KEY"))
        self.assertFalse(patterns.is_secret_name("NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY"))


class Lexer(unittest.TestCase):
    def test_comments_and_strings_are_blanked(self):
        src = "const a = 'eval(x)'; // eval(y)\n/* eval(z) */ eval(w);\n"
        lx = jsast.lex(src)
        self.assertEqual(len(lx.code), len(src))
        self.assertEqual(lx.code.count("eval("), 1)
        self.assertEqual(lx.nocomment.count("eval("), 2)

    def test_nested_template(self):
        src = "const s = `a ${fn(`inner ${x} text`)} tail eval(1)`; done();"
        lx = jsast.lex(src)
        self.assertIn("fn(", lx.code)
        self.assertNotIn("eval(", lx.code)
        self.assertIn("done()", lx.code)

    def test_regex_with_quotes_and_slashes(self):
        src = "const re = /['\"\\/]+eval\\(/g; const b = a / 2; call('x');"
        lx = jsast.lex(src)
        self.assertNotIn("eval", lx.code)
        self.assertIn("a / 2", lx.code)
        self.assertIn("call(", lx.code)

    def test_jsx_and_typescript(self):
        src = (
            "export default function Page<T extends object>({ items }: { items: Array<T> }): JSX.Element {\n"
            "  return <div className=\"x\">{items.map((i) => <span key={String(i)}>ok</span>)}</div>;\n"
            "}\n"
        )
        funcs = jsast.find_functions(src)
        self.assertEqual(funcs[0].name, "Page")
        self.assertEqual((funcs[0].start_line, funcs[0].end_line), (1, 3))

    def test_minified(self):
        src = "var a=function(e){return e+1},b=async(t)=>{await fetch(t)};" * 200
        lx = jsast.lex(src)
        self.assertEqual(len(lx.code), len(src))
        self.assertTrue(jsast.find_calls(src, ["fetch"]))

    def test_imports(self):
        src = (
            "import React, { useState as useS, type FC } from 'react';\n"
            "import * as Icons from \"lucide-react\";\n"
            "import './side-effect.css';\n"
            "const fs = require('node:fs');\n"
            "const { exec } = require('child_process');\n"
            "const mod = await import('@scope/pkg/sub');\n"
            "// import fake from 'commented-out';\n"
        )
        specs = jsast.import_specs(src)
        self.assertEqual(sorted(specs), sorted(["react", "lucide-react", "./side-effect.css", "node:fs", "child_process", "@scope/pkg/sub"]))
        imps = {i.spec: i for i in jsast.find_imports(src)}
        self.assertEqual(imps["react"].default, "React")
        self.assertIn("useS", imps["react"].names)
        self.assertEqual(imps["lucide-react"].namespace, "Icons")
        self.assertIn("exec", imps["child_process"].names)
        self.assertEqual(jsast.package_of("@scope/pkg/sub"), "@scope/pkg")
        self.assertIsNone(jsast.package_of("node:fs"))
        self.assertIsNone(jsast.package_of("@/lib/x"))

    def test_exports_and_directives(self):
        src = "'use server'\nexport async function POST(req: Request) { return 1 }\nexport const GET = async () => 2\nexport default handler\n"
        names = [e.name for e in jsast.find_exports(src)]
        self.assertIn("POST", names)
        self.assertIn("GET", names)
        self.assertTrue(jsast.has_directive(src, "use server"))
        self.assertFalse(jsast.has_directive(src, "use client"))
        self.assertTrue(jsast.has_directive("// c\n/* b */\n\"use client\";\nimport x from 'y'", "use client"))
        inline = "export async function save(fd) {\n  'use server'\n  await db.insert(fd)\n}\n"
        self.assertEqual([f.name for f in jsast.functions_with_directive(inline, "use server")], ["save"])

    def test_functions_with_return_type_braces(self):
        src = "async function load(id: string): Promise<{ ok: boolean }> {\n  const a = { b: 1 };\n  return { ok: !!a };\n}\nconst add = (a: number, b: number) => a + b;\n"
        funcs = {f.name: f for f in jsast.find_functions(src)}
        self.assertEqual(funcs["load"].end_line, 4)
        self.assertIn("add", funcs)

    def test_calls_and_args(self):
        src = "stripe.checkout.sessions.create({ price: body.priceId, mode: 'payment' });\n// stripe.checkout.sessions.create(ignored)\nfetch(url, { method: 'POST' });"
        calls = jsast.find_calls(src, ["stripe.*", "fetch"])
        self.assertEqual([c.name for c in calls], ["stripe.checkout.sessions.create", "fetch"])
        self.assertIn("body.priceId", calls[0].args)
        self.assertEqual(jsast.split_args(calls[1].args), ["url", "{ method: 'POST' }"])
        self.assertEqual(jsast.string_value("'abc'"), "abc")
        self.assertIsNone(jsast.string_value("`a${b}`"))


class SqlSplitter(unittest.TestCase):
    def test_split_respects_quotes_and_dollar_bodies(self):
        sql = (
            "-- comment; with semicolon\n"
            "create table a (id int, note text default 'x;y');\n"
            "/* block; comment */\n"
            "create function f() returns void language plpgsql as $fn$ begin perform 1; perform 2; end $fn$;\n"
            "insert into \"odd;name\" values (1);\n"
        )
        stmts = sqlparse_lite.split(sql)
        self.assertEqual(len(stmts), 3)
        self.assertEqual(stmts[0].line, 2)
        self.assertIn("perform 2", stmts[1].text)

    def test_schema_state(self):
        files = [
            ("supabase/migrations/20240102000000_b.sql", "alter table public.notes enable row level security;\n"
             "drop policy \"open\" on notes;\ncreate policy \"own\" on public.notes for select to authenticated using ((select auth.uid()) = user_id);\n"),
            ("supabase/migrations/20240101000000_a.sql", "create table if not exists notes (id uuid primary key, user_id uuid references auth.users(id), body text);\n"
             "create policy \"open\" on notes for all using (true);\n"
             "create table private.audit (id int);\n"
             "create table \"Quoted Name\" (id int);\n"),
        ]
        schema = sqlparse_lite.apply(files)
        notes = schema.tables["public.notes"]
        self.assertTrue(notes.rls)
        self.assertEqual(notes.columns["user_id"].references, "auth.users")
        pols = schema.policies_for("public.notes")
        self.assertEqual([p.name for p in pols], ["own"])
        self.assertEqual((pols[0].command, pols[0].roles), ("select", ["authenticated"]))
        self.assertIn("auth.uid()", pols[0].using)
        self.assertIn("private.audit", schema.tables)
        self.assertIn("public.Quoted Name", schema.tables)

    def test_policy_variants(self):
        sql = (
            "create table t (id int, owner uuid);\nalter table t enable row level security;\nalter table t force row level security;\n"
            "create policy p1 on t as restrictive for update to authenticated, anon using (owner = auth.uid()) with check (owner = auth.uid());\n"
            "create policy p2 on t for insert with check (true);\n"
            "alter policy p2 on t to authenticated with check (owner = auth.uid());\n"
        )
        schema = sqlparse_lite.apply([("m.sql", sql)])
        p1, p2 = schema.policies_for("public.t")
        self.assertFalse(p1.permissive)
        self.assertEqual(p1.roles, ["authenticated", "anon"])
        self.assertEqual(sqlparse_lite.normalise_expr(p1.check), "owner = auth.uid()")
        self.assertEqual(p2.roles, ["authenticated"])
        self.assertIn("auth.uid()", p2.check)
        self.assertTrue(schema.tables["public.t"].rls_forced)

    def test_functions_views_grants_buckets(self):
        sql = (
            "create or replace function public.make_admin(uid uuid) returns void language sql security definer as $$ update profiles set role='admin' where id = uid $$;\n"
            "create function private.safe() returns void language sql security definer set search_path = '' as $$ select 1 $$;\n"
            "create view public.v as select * from t;\n"
            "create view public.v2 with (security_invoker = true) as select * from t;\n"
            "create materialized view public.mv as select 1;\n"
            "grant all on all tables in schema public to anon;\n"
            "revoke execute on function public.make_admin(uuid) from public, anon;\n"
            "create index t_owner_idx on public.t (owner);\n"
            "insert into storage.buckets (id, name, public) values ('ids', 'ids', true), ('avatars', 'avatars', false);\n"
            "alter publication supabase_realtime add table public.messages;\n"
            "drop table if exists gone;\n"
            "this is not sql at all;\n"
        )
        schema = sqlparse_lite.apply([("m.sql", sql)])
        self.assertTrue(schema.functions["public.make_admin"].security_definer)
        self.assertIsNone(schema.functions["public.make_admin"].search_path)
        self.assertEqual(schema.functions["private.safe"].search_path, "''")
        self.assertFalse(schema.views["public.v"].security_invoker)
        self.assertTrue(schema.views["public.v2"].security_invoker)
        self.assertTrue(schema.views["public.mv"].materialized)
        self.assertEqual(schema.grants[0].object_kind, "all-tables")
        self.assertTrue(schema.grants[1].revoke)
        self.assertEqual(schema.grants[1].target, "public.make_admin")
        self.assertEqual(schema.indexes[0].columns, ("owner",))
        self.assertTrue(schema.buckets["ids"].public)
        self.assertFalse(schema.buckets["avatars"].public)
        self.assertEqual(schema.realtime_tables[0][0], "public.messages")


class FindingsModel(unittest.TestCase):
    def test_constructor_redacts(self):
        secret = fake("sk_", "live_", "Fx9aQz7k" * 4)
        f = findings.Finding("SEC-006", "Key %s is in code" % secret, file="a\\b.ts", line=3, snippet="const k = '%s'" % secret, detail=secret)
        blob = findings.dumps(f.to_dict())
        self.assertNotIn(secret, blob)
        self.assertEqual(f.file, "a/b.ts")
        self.assertEqual(f.id, "SEC-006:a/b.ts:3")
        self.assertEqual(f.severity, catalog.get("SEC-006").severity)

    def test_fingerprint_ignores_line_and_whitespace(self):
        a = findings.Finding("DB-002", "m", file="x.sql", line=3, snippet="create  policy p on t using (true);")
        b = findings.Finding("DB-002", "m", file="x.sql", line=30, snippet="create policy p on t\n using (true);")
        self.assertEqual(a.fingerprint, b.fingerprint)
        self.assertNotEqual(a.fingerprint, findings.Finding("DB-003", "m", file="x.sql", line=3, snippet=a.snippet).fingerprint)

    def test_dedupe_keeps_higher_confidence(self):
        a = findings.Finding("DB-002", "m", file="x.sql", line=3, snippet="s", confidence="possible")
        b = findings.Finding("DB-002", "m", file="x.sql", line=3, snippet="s", confidence="confirmed")
        self.assertEqual([f.confidence for f in findings.dedupe([a, b])], ["confirmed"])

    def test_unknown_check_rejected(self):
        with self.assertRaises(KeyError):
            findings.Finding("NOPE-001", "m")

    def test_snippet_limit_and_project_id(self):
        f = findings.Finding("OBS-001", "m", snippet="x" * 1000)
        self.assertLessEqual(len(f.snippet), findings.MAX_SNIPPET)
        self.assertEqual(f.id, "OBS-001:project")

    def test_summarise_and_merge(self):
        env = findings.Envelope("t")
        env.add(findings.Finding("DB-002", "m", file="x.sql", line=1, snippet="a"))
        env.add(findings.Finding("FE-003", "m", file="y.ts", line=1, snippet="b"))
        doc = findings.merge([env.to_dict(), env.to_dict()])
        self.assertEqual(len(doc["findings"]), 2)
        s = findings.summarise(doc["findings"])
        self.assertEqual((s["total"], s["by_severity"]["critical"], s["by_severity"]["low"]), (2, 1, 1))


class Catalog(unittest.TestCase):
    def test_count_and_fields(self):
        self.assertEqual(len(catalog.CHECKS), 252)
        for c in catalog.CHECKS.values():
            self.assertIn(c.severity, findings.SEVERITIES, c.id)
            self.assertIn(c.mode, ("scan", "review", "scan+review"), c.id)
            self.assertEqual(bool(c.scanner), c.is_scan, c.id)


class WalkerBasics(unittest.TestCase):
    def test_classification_and_gitignore(self):
        files = {
            "package.json": '{"dependencies": {"next": "15.5.9", "react": "19.0.0"}}',
            ".gitignore": "node_modules\n.env*\n!.env.example\n/secret-dir/\n",
            ".env": "A=1\n", ".env.example": "A=\n",
            "secret-dir/x.ts": "export const a = 1",
            "app/page.tsx": "export default function P() { return null }",
            "app/api/x/route.ts": "export async function GET() {}",
            "components/Button.tsx": "'use client'\nimport { helper } from '@/lib/helper'\nexport function B() {}",
            "lib/helper.ts": "export const helper = 1",
            "lib/db.ts": "import 'server-only'\nexport const db = 1",
            "supabase/migrations/1_a.sql": "select 1;",
            "README.md": "# hi", "public/logo.png": b"\x89PNG\x00\x00",
            "node_modules/x/index.js": "module.exports = 1",
            "app/page.test.tsx": "test('x', () => {})",
        }
        with helpers.TempApp(files) as root:
            p = walker.Project(root)
            kinds = {f.rel: p.classify(f) for f in p.files}
            self.assertEqual(kinds["app/page.tsx"], "server")
            self.assertEqual(kinds["app/api/x/route.ts"], "server")
            self.assertEqual(kinds["components/Button.tsx"], "client")
            self.assertEqual(kinds["lib/helper.ts"], "shared")
            self.assertEqual(kinds["lib/db.ts"], "server")
            self.assertEqual(kinds["supabase/migrations/1_a.sql"], "migration")
            self.assertEqual(kinds["README.md"], "doc")
            self.assertEqual(kinds["app/page.test.tsx"], "test")
            self.assertNotIn("node_modules/x/index.js", kinds)
            self.assertNotIn("secret-dir/x.ts", kinds)
            self.assertIn(".env", kinds)  # env files are examined even when ignored
            self.assertFalse(p.will_be_committed(".env"))
            self.assertTrue(p.will_be_committed(".env.example"))
            self.assertTrue(walker.is_env_example(".env.example"))
            self.assertEqual([a.rel for a in p.assets], ["public/logo.png"])

    def test_robust_to_bad_bytes(self):
        with helpers.TempApp({"a.ts": b"\xff\xfe\x00\x00bad", "b.ts": b"const x = '\xe9';\n", "package.json": "{not json"}) as root:
            p = walker.Project(root)
            for f in p.files:
                p.text(f)
            self.assertEqual(p.package, {})
            self.assertTrue(p.warnings)


if __name__ == "__main__":
    unittest.main()
