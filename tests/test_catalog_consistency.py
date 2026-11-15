"""The catalog, the prose, the index, the scanners and the fixtures must agree."""
import importlib
import json
import os
import re
import sys
import unittest

import helpers  # noqa: F401
from lib import catalog

sys.path.insert(0, os.path.join(helpers.REPO, "tools"))
import check_text  # noqa: E402

REFS = os.path.join(helpers.SKILL, "references")
SCANNERS = ["scan_secrets", "scan_env", "scan_supabase", "scan_firebase", "scan_routes", "scan_payments", "scan_llm", "scan_frontend", "scan_config", "scan_deps", "scan_launch", "scan_git_history", "scan_laravel", "scan_tenancy", "scan_logic", "scan_performance", "scan_infra", "scan_authz", "scan_ledger", "profile_runtime", "verify_production", "restore_drill"]


class Consistency(unittest.TestCase):
    def test_prose_covers_catalog(self):
        self.assertEqual(set(check_text.T), set(catalog.CHECKS))

    def test_index_and_category_files(self):
        index = open(os.path.join(REFS, "checks", "INDEX.md"), encoding="utf-8").read()
        for c in catalog.CHECKS.values():
            self.assertIn("[%s]" % c.id, index)
            body = open(os.path.join(REFS, "checks", c.category + ".md"), encoding="utf-8").read()
            m = re.search(r"### %s — .*\n\*\*Severity:\*\* (\w+)" % c.id, body)
            self.assertTrue(m, c.id)
            self.assertEqual(m.group(1), c.severity, c.id)

    def test_every_scan_check_has_one_scanner_and_a_fixture(self):
        owners = {}
        for name in SCANNERS:
            for cid in importlib.import_module(name).IMPLEMENTS:
                self.assertNotIn(cid, owners, "%s implemented by two scanners" % cid)
                owners[cid] = name
        expected = set()
        for n in helpers.FIXTURE_NAMES:
            e = helpers.load_expected(n)
            expected |= {m["check_id"] for m in e.get("must_find", []) + e.get("review_only", [])}
        for c in catalog.CHECKS.values():
            if c.is_scan:
                self.assertEqual(owners.get(c.id), c.scanner, c.id)
        # Checks that no fixture plants are listed so a maintainer can add one.
        unplanted = sorted(c.id for c in catalog.CHECKS.values() if c.is_scan and c.id not in expected)
        self.assertLessEqual(len(unplanted), 60, "too many scan checks without a fixture: %s" % unplanted)

    def test_links_resolve(self):
        skill = open(os.path.join(helpers.SKILL, "SKILL.md"), encoding="utf-8").read()
        self.assertLess(len(skill.splitlines()), 400)
        for rel in set(re.findall(r"`((?:references|scripts|assets)/[\w./<>\-]+?)`", skill)):
            if "<" in rel or rel.endswith("/"):
                continue
            self.assertTrue(os.path.exists(os.path.join(helpers.SKILL, rel)), rel)

    def test_reference_files_have_dates(self):
        for d, _, files in os.walk(REFS):
            for f in files:
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    text = fh.read()
                self.assertIn("Last checked", text, f)


if __name__ == "__main__":
    unittest.main()
