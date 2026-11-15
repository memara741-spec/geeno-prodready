"""Run every scanner on every fixture and compare with expected.json."""
import os
import sys
import unittest

import helpers  # noqa: F401

sys.path.insert(0, os.path.join(helpers.REPO, "tools"))
import expect  # noqa: E402


class FixturesExpected(unittest.TestCase):
    def test_all_fixtures(self):
        modules = expect.available()
        for name in helpers.FIXTURE_NAMES:
            with self.subTest(fixture=name):
                doc = expect.scan_fixture(name, modules)
                r = expect.evaluate(name, doc)
                self.assertEqual(r["missing"], [], "missing findings")
                self.assertEqual(r["forbidden"], [], "forbidden findings")
                self.assertLessEqual(len(r["fp_crit"]), r["limit"], "false-positive criticals")
                self.assertEqual(r["over"], [], "findings above the severity cap")

    def test_no_planted_secret_in_output(self):
        import json
        modules = expect.available()
        for name in helpers.FIXTURE_NAMES:
            planted = helpers.load_expected(name).get("planted_secrets", [])
            blob = json.dumps(expect.scan_fixture(name, modules))
            for s in planted:
                self.assertNotIn(s, blob, "%s leaked a planted secret" % name)


if __name__ == "__main__":
    unittest.main()
