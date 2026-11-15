# prodready maintainer commands. Everything here uses only the Python standard library.
# On Windows without make, run the python commands directly (see CONTRIBUTING.md).

PYTHON ?= python3
SKILL := skills/prodready
SCRIPTS := $(SKILL)/scripts

.PHONY: test lint package demo fixtures-scan check-version clean help

help:
	@echo "make test           run the whole test suite"
	@echo "make lint           byte-compile every script (and run ruff if installed)"
	@echo "make package        build dist/prodready-skill.zip"
	@echo "make demo           regenerate docs/demo/sample-report.md and .html"
	@echo "make fixtures-scan  scan every fixture into dist/fixture-findings/"
	@echo "make check-version  check manifests and changelog against the tool version"

test:
	$(PYTHON) -m unittest discover -s tests -t tests

lint:
	$(PYTHON) -m compileall -q $(SCRIPTS) tests tools
	@$(PYTHON) -m ruff --version >/dev/null 2>&1 && $(PYTHON) -m ruff check $(SCRIPTS) tests tools || echo "ruff not installed; skipped (optional)"

package:
	$(PYTHON) tools/package.py

demo:
	$(PYTHON) tools/make_demo.py

fixtures-scan:
	$(PYTHON) tools/scan_fixtures.py

check-version:
	$(PYTHON) tools/check_version.py

clean:
	$(PYTHON) -c "import shutil; shutil.rmtree('dist', ignore_errors=True)"
