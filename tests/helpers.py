"""Shared helpers for the test suite. Standard library only."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from typing import Any, Dict, Iterable, List, Optional

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(REPO, "skills", "prodready")
SCRIPTS = os.path.join(SKILL, "scripts")
FIXTURES = os.path.join(REPO, "fixtures")

if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

os.environ.setdefault("PRODREADY_FIXED_TIME", "2026-01-01T00:00:00Z")

from lib import walker  # noqa: E402

FIXTURE_NAMES = [
    "lovable-supabase-vite", "nextjs-supabase-stripe", "nextjs-prisma-authjs", "firebase-react", "express-mongo-jwt",
    "nextjs-ai-chat", "expo-supabase", "clean-nextjs-supabase", "clean-vite-firebase",
]
CLEAN_FIXTURES = ["clean-nextjs-supabase", "clean-vite-firebase"]


def fake(*parts: str) -> str:
    """Join parts into a key-shaped test value, so no test file holds a complete key literal."""
    return "".join(parts)


def write_tree(root: str, files: Dict[str, str]) -> None:
    for rel, content in files.items():
        full = os.path.join(root, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        if isinstance(content, bytes):
            with open(full, mode) as fh:
                fh.write(content)
        else:
            with open(full, mode, encoding="utf-8", newline="\n") as fh:
                fh.write(content)


class TempApp:
    """A temporary app directory built from a dict of path -> content."""

    def __init__(self, files: Dict[str, str]) -> None:
        self.dir = tempfile.mkdtemp(prefix="prodready-test-")
        write_tree(self.dir, files)

    def __enter__(self) -> str:
        return self.dir

    def __exit__(self, *exc: Any) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


def run_scanner(module_name: str, root: str, config: Optional[dict] = None) -> Dict[str, Any]:
    """Run one scanner in-process on a directory and return its JSON document."""
    import importlib

    import detect_stack

    module = importlib.import_module(module_name)
    project = walker.Project(root)
    if config:
        project.config.update(config)
    stack = detect_stack.detect(project)
    project.stack = stack
    return module.scan(project.root, stack, project).to_dict()


def scan_files(module_name: str, files: Dict[str, str], config: Optional[dict] = None) -> Dict[str, Any]:
    with TempApp(files) as root:
        return run_scanner(module_name, root, config)


def ids(doc: Dict[str, Any]) -> List[str]:
    return [f["check_id"] for f in doc["findings"]]


def find(doc: Dict[str, Any], check_id: str, file: Optional[str] = None) -> List[Dict[str, Any]]:
    return [f for f in doc["findings"] if f["check_id"] == check_id and (file is None or f.get("file") == file)]


class ScannerCase(unittest.TestCase):
    """Base class: table-driven positive and negative cases for one scanner."""

    scanner = ""

    def assertFinds(self, check_id: str, files: Dict[str, str], file: Optional[str] = None, confidence: Optional[str] = None, config: Optional[dict] = None) -> Dict[str, Any]:
        doc = scan_files(self.scanner, files, config)
        hits = find(doc, check_id, file)
        self.assertTrue(hits, "%s expected %s%s, got %s" % (self.scanner, check_id, " in " + file if file else "", sorted(set(ids(doc)))))
        if confidence:
            self.assertIn(confidence, [h["confidence"] for h in hits])
        return hits[0]

    def assertClean(self, check_id: str, files: Dict[str, str], config: Optional[dict] = None) -> None:
        doc = scan_files(self.scanner, files, config)
        hits = find(doc, check_id)
        self.assertFalse(hits, "%s unexpectedly reported %s: %s" % (self.scanner, check_id, [(h.get("file"), h.get("snippet")) for h in hits]))


def fixture_path(name: str) -> str:
    return os.path.join(FIXTURES, name)


def load_expected(name: str) -> Dict[str, Any]:
    with open(os.path.join(fixture_path(name), "expected.json"), "r", encoding="utf-8") as fh:
        return json.load(fh)
