"""Redaction of secret values. Nothing the scanners print may contain a secret.

``redact(value)`` shortens one value; ``redact_text(text)`` finds every
credential-shaped value in a string and replaces it. The ``Finding``
constructor calls ``redact_text`` on every free-text field, so a finding
cannot be built with an unredacted secret.
"""
from __future__ import annotations

import re

from . import patterns

ELLIPSIS = "…"
_PEM_RE = re.compile(r"-----BEGIN ((?:[A-Z]+ )*)PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )*PRIVATE KEY-----|$)")
_PRIVATE_KEY_FIELD_RE = re.compile(r"(\"private_key\"\s*:\s*\")[^\"]*(\")")


def redact(value: str) -> str:
    """First four characters, an ellipsis, the last two, and the length."""
    n = len(value)
    if n < 12:
        return "[redacted] (%d chars)" % n
    return "%s%s%s (%d chars)" % (value[:4], ELLIPSIS, value[-2:], n)


def redact_text(text: str) -> str:
    """Replace every credential-shaped value in ``text`` with its redacted form."""
    if not text:
        return text
    text = _PEM_RE.sub(lambda m: "-----BEGIN %sPRIVATE KEY----- [redacted]" % m.group(1), text)
    text = _PRIVATE_KEY_FIELD_RE.sub(lambda m: m.group(1) + "[redacted]" + m.group(2), text)
    matches = [m for m in patterns.find_secrets(text) if m.pattern.id != "private-key"]
    if not matches:
        return text
    out = []
    pos = 0
    for m in matches:
        if m.start < pos:
            continue
        out.append(text[pos:m.start])
        out.append(redact(m.value))
        pos = m.end
    out.append(text[pos:])
    return "".join(out)
